#![forbid(unsafe_code)]
//! A small durable ordered key-value store in one file.
//!
//! The whole state lives in memory. Durability comes from a checksummed
//! snapshot plus an append-only log that is *overwritten in place* in a
//! pre-zeroed region, so a commit is one write and one `fdatasync` of
//! already-allocated blocks, with no file-size change.
//!
//! File layout: two header blocks, then a log region and two snapshot slots.
//! A header names the live snapshot, its hash, and the three regions. A
//! snapshot is written to the idle slot and published by writing the other
//! header block; the older header stays valid until then, so a crash leaves
//! the old or the new state. Log records chain their checksum from the
//! snapshot hash, so records left over from an earlier log are never replayed.
//!
//! After any write or sync error the store is poisoned and refuses further
//! commits: a failed `fsync` may have dropped dirty pages, so retrying could
//! report success for data that never reached the disk.
#![deny(missing_docs)]

use aws_lc_rs::digest::{Context, SHA256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, ErrorKind},
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const BLOCK: u64 = 4096;
const DATA_START: u64 = 2 * BLOCK;
const HEADER_MAGIC: &[u8; 8] = b"PHKVHDR1";
const HEADER_LEN: usize = 120;
const RECORD_MAGIC: u32 = 0x5048_4b52;
const RECORD_HEAD: usize = 48;
const MIN_LOG: u64 = 1 << 20;
const MIN_HEADROOM: u64 = 256 << 10;
const PUT: u8 = 1;
const DELETE: u8 = 2;

type Hash = [u8; 32];

/// One change inside an atomic batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Set `key` to `value`.
    Put(Vec<u8>, Vec<u8>),
    /// Remove `key`; removing a missing key is not an error.
    Delete(Vec<u8>),
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("pharos-kv: {message}"))
}

fn round_up(n: u64) -> u64 {
    n.div_ceil(BLOCK) * BLOCK
}

fn sha(parts: &[&[u8]]) -> Hash {
    let mut context = Context::new(&SHA256);
    for part in parts {
        context.update(part);
    }
    let mut out = [0; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Region {
    off: u64,
    cap: u64,
}

impl Region {
    fn end(self) -> u64 {
        self.off + self.cap
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    generation: u64,
    seq: u64,
    live: usize,
    snap_len: u64,
    snap_hash: Hash,
    log: Region,
    snap: [Region; 2],
}

impl Header {
    fn slot(&self) -> u64 {
        (self.generation % 2) * BLOCK
    }

    fn end(&self) -> u64 {
        self.log
            .end()
            .max(self.snap[0].end())
            .max(self.snap[1].end())
    }

    fn chain_seed(&self) -> Hash {
        sha(&[&self.snap_hash, &self.generation.to_le_bytes()])
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(BLOCK as usize);
        b.extend_from_slice(HEADER_MAGIC);
        for v in [self.generation, self.seq, self.live as u64, self.snap_len] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.snap_hash);
        for r in [self.log, self.snap[0], self.snap[1]] {
            b.extend_from_slice(&r.off.to_le_bytes());
            b.extend_from_slice(&r.cap.to_le_bytes());
        }
        let check = sha(&[&b]);
        b.extend_from_slice(&check);
        b.resize(BLOCK as usize, 0);
        b
    }

    fn decode(b: &[u8]) -> Option<Header> {
        let body = b.get(..HEADER_LEN)?;
        if &body[..8] != HEADER_MAGIC || sha(&[body])[..] != *b.get(HEADER_LEN..HEADER_LEN + 32)? {
            return None;
        }
        let u = |i: usize| -> Option<u64> {
            Some(u64::from_le_bytes(body.get(i..i + 8)?.try_into().ok()?))
        };
        let region = |i: usize| {
            Some(Region {
                off: u(i)?,
                cap: u(i + 8)?,
            })
        };
        let live = usize::try_from(u(24)?).ok().filter(|live| *live < 2)?;
        Some(Header {
            generation: u(8)?,
            seq: u(16)?,
            live,
            snap_len: u(32)?,
            snap_hash: body.get(40..72)?.try_into().ok()?,
            log: region(72)?,
            snap: [region(88)?, region(104)?],
        })
    }
}

#[cfg(test)]
#[derive(Default)]
struct Fault {
    count: std::sync::atomic::AtomicUsize,
    at: std::sync::atomic::AtomicUsize,
    torn: std::sync::atomic::AtomicBool,
    dead: std::sync::atomic::AtomicBool,
    // 'w' + offset for every write, 's' for every sync, in call order.
    events: std::sync::Mutex<Vec<(char, u64)>>,
}

#[cfg(test)]
impl Fault {
    // Simulates a crash: the Nth I/O call and everything after it never happens.
    fn crash_now(&self) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        if self.dead.load(SeqCst) {
            return true;
        }
        let n = self.count.fetch_add(1, SeqCst);
        let hit = n >= self.at.load(SeqCst);
        if hit {
            self.dead.store(true, SeqCst);
        }
        hit
    }
}

struct Io {
    file: File,
    #[cfg(test)]
    fault: Fault,
}

impl Io {
    fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(test)]
            fault: Fault {
                at: usize::MAX.into(),
                ..Fault::default()
            },
        }
    }

    fn write_at(&self, buf: &[u8], off: u64) -> io::Result<()> {
        #[cfg(test)]
        self.fault.events.lock().unwrap().push(('w', off));
        #[cfg(test)]
        if self.fault.crash_now() {
            if self.fault.torn.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = self.file.write_all_at(&buf[..buf.len() / 2], off);
            }
            return Err(io::Error::other("injected crash"));
        }
        self.file.write_all_at(buf, off)
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(test)]
        self.fault.events.lock().unwrap().push(('s', 0));
        #[cfg(test)]
        if self.fault.crash_now() {
            return Err(io::Error::other("injected crash"));
        }
        self.file.sync_all()
    }

    fn sync_data(&self) -> io::Result<()> {
        #[cfg(test)]
        self.fault.events.lock().unwrap().push(('s', 0));
        #[cfg(test)]
        if self.fault.crash_now() {
            return Err(io::Error::other("injected crash"));
        }
        self.file.sync_data()
    }

    fn read_at(&self, len: u64, off: u64) -> io::Result<Vec<u8>> {
        let end = off
            .checked_add(len)
            .ok_or_else(|| invalid(format!("region at {off} of length {len} overflows")))?;
        if end > self.file.metadata()?.len() {
            return Err(invalid(format!(
                "region at {off} of length {len} is beyond the end of the file"
            )));
        }
        let mut buf = vec![0; usize::try_from(len).map_err(|_| invalid("region too large"))?];
        self.file.read_exact_at(&mut buf, off)?;
        Ok(buf)
    }

    fn zero_fill(&self, off: u64, len: u64) -> io::Result<()> {
        let chunk = vec![0u8; 64 << 10];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(chunk.len() as u64);
            self.write_at(&chunk[..n as usize], off + done)?;
            done += n;
        }
        Ok(())
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| invalid("truncated data"))?;
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> io::Result<usize> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
}

fn put_entry(out: &mut Vec<u8>, key: &[u8], value: &[u8]) -> io::Result<()> {
    let (k, v) = (u32::try_from(key.len()), u32::try_from(value.len()));
    let (Ok(k), Ok(v)) = (k, v) else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "pharos-kv: key or value over 4 GiB",
        ));
    };
    out.extend_from_slice(&k.to_le_bytes());
    out.extend_from_slice(&v.to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    Ok(())
}

fn encode_snapshot(map: &BTreeMap<Vec<u8>, Vec<u8>>) -> io::Result<Vec<u8>> {
    let mut out = (map.len() as u64).to_le_bytes().to_vec();
    for (k, v) in map {
        put_entry(&mut out, k, v)?;
    }
    Ok(out)
}

fn decode_snapshot(data: &[u8]) -> io::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut cursor = Cursor(data);
    let count = u64::from_le_bytes(
        cursor
            .take(8)?
            .try_into()
            .map_err(|_| invalid("truncated data"))?,
    );
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let (k, v) = (cursor.u32()?, cursor.u32()?);
        let key = cursor.take(k)?.to_vec();
        map.insert(key, cursor.take(v)?.to_vec());
    }
    if !cursor.0.is_empty() {
        return Err(invalid("trailing bytes after snapshot"));
    }
    Ok(map)
}

fn encode_ops(ops: &[Op]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            Op::Put(k, v) => {
                out.push(PUT);
                put_entry(&mut out, k, v)?;
            }
            Op::Delete(k) => {
                out.push(DELETE);
                put_entry(&mut out, k, &[])?;
            }
        }
    }
    Ok(out)
}

fn decode_ops(data: &[u8]) -> io::Result<Vec<Op>> {
    let mut cursor = Cursor(data);
    let mut ops = Vec::new();
    while !cursor.0.is_empty() {
        let tag = cursor.u8()?;
        let (k, v) = (cursor.u32()?, cursor.u32()?);
        let key = cursor.take(k)?.to_vec();
        let value = cursor.take(v)?.to_vec();
        ops.push(match tag {
            PUT => Op::Put(key, value),
            DELETE => Op::Delete(key),
            _ => return Err(invalid("unknown operation")),
        });
    }
    Ok(ops)
}

fn apply(map: &mut BTreeMap<Vec<u8>, Vec<u8>>, ops: impl IntoIterator<Item = Op>) {
    for op in ops {
        match op {
            Op::Put(k, v) => {
                map.insert(k, v);
            }
            Op::Delete(k) => {
                map.remove(&k);
            }
        }
    }
}

// Log sized so compaction triggers once the log reaches the snapshot size (bounds write
// amplification) or MIN_LOG, with headroom for the record that crosses the trigger.
fn trigger(snap_len: u64) -> u64 {
    snap_len.max(MIN_LOG)
}

fn log_capacity(snap_len: u64) -> u64 {
    round_up(trigger(snap_len) + MIN_HEADROOM.max(snap_len / 8))
}

fn slot_capacity(snap_len: u64) -> u64 {
    round_up(snap_len + snap_len / 4 + (64 << 10))
}

/// Take an advisory lock on `file`, shared or exclusive, waiting up to one second.
///
/// Fails with [`ErrorKind::WouldBlock`] if another process holds a conflicting lock.
pub fn lock(file: &File, shared: bool) -> io::Result<()> {
    // bbolt v1.5.0 bolt_unix.go:17-45: flock with a one-second timeout and 50 ms retries.
    let start = Instant::now();
    loop {
        let result = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match result {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < Duration::from_secs(1) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    "pharos-kv: database lock timeout",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

/// A durable ordered map of byte keys to byte values.
pub struct Db {
    io: Io,
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    header: Header,
    chain: Hash,
    seq: u64,
    log_pos: u64,
    writable: bool,
    poisoned: bool,
}

impl Db {
    /// Open or create the database at `path` with mode 0600 and an exclusive advisory lock.
    ///
    /// Waits up to one second for the lock, like bbolt.
    pub fn open_path(path: &Path) -> io::Result<Db> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        lock(&file, false)?;
        if Db::is_blank(&file)? {
            Db::create(file, &[])
        } else {
            Db::open(file)
        }
    }

    /// Whether `file` is empty or has only zeroes where the headers go.
    ///
    /// That is what a crash during [`Db::create`] leaves behind, so such a file is safe to
    /// initialise again.
    pub fn is_blank(file: &File) -> io::Result<bool> {
        let mut head = vec![0u8; DATA_START as usize];
        let mut filled = 0;
        while filled < head.len() {
            match file.read_at(&mut head[filled..], filled as u64)? {
                0 => break,
                n => filled += n,
            }
        }
        Ok(head[..filled].iter().all(|b| *b == 0))
    }

    /// Initialise an empty or blank (see [`Db::is_blank`]) `file` whose first state is `initial`.
    ///
    /// The file only becomes a database when the final header write is synced, so a
    /// crash during creation leaves a blank file that can be initialised again.
    pub fn create(file: File, initial: &[Op]) -> io::Result<Db> {
        Db::create_with(Io::new(file), initial)
    }

    fn create_with(io: Io, initial: &[Op]) -> io::Result<Db> {
        if !Db::is_blank(&io.file)? {
            return Err(invalid("file is not empty"));
        }
        io.file.set_len(0)?;
        let mut map = BTreeMap::new();
        apply(&mut map, initial.iter().cloned());
        let snapshot = encode_snapshot(&map)?;
        let len = snapshot.len() as u64;
        let log = Region {
            off: DATA_START,
            cap: log_capacity(len),
        };
        let slot = slot_capacity(len);
        let snap = [
            Region {
                off: log.end(),
                cap: slot,
            },
            Region {
                off: log.end() + slot,
                cap: slot,
            },
        ];
        let header = Header {
            generation: 0,
            seq: 0,
            live: 0,
            snap_len: len,
            snap_hash: sha(&[&snapshot]),
            log,
            snap,
        };
        io.zero_fill(log.off, log.cap)?;
        io.write_at(&snapshot, snap[0].off)?;
        io.sync()?;
        io.write_at(&header.encode(), header.slot())?;
        io.sync()?;
        Ok(Db::assemble(io, map, header, 0, 0, true))
    }

    /// Open an existing database for reading and writing, replaying its log.
    ///
    /// The caller is responsible for locking `file`; see [`Db::open_path`].
    pub fn open(file: File) -> io::Result<Db> {
        Db::recover(file, true)
    }

    /// Open an existing database for reading only; [`Db::commit`] will fail.
    pub fn open_read_only(file: File) -> io::Result<Db> {
        Db::recover(file, false)
    }

    fn assemble(
        io: Io,
        map: BTreeMap<Vec<u8>, Vec<u8>>,
        header: Header,
        seq: u64,
        log_pos: u64,
        writable: bool,
    ) -> Db {
        Db {
            chain: header.chain_seed(),
            io,
            map,
            header,
            seq,
            log_pos,
            writable,
            poisoned: false,
        }
    }

    fn recover(file: File, writable: bool) -> io::Result<Db> {
        let io = Io::new(file);
        let len = io.file.metadata()?.len();
        let blocks = io.read_at(DATA_START.min(len), 0)?;
        let mut live_header = None;
        for (index, block) in blocks.chunks(BLOCK as usize).enumerate() {
            match Header::decode(block) {
                Some(header) => {
                    if live_header
                        .as_ref()
                        .is_none_or(|best: &Header| header.generation > best.generation)
                    {
                        live_header = Some(header);
                    }
                }
                // A header is one sector, so a block that has the magic but fails its checksum
                // is rot, not a torn flip. Falling back to the other header could silently
                // drop acknowledged commits (#93 D8), so refuse instead.
                None if block.starts_with(HEADER_MAGIC) => {
                    return Err(invalid(format!("header block {index} is damaged")));
                }
                None => {}
            }
        }
        let header = live_header.ok_or_else(|| invalid("no valid header"))?;
        let regions = [header.log, header.snap[0], header.snap[1]];
        if regions
            .iter()
            .any(|r| r.off < DATA_START || r.off.checked_add(r.cap).is_none())
            || header.snap_len > header.snap[header.live].cap
        {
            return Err(invalid("header regions out of bounds"));
        }
        let snapshot = io.read_at(header.snap_len, header.snap[header.live].off)?;
        if sha(&[&snapshot]) != header.snap_hash {
            return Err(invalid("snapshot checksum mismatch"));
        }
        let mut map = decode_snapshot(&snapshot)?;
        let log = io.read_at(header.log.cap, header.log.off)?;
        let (mut pos, mut seq, mut chain) = (0usize, header.seq, header.chain_seed());
        // The log ends at the first record that is not the next link of the chain: a torn
        // write, or a leftover from before the last compaction.
        while let Some(rest) = log.get(pos..).filter(|r| r.len() >= RECORD_HEAD) {
            let mut head = Cursor(rest);
            let (magic, body_len) = (head.u32()?, head.u32()?);
            let next = u64::from_le_bytes(
                head.take(8)?
                    .try_into()
                    .map_err(|_| invalid("truncated data"))?,
            );
            let Some(body) = RECORD_HEAD
                .checked_add(body_len)
                .and_then(|end| rest.get(RECORD_HEAD..end))
            else {
                break;
            };
            if magic != RECORD_MAGIC as usize || next != seq + 1 {
                break;
            }
            // #93 D5Z: the checksum chains from the previous record and covers the framing, so a
            // stale or torn record can neither be replayed nor change the framing unnoticed.
            let check = sha(&[&chain, &rest[..16], body]);
            if check[..] != rest[16..48] {
                break;
            }
            apply(&mut map, decode_ops(body)?);
            seq = next;
            chain = check;
            pos += round_up((RECORD_HEAD + body_len) as u64) as usize;
        }
        let mut db = Db::assemble(io, map, header, seq, pos as u64, writable);
        db.chain = chain;
        Ok(db)
    }

    /// Whether `file` starts with a pharos-kv header, valid or damaged.
    ///
    /// Lets a caller that also reads another format choose the right reader and report the
    /// right error.
    pub fn looks_like_database(file: &File) -> io::Result<bool> {
        let mut magic = [0u8; 8];
        for slot in [0, BLOCK] {
            if file.read_exact_at(&mut magic, slot).is_ok() && &magic == HEADER_MAGIC {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Value stored under `key`.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.map.get(key).map(Vec::as_slice)
    }

    /// All entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.map.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the database has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn poison<T>(&mut self, error: io::Error) -> io::Result<T> {
        self.poisoned = true;
        Err(error)
    }

    /// Apply `ops` atomically and durably.
    ///
    /// Returns once the batch is synced to disk. On error nothing is visible after a
    /// reopen unless the error came after the sync, and the store refuses further commits.
    pub fn commit(&mut self, ops: &[Op]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "pharos-kv: opened read-only",
            ));
        }
        if self.poisoned {
            return Err(io::Error::other(
                "pharos-kv: store failed earlier and refuses further commits",
            ));
        }
        if ops.is_empty() {
            return Ok(());
        }
        let body = encode_ops(ops)?;
        let body_len = u32::try_from(body.len())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "pharos-kv: batch over 4 GiB"))?;
        let record_len = round_up((RECORD_HEAD + body.len()) as u64);
        if self.log_pos + record_len > self.header.log.cap {
            // The record does not fit: fold the batch into a new snapshot instead. The map is
            // updated first to avoid a copy; if the install fails the store is poisoned and
            // never commits again, so the map running ahead of the disk is harmless.
            apply(&mut self.map, ops.iter().cloned());
            let snapshot = encode_snapshot(&self.map)?;
            self.seq += 1;
            return self.install(&snapshot).or_else(|error| self.poison(error));
        }
        let seq = self.seq + 1;
        let mut record = Vec::with_capacity(record_len as usize);
        record.extend_from_slice(&RECORD_MAGIC.to_le_bytes());
        record.extend_from_slice(&body_len.to_le_bytes());
        record.extend_from_slice(&seq.to_le_bytes());
        let check = sha(&[&self.chain, &record, &body]);
        record.extend_from_slice(&check);
        record.extend_from_slice(&body);
        record.resize(record_len as usize, 0);
        let written = self
            .io
            .write_at(&record, self.header.log.off + self.log_pos)
            // POSIX.1-2017 fdatasync(): the record is on the device before the commit returns.
            .and_then(|()| self.io.sync_data());
        if let Err(error) = written {
            return self.poison(error);
        }
        apply(&mut self.map, ops.iter().cloned());
        self.seq = seq;
        self.chain = check;
        self.log_pos += record_len;
        Ok(())
    }

    /// Whether the log has grown enough that [`Db::compact`] should run.
    #[must_use]
    pub fn needs_compaction(&self) -> bool {
        self.log_pos >= trigger(self.header.snap_len)
    }

    /// Replace the log with a fresh snapshot of the current state.
    ///
    /// Call it after replying to the client: it is the slowest step of a commit cycle
    /// (a few milliseconds at 1 MiB). A failure poisons the store but loses no committed data.
    pub fn compact(&mut self) -> io::Result<()> {
        if !self.writable || self.poisoned {
            return Err(io::Error::other(
                "pharos-kv: store is read-only or failed earlier",
            ));
        }
        let snapshot = encode_snapshot(&self.map)?;
        self.install(&snapshot).or_else(|error| self.poison(error))
    }

    // shortcut: regions abandoned by a relocation are never reclaimed, so the file grows by about
    // the size of the Zone each time the Zone outgrows its slots; rewrite the file when that matters.
    // Write `snapshot` into the idle slot (a new region at the end of the file if it does not
    // fit), then publish it by flipping to the other header block.
    fn install(&mut self, snapshot: &[u8]) -> io::Result<()> {
        let len = snapshot.len() as u64;
        let idle = 1 - self.header.live;
        let mut next = self.header.clone();
        let mut end = next.end();
        if len > next.snap[idle].cap {
            next.snap[idle] = Region {
                off: end,
                cap: slot_capacity(len),
            };
            end = next.snap[idle].end();
        }
        if log_capacity(len) > next.log.cap {
            next.log = Region {
                off: end,
                cap: log_capacity(len),
            };
            self.io.zero_fill(next.log.off, next.log.cap)?;
        }
        self.io.write_at(snapshot, next.snap[idle].off)?;
        self.io.sync()?;
        next.generation += 1;
        next.seq = self.seq;
        next.live = idle;
        next.snap_len = len;
        next.snap_hash = sha(&[snapshot]);
        self.io.write_at(&next.encode(), next.slot())?;
        self.io.sync()?;
        self.chain = next.chain_seed();
        self.header = next;
        self.log_pos = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
