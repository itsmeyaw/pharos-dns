use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, ErrorKind},
    os::unix::fs::FileExt,
};

const HEADER: usize = 16;
const META_LEN: usize = 80;
const LEAF: u16 = 2;
const BRANCH: u16 = 1;
const META: u16 = 4;
const FREELIST: u16 = 16;
const BUCKET: u32 = 1;
const MAGIC: u32 = 0xed0c_daed;
const VERSION: u32 = 2;
const BUCKET_NAME: &[u8] = b"dynupdate-v1";

fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "invalid bbolt database")
}

fn u16_at(data: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        data.get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u32_at(data: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        data.get(offset..offset + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u64_at(data: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u64::from_ne_bytes(
        data.get(offset..offset + 8)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}
fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}
fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

// bbolt v1.5.0 internal/common/meta.go:60-64: meta checksums use FNV-1a over the metadata before checksum.
fn checksum(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
    })
}

#[derive(Clone, Copy)]
struct MetaPage {
    page_size: usize,
    root: u64,
    sequence: u64,
    freelist: u64,
    high: u64,
    txid: u64,
}

impl MetaPage {
    // bbolt v1.5.0 internal/common/meta.go:12-33: validate magic, version and checksum before trusting a meta page.
    fn parse(data: &[u8], id: u64) -> io::Result<Self> {
        if data.len() < META_LEN
            || u64_at(data, 0)? != id
            || u16_at(data, 8)? != META
            || u32_at(data, 16)? != MAGIC
            || u32_at(data, 20)? != VERSION
            || u64_at(data, 72)? != checksum(&data[16..72])
        {
            return Err(invalid());
        }
        let page_size = u32_at(data, 24)? as usize;
        let meta = Self {
            page_size,
            root: u64_at(data, 32)?,
            sequence: u64_at(data, 40)?,
            freelist: u64_at(data, 48)?,
            high: u64_at(data, 56)?,
            txid: u64_at(data, 64)?,
        };
        if !(1024..=16 * 1024 * 1024).contains(&page_size)
            || !page_size.is_power_of_two()
            || meta.root < 2
            || meta.root >= meta.high
            || meta.freelist < 2
            || meta.freelist >= meta.high
        {
            return Err(invalid());
        }
        Ok(meta)
    }

    // bbolt v1.5.0 internal/common/meta.go:41-57: the transaction ID chooses the meta slot.
    fn encode(self) -> Vec<u8> {
        let mut data = vec![0; self.page_size];
        put64(&mut data, 0, self.txid % 2);
        put16(&mut data, 8, META);
        put32(&mut data, 16, MAGIC);
        put32(&mut data, 20, VERSION);
        put32(&mut data, 24, self.page_size as u32);
        put64(&mut data, 32, self.root);
        put64(&mut data, 40, self.sequence);
        put64(&mut data, 48, self.freelist);
        put64(&mut data, 56, self.high);
        put64(&mut data, 64, self.txid);
        let sum = checksum(&data[16..72]);
        put64(&mut data, 72, sum);
        data
    }
}

struct Store {
    file: File,
    meta: MetaPage,
}

type Entries = BTreeMap<Vec<u8>, (u32, Vec<u8>)>;

impl Store {
    // bbolt v1.5.0 db.go:646-684: an empty database starts with two metas, an empty freelist and an empty root leaf.
    fn create(file: File) -> io::Result<Self> {
        let mut meta = MetaPage {
            page_size: 4096,
            root: 3,
            sequence: 0,
            freelist: 2,
            high: 4,
            txid: 0,
        };
        file.write_all_at(&meta.encode(), 0)?;
        meta.txid = 1;
        file.write_all_at(&meta.encode(), 4096)?;
        let mut free = vec![0; 4096];
        put64(&mut free, 0, 2);
        put16(&mut free, 8, FREELIST);
        file.write_all_at(&free, 8192)?;
        let mut root = vec![0; 4096];
        put64(&mut root, 0, 3);
        put16(&mut root, 8, LEAF);
        file.write_all_at(&root, 12288)?;
        file.sync_all()?;
        Ok(Self { file, meta })
    }

    // bbolt v1.5.0 db.go:329-414: if the first meta is invalid, find the second at a possible page boundary.
    fn open(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        let mut buf = [0; META_LEN];
        file.read_exact_at(&mut buf, 0)?;
        let first = MetaPage::parse(&buf, 0).ok();
        let sizes: Vec<usize> = first
            .map(|meta| vec![meta.page_size])
            .unwrap_or_else(|| (0..=14).map(|n| 1024usize << n).collect());
        let mut second = None;
        for size in sizes {
            if (size as u64).saturating_add(META_LEN as u64) > len {
                continue;
            }
            if file.read_exact_at(&mut buf, size as u64).is_ok()
                && let Ok(meta) = MetaPage::parse(&buf, 1)
                && meta.page_size == size
            {
                second = Some(meta);
                break;
            }
        }
        let meta = match (first, second) {
            (Some(a), Some(b)) => {
                if b.txid > a.txid {
                    b
                } else {
                    a
                }
            }
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => return Err(invalid()),
        };
        if meta
            .high
            .checked_mul(meta.page_size as u64)
            .is_none_or(|end| end > len)
        {
            return Err(invalid());
        }
        Ok(Self { file, meta })
    }

    // bbolt v1.5.0 internal/common/page.go:31-36: overflow pages immediately follow their header page.
    fn page(&self, id: u64) -> io::Result<Vec<u8>> {
        if id < 2 || id >= self.meta.high {
            return Err(invalid());
        }
        let offset = id
            .checked_mul(self.meta.page_size as u64)
            .ok_or_else(invalid)?;
        let mut header = [0; HEADER];
        self.file.read_exact_at(&mut header, offset)?;
        let count = u64::from(u32_at(&header, 12)?) + 1;
        if u64_at(&header, 0)? != id || id.checked_add(count).is_none_or(|end| end > self.meta.high)
        {
            return Err(invalid());
        }
        let len = usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(self.meta.page_size))
            .ok_or_else(invalid)?;
        let mut data = vec![0; len];
        self.file.read_exact_at(&mut data, offset)?;
        Ok(data)
    }

    fn tree(&self, root: u64, pages: &mut BTreeSet<u64>) -> io::Result<Entries> {
        let mut entries = Entries::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            let data = self.page(id)?;
            let overflow = u64::from(u32_at(&data, 12)?);
            for page in id..=id + overflow {
                if !pages.insert(page) {
                    return Err(invalid());
                }
            }
            match u16_at(&data, 8)? {
                LEAF => {
                    for (key, value) in leaf_entries(&data)? {
                        if entries.insert(key, value).is_some() {
                            return Err(invalid());
                        }
                    }
                }
                BRANCH => {
                    let count = usize::from(u16_at(&data, 10)?);
                    if HEADER
                        .checked_add(count.checked_mul(16).ok_or_else(invalid)?)
                        .is_none_or(|end| end > data.len())
                    {
                        return Err(invalid());
                    }
                    for index in 0..count {
                        pending.push(u64_at(&data, HEADER + index * 16 + 8)?);
                    }
                }
                _ => return Err(invalid()),
            }
        }
        Ok(entries)
    }

    fn contents(&self) -> io::Result<(Entries, Entries, BTreeSet<u64>)> {
        let mut pages = BTreeSet::new();
        let root = self.tree(self.meta.root, &mut pages)?;
        let (flags, data) = root.get(BUCKET_NAME).ok_or_else(invalid)?;
        if flags & BUCKET == 0 || data.len() < 16 {
            return Err(invalid());
        }
        // bbolt v1.5.0 internal/common/bucket.go:10-17: small buckets may store a leaf inline after the bucket header.
        let id = u64_at(data, 0)?;
        let contents = if id == 0 {
            leaf_entries(data.get(16..).ok_or_else(invalid)?)?
        } else {
            self.tree(id, &mut pages)?
        };
        Ok((root, contents, pages))
    }

    fn read(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let (_, contents, _) = self.contents()?;
        let get = |key: &[u8]| {
            contents
                .get(key)
                .filter(|(flags, _)| *flags == 0)
                .map(|(_, value)| value.clone())
                .ok_or_else(invalid)
        };
        Ok((get(b"origin")?, get(b"records")?))
    }

    fn free_pages(&self) -> io::Result<(BTreeSet<u64>, u64)> {
        let data = self.page(self.meta.freelist)?;
        if u16_at(&data, 8)? != FREELIST {
            return Err(invalid());
        }
        // bbolt v1.5.0 internal/common/page.go:115-130: a count of 65535 stores the actual count in the first entry.
        let count = u16_at(&data, 10)?;
        let (start, count) = if count == u16::MAX {
            (
                24usize,
                usize::try_from(u64_at(&data, 16)?).map_err(|_| invalid())?,
            )
        } else {
            (16usize, usize::from(count))
        };
        if start
            .checked_add(count.checked_mul(8).ok_or_else(invalid)?)
            .is_none_or(|end| end > data.len())
        {
            return Err(invalid());
        }
        let mut free = BTreeSet::new();
        for index in 0..count {
            let id = u64_at(&data, start + index * 8)?;
            if id < 2 || id >= self.meta.high || !free.insert(id) {
                return Err(invalid());
            }
        }
        Ok((free, u64::from(u32_at(&data, 12)?)))
    }

    fn commit(&mut self, origin: &[u8], records: &[u8]) -> io::Result<()> {
        let (mut root, mut contents, old_pages) = match self.contents() {
            Ok(value) => value,
            Err(_) => {
                let mut pages = BTreeSet::new();
                let root = self.tree(self.meta.root, &mut pages)?;
                if root.contains_key(BUCKET_NAME) {
                    return Err(invalid());
                }
                (root, Entries::new(), pages)
            }
        };
        contents.insert(b"origin".to_vec(), (0, origin.to_vec()));
        contents.insert(b"records".to_vec(), (0, records.to_vec()));
        let (mut free, old_free_overflow) = self.free_pages()?;
        if old_pages.iter().any(|id| free.contains(id))
            || (self.meta.freelist..=self.meta.freelist + old_free_overflow)
                .any(|id| free.contains(&id) || old_pages.contains(&id))
        {
            return Err(invalid());
        }
        let mut high = self.meta.high;
        let needed = leaf_size(&contents)?;
        let count = needed.div_ceil(self.meta.page_size);
        let bucket_id = allocate(&mut free, &mut high, count)?;
        let mut bucket_header = vec![0; 16];
        put64(&mut bucket_header, 0, bucket_id);
        if let Some((_, previous)) = root.get(BUCKET_NAME)
            && previous.len() >= 16
        {
            bucket_header[8..16].copy_from_slice(&previous[8..16]);
        }
        root.insert(BUCKET_NAME.to_vec(), (BUCKET, bucket_header));
        let root_count = leaf_size(&root)?.div_ceil(self.meta.page_size);
        let root_id = allocate(&mut free, &mut high, root_count)?;
        // Include old pages and one overflow count when sizing the next freelist.
        let possible_free = free
            .len()
            .checked_add(old_pages.len())
            .and_then(|n| n.checked_add(old_free_overflow as usize + 1))
            .ok_or_else(invalid)?;
        let free_bytes = HEADER
            .checked_add(8)
            .and_then(|n| n.checked_add(possible_free.checked_mul(8)?))
            .ok_or_else(invalid)?;
        let free_count = free_bytes.div_ceil(self.meta.page_size);
        // bbolt v1.5.0 tx.go:217-232: the new freelist must not overwrite pages reachable by the current meta.
        let free_id = allocate(&mut free, &mut high, free_count)?;
        free.extend(old_pages);
        free.extend(self.meta.freelist..=self.meta.freelist + old_free_overflow);
        let mut freelist = vec![0; free_count * self.meta.page_size];
        put64(&mut freelist, 0, free_id);
        put16(&mut freelist, 8, FREELIST);
        put32(&mut freelist, 12, (free_count - 1) as u32);
        let start = if free.len() >= usize::from(u16::MAX) {
            put16(&mut freelist, 10, u16::MAX);
            put64(&mut freelist, 16, free.len() as u64);
            24
        } else {
            put16(&mut freelist, 10, free.len() as u16);
            16
        };
        for (index, id) in free.into_iter().enumerate() {
            put64(&mut freelist, start + index * 8, id);
        }
        self.file.write_all_at(
            &encode_leaf(bucket_id, count, self.meta.page_size, &contents)?,
            bucket_id * self.meta.page_size as u64,
        )?;
        self.file.write_all_at(
            &encode_leaf(root_id, root_count, self.meta.page_size, &root)?,
            root_id * self.meta.page_size as u64,
        )?;
        self.file
            .write_all_at(&freelist, free_id * self.meta.page_size as u64)?;
        // bbolt v1.5.0 tx.go:244-273: flush all new pages before writing and syncing the next meta page.
        self.file.sync_all()?;
        let next = MetaPage {
            root: root_id,
            freelist: free_id,
            high,
            txid: self.meta.txid.checked_add(1).ok_or_else(invalid)?,
            ..self.meta
        };
        self.file
            .write_all_at(&next.encode(), (next.txid % 2) * next.page_size as u64)?;
        self.file.sync_all()?;
        self.meta = next;
        Ok(())
    }
}

// bbolt v1.5.0 internal/common/page.go:193-247: each leaf element's position is relative to the element itself.
fn leaf_entries(data: &[u8]) -> io::Result<Entries> {
    if data.len() < HEADER || u16_at(data, 8)? != LEAF {
        return Err(invalid());
    }
    let count = usize::from(u16_at(data, 10)?);
    if HEADER
        .checked_add(count.checked_mul(16).ok_or_else(invalid)?)
        .is_none_or(|end| end > data.len())
    {
        return Err(invalid());
    }
    let mut entries = Entries::new();
    for index in 0..count {
        let element = HEADER + index * 16;
        let flags = u32_at(data, element)?;
        let start = element
            .checked_add(u32_at(data, element + 4)? as usize)
            .ok_or_else(invalid)?;
        let mid = start
            .checked_add(u32_at(data, element + 8)? as usize)
            .ok_or_else(invalid)?;
        let end = mid
            .checked_add(u32_at(data, element + 12)? as usize)
            .ok_or_else(invalid)?;
        let key = data.get(start..mid).ok_or_else(invalid)?.to_vec();
        let value = data.get(mid..end).ok_or_else(invalid)?.to_vec();
        if entries.insert(key, (flags, value)).is_some() {
            return Err(invalid());
        }
    }
    Ok(entries)
}

fn leaf_size(entries: &Entries) -> io::Result<usize> {
    if entries.len() > usize::from(u16::MAX) {
        return Err(invalid());
    }
    entries
        .iter()
        .try_fold(HEADER + entries.len() * 16, |size, (key, (_, value))| {
            size.checked_add(key.len())?.checked_add(value.len())
        })
        .ok_or_else(invalid)
}

fn encode_leaf(id: u64, count: usize, size: usize, entries: &Entries) -> io::Result<Vec<u8>> {
    let mut data = vec![0; count.checked_mul(size).ok_or_else(invalid)?];
    put64(&mut data, 0, id);
    put16(&mut data, 8, LEAF);
    put16(
        &mut data,
        10,
        entries.len().try_into().map_err(|_| invalid())?,
    );
    put32(
        &mut data,
        12,
        (count - 1).try_into().map_err(|_| invalid())?,
    );
    let mut offset = HEADER + entries.len() * 16;
    for (index, (key, (flags, value))) in entries.iter().enumerate() {
        let element = HEADER + index * 16;
        put32(&mut data, element, *flags);
        put32(
            &mut data,
            element + 4,
            (offset - element).try_into().map_err(|_| invalid())?,
        );
        put32(
            &mut data,
            element + 8,
            key.len().try_into().map_err(|_| invalid())?,
        );
        put32(
            &mut data,
            element + 12,
            value.len().try_into().map_err(|_| invalid())?,
        );
        data[offset..offset + key.len()].copy_from_slice(key);
        offset += key.len();
        data[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len();
    }
    Ok(data)
}

fn allocate(free: &mut BTreeSet<u64>, high: &mut u64, count: usize) -> io::Result<u64> {
    let count = u64::try_from(count).map_err(|_| invalid())?;
    let found = free.iter().copied().find(|start| {
        (0..count).all(|offset| {
            start
                .checked_add(offset)
                .is_some_and(|id| free.contains(&id))
        })
    });
    if let Some(start) = found {
        for offset in 0..count {
            free.remove(&(start + offset));
        }
        Ok(start)
    } else {
        let start = *high;
        *high = high.checked_add(count).ok_or_else(invalid)?;
        Ok(start)
    }
}

#[cfg(test)]
mod tests {
    use super::Store;
    use std::{
        fs::OpenOptions,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-bbolt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn go(mode: &str, path: &std::path::Path) -> Option<std::process::Output> {
        match Command::new("go")
            .args(["run", ".", mode])
            .arg(path)
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/bbolt"))
            .output()
        {
            Ok(output) => Some(output),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping bbolt interop: Go is not installed");
                None
            }
            Err(error) => panic!("failed to run Go: {error}"),
        }
    }

    #[test]
    fn rejects_existing_unrecognized_database() {
        let path = path();
        std::fs::write(&path, b"not a bbolt database").unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(Store::open(file).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reads_go_bbolt_database() {
        let path = path();
        let Some(output) = go("write", &path) else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let store = Store::open(file).unwrap();
        assert_eq!(
            store.read().unwrap(),
            (b"example.org.".to_vec(), b"record data".to_vec())
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn go_reads_written_bbolt_database_after_many_commits() {
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        for _ in 0..20 {
            store.commit(b"example.org.", b"record data").unwrap();
        }
        drop(store);
        let Some(output) = go("read", &path) else {
            std::fs::remove_file(path).unwrap();
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"example.org.\nrecord data\n");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn repeated_small_commits_reuse_free_pages() {
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        for _ in 0..100 {
            store.commit(b"example.org.", b"record data").unwrap();
        }
        assert!(store.file.metadata().unwrap().len() <= 4096 * 12);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn preserves_go_branch_and_other_buckets_after_commit() {
        let path = path();
        let Some(output) = go("write-complex", &path) else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut store = Store::open(file).unwrap();
        assert_eq!(
            store.read().unwrap(),
            (b"example.org.".to_vec(), b"record data".to_vec())
        );
        store.commit(b"example.org.", b"record data").unwrap();
        drop(store);
        let output = go("verify-complex", &path).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_file(path).unwrap();
    }
}
