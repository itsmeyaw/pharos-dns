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

fn zeroed(len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| invalid())?;
    bytes.resize(len, 0);
    Ok(bytes)
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

pub(super) struct Store {
    file: File,
    meta: MetaPage,
    uncertain: bool,
    max_zone_bytes: usize,
}

type Entries = BTreeMap<Vec<u8>, (u32, Vec<u8>)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitPoint {
    BucketWritten,
    RootWritten,
    FreelistWritten,
    DataSynced,
    MetaWritten,
    MetaSynced,
}

impl Store {
    // bbolt v1.5.0 db.go:646-684: an empty database starts with two metas, an empty freelist and an empty root leaf.
    pub(super) fn create(file: File) -> io::Result<Self> {
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
        Ok(Self {
            file,
            meta,
            uncertain: false,
            max_zone_bytes: usize::MAX,
        })
    }

    // bbolt v1.5.0 db.go:329-414: if the first meta is invalid, find the second at a possible page boundary.
    pub(super) fn open(file: File) -> io::Result<Self> {
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
        Ok(Self {
            file,
            meta,
            uncertain: false,
            max_zone_bytes: usize::MAX,
        })
    }

    pub(super) fn open_limited(file: File, max_zone_bytes: usize) -> io::Result<Self> {
        let mut store = Self::open(file)?;
        store.max_zone_bytes = max_zone_bytes;
        Ok(store)
    }

    pub(super) fn set_limit(&mut self, max_zone_bytes: usize) {
        self.max_zone_bytes = max_zone_bytes;
    }

    // bbolt v1.5.0 internal/common/page.go:31-36: overflow pages immediately follow their header page.
    fn page(&self, id: u64) -> io::Result<Vec<u8>> {
        self.page_inner(id, false)
    }

    fn page_inner(&self, id: u64, zone: bool) -> io::Result<Vec<u8>> {
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
        let extent = usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(self.meta.page_size))
            .ok_or_else(invalid)?;
        let flags = u16_at(&header, 8)?;
        let entries = usize::from(u16_at(&header, 10)?);
        // bbolt v1.5.0 internal/common/page.go:193-247: element offsets bound the used part of an overflow page.
        let mut used = match flags {
            LEAF | BRANCH => {
                let table = HEADER
                    .checked_add(entries.checked_mul(16).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?;
                if table > extent {
                    return Err(invalid());
                }
                let mut descriptors = zeroed(table)?;
                self.file.read_exact_at(&mut descriptors, offset)?;
                let mut end = table;
                for index in 0..entries {
                    let element = HEADER + index * 16;
                    let (position, key_len, value_len) = if flags == LEAF {
                        (
                            u32_at(&descriptors, element + 4)?,
                            u32_at(&descriptors, element + 8)?,
                            u32_at(&descriptors, element + 12)?,
                        )
                    } else {
                        (
                            u32_at(&descriptors, element)?,
                            u32_at(&descriptors, element + 4)?,
                            0,
                        )
                    };
                    let end_of_entry = element
                        .checked_add(position as usize)
                        .and_then(|n| n.checked_add(key_len as usize))
                        .and_then(|n| n.checked_add(value_len as usize))
                        .ok_or_else(invalid)?;
                    if zone && flags == LEAF && key_len == 7 {
                        let key_offset =
                            element.checked_add(position as usize).ok_or_else(invalid)?;
                        if key_offset.checked_add(7).is_none_or(|end| end > extent) {
                            return Err(invalid());
                        }
                        let mut key = [0; 7];
                        self.file.read_exact_at(
                            &mut key,
                            offset.checked_add(key_offset as u64).ok_or_else(invalid)?,
                        )?;
                        if key == *b"records" && value_len as usize > self.max_zone_bytes {
                            return Err(invalid());
                        }
                    }
                    end = end.max(end_of_entry);
                }
                if count > 1 && end <= extent - self.meta.page_size {
                    return Err(invalid());
                }
                end
            }
            FREELIST => {
                // bbolt v1.5.0 internal/common/page.go:115-130: large freelists carry their count in the first entry.
                let (prefix, entries) = if entries == usize::from(u16::MAX) {
                    let mut count_bytes = [0; 8];
                    self.file
                        .read_exact_at(&mut count_bytes, offset + HEADER as u64)?;
                    (
                        HEADER + 8,
                        usize::try_from(u64::from_ne_bytes(count_bytes)).map_err(|_| invalid())?,
                    )
                } else {
                    (HEADER, entries)
                };
                if entries as u64 > self.meta.high.saturating_sub(2) {
                    return Err(invalid());
                }
                prefix
                    .checked_add(entries.checked_mul(8).ok_or_else(invalid)?)
                    .ok_or_else(invalid)?
            }
            _ => return Err(invalid()),
        };
        used = used.max(HEADER);
        if used > extent {
            return Err(invalid());
        }
        let mut data = zeroed(used)?;
        self.file.read_exact_at(&mut data, offset)?;
        Ok(data)
    }

    fn tree(&self, root: u64, pages: &mut BTreeSet<u64>) -> io::Result<Entries> {
        self.tree_inner(root, pages, false)
    }

    fn tree_inner(&self, root: u64, pages: &mut BTreeSet<u64>, zone: bool) -> io::Result<Entries> {
        let mut entries = Entries::new();
        let mut pending: Vec<(u64, Option<Vec<u8>>, Option<Vec<u8>>)> = vec![(root, None, None)];
        while let Some((id, lower, upper)) = pending.pop() {
            let data = self.page_inner(id, zone)?;
            let overflow = u64::from(u32_at(&data, 12)?);
            for page in id..=id + overflow {
                if !pages.insert(page) {
                    return Err(invalid());
                }
            }
            match u16_at(&data, 8)? {
                LEAF => {
                    let leaf = leaf_entries(&data)?;
                    if lower.as_ref().is_some_and(|bound| {
                        leaf.first_key_value().is_none_or(|(key, _)| key != bound)
                    }) || upper.as_ref().is_some_and(|bound| {
                        leaf.last_key_value().is_some_and(|(key, _)| key >= bound)
                    }) {
                        return Err(invalid());
                    }
                    for (key, value) in leaf {
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
                    if count == 0 {
                        return Err(invalid());
                    }
                    let table_end = HEADER + count * 16;
                    let mut previous_end = table_end;
                    let mut children: Vec<(Vec<u8>, u64)> = Vec::with_capacity(count);
                    for index in 0..count {
                        let element = HEADER + index * 16;
                        let start = element
                            .checked_add(u32_at(&data, element)? as usize)
                            .ok_or_else(invalid)?;
                        let end = start
                            .checked_add(u32_at(&data, element + 4)? as usize)
                            .ok_or_else(invalid)?;
                        if start < previous_end || start == end {
                            return Err(invalid());
                        }
                        let key = data.get(start..end).ok_or_else(invalid)?.to_vec();
                        if children
                            .last()
                            .is_some_and(|(previous, _)| previous >= &key)
                        {
                            return Err(invalid());
                        }
                        children.push((key, u64_at(&data, element + 8)?));
                        previous_end = end;
                    }
                    if lower.as_ref().is_some_and(|bound| &children[0].0 != bound)
                        || upper
                            .as_ref()
                            .is_some_and(|bound| &children[count - 1].0 >= bound)
                    {
                        return Err(invalid());
                    }
                    for index in 0..count {
                        let high = children
                            .get(index + 1)
                            .map(|(key, _)| key.clone())
                            .or_else(|| upper.clone());
                        pending.push((children[index].1, Some(children[index].0.clone()), high));
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
            self.tree_inner(id, &mut pages, true)?
        };
        Ok((root, contents, pages))
    }

    pub(super) fn read(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let (root, contents, pages) = self.contents()?;
        self.checked_free(&root, &contents, &pages)?;
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

    // bbolt v1.5.0 tx_check.go:50-100: reachable pages must not appear on the freelist.
    fn checked_free(
        &self,
        root: &Entries,
        contents: &Entries,
        replaced: &BTreeSet<u64>,
    ) -> io::Result<(BTreeSet<u64>, u64)> {
        let mut live = replaced.clone();
        let mut pending = Vec::new();
        for (key, (flags, value)) in root {
            if *flags & !BUCKET != 0 {
                return Err(invalid());
            }
            if *flags & BUCKET != 0 && key.as_slice() != BUCKET_NAME {
                pending.push(value.clone());
            }
        }
        for (flags, value) in contents.values() {
            if *flags & !BUCKET != 0 {
                return Err(invalid());
            }
            if *flags & BUCKET != 0 {
                pending.push(value.clone());
            }
        }
        while let Some(bucket) = pending.pop() {
            let id = u64_at(&bucket, 0)?;
            let entries = if id == 0 {
                leaf_entries(bucket.get(16..).ok_or_else(invalid)?)?
            } else {
                self.tree(id, &mut live)?
            };
            for (flags, value) in entries.into_values() {
                if flags & !BUCKET != 0 {
                    return Err(invalid());
                }
                if flags & BUCKET != 0 {
                    pending.push(value);
                }
            }
        }
        let (free, overflow) = self.free_pages()?;
        if live.iter().any(|id| free.contains(id))
            || (self.meta.freelist..=self.meta.freelist + overflow)
                .any(|id| free.contains(&id) || live.contains(&id))
        {
            return Err(invalid());
        }
        Ok((free, overflow))
    }

    pub(super) fn commit(&mut self, origin: &[u8], records: &[u8]) -> io::Result<()> {
        self.commit_with(origin, records, |_| Ok(()))
    }

    fn commit_with(
        &mut self,
        origin: &[u8],
        records: &[u8],
        mut checkpoint: impl FnMut(CommitPoint) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.uncertain {
            return Err(io::Error::other("bbolt commit status is uncertain"));
        }
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
        let (mut free, old_free_overflow) = self.checked_free(&root, &contents, &old_pages)?;
        let mut high = self.meta.high;
        let (bucket_id, bucket_pages) =
            build_tree(&contents, self.meta.page_size, &mut free, &mut high)?;
        let mut bucket_header = vec![0; 16];
        put64(&mut bucket_header, 0, bucket_id);
        if let Some((_, previous)) = root.get(BUCKET_NAME)
            && previous.len() >= 16
        {
            bucket_header[8..16].copy_from_slice(&previous[8..16]);
        }
        root.insert(BUCKET_NAME.to_vec(), (BUCKET, bucket_header));
        let (root_id, root_pages) = build_tree(&root, self.meta.page_size, &mut free, &mut high)?;
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
        let mut freelist = zeroed(
            free_count
                .checked_mul(self.meta.page_size)
                .ok_or_else(invalid)?,
        )?;
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
        for (id, data) in bucket_pages {
            self.file
                .write_all_at(&data, id * self.meta.page_size as u64)?;
            checkpoint(CommitPoint::BucketWritten)?;
        }
        for (id, data) in root_pages {
            self.file
                .write_all_at(&data, id * self.meta.page_size as u64)?;
            checkpoint(CommitPoint::RootWritten)?;
        }
        self.file
            .write_all_at(&freelist, free_id * self.meta.page_size as u64)?;
        checkpoint(CommitPoint::FreelistWritten)?;
        // bbolt v1.5.0 tx.go:244-273: flush all new pages before writing and syncing the next meta page.
        self.file.sync_all()?;
        checkpoint(CommitPoint::DataSynced)?;
        let next = MetaPage {
            root: root_id,
            freelist: free_id,
            high,
            txid: self.meta.txid.checked_add(1).ok_or_else(invalid)?,
            ..self.meta
        };
        // bbolt v1.5.0 tx.go:272-284: a failed meta write may already be visible; prevent later writes until reopen.
        self.uncertain = true;
        self.file
            .write_all_at(&next.encode(), (next.txid % 2) * next.page_size as u64)?;
        checkpoint(CommitPoint::MetaWritten)?;
        self.file.sync_all()?;
        checkpoint(CommitPoint::MetaSynced)?;
        self.meta = next;
        self.uncertain = false;
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
    let table_end = HEADER + count * 16;
    let mut previous_end = table_end;
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
        if flags & !BUCKET != 0 || start < previous_end || start == mid {
            return Err(invalid());
        }
        let key = data.get(start..mid).ok_or_else(invalid)?.to_vec();
        let value = data.get(mid..end).ok_or_else(invalid)?.to_vec();
        if entries
            .last_key_value()
            .is_some_and(|(previous, _)| previous >= &key)
        {
            return Err(invalid());
        }
        previous_end = end;
        if entries.insert(key, (flags, value)).is_some() {
            return Err(invalid());
        }
    }
    Ok(entries)
}

type LeafEntry<'a> = (&'a [u8], u32, &'a [u8]);
type PageWrite = (u64, Vec<u8>);

// bbolt v1.5.0 node.go:286-344: split sorted nodes and spill leaves before their branch parents.
fn build_tree(
    entries: &Entries,
    size: usize,
    free: &mut BTreeSet<u64>,
    high: &mut u64,
) -> io::Result<(u64, Vec<PageWrite>)> {
    const TARGET: usize = 1 << 20;
    let mut pages = Vec::new();
    let mut level: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut items = entries.iter().peekable();
    while items.peek().is_some() || level.is_empty() {
        let mut leaf: Vec<LeafEntry<'_>> = Vec::new();
        let mut bytes = HEADER;
        while let Some((key, (flags, value))) = items.peek().copied() {
            // bbolt v1.5.0 bucket.go:13-14: keys are limited to 32 KiB.
            if key.is_empty() || key.len() > 32768 {
                return Err(invalid());
            }
            let extra = 16usize
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or_else(invalid)?;
            let next = bytes.checked_add(extra).ok_or_else(invalid)?;
            if !leaf.is_empty() && (leaf.len() == usize::from(u16::MAX) || next > TARGET.max(size))
            {
                break;
            }
            leaf.push((key, *flags, value));
            bytes = next;
            items.next();
        }
        let count = bytes.div_ceil(size);
        let id = allocate(free, high, count)?;
        let first = leaf.first().map_or_else(Vec::new, |entry| entry.0.to_vec());
        pages.push((id, encode_leaf(id, count, size, &leaf)?));
        level.push((first, id));
    }
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut offset = 0;
        while offset < level.len() {
            let mut end = offset;
            let mut bytes = HEADER;
            while end < level.len() {
                let extra = 16usize
                    .checked_add(level[end].0.len())
                    .ok_or_else(invalid)?;
                let needed = bytes.checked_add(extra).ok_or_else(invalid)?;
                if end > offset
                    && (end - offset == usize::from(u16::MAX) || needed > TARGET.max(size))
                {
                    break;
                }
                bytes = needed;
                end += 1;
            }
            if level.len() - end == 1 && end - offset > 2 {
                end -= 1;
                bytes -= 16 + level[end].0.len();
            }
            if end - offset == 1 && level.len() > 1 {
                return Err(invalid());
            }
            let count = bytes.div_ceil(size);
            let id = allocate(free, high, count)?;
            pages.push((id, encode_branch(id, count, size, &level[offset..end])?));
            next.push((level[offset].0.clone(), id));
            offset = end;
        }
        level = next;
    }
    Ok((level[0].1, pages))
}

fn encode_leaf(
    id: u64,
    count: usize,
    size: usize,
    entries: &[LeafEntry<'_>],
) -> io::Result<Vec<u8>> {
    let mut data = zeroed(count.checked_mul(size).ok_or_else(invalid)?)?;
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
    for (index, (key, flags, value)) in entries.iter().enumerate() {
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

// bbolt v1.5.0 internal/common/page.go:165-190: branch entries store relative key offsets and child page IDs.
fn encode_branch(
    id: u64,
    count: usize,
    size: usize,
    entries: &[(Vec<u8>, u64)],
) -> io::Result<Vec<u8>> {
    let mut data = zeroed(count.checked_mul(size).ok_or_else(invalid)?)?;
    put64(&mut data, 0, id);
    put16(&mut data, 8, BRANCH);
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
    for (index, (key, child)) in entries.iter().enumerate() {
        let element = HEADER + index * 16;
        put32(
            &mut data,
            element,
            (offset - element).try_into().map_err(|_| invalid())?,
        );
        put32(
            &mut data,
            element + 4,
            key.len().try_into().map_err(|_| invalid())?,
        );
        put64(&mut data, element + 8, *child);
        data[offset..offset + key.len()].copy_from_slice(key);
        offset += key.len();
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
    use super::{CommitPoint, Store};
    use std::{
        fs::OpenOptions,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
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
    fn impossible_allocation_is_an_error() {
        assert!(super::zeroed(usize::MAX).is_err());
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

    #[test]
    fn reads_database_written_by_coredns_updates() {
        let path = path();
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/dynupdate/coredns.db"
            ),
            &path,
        )
        .unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut store = Store::open(file).unwrap();
        let (origin, records) = store.read().unwrap();
        assert_eq!(origin, b"example.org.");
        assert!(records.len() > 100);
        store.commit(&origin, &records).unwrap();
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
        assert!(output.stdout.starts_with(b"example.org.\n"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn falls_back_to_prior_meta_when_latest_is_corrupt() {
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        store.commit(b"example.org.", b"old").unwrap();
        store.commit(b"example.org.", b"new").unwrap();
        use std::os::unix::fs::FileExt;
        store.file.write_all_at(&[0; 8], 4096 + 72).unwrap();
        drop(store);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(Store::open(file).unwrap().read().unwrap().1, b"old");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn hard_link_sees_committed_data() {
        let path = path();
        let alias = path.with_extension("alias");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        store.commit(b"example.org.", b"new").unwrap();
        drop(store);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&alias)
            .unwrap();
        assert_eq!(Store::open(file).unwrap().read().unwrap().1, b"new");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(alias).unwrap();
    }

    #[test]
    fn commits_never_overwrite_pages_reachable_from_current_meta() {
        use std::os::unix::fs::FileExt;
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        store.commit(b"example.org.", b"old").unwrap();
        let (_, _, mut pages) = store.contents().unwrap();
        pages.insert(store.meta.freelist);
        let old = pages
            .iter()
            .map(|id| (*id, store.page(*id).unwrap()))
            .collect::<Vec<_>>();
        store.commit(b"example.org.", b"new").unwrap();
        for (id, bytes) in old {
            let mut actual = vec![0; bytes.len()];
            store
                .file
                .read_exact_at(&mut actual, id * store.meta.page_size as u64)
                .unwrap();
            assert_eq!(actual, bytes, "page {id} changed");
        }
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn crashes_at_commit_steps_leave_old_or_new_zone() {
        const ENV: &str = "PHAROS_BBOLT_CRASH_POINT";
        if let Ok(stage) = std::env::var(ENV) {
            let path = std::env::var_os("PHAROS_BBOLT_CRASH_FILE").unwrap();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            let mut store = Store::open(file).unwrap();
            let requested = std::env::var("PHAROS_BBOLT_CRASH_OCCURRENCE")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(1);
            let mut seen = 0;
            let records = if std::env::var_os("PHAROS_BBOLT_LARGE_CRASH").is_some() {
                vec![42; 1 << 20]
            } else {
                b"new".to_vec()
            };
            let _ = store.commit_with(b"example.org.", &records, |point| {
                if format!("{point:?}") == stage {
                    seen += 1;
                    if seen == requested {
                        std::process::exit(73);
                    }
                }
                Ok(())
            });
            panic!("requested crash point not reached");
        }
        for point in [
            CommitPoint::BucketWritten,
            CommitPoint::RootWritten,
            CommitPoint::FreelistWritten,
            CommitPoint::DataSynced,
            CommitPoint::MetaWritten,
            CommitPoint::MetaSynced,
        ] {
            let path = path();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let mut store = Store::create(file).unwrap();
            store.commit(b"example.org.", b"old").unwrap();
            drop(store);
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "dynupdate::bbolt::tests::crashes_at_commit_steps_leave_old_or_new_zone",
                ])
                .env(ENV, format!("{point:?}"))
                .env("PHAROS_BBOLT_CRASH_FILE", &path)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let data = Store::open(file).unwrap().read().unwrap().1;
            assert!(data == b"old" || data == b"new", "{point:?}");
            if matches!(
                point,
                CommitPoint::BucketWritten
                    | CommitPoint::RootWritten
                    | CommitPoint::FreelistWritten
                    | CommitPoint::DataSynced
            ) {
                assert_eq!(data, b"old", "{point:?}");
            }
            std::fs::remove_file(path).unwrap();
        }
        for occurrence in 1..=3 {
            let path = path();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let mut store = Store::create(file).unwrap();
            store.commit(b"example.org.", b"old").unwrap();
            drop(store);
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "dynupdate::bbolt::tests::crashes_at_commit_steps_leave_old_or_new_zone",
                ])
                .env(ENV, "BucketWritten")
                .env("PHAROS_BBOLT_CRASH_FILE", &path)
                .env("PHAROS_BBOLT_CRASH_OCCURRENCE", occurrence.to_string())
                .env("PHAROS_BBOLT_LARGE_CRASH", "1")
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(73));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            assert_eq!(Store::open(file).unwrap().read().unwrap().1, b"old");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn data_is_synced_before_meta_is_written() {
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        let mut stages = Vec::new();
        store
            .commit_with(b"example.org.", b"data", |stage| {
                stages.push(stage);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            stages,
            [
                CommitPoint::BucketWritten,
                CommitPoint::RootWritten,
                CommitPoint::FreelistWritten,
                CommitPoint::DataSynced,
                CommitPoint::MetaWritten,
                CommitPoint::MetaSynced
            ]
        );
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn opens_databases_across_four_and_sixteen_kib_page_sizes() {
        for (write, read) in [("write-4096", "read-16384"), ("write-16384", "read-4096")] {
            let path = path();
            let Some(output) = go(write, &path) else {
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
                store.meta.page_size,
                if write == "write-4096" { 4096 } else { 16384 }
            );
            assert_eq!(
                store.read().unwrap(),
                (b"example.org.".to_vec(), b"record data".to_vec())
            );
            store.commit(b"example.org.", b"record data").unwrap();
            drop(store);
            let output = go(read, &path).unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"example.org.\nrecord data\n");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn rejects_freelist_referencing_another_live_bucket() {
        use std::os::unix::fs::FileExt;
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
        let root = store
            .tree(store.meta.root, &mut std::collections::BTreeSet::new())
            .unwrap();
        let live = super::u64_at(&root.get(b"preserved".as_slice()).unwrap().1, 0).unwrap();
        assert_ne!(live, 0);
        let before = store.page(live).unwrap();
        let offset = store.meta.freelist * store.meta.page_size as u64;
        store
            .file
            .write_all_at(&1u16.to_ne_bytes(), offset + 10)
            .unwrap();
        store
            .file
            .write_all_at(&live.to_ne_bytes(), offset + 16)
            .unwrap();
        assert!(store.read().is_err());
        assert!(store.commit(b"example.org.", b"new").is_err());
        assert_eq!(store.page(live).unwrap(), before);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_meta_sync_does_not_allow_another_commit() {
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        store.commit(b"example.org.", b"old").unwrap();
        let result = store.commit_with(b"example.org.", b"new", |point| {
            if point == CommitPoint::MetaWritten {
                return Err(std::io::Error::other("injected sync failure"));
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(store.read().unwrap().1, b"old");
        assert!(store.commit(b"example.org.", b"later").is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forged_empty_overflow_page_is_rejected() {
        use std::os::unix::fs::FileExt;
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        store.meta.high = 16384;
        store
            .file
            .set_len(store.meta.high * store.meta.page_size as u64)
            .unwrap();
        store
            .file
            .write_all_at(&store.meta.encode(), store.meta.page_size as u64)
            .unwrap();
        store
            .file
            .write_all_at(
                &16380u32.to_ne_bytes(),
                3 * store.meta.page_size as u64 + 12,
            )
            .unwrap();
        assert!(store.page(3).is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_oversized_zone_value_before_loading_it() {
        let path = path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut store = Store::create(file).unwrap();
        store.commit(b"example.org.", &vec![42; 1 << 20]).unwrap();
        drop(store);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let store = Store::open_limited(file, 100).unwrap();
        assert!(store.read().is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_corrupt_empty_key_even_when_zone_records_are_intact() {
        use std::os::unix::fs::FileExt;
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
        let store = Store::open(file).unwrap();
        let mut corrupted = false;
        for id in 2..store.meta.high {
            let Ok(page) = store.page(id) else { continue };
            if super::u16_at(&page, 8).unwrap() != super::LEAF {
                continue;
            }
            let count = usize::from(super::u16_at(&page, 10).unwrap());
            for index in 0..count {
                let element = super::HEADER + index * 16;
                let start = element + super::u32_at(&page, element + 4).unwrap() as usize;
                let len = super::u32_at(&page, element + 8).unwrap() as usize;
                if page.get(start..start + len) == Some(b"extra-0000".as_slice()) {
                    store
                        .file
                        .write_all_at(
                            &0u32.to_ne_bytes(),
                            id * store.meta.page_size as u64 + element as u64 + 8,
                        )
                        .unwrap();
                    corrupted = true;
                    break;
                }
            }
            if corrupted {
                break;
            }
        }
        assert!(corrupted);
        assert!(store.read().is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "plugin-file")]
    #[test]
    fn coredns_serves_a_database_updated_by_rust() {
        use pharos_proto::{Class, Name, Type, zone::ZoneRecord};
        use std::time::{Duration, Instant};
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/coredns/v1.15.0/coredns");
        if !binary.is_file() || Command::new("dig").arg("-v").output().is_err() {
            eprintln!("skipping CoreDNS database interop: CoreDNS or dig is unavailable");
            return;
        }
        let dir = path();
        std::fs::create_dir(&dir).unwrap();
        let database = dir.join("db");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/dynupdate/coredns.db"
            ),
            &database,
        )
        .unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database)
            .unwrap();
        let mut store = Store::open(file).unwrap();
        let (origin, records) = store.read().unwrap();
        let apex: Name = "example.org.".parse().unwrap();
        let zone = crate::zone::Zone::from_records(
            apex.clone(),
            crate::dynupdate::wire::decode(&records, 10000, 8 << 20).unwrap(),
        )
        .unwrap();
        let addition = ZoneRecord {
            owner: "rust.example.org.".parse().unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 60,
            rdata: vec![192, 0, 2, 77],
        };
        let (zone, changed) = zone.apply_updates(&[addition]).unwrap();
        assert!(changed);
        store
            .commit(
                &origin,
                &crate::dynupdate::wire::encode(zone.records()).unwrap(),
            )
            .unwrap();
        drop(store);
        let seed = dir.join("seed");
        std::fs::write(
            &seed,
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
        )
        .unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let config = dir.join("Corefile");
        std::fs::write(&config, format!("example.org:{port} {{\n bind 127.0.0.1\n dynupdate {{\n file {}\n database {}\n allow key.example.org. * A\n }}\n}}\n", seed.display(), database.display())).unwrap();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            Command::new(binary)
                .args(["-conf", config.to_str().unwrap()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "CoreDNS exited before answering"
            );
            let output = Command::new("dig")
                .args([
                    "@127.0.0.1",
                    "-p",
                    &port.to_string(),
                    "+time=1",
                    "+tries=1",
                    "+short",
                    "rust.example.org.",
                    "A",
                ])
                .output()
                .unwrap();
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout).trim() == "192.0.2.77"
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "CoreDNS did not serve the Rust update: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(child);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn updates_go_bucket_with_more_than_u16_keys() {
        let path = path();
        let Some(output) = go("write-many-keys", &path) else {
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
        assert_eq!(store.read().unwrap().1, b"record data");
        store.commit(b"example.org.", b"record data").unwrap();
        drop(store);
        let output = go("verify-many-keys", &path).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn branch_split_never_leaves_one_child() {
        let mut entries = super::Entries::new();
        for index in 0..32u32 {
            let mut key = vec![0; 32768];
            key[..4].copy_from_slice(&index.to_be_bytes());
            entries.insert(key, (0, vec![0; 1 << 20]));
        }
        assert!(
            super::build_tree(
                &entries,
                4096,
                &mut std::collections::BTreeSet::new(),
                &mut 4
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_corrupt_branch_key_even_when_children_are_valid() {
        use std::os::unix::fs::FileExt;
        let path = path();
        let Some(output) = go("write-many-keys", &path) else {
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
        let root = store
            .tree(store.meta.root, &mut std::collections::BTreeSet::new())
            .unwrap();
        let bucket = super::u64_at(&root.get(b"dynupdate-v1".as_slice()).unwrap().1, 0).unwrap();
        let page = store.page(bucket).unwrap();
        assert_eq!(super::u16_at(&page, 8).unwrap(), super::BRANCH);
        store
            .file
            .write_all_at(
                &0u32.to_ne_bytes(),
                bucket * store.meta.page_size as u64 + super::HEADER as u64 + 4,
            )
            .unwrap();
        assert!(store.read().is_err());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
