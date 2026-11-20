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
}

pub(super) struct Store {
    file: File,
    meta: MetaPage,
    max_zone_bytes: usize,
}

type Entries = BTreeMap<Vec<u8>, (u32, Vec<u8>)>;
type PendingPage = (u64, Option<Vec<u8>>, Option<Vec<u8>>);

impl Store {
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
            max_zone_bytes: usize::MAX,
        })
    }

    pub(super) fn open_limited(file: File, max_zone_bytes: usize) -> io::Result<Self> {
        let mut store = Self::open(file)?;
        store.max_zone_bytes = max_zone_bytes;
        Ok(store)
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
                        if u32_at(&descriptors, element)? & !BUCKET != 0 {
                            return Err(invalid());
                        }
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
                    let key_offset = element.checked_add(position as usize).ok_or_else(invalid)?;
                    // bbolt v1.5.0 bucket.go:13-14: valid keys are nonempty and at most 32 KiB.
                    if key_len == 0 || key_len > 32768 || key_offset < table {
                        return Err(invalid());
                    }
                    let end_of_entry = element
                        .checked_add(position as usize)
                        .and_then(|n| n.checked_add(key_len as usize))
                        .and_then(|n| n.checked_add(value_len as usize))
                        .ok_or_else(invalid)?;
                    if end_of_entry > extent {
                        return Err(invalid());
                    }
                    if zone && flags == LEAF && key_len == 7 {
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
        let mut pending: Vec<PendingPage> = vec![(root, None, None)];
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

#[cfg(test)]
mod tests;
