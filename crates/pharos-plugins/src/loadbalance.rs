//! Loadbalance Directive configuration.

mod weighted;

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use pharos_corefile::{Cursor, Error};
use pharos_proto::{Message, NameRef, NameWirePart, Rcode, Type};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct LoadBalance {
    pub weight_file: Option<PathBuf>,
    pub reload: Duration,
    weights: Option<weighted::Weights>,
    weighted_policy: bool,
    prefer: Vec<Subnet>,
}

impl LoadBalance {
    pub(crate) fn parse(cursor: &mut Cursor<'_>, root: Option<&Path>) -> Result<Self, Error> {
        let mut lb = Self {
            weight_file: None,
            reload: Duration::from_secs(30),
            weights: None,
            weighted_policy: false,
            prefer: Vec::new(),
        };
        while cursor.next() {
            let args = cursor.remaining_args();
            match args.first().map(String::as_str) {
                None | Some("round_robin") if args.len() <= 1 => lb.weighted_policy = false,
                Some("weighted") if args.len() == 2 => {
                    lb.weighted_policy = true;
                    lb.prefer.clear();
                    lb.reload = Duration::from_secs(30);
                    lb.weight_file = Some(crate::resolve_path(PathBuf::from(&args[1]), root));
                    while cursor.next_block() {
                        if cursor.val() != "reload" {
                            return Err(cursor.error("unknown weighted property"));
                        }
                        let args = cursor.remaining_args();
                        if args.len() != 1 {
                            return Err(cursor.arg_err());
                        }
                        lb.reload = crate::health::parse_duration(&args[0])
                            .ok_or_else(|| cursor.error("invalid reload duration"))?;
                    }
                }
                _ => return Err(cursor.arg_err()),
            }
            while cursor.next_block() {
                if cursor.val() != "prefer" {
                    return Err(cursor.error("unknown loadbalance property"));
                }
                for cidr in cursor.remaining_args() {
                    lb.prefer
                        .push(Subnet::parse(&cidr).ok_or_else(|| cursor.error("invalid CIDR"))?);
                }
            }
        }
        lb.weights = lb
            .weight_file
            .as_ref()
            .map(|path| weighted::Weights::new(path.clone(), lb.reload));
        Ok(lb)
    }

    pub(crate) fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        if let Some(weights) = &self.weights {
            weights.register_hooks(lifecycle);
        }
    }
}

impl Plugin for LoadBalance {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response {
            shuffle(
                cx.response,
                self.weights.as_ref().filter(|_| self.weighted_policy),
                &self.prefer,
            );
        }
        outcome
    }
}

#[derive(Clone, Copy, Default)]
struct Record {
    start: u16,
    end: u16,
    destination: u16,
    sequence: u16,
    group: u8,
    weight: u8,
    priority: usize,
}

const EMPTY_RECORD: Record = Record {
    start: 0,
    end: 0,
    destination: 0,
    sequence: 0,
    group: 0,
    weight: 0,
    priority: 0,
};

struct Scratch {
    records: [Record; 5957],
    order: [Record; 5957],
    original: [u8; 65535],
    pointers: [Pointer; 32768],
    seen: [u8; 8192],
    direct: [u8; 8192],
    labels: [u8; 8192],
}

#[derive(Clone, Copy, Default)]
struct Pointer {
    source: u16,
    destination: u16,
    target: u16,
    original_target: u16,
}

#[derive(Debug)]
struct Subnet {
    address: IpAddr,
    prefix: u32,
}

impl Subnet {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let mut address: IpAddr = address.parse().ok()?;
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let mut prefix: u32 = prefix.parse().ok()?;
        if prefix > if address.is_ipv4() { 32 } else { 128 } {
            return None;
        }
        if let IpAddr::V6(ip) = address
            && prefix >= 96
            && let Some(ip) = ip.to_ipv4_mapped()
        {
            address = IpAddr::V4(ip);
            prefix -= 96;
        }
        Some(Self { address, prefix })
    }

    // RFC 1035 §3.4.1: A RDATA is a 32-bit Internet address.
    // RFC 3596 §2.2: AAAA RDATA is a 128-bit address in network byte order.
    fn contains(&self, rr: &pharos_proto::Record<'_>) -> bool {
        let address = match (rr.rtype, rr.rdata) {
            (Type::A, [a, b, c, d]) => IpAddr::V4(std::net::Ipv4Addr::new(*a, *b, *c, *d)),
            (Type::AAAA, bytes) if bytes.len() == 16 => IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).unwrap(),
            ))
            .to_canonical(),
            _ => return false,
        };
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix).unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix).unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Scratch> = const { std::cell::RefCell::new(Scratch {
        records: [EMPTY_RECORD; 5957],
        order: [EMPTY_RECORD; 5957],
        original: [0; 65535],
        pointers: [Pointer { source: 0, destination: 0, target: 0, original_target: 0 }; 32768],
        seen: [0; 8192],
        direct: [0; 8192],
        labels: [0; 8192],
    }) };
    static RANDOM: std::cell::Cell<u64> = {
        let mut seed = [0; 8];
        let _ = getrandom::getrandom(&mut seed);
        std::cell::Cell::new(u64::from_ne_bytes(seed).max(1))
    };
}

fn random(limit: usize) -> usize {
    RANDOM.with(|random| {
        let mut value = random.get();
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        random.set(value);
        (value % limit as u64) as usize
    })
}

fn relocated(records: &[Record], offset: usize) -> usize {
    let index = records.partition_point(|record| usize::from(record.start) <= offset);
    if index == 0 {
        return offset;
    }
    let record = records[index - 1];
    if offset < usize::from(record.end) {
        usize::from(record.destination) + offset - usize::from(record.start)
    } else {
        offset
    }
}

fn bit(bits: &[u8], offset: usize) -> bool {
    bits[offset / 8] & (1 << (offset % 8)) != 0
}

fn mark(bits: &mut [u8], offset: usize) {
    bits[offset / 8] |= 1 << (offset % 8);
}

struct PointerCollector<'a> {
    records: &'a [Record],
    pointers: &'a mut [Pointer],
    seen: &'a mut [u8],
    direct: &'a mut [u8],
    labels: &'a mut [u8],
    count: usize,
}

impl PointerCollector<'_> {
    fn visit(&mut self, name: NameRef<'_>) -> bool {
        let mut previous = None;
        let mut pointer_limit = usize::MAX;
        for part in name.wire_parts() {
            let (offset, len) = match part {
                NameWirePart::Label { offset, len } => (offset, len),
                NameWirePart::Root { offset } => (offset, 1),
                NameWirePart::Pointer { offset, .. } => (offset, 2),
            };
            let destination = relocated(self.records, offset);
            // A referenced name can cross record boundaries; its encoding must stay contiguous.
            if destination + len > pointer_limit
                || previous
                    .is_some_and(|(old_end, new_end)| old_end == offset && new_end != destination)
                || (0..len).any(|i| relocated(self.records, offset + i) != destination + i)
            {
                return false;
            }
            if let NameWirePart::Pointer { target, .. } = part {
                if offset >= name.offset() && offset < name.offset() + name.wire_len() {
                    mark(self.direct, offset);
                }
                let target_after = relocated(self.records, target);
                // RFC 1035 §4.1.4: compression pointers use a 14-bit offset to a prior occurrence.
                if target_after > 0x3fff || target_after >= destination {
                    return false;
                }
                if !bit(self.seen, offset) {
                    if self.count == self.pointers.len() {
                        return false;
                    }
                    mark(self.seen, offset);
                    self.pointers[self.count] = Pointer {
                        source: offset as u16,
                        destination: destination as u16,
                        target: target_after as u16,
                        original_target: target as u16,
                    };
                    self.count += 1;
                }
                pointer_limit = destination;
                previous = None;
            } else {
                for byte in offset..offset + len {
                    mark(self.labels, byte);
                }
                previous = Some((offset + len, destination + len));
            }
        }
        true
    }

    fn safe(&mut self) -> bool {
        // Rewriting must not alter opaque data, literal labels, or overlapping pointers.
        if !self.pointers[..self.count].iter().all(|pointer| {
            let source = usize::from(pointer.source);
            pointer.target == pointer.original_target
                || (bit(self.direct, source)
                    && !bit(self.labels, source)
                    && !bit(self.labels, source + 1))
        }) {
            return false;
        }
        let pointers = &mut self.pointers[..self.count];
        pointers.sort_unstable_by_key(|pointer| pointer.source);
        pointers.windows(2).all(|pair| {
            usize::from(pair[0].source) + 1 != usize::from(pair[1].source)
                || pair[0].target.to_be_bytes()[1]
                    == 0xc0 | (pair[1].target.to_be_bytes()[0] & 0x3f)
        })
    }
}

fn shuffle(wire: &mut [u8], weights: Option<&weighted::Weights>, prefer: &[Subnet]) {
    if wire.len() > usize::from(u16::MAX) {
        return;
    }
    let weight_data = weights.map(weighted::Weights::load);
    SCRATCH.with(|scratch| {
        let Ok(message) = Message::parse(wire) else {
            return;
        };
        // RFC 8945 §4.3.2: a TSIG MAC covers the DNS message in wire format.
        if message.rcode() != Rcode::NOERROR
            || message
                .questions()
                .next()
                .is_none_or(|q| matches!(q.qtype, Type::AXFR | Type::IXFR))
            || message.additionals().any(|rr| rr.rtype == Type::TSIG)
        {
            return;
        }
        let weighted_query = message
            .questions()
            .next()
            .is_some_and(|q| matches!(q.qtype, Type::A | Type::AAAA | Type::SRV));
        if weights.is_some() && !weighted_query && prefer.is_empty() {
            return;
        }
        let mut scratch = scratch.borrow_mut();
        let Scratch {
            records,
            order,
            original,
            pointers,
            seen,
            direct,
            labels,
        } = &mut *scratch;
        // Every RR occupies at least 11 bytes; no valid DNS Message can exceed this bound.
        let mut sections = [(0usize, 0usize); 3];
        let mut count = 0;
        for (section, iter) in [
            message.answers(),
            message.authorities(),
            message.additionals(),
        ]
        .into_iter()
        .enumerate()
        {
            let first = count;
            for rr in iter {
                if count == records.len() {
                    return;
                }
                records[count] = Record {
                    start: (rr.ttl_offset - 4 - rr.name.wire_len()) as u16,
                    end: (rr.rdata_offset + rr.rdata.len()) as u16,
                    destination: (rr.ttl_offset - 4 - rr.name.wire_len()) as u16,
                    sequence: 0,
                    group: match rr.rtype {
                        Type::CNAME => 0,
                        Type::A | Type::AAAA => 2,
                        Type::MX => 3,
                        _ => 1,
                    },
                    weight: weight_data
                        .as_ref()
                        .map_or(1, |data| weighted::weight(data, &rr)),
                    priority: prefer
                        .iter()
                        .position(|subnet| subnet.contains(&rr))
                        .unwrap_or(prefer.len()),
                };
                count += 1;
            }
            sections[section] = (first, count);
        }
        order[..count].copy_from_slice(&records[..count]);
        for (section, (first, end)) in sections.into_iter().enumerate() {
            if end <= first + 1 || (weights.is_some() && section == 1) {
                continue;
            }
            let section_start = usize::from(records[first].start);
            let items = &mut order[first..end];
            if weights.is_some() && prefer.is_empty() && !items.iter().any(|item| item.group == 2) {
                continue;
            }
            // The original offset preserves order within each category without allocation.
            items.sort_unstable_by_key(|item| (item.group, item.start));
            for group in [2, 3] {
                let first = items
                    .iter()
                    .position(|item| item.group == group)
                    .unwrap_or(items.len());
                let end = items
                    .iter()
                    .rposition(|item| item.group == group)
                    .map_or(first, |i| i + 1);
                if weights.is_some() {
                    if weighted_query && group == 2 && first < end {
                        let total: usize = items[first..end]
                            .iter()
                            .map(|item| usize::from(item.weight))
                            .sum();
                        let mut choice = random(total);
                        for i in first..end {
                            if choice < usize::from(items[i].weight) {
                                items.swap(first, i);
                                break;
                            }
                            choice -= usize::from(items[i].weight);
                        }
                    }
                } else {
                    for i in first..end.saturating_sub(1) {
                        items.swap(i, i + random(end - i));
                    }
                }
            }
            if !prefer.is_empty() && section != 1 {
                for (sequence, item) in items.iter_mut().enumerate() {
                    item.sequence = sequence as u16;
                }
                let key = |record: &Record| {
                    let group = match record.group {
                        0 => 0,
                        2 => 1,
                        3 => 2,
                        _ => 3,
                    };
                    (
                        group,
                        if group == 1 { record.priority } else { 0 },
                        record.sequence,
                    )
                };
                items.sort_unstable_by_key(key);
            }
            let mut dest = section_start;
            for item in items.iter() {
                let len = usize::from(item.end - item.start);
                let index = records[..count]
                    .binary_search_by_key(&item.start, |record| record.start)
                    .expect("record came from this Message");
                records[index].destination = dest as u16;
                dest += len;
            }
        }
        seen.fill(0);
        direct.fill(0);
        labels.fill(0);
        let pointer_count = {
            let mut collector = PointerCollector {
                records: &records[..count],
                pointers,
                seen,
                direct,
                labels,
                count: 0,
            };
            for question in message.questions() {
                if !collector.visit(question.name) {
                    return;
                }
            }
            for rr in message
                .answers()
                .chain(message.authorities())
                .chain(message.additionals())
            {
                if !collector.visit(rr.name) {
                    return;
                }
                let Ok(names) = rr.compressible_names() else {
                    return;
                };
                for name in names.into_iter().flatten() {
                    if !collector.visit(name) {
                        return;
                    }
                }
            }
            if !collector.safe() {
                return;
            }
            collector.count
        };
        original[..wire.len()].copy_from_slice(wire);
        for item in &order[..count] {
            let index = records[..count]
                .binary_search_by_key(&item.start, |record| record.start)
                .expect("record came from this Message");
            let destination = usize::from(records[index].destination);
            let len = usize::from(item.end - item.start);
            wire[destination..destination + len]
                .copy_from_slice(&original[usize::from(item.start)..usize::from(item.end)]);
        }
        // RFC 1035 §4.1.4: a compression pointer has two leading one bits and a 14-bit offset.
        for pointer in &pointers[..pointer_count] {
            let destination = usize::from(pointer.destination);
            wire[destination..destination + 2]
                .copy_from_slice(&(0xc000 | pointer.target).to_be_bytes());
        }
    });
}
