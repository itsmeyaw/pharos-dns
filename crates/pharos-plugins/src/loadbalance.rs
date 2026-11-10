//! Loadbalance Directive configuration.

use std::{path::PathBuf, time::Duration};

use pharos_corefile::{Cursor, Error};
use pharos_proto::{Message, Rcode, Type};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct LoadBalance {
    pub weight_file: Option<PathBuf>,
    pub reload: Duration,
}

impl LoadBalance {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        cursor.next();
        let args = cursor.remaining_args();
        let mut lb = Self {
            weight_file: None,
            reload: Duration::from_secs(30),
        };
        match args.first().map(String::as_str) {
            None | Some("round_robin") if args.len() <= 1 => {}
            Some("weighted") if args.len() == 2 => {
                // shortcut: relative paths use the working directory; join with `root` once that Plugin exists.
                lb.weight_file = Some(PathBuf::from(&args[1]));
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
        if cursor.next_block() {
            return Err(cursor.error("unknown loadbalance property"));
        }
        Ok(lb)
    }
}

impl Plugin for LoadBalance {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response && self.weight_file.is_none() {
            shuffle(cx.response);
        }
        outcome
    }
}

#[derive(Clone, Copy, Default)]
struct Record {
    start: u16,
    end: u16,
    group: u8,
}

thread_local! {
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

fn shuffle(wire: &mut [u8]) {
    if wire.len() > usize::from(u16::MAX) {
        return;
    }
    let Ok(message) = Message::parse(wire) else {
        return;
    };
    if message.rcode() != Rcode::NOERROR
        || message
            .questions()
            .next()
            .is_none_or(|q| matches!(q.qtype, Type::AXFR | Type::IXFR))
        || message.additionals().any(|rr| rr.rtype == Type::TSIG)
    {
        return;
    }
    // Every RR occupies at least 11 bytes; no valid DNS Message can exceed this bound.
    let mut records = [Record::default(); 5957];
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
                group: match rr.rtype {
                    Type::CNAME => 0,
                    Type::A | Type::AAAA => 2,
                    Type::MX => 3,
                    _ => 1,
                },
            };
            count += 1;
        }
        sections[section] = (first, count);
    }
    // Opaque RDATA can contain names too: conservatively treat pointer-shaped bytes as pointers.
    for pair in wire.windows(2) {
        if pair[0] & 0xc0 != 0xc0 {
            continue;
        }
        let target = usize::from(u16::from_be_bytes([pair[0] & 0x3f, pair[1]]));
        if sections.iter().any(|&(first, end)| {
            end > first + 1
                && target >= usize::from(records[first].start)
                && target < usize::from(records[end - 1].end)
        }) {
            return;
        }
    }
    let mut order = [Record::default(); 5957];
    for (first, end) in sections {
        if end <= first + 1 {
            continue;
        }
        let section_start = usize::from(records[first].start);
        let actual = &mut records[first..end];
        let items = &mut order[..actual.len()];
        items.copy_from_slice(actual);
        // Stable partition into CNAME, other, address and MX records.
        for i in 1..items.len() {
            let mut j = i;
            while j > 0 && items[j - 1].group > items[j].group {
                items.swap(j - 1, j);
                j -= 1;
            }
        }
        for group in [2, 3] {
            let first = items
                .iter()
                .position(|item| item.group == group)
                .unwrap_or(items.len());
            let end = items
                .iter()
                .rposition(|item| item.group == group)
                .map_or(first, |i| i + 1);
            for i in first..end.saturating_sub(1) {
                items.swap(i, i + random(end - i));
            }
        }
        let mut dest = section_start;
        for (index, item) in items.iter().enumerate() {
            let selected = actual[index..]
                .iter()
                .position(|rr| rr.start == item.start)
                .unwrap()
                + index;
            let len = usize::from(item.end - item.start);
            let preceding: usize = actual[index..selected]
                .iter()
                .map(|rr| usize::from(rr.end - rr.start))
                .sum();
            wire[dest..dest + preceding + len].rotate_right(len);
            actual[index..=selected].rotate_right(1);
            dest += len;
        }
    }
}
