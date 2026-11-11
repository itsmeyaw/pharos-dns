//! Internal Query and Response rewriting.

use std::fmt::Write;

use pharos_corefile::{Cursor, Error};
use pharos_proto::{Message, MessageMut, Rcode, Type};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
struct Rule {
    matcher: Matcher,
    action: Action,
    stop: bool,
}

#[derive(Debug)]
enum Action {
    Ttl(u32, u32),
    Rcode(u16, u16),
}

#[derive(Debug)]
enum Matcher {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Substring(String),
    Regex(regex::Regex),
}

impl Matcher {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(value) => name == value,
            Self::Prefix(value) => name.starts_with(value),
            Self::Suffix(value) => name.ends_with(value),
            Self::Substring(value) => name.contains(value),
            Self::Regex(value) => value.is_match(name),
        }
    }
}

#[derive(Debug)]
pub struct Rewrite {
    rules: Vec<Rule>,
}

impl Rewrite {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let mut rules = Vec::new();
        while cursor.next() {
            let mut args = cursor.remaining_args();
            if args.len() < 2 {
                while cursor.next_block() {
                    args.push(cursor.val().to_owned());
                }
            }
            let mut args = args.as_slice();
            let stop = if args
                .first()
                .is_some_and(|arg| arg.eq_ignore_ascii_case("continue"))
            {
                args = &args[1..];
                false
            } else {
                if args
                    .first()
                    .is_some_and(|arg| arg.eq_ignore_ascii_case("stop"))
                {
                    args = &args[1..];
                }
                true
            };
            let Some((kind, args)) = args.split_first() else {
                return Err(cursor.arg_err());
            };
            let (mode, name, action) = if kind.eq_ignore_ascii_case("ttl") {
                let (mode, name, ttl) = match args {
                    [name, ttl] => ("exact", name, ttl),
                    [mode, name, ttl] => (mode.as_str(), name, ttl),
                    _ => return Err(cursor.arg_err()),
                };
                let (min, max) = ttl_range(ttl).ok_or_else(|| cursor.error("invalid TTL"))?;
                (mode, name, Action::Ttl(min, max))
            } else if kind.eq_ignore_ascii_case("rcode") {
                let (mode, name, old, new) = match args {
                    [name, old, new] => ("exact", name, old, new),
                    [mode, name, old, new] => (mode.as_str(), name, old, new),
                    _ => return Err(cursor.arg_err()),
                };
                let old = rcode(old).ok_or_else(|| cursor.error("invalid RCODE"))?;
                let new = rcode(new).ok_or_else(|| cursor.error("invalid RCODE"))?;
                (mode, name, Action::Rcode(old, new))
            } else {
                return Err(cursor.error("unsupported rewrite rule"));
            };
            let matcher = if mode.eq_ignore_ascii_case("regex") {
                if name.len() > 10_000 {
                    return Err(cursor.error("regex pattern too long"));
                }
                Matcher::Regex(regex::Regex::new(name).map_err(|_| cursor.error("invalid regex"))?)
            } else {
                let mut name = name.to_ascii_lowercase();
                if !name.ends_with('.') {
                    name.push('.');
                }
                if mode.eq_ignore_ascii_case("exact") {
                    Matcher::Exact(name)
                } else if mode.eq_ignore_ascii_case("prefix") {
                    Matcher::Prefix(name)
                } else if mode.eq_ignore_ascii_case("suffix") {
                    Matcher::Suffix(name)
                } else if mode.eq_ignore_ascii_case("substring") {
                    Matcher::Substring(name)
                } else {
                    return Err(cursor.error("invalid match type"));
                }
            };
            rules.push(Rule {
                matcher,
                action,
                stop,
            });
        }
        Ok(Self { rules })
    }
}

fn rcode(value: &str) -> Option<u16> {
    if let Ok(value) = value.parse::<u16>() {
        return (value <= 23).then_some(value);
    }
    const CODES: [(&str, u16); 20] = [
        ("NOERROR", 0),
        ("FORMERR", 1),
        ("SERVFAIL", 2),
        ("NXDOMAIN", 3),
        ("NOTIMP", 4),
        ("NOTIMPL", 4),
        ("REFUSED", 5),
        ("YXDOMAIN", 6),
        ("YXRRSET", 7),
        ("NXRRSET", 8),
        ("NOTAUTH", 9),
        ("NOTZONE", 10),
        ("DSOTYPENI", 11),
        ("BADSIG", 16),
        ("BADKEY", 17),
        ("BADTIME", 18),
        ("BADMODE", 19),
        ("BADNAME", 20),
        ("BADALG", 21),
        ("BADTRUNC", 22),
    ];
    CODES
        .iter()
        .find_map(|(name, code)| value.eq_ignore_ascii_case(name).then_some(*code))
        .or_else(|| value.eq_ignore_ascii_case("BADCOOKIE").then_some(23))
}

fn ttl_range(value: &str) -> Option<(u32, u32)> {
    if let Some((min, max)) = value.split_once('-') {
        if min.is_empty() && max.is_empty() {
            return None;
        }
        let min = if min.is_empty() { 0 } else { min.parse().ok()? };
        let max = if max.is_empty() {
            i32::MAX as u32
        } else {
            max.parse().ok()?
        };
        (min <= max).then_some((min, max))
    } else {
        let value = value.parse().ok()?;
        Some((value, value))
    }
}

struct NameText {
    bytes: [u8; 1024],
    len: usize,
}
impl std::fmt::Write for NameText {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl Plugin for Rewrite {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut name = NameText {
            bytes: [0; 1024],
            len: 0,
        };
        if write!(name, "{}", question.name).is_err() {
            return next.run(cx).await;
        }
        name.bytes[..name.len].make_ascii_lowercase();
        let name = std::str::from_utf8(&name.bytes[..name.len]).expect("DNS presentation is UTF-8");
        let end = self
            .rules
            .iter()
            .position(|rule| rule.stop && rule.matcher.matches(name))
            .map_or(self.rules.len(), |i| i + 1);
        let outcome = next.run(cx).await;
        let rewrite_rcode = |mut code: u16| {
            for rule in self.rules[..end]
                .iter()
                .rev()
                .filter(|rule| rule.matcher.matches(name))
            {
                if let Action::Rcode(from, to) = rule.action
                    && code == from
                {
                    code = to;
                }
            }
            code
        };
        if let Outcome::Unanswered(code) = outcome {
            return Outcome::Unanswered(Rcode(rewrite_rcode(code.0)));
        }
        if outcome == Outcome::Response
            && let Ok(response) = Message::parse(cx.response)
        {
            let old = response.rcode().0;
            let records = usize::from(response.answer_count())
                + usize::from(response.authority_count())
                + usize::from(response.additional_count());
            let opt = response
                .additionals()
                .find(|rr| rr.rtype == Type::OPT)
                .map(|rr| rr.ttl_offset);
            let mut new = old;
            for _ in 0..records.max(1) {
                new = rewrite_rcode(new);
            }
            // RFC 6891 §6.1.3: the high RCODE bits occupy the OPT extended RCODE.
            if new != old {
                cx.response[3] = (cx.response[3] & 0xf0) | (new as u8 & 0x0f);
                if let Some(offset) = opt {
                    cx.response[offset] = (new >> 4) as u8;
                }
            }
            let Ok(mut response) = MessageMut::parse(cx.response) else {
                return outcome;
            };
            // RFC 6891 §6.1.3: OPT's TTL field contains EDNS metadata, not a TTL.
            response.rewrite_ttls(|mut ttl| {
                for rule in self.rules[..end]
                    .iter()
                    .rev()
                    .filter(|rule| rule.matcher.matches(name))
                {
                    if let Action::Ttl(min, max) = rule.action {
                        ttl = ttl.max(min).min(max);
                    }
                }
                ttl
            });
        }
        outcome
    }
}
