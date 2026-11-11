//! Internal Query and Response rewriting.

use std::fmt::Write;

use pharos_corefile::{Cursor, Error};
use pharos_proto::{
    Class, Message, MessageBuilder, MessageMut, Name, NameRef, Rcode, Rdata, Section, Type,
};
use pharos_server::{Context, Error as ServerError, Next, Outcome, Plugin};

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
    Type(Type, Type),
    Class(Class, Class),
    Name(String, bool),
}

#[derive(Debug)]
enum Matcher {
    Any,
    Exact(String),
    Prefix(String),
    Suffix(String),
    Substring(String),
    Regex(regex::Regex),
}

impl Matcher {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Any => true,
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
            if kind.eq_ignore_ascii_case("name") {
                let (mode, from, to) = match args {
                    [from, to] => ("exact", from, to),
                    [mode, from, to] => (mode.as_str(), from, to),
                    _ => return Err(cursor.arg_err()),
                };
                let normal = |value: &str| {
                    let mut value = value.to_ascii_lowercase();
                    if !value.ends_with('.') {
                        value.push('.');
                    }
                    value
                };
                let matcher = match mode.to_ascii_lowercase().as_str() {
                    "exact" => Matcher::Exact(normal(from)),
                    "prefix" => Matcher::Prefix(normal(from)),
                    "suffix" => Matcher::Suffix(normal(from)),
                    "substring" => Matcher::Substring(normal(from)),
                    _ => return Err(cursor.error("invalid name match type")),
                };
                rules.push(Rule {
                    matcher,
                    action: Action::Name(normal(to), mode.eq_ignore_ascii_case("exact")),
                    stop,
                });
                continue;
            }
            if kind.eq_ignore_ascii_case("type") || kind.eq_ignore_ascii_case("class") {
                let [from, to] = args else {
                    return Err(cursor.arg_err());
                };
                let action = if kind.eq_ignore_ascii_case("type") {
                    let parse = |value: &str| {
                        (0..=261)
                            .chain([32768, 32769, 65535])
                            .map(Type)
                            .find(|typ| {
                                !typ.to_string().starts_with("TYPE")
                                    && typ.to_string().eq_ignore_ascii_case(value)
                            })
                    };
                    Action::Type(
                        parse(from).ok_or_else(|| cursor.error("invalid type"))?,
                        parse(to).ok_or_else(|| cursor.error("invalid type"))?,
                    )
                } else {
                    let parse = |value: &str| match value.to_ascii_uppercase().as_str() {
                        "IN" => Some(Class::IN),
                        "CS" => Some(Class::CS),
                        "CH" => Some(Class::CH),
                        "HS" => Some(Class::HS),
                        "NONE" => Some(Class::NONE),
                        "ANY" => Some(Class::ANY),
                        _ => None,
                    };
                    Action::Class(
                        parse(from).ok_or_else(|| cursor.error("invalid class"))?,
                        parse(to).ok_or_else(|| cursor.error("invalid class"))?,
                    )
                };
                rules.push(Rule {
                    matcher: Matcher::Any,
                    action,
                    stop,
                });
                continue;
            }
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

fn remap<'a>(
    source: NameRef<'a>,
    from: NameRef<'_>,
    to: NameRef<'_>,
    buffer: &'a mut [u8; 255],
) -> NameRef<'a> {
    let count = source.labels().count();
    let suffix = from.labels().count();
    if count < suffix
        || (suffix == 0 && count != 0)
        || !source.labels().skip(count - suffix).eq(from.labels())
    {
        return source;
    }
    let mut len = 0;
    for label in source.labels().take(count - suffix).chain(to.labels()) {
        if len + 1 + label.len() >= buffer.len() {
            return source;
        }
        buffer[len] = label.len() as u8;
        len += 1;
        buffer[len..len + label.len()].copy_from_slice(label);
        len += label.len();
    }
    buffer[len] = 0;
    NameRef::parse(&buffer[..=len], 0).expect("valid remapped name")
}

impl Plugin for Rewrite {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let original_query = cx.query;
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
        let mut end = self.rules.len();
        let mut name_rewritten = false;
        for (index, rule) in self.rules.iter().enumerate() {
            let matched = match rule.action {
                Action::Type(from, to)
                    if from.0 != 0
                        && to.0 != 0
                        && cx.query.questions().next().is_some_and(|q| q.qtype == from) =>
                {
                    cx.query = cx.query.with_question_type(to);
                    true
                }
                Action::Class(from, to)
                    if from.0 != 0
                        && to.0 != 0
                        && cx
                            .query
                            .questions()
                            .next()
                            .is_some_and(|q| q.qclass == from) =>
                {
                    cx.query = cx.query.with_question_class(to);
                    true
                }
                Action::Type(..) | Action::Class(..) => false,
                Action::Name(ref target, auto) if rule.matcher.matches(name) => {
                    let mut text = NameText {
                        bytes: [0; 1024],
                        len: 0,
                    };
                    let result = match &rule.matcher {
                        Matcher::Exact(_) => text.write_str(target),
                        Matcher::Prefix(from) => text
                            .write_str(target)
                            .and_then(|()| text.write_str(name.strip_prefix(from).unwrap())),
                        Matcher::Suffix(from) => text
                            .write_str(name.strip_suffix(from).unwrap())
                            .and_then(|()| text.write_str(target)),
                        Matcher::Substring(from) => {
                            let mut result = Ok(());
                            for (index, part) in name.split(from).enumerate() {
                                if index != 0 {
                                    result = result.and_then(|()| text.write_str(target));
                                }
                                result = result.and_then(|()| text.write_str(part));
                            }
                            result
                        }
                        _ => unreachable!("validated name matcher"),
                    };
                    if result.is_err() {
                        return Outcome::Error(ServerError::InvalidQuery);
                    }
                    let mut wire = [0; 255];
                    let Ok(text) = std::str::from_utf8(&text.bytes[..text.len]) else {
                        return Outcome::Error(ServerError::InvalidQuery);
                    };
                    let Ok(wire) = Name::parse_absolute_into(text, &mut wire) else {
                        return Outcome::Error(ServerError::InvalidQuery);
                    };
                    cx.query = cx
                        .query
                        .with_question_name(NameRef::parse(wire, 0).expect("validated name"));
                    name_rewritten |= auto;
                    true
                }
                Action::Name(..) => false,
                _ => rule.matcher.matches(name),
            };
            if matched && rule.stop {
                end = index + 1;
                break;
            }
        }
        let rewritten_query = cx.query;
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
        if outcome == Outcome::Response && name_rewritten {
            let mut scratch = [0u8; 65535];
            if cx.response.len() > scratch.len() {
                return Outcome::Error(ServerError::InvalidQuery);
            }
            scratch[..cx.response.len()].copy_from_slice(cx.response);
            let Ok(response) = Message::parse(&scratch[..cx.response.len()]) else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            let Some(original) = original_query.questions().next() else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            let Some(rewritten) = rewritten_query.questions().next() else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            let Ok(mut builder) = MessageBuilder::new(
                cx.response,
                cx.max_response_size.max(512),
                response.id(),
                response.flags(),
            ) else {
                return Outcome::Error(ServerError::ResponseBufferTooSmall);
            };
            for (index, q) in response.questions().enumerate() {
                let q = if index == 0 { original } else { q };
                if builder.question(q.name, q.qtype, q.qclass).is_err() {
                    return Outcome::Error(ServerError::InvalidQuery);
                }
            }
            for (section, records) in [
                (Section::Answer, response.answers()),
                (Section::Authority, response.authorities()),
                (Section::Additional, response.additionals()),
            ] {
                for rr in records {
                    let mut owner_buffer = [0; 255];
                    let owner = remap(rr.name, rewritten.name, original.name, &mut owner_buffer);
                    let Ok(data) = rr.data() else {
                        return Outcome::Error(ServerError::InvalidQuery);
                    };
                    let mut value_buffer = [0; 255];
                    macro_rules! map {
                        ($value:expr) => {
                            remap($value, rewritten.name, original.name, &mut value_buffer)
                        };
                    }
                    let data = match data {
                        Rdata::Cname(value) => Rdata::Cname(map!(value)),
                        Rdata::Ns(value) => Rdata::Ns(map!(value)),
                        Rdata::Ptr(value) => Rdata::Ptr(map!(value)),
                        Rdata::Mx {
                            preference,
                            exchange,
                        } => Rdata::Mx {
                            preference,
                            exchange: map!(exchange),
                        },
                        Rdata::Soa {
                            mname,
                            rname,
                            serial,
                            refresh,
                            retry,
                            expire,
                            minimum,
                        } => Rdata::Soa {
                            mname: map!(mname),
                            rname,
                            serial,
                            refresh,
                            retry,
                            expire,
                            minimum,
                        },
                        Rdata::Srv {
                            priority,
                            weight,
                            port,
                            target,
                        } => Rdata::Srv {
                            priority,
                            weight,
                            port,
                            target: map!(target),
                        },
                        Rdata::Naptr {
                            order,
                            preference,
                            flags,
                            services,
                            regexp,
                            replacement,
                        } => Rdata::Naptr {
                            order,
                            preference,
                            flags,
                            services,
                            regexp,
                            replacement: map!(replacement),
                        },
                        other => other,
                    };
                    if builder
                        .record_with(section, owner, rr.rtype, rr.class, rr.ttl, |writer| {
                            data.write(writer)
                        })
                        .is_err()
                    {
                        return Outcome::Error(ServerError::InvalidQuery);
                    }
                }
            }
            let _ = builder.finish();
        }
        outcome
    }
}
