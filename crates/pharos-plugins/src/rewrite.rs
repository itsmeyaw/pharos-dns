//! Internal Query and Response rewriting.

use std::fmt::Write;

use pharos_corefile::{Cursor, Error};
use pharos_proto::{
    Class, FixedBuffer, Message, MessageBuilder, MessageMut, Name, NameRef, Rdata, Section, Type,
};
use pharos_server::{Context, Error as ServerError, Metadata, Next, Outcome, Plugin};

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
    Name(String, bool, Option<Vec<NamePart>>, Vec<AnswerRule>),
    Cname(Matcher, String),
    Edns(u16, EdnsValue, EdnsAction, bool),
}

#[derive(Debug)]
enum EdnsValue {
    Local(Vec<u8>),
    Variable(String),
    Nsid,
    Subnet(u8, u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EdnsAction {
    Set,
    Append,
    Replace,
    Unset,
}

#[derive(Debug)]
struct AnswerRule {
    value: bool,
    pattern: regex::Regex,
    replacement: String,
}

#[derive(Debug)]
enum NamePart {
    Literal(String),
    Capture(usize),
    Label(String),
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
    edns_buffers: Vec<tokio::sync::Mutex<EdnsScratch>>,
}

#[derive(Debug)]
struct EdnsScratch {
    wire: Vec<u8>,
    matched: Vec<u8>,
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
            if kind.eq_ignore_ascii_case("edns0") {
                let Some([typ, action, rest @ ..]) = args.get(..) else {
                    return Err(cursor.arg_err());
                };
                let action = match action.to_ascii_lowercase().as_str() {
                    "set" => EdnsAction::Set,
                    "append" => EdnsAction::Append,
                    "replace" => EdnsAction::Replace,
                    "unset" => EdnsAction::Unset,
                    _ => return Err(cursor.error("invalid EDNS action")),
                };
                let (revert, rest) = if action != EdnsAction::Unset
                    && rest.last().is_some_and(|value| value == "revert")
                {
                    (true, &rest[..rest.len() - 1])
                } else {
                    (false, rest)
                };
                let (code, data) = if typ.eq_ignore_ascii_case("local") {
                    let (code, data) = match (action, rest) {
                        (EdnsAction::Unset, [code]) => (code.as_str(), ""),
                        (EdnsAction::Unset, _) => return Err(cursor.arg_err()),
                        (_, [code, data]) => (code.as_str(), data.as_str()),
                        _ => return Err(cursor.arg_err()),
                    };
                    let code =
                        parse_edns_number(code).ok_or_else(|| cursor.error("invalid EDNS code"))?;
                    let data = if data.starts_with('{') && data.ends_with('}') {
                        let variable = &data[1..data.len() - 1];
                        if !matches!(
                            variable,
                            "qname"
                                | "qtype"
                                | "client_ip"
                                | "client_port"
                                | "protocol"
                                | "server_ip"
                                | "server_port"
                        ) && !variable
                            .split_once('/')
                            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
                        {
                            return Err(cursor.error("invalid EDNS variable"));
                        }
                        EdnsValue::Variable(variable.to_owned())
                    } else if let Some(hex) = data.strip_prefix("0x") {
                        if hex.len() % 2 != 0 {
                            return Err(cursor.error("invalid hex data"));
                        }
                        EdnsValue::Local(
                            hex.as_bytes()
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|pair| {
                                    let pair = std::str::from_utf8(pair)
                                        .map_err(|_| cursor.error("invalid hex data"))?;
                                    u8::from_str_radix(pair, 16)
                                        .map_err(|_| cursor.error("invalid hex data"))
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        )
                    } else {
                        EdnsValue::Local(data.as_bytes().to_vec())
                    };
                    (code, data)
                } else if typ.eq_ignore_ascii_case("nsid") {
                    if !rest.is_empty() {
                        return Err(cursor.arg_err());
                    }
                    (3, EdnsValue::Nsid)
                } else if typ.eq_ignore_ascii_case("subnet") {
                    let (v4, v6) = match (action, rest) {
                        (EdnsAction::Unset, []) => (0, 0),
                        (_, [v4, v6]) if action != EdnsAction::Unset => (
                            parse_edns_number(v4)
                                .filter(|v| *v <= 32)
                                .ok_or_else(|| cursor.error("invalid IPv4 prefix"))?
                                as u8,
                            parse_edns_number(v6)
                                .filter(|v| *v <= 128)
                                .ok_or_else(|| cursor.error("invalid IPv6 prefix"))?
                                as u8,
                        ),
                        _ => return Err(cursor.arg_err()),
                    };
                    (8, EdnsValue::Subnet(v4, v6))
                } else {
                    return Err(cursor.error("unsupported EDNS rule"));
                };
                rules.push(Rule {
                    matcher: Matcher::Any,
                    action: Action::Edns(code, data, action, revert),
                    stop,
                });
                continue;
            }
            if kind.eq_ignore_ascii_case("cname") {
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
                let lower = from.to_ascii_lowercase();
                let matcher = match mode.to_ascii_lowercase().as_str() {
                    "exact" => Matcher::Exact(normal(from)),
                    "prefix" => Matcher::Prefix(lower),
                    "suffix" => Matcher::Suffix(lower),
                    "substring" => Matcher::Substring(lower),
                    "regex" => {
                        if lower.len() > 10_000 {
                            return Err(cursor.error("regex pattern too long"));
                        }
                        Matcher::Regex(
                            regex::Regex::new(&lower).map_err(|_| cursor.error("invalid regex"))?,
                        )
                    }
                    _ => return Err(cursor.error("invalid CNAME match type")),
                };
                let replacement = if mode.eq_ignore_ascii_case("exact") {
                    normal(to)
                } else {
                    to.to_ascii_lowercase()
                };
                rules.push(Rule {
                    matcher: Matcher::Any,
                    action: Action::Cname(matcher, replacement),
                    stop,
                });
                continue;
            }
            if kind.eq_ignore_ascii_case("name") {
                let (mode, from, to, extra) = match args {
                    [from, to] => ("exact", from, to, &[][..]),
                    [mode, from, to, extra @ ..] => (mode.as_str(), from, to, extra),
                    _ => return Err(cursor.arg_err()),
                };
                let (metadata, extra) = if extra.first().is_some_and(|value| value == "metadata") {
                    (true, &extra[1..])
                } else {
                    (false, extra)
                };
                if metadata && !mode.eq_ignore_ascii_case("regex") {
                    return Err(cursor.error("metadata requires regex"));
                }
                let (auto, answers) =
                    answer_rules(extra).ok_or_else(|| cursor.error("invalid answer rules"))?;
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
                    "regex" => {
                        if from.len() > 10_000 {
                            return Err(cursor.error("regex pattern too long"));
                        }
                        let pattern =
                            regex::Regex::new(from).map_err(|_| cursor.error("invalid regex"))?;
                        let used = (0..=100)
                            .filter(|index| to.contains(&format!("{{{index}}}")))
                            .count();
                        if !metadata && used > pattern.captures_len() - 1 {
                            return Err(cursor.error("too many capture groups"));
                        }
                        Matcher::Regex(pattern)
                    }
                    _ => return Err(cursor.error("invalid name match type")),
                };
                let parts = if metadata {
                    let Matcher::Regex(pattern) = &matcher else {
                        unreachable!()
                    };
                    let mut replacement = to.to_owned();
                    if !replacement.ends_with('.') {
                        replacement.push('.');
                    }
                    Some(
                        name_parts(&replacement, pattern.captures_len() - 1)
                            .ok_or_else(|| cursor.error("invalid metadata replacement"))?,
                    )
                } else {
                    None
                };
                rules.push(Rule {
                    matcher,
                    action: Action::Name(
                        normal(to),
                        auto || mode.eq_ignore_ascii_case("exact"),
                        parts,
                        answers,
                    ),
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
        let edns_buffers = if rules
            .iter()
            .any(|rule| matches!(rule.action, Action::Edns(..)))
        {
            (0..=10)
                .map(|_| {
                    let buffer = tokio::sync::Mutex::new(EdnsScratch {
                        wire: vec![0; 2 * 65535],
                        matched: vec![0; rules.len()],
                    });
                    // Initialize the platform mutex at setup, not on the first Query.
                    drop(buffer.try_lock().expect("new scratch buffer"));
                    buffer
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(Self {
            rules,
            edns_buffers,
        })
    }
}

fn answer_rules(args: &[String]) -> Option<(bool, Vec<AnswerRule>)> {
    if args.is_empty() {
        return Some((false, Vec::new()));
    }
    if args[0] != "answer" {
        return None;
    }
    let mut index = 0;
    let mut auto = false;
    let mut rules = Vec::new();
    while index < args.len() {
        if args[index] == "answer" {
            index += 1;
        }
        let kind = args.get(index)?;
        index += 1;
        if kind == "auto" {
            auto = true;
            continue;
        }
        if kind != "name" && kind != "value" {
            return None;
        }
        let from = args.get(index)?;
        let to = args.get(index + 1)?;
        index += 2;
        if from.len() > 10_000 {
            return None;
        }
        let pattern = regex::Regex::new(from).ok()?;
        let used = (0..=100)
            .filter(|number| to.contains(&format!("{{{number}}}")))
            .count();
        if used > pattern.captures_len() - 1 {
            return None;
        }
        let mut replacement = to.to_ascii_lowercase();
        if !replacement.ends_with('.') {
            replacement.push('.');
        }
        rules.push(AnswerRule {
            value: kind == "value",
            pattern,
            replacement,
        });
    }
    if auto && rules.iter().any(|rule| !rule.value) {
        return None;
    }
    Some((auto, rules))
}

fn name_parts(mut replacement: &str, groups: usize) -> Option<Vec<NamePart>> {
    let mut parts = Vec::new();
    while !replacement.is_empty() {
        let (before, rest) = replacement
            .split_once('{')
            .map_or((replacement, None), |(a, b)| (a, Some(b)));
        if before.contains('}') {
            return None;
        }
        if !before.is_empty() {
            parts.push(NamePart::Literal(before.to_lowercase()));
        }
        let Some(rest) = rest else {
            break;
        };
        let (label, after) = rest.split_once('}')?;
        if let Ok(index) = label.parse::<usize>() {
            if index > groups {
                return None;
            }
            parts.push(NamePart::Capture(index));
        } else if label
            .split_once('/')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
            && !label.contains(['{', '}'])
        {
            parts.push(NamePart::Label(label.to_owned()));
        } else {
            return None;
        }
        replacement = after;
    }
    Some(parts)
}

fn parse_edns_number(value: &str) -> Option<u16> {
    let value = value.strip_prefix('+').unwrap_or(value);
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        u16::from_str_radix(binary, 2).ok()
    } else if let Some(octal) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        u16::from_str_radix(octal, 8).ok()
    } else if value.len() > 1 && value.starts_with('0') {
        u16::from_str_radix(&value[1..], 8).ok()
    } else {
        value.parse().ok()
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

fn cname_replacement(
    matcher: &Matcher,
    replacement: &str,
    value: NameRef<'_>,
) -> Option<(NameText, Name)> {
    let mut source = NameText {
        bytes: [0; 1024],
        len: 0,
    };
    write!(source, "{value}").ok()?;
    let input = std::str::from_utf8(&source.bytes[..source.len]).ok()?;
    if !matcher.matches(input) {
        return None;
    }
    let mut text = NameText {
        bytes: [0; 1024],
        len: 0,
    };
    match matcher {
        Matcher::Exact(_) => text.write_str(replacement).ok()?,
        Matcher::Prefix(from) => {
            text.write_str(replacement).ok()?;
            text.write_str(input.strip_prefix(from)?).ok()?;
        }
        Matcher::Suffix(from) => {
            text.write_str(input.strip_suffix(from)?).ok()?;
            text.write_str(replacement).ok()?;
        }
        Matcher::Substring(from) => {
            for (index, part) in input.split(from).enumerate() {
                if index > 0 {
                    text.write_str(replacement).ok()?;
                }
                text.write_str(part).ok()?;
            }
        }
        Matcher::Regex(pattern) => {
            // shortcut: regex captures allocate; non-regex rules remain allocation-free.
            let captures = pattern.captures(input)?;
            let mut result = replacement.to_owned();
            for (index, capture) in captures.iter().enumerate() {
                result = result.replace(
                    &format!("{{{index}}}"),
                    capture.map_or("", |value| value.as_str()),
                );
            }
            text.write_str(&result).ok()?;
        }
        Matcher::Any => return None,
    }
    let text = std::str::from_utf8(&text.bytes[..text.len]).ok()?;
    let mut wire = [0; 255];
    let wire = Name::parse_absolute_into(text, &mut wire).ok()?;
    Some((source, NameRef::parse(wire, 0).ok()?.to_name()))
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

fn remap_response<'a>(
    source: NameRef<'a>,
    from: NameRef<'_>,
    to: NameRef<'_>,
    suffix: Option<(&str, &str)>,
    buffer: &'a mut [u8; 255],
) -> NameRef<'a> {
    let Some((old, new)) = suffix else {
        return remap(source, from, to, buffer);
    };
    let mut text = NameText {
        bytes: [0; 1024],
        len: 0,
    };
    if write!(text, "{source}").is_err() {
        return source;
    }
    let text = std::str::from_utf8(&text.bytes[..text.len]).expect("DNS presentation is UTF-8");
    let Some(prefix) = text.strip_suffix(old) else {
        return source;
    };
    let mut rewritten = NameText {
        bytes: [0; 1024],
        len: 0,
    };
    if rewritten
        .write_str(prefix)
        .and_then(|()| rewritten.write_str(new))
        .is_err()
    {
        return source;
    }
    let text =
        std::str::from_utf8(&rewritten.bytes[..rewritten.len]).expect("DNS presentation is UTF-8");
    match Name::parse_absolute_into(text, buffer) {
        Ok(wire) => NameRef::parse(wire, 0).expect("validated name"),
        Err(_) => source,
    }
}

fn apply_answer<'a>(
    source: NameRef<'a>,
    names: (NameRef<'_>, NameRef<'_>),
    suffix: Option<(&str, &str)>,
    auto: bool,
    answers: &[AnswerRule],
    value: bool,
    buffer: &'a mut [u8; 255],
) -> NameRef<'a> {
    let (from, to) = names;
    if !answers.iter().any(|rule| rule.value == value) {
        return if auto {
            remap_response(source, from, to, suffix, buffer)
        } else {
            source
        };
    }
    // shortcut: explicit answer regex captures allocate, outside the non-regex path.
    let mut text = source.to_string();
    for rule in answers.iter().rev().filter(|rule| rule.value == value) {
        let Some(captures) = rule.pattern.captures(&text) else {
            continue;
        };
        let mut replacement = rule.replacement.clone();
        for (index, capture) in captures.iter().enumerate() {
            replacement = replacement.replace(
                &format!("{{{index}}}"),
                capture.map_or("", |value| value.as_str()),
            );
        }
        text = replacement;
    }
    let mut intermediate = [0; 255];
    let Ok(wire) = Name::parse_absolute_into(&text, &mut intermediate) else {
        return source;
    };
    let current = NameRef::parse(wire, 0).expect("validated name");
    let mut mapped_buffer = [0; 255];
    let mapped = if auto {
        remap_response(current, from, to, suffix, &mut mapped_buffer)
    } else {
        current
    };
    let mut len = 0;
    for label in mapped.labels() {
        if len + label.len() + 1 >= buffer.len() {
            return source;
        }
        buffer[len] = label.len() as u8;
        len += 1;
        buffer[len..len + label.len()].copy_from_slice(label);
        len += label.len();
    }
    buffer[len] = 0;
    NameRef::parse(&buffer[..=len], 0).expect("validated name")
}

fn apply_rule(
    rule: &Rule,
    query: &mut Message<'_>,
    metadata: &Metadata<'_>,
) -> Result<bool, ServerError> {
    let Some(question) = query.questions().next() else {
        return Ok(false);
    };
    let mut name = NameText {
        bytes: [0; 1024],
        len: 0,
    };
    write!(name, "{}", question.name).map_err(|_| ServerError::InvalidQuery)?;
    name.bytes[..name.len].make_ascii_lowercase();
    let name =
        std::str::from_utf8(&name.bytes[..name.len]).map_err(|_| ServerError::InvalidQuery)?;
    match &rule.action {
        Action::Type(from, to) => {
            if from.0 == 0 || to.0 == 0 || question.qtype != *from {
                return Ok(false);
            }
            *query = query.with_question_type(*to);
            Ok(true)
        }
        Action::Class(from, to) => {
            if from.0 == 0 || to.0 == 0 || question.qclass != *from {
                return Ok(false);
            }
            *query = query.with_question_class(*to);
            Ok(true)
        }
        Action::Name(target, _, parts, _) => {
            if !rule.matcher.matches(name) {
                return Ok(false);
            }
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
                Matcher::Regex(pattern) => {
                    // shortcut: regex captures allocate; non-regex rules remain allocation-free.
                    let captures = pattern.captures(name).expect("matched regex");
                    if let Some(parts) = parts {
                        let mut result = Ok(());
                        for part in parts {
                            match part {
                                NamePart::Literal(value) => {
                                    result = result.and_then(|()| text.write_str(value))
                                }
                                NamePart::Capture(index) => {
                                    result = result.and_then(|()| {
                                        text.write_str(
                                            captures.get(*index).map_or("", |value| value.as_str()),
                                        )
                                    })
                                }
                                NamePart::Label(label) => {
                                    if !metadata.enabled() {
                                        return Ok(false);
                                    }
                                    let Some(value) =
                                        metadata.get(label).filter(|value| !value.is_empty())
                                    else {
                                        return Ok(false);
                                    };
                                    result =
                                        result.and_then(|()| text.write_str(&value.to_lowercase()));
                                }
                            }
                        }
                        result
                    } else {
                        let mut replacement = target.clone();
                        for (index, value) in captures.iter().enumerate() {
                            replacement = replacement.replace(
                                &format!("{{{index}}}"),
                                value.map_or("", |value| value.as_str()),
                            );
                        }
                        text.write_str(&replacement)
                    }
                }
                Matcher::Any => unreachable!("validated name matcher"),
            };
            result.map_err(|_| ServerError::InvalidQuery)?;
            let mut wire = [0; 255];
            let text = std::str::from_utf8(&text.bytes[..text.len])
                .map_err(|_| ServerError::InvalidQuery)?;
            let wire = Name::parse_absolute_into(text, &mut wire)
                .map_err(|_| ServerError::InvalidQuery)?;
            *query = query.with_question_name(NameRef::parse(wire, 0).expect("validated name"));
            Ok(true)
        }
        Action::Cname(..) => Ok(true),
        _ => Ok(rule.matcher.matches(name)),
    }
}

fn active_at(
    rules: &[Rule],
    index: usize,
    mut query: Message<'_>,
    metadata: &Metadata<'_>,
) -> bool {
    for (position, rule) in rules.iter().enumerate().take(index + 1) {
        let matched = apply_rule(rule, &mut query, metadata).unwrap_or(false);
        if position == index {
            return matched;
        }
        if matched && rule.stop {
            return false;
        }
    }
    false
}

fn states_at<'a>(
    rules: &[Rule],
    index: usize,
    mut query: Message<'a>,
    metadata: &Metadata<'_>,
    recorded: Option<&[u8]>,
) -> Option<(Message<'a>, Message<'a>)> {
    for (position, rule) in rules.iter().enumerate().take(index + 1) {
        let before = query;
        let matched = if recorded.is_some_and(|bits| bits[position] == 0) {
            false
        } else if matches!(rule.action, Action::Edns(..)) {
            recorded.is_none_or(|bits| bits[position] != 0)
        } else {
            apply_rule(rule, &mut query, metadata).ok()?
        };
        if position == index {
            return matched.then_some((before, query));
        }
        if matched && rule.stop {
            return None;
        }
    }
    None
}

fn copy_name(source: NameRef<'_>, output: &mut [u8; 255]) -> Option<usize> {
    let mut len = 0;
    for label in source.labels() {
        if len + label.len() + 1 >= output.len() {
            return None;
        }
        output[len] = label.len() as u8;
        len += 1;
        output[len..len + label.len()].copy_from_slice(label);
        len += label.len();
    }
    output[len] = 0;
    Some(len + 1)
}

fn apply_history<'a>(
    source: NameRef<'a>,
    original: Message<'_>,
    metadata: &Metadata<'_>,
    rules: (&[Rule], Option<&[u8]>),
    end: usize,
    value: bool,
    output: &'a mut [u8; 255],
) -> NameRef<'a> {
    let (rules, recorded) = rules;
    let mut current = [0; 255];
    let Some(mut len) = copy_name(source, &mut current) else {
        return source;
    };
    for index in (0..end).rev() {
        let Action::Name(target, auto, _, answers) = &rules[index].action else {
            continue;
        };
        if !auto && answers.is_empty() {
            continue;
        }
        let Some((before, after)) = states_at(rules, index, original, metadata, recorded) else {
            continue;
        };
        let (Some(before), Some(after)) = (before.questions().next(), after.questions().next())
        else {
            continue;
        };
        let suffix = match (&rules[index].matcher, auto) {
            (Matcher::Suffix(from), true) => Some((target.as_str(), from.as_str())),
            _ => None,
        };
        let name = NameRef::parse(&current[..len], 0).expect("validated name");
        let mut mapped = [0; 255];
        let result = apply_answer(
            name,
            (after.name, before.name),
            suffix,
            *auto,
            answers,
            value,
            &mut mapped,
        );
        let mut next = [0; 255];
        let Some(next_len) = copy_name(result, &mut next) else {
            return source;
        };
        current = next;
        len = next_len;
    }
    output[..len].copy_from_slice(&current[..len]);
    NameRef::parse(&output[..len], 0).expect("validated name")
}

struct EdnsState<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

fn subnet_data(ip: std::net::IpAddr, v4: u8, v6: u8, output: &mut [u8; 20]) -> &[u8] {
    let (family, prefix, address): (u16, u8, [u8; 16]) = match ip {
        std::net::IpAddr::V4(ip) => {
            let mut address = [0; 16];
            address[..4].copy_from_slice(&ip.octets());
            (1, v4, address)
        }
        std::net::IpAddr::V6(ip) => (2, v6, ip.octets()),
    };
    output[..2].copy_from_slice(&family.to_be_bytes());
    output[2] = prefix;
    output[3] = 0;
    let len = usize::from(prefix.div_ceil(8));
    output[4..4 + len].copy_from_slice(&address[..len]);
    // RFC 7871 §6: host bits after the source prefix are zero.
    if !prefix.is_multiple_of(8) {
        output[3 + len] &= u8::MAX << (8 - prefix % 8);
    }
    &output[..4 + len]
}

fn edns_variable<'a>(
    cx: &'a Context<'_, '_>,
    query: &Message<'_>,
    variable: &str,
    output: &'a mut [u8; 1024],
) -> Option<&'a [u8]> {
    match variable {
        "qname" => {
            let mut text = NameText {
                bytes: [0; 1024],
                len: 0,
            };
            write!(text, "{}", query.questions().next()?.name).ok()?;
            output[..text.len].copy_from_slice(&text.bytes[..text.len]);
            Some(&output[..text.len])
        }
        "qtype" => {
            output[..2].copy_from_slice(&query.questions().next()?.qtype.0.to_be_bytes());
            Some(&output[..2])
        }
        "client_port" | "server_port" => {
            let port = if variable == "client_port" {
                cx.client.port()
            } else {
                cx.local.port()
            };
            output[..2].copy_from_slice(&port.to_be_bytes());
            Some(&output[..2])
        }
        "client_ip" | "server_ip" => {
            let ip = if variable == "client_ip" {
                cx.client.ip()
            } else {
                cx.local.ip()
            };
            match (cx.client.ip(), ip) {
                (std::net::IpAddr::V4(_), std::net::IpAddr::V4(ip)) => {
                    output[..4].copy_from_slice(&ip.octets());
                    Some(&output[..4])
                }
                (std::net::IpAddr::V6(_), std::net::IpAddr::V6(ip)) => {
                    output[..16].copy_from_slice(&ip.octets());
                    Some(&output[..16])
                }
                _ => None,
            }
        }
        "protocol" => Some(match cx.protocol {
            pharos_server::Protocol::Udp => b"udp",
            pharos_server::Protocol::Tcp => b"tcp",
        }),
        label => cx
            .metadata
            .enabled()
            .then(|| cx.metadata.get(label))
            .flatten()
            .filter(|value| !value.is_empty())
            .map(str::as_bytes),
    }
}

impl<'a> EdnsState<'a> {
    fn new(bytes: &'a mut [u8], query: &Message<'_>) -> Self {
        let original = query.opt().map_or(&[][..], |opt| opt.options().as_bytes());
        Self::from_bytes(bytes, original)
    }

    fn from_bytes(bytes: &'a mut [u8], original: &[u8]) -> Self {
        bytes[..original.len()].copy_from_slice(original);
        Self {
            bytes,
            len: original.len(),
        }
    }

    fn first(&self, code: u16) -> Option<&[u8]> {
        let mut position = 0;
        while position < self.len {
            let current = u16::from_be_bytes([self.bytes[position], self.bytes[position + 1]]);
            let len = usize::from(u16::from_be_bytes([
                self.bytes[position + 2],
                self.bytes[position + 3],
            ]));
            if current == code {
                return Some(&self.bytes[position + 4..position + 4 + len]);
            }
            position += 4 + len;
        }
        None
    }

    fn remove_first(&mut self, code: u16) {
        let mut position = 0;
        while position < self.len {
            let current = u16::from_be_bytes([self.bytes[position], self.bytes[position + 1]]);
            let len = usize::from(u16::from_be_bytes([
                self.bytes[position + 2],
                self.bytes[position + 3],
            ]));
            let next = position + 4 + len;
            if current == code {
                self.bytes.copy_within(next..self.len, position);
                self.len -= next - position;
                break;
            }
            position = next;
        }
    }

    fn apply(
        &mut self,
        code: u16,
        data: &[u8],
        action: EdnsAction,
        append_existing: bool,
    ) -> Result<bool, ServerError> {
        let mut position = 0;
        let mut first = None;
        while position < self.len {
            let current = u16::from_be_bytes([self.bytes[position], self.bytes[position + 1]]);
            let len = usize::from(u16::from_be_bytes([
                self.bytes[position + 2],
                self.bytes[position + 3],
            ]));
            let next = position + 4 + len;
            if current == code {
                if action == EdnsAction::Unset {
                    self.bytes.copy_within(next..self.len, position);
                    self.len -= next - position;
                    continue;
                }
                first = Some((position, next));
                break;
            }
            position = next;
        }
        if action == EdnsAction::Unset {
            return Ok(true);
        }
        if action == EdnsAction::Append && first.is_some() && !append_existing {
            return Ok(false);
        }
        if action == EdnsAction::Replace && first.is_none() {
            return Ok(false);
        }
        let (start, old_end) = if action == EdnsAction::Append {
            (self.len, self.len)
        } else {
            first.unwrap_or((self.len, self.len))
        };
        let data_len = u16::try_from(data.len()).map_err(|_| ServerError::InvalidQuery)?;
        let new_end = start + 4 + data.len();
        let total = self.len - (old_end - start) + 4 + data.len();
        if total > self.bytes.len() {
            return Err(ServerError::ResponseBufferTooSmall);
        }
        self.bytes.copy_within(old_end..self.len, new_end);
        self.bytes[start..start + 2].copy_from_slice(&code.to_be_bytes());
        self.bytes[start + 2..start + 4].copy_from_slice(&data_len.to_be_bytes());
        self.bytes[start + 4..new_end].copy_from_slice(data);
        self.len = total;
        Ok(true)
    }
}

fn apply_edns(
    rule: &Rule,
    query: &Message<'_>,
    cx: &Context<'_, '_>,
    state: &mut EdnsState<'_>,
) -> Result<Option<bool>, ServerError> {
    let Action::Edns(code, value, action, _) = &rule.action else {
        return Ok(None);
    };
    let mut data = [0; 1024];
    let value = match value {
        EdnsValue::Local(bytes) => Some((bytes.as_slice(), true)),
        EdnsValue::Variable(variable) => {
            edns_variable(cx, query, variable, &mut data).map(|value| (value, false))
        }
        EdnsValue::Nsid => Some((&[][..], true)),
        EdnsValue::Subnet(v4, v6) => {
            let mut subnet = [0; 20];
            let bytes = subnet_data(cx.client.ip(), *v4, *v6, &mut subnet);
            data[..bytes.len()].copy_from_slice(bytes);
            Some((&data[..bytes.len()], false))
        }
    };
    value
        .map(|(value, append_existing)| state.apply(*code, value, *action, append_existing))
        .transpose()
}

fn edns_query(query: Message<'_>, options: &[u8], output: &mut [u8]) -> Result<usize, ServerError> {
    let mut fixed = FixedBuffer::new(output);
    let mut builder = MessageBuilder::new(&mut fixed, 65535, query.id(), query.flags())
        .map_err(ServerError::Build)?;
    for question in query.questions() {
        if !builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(ServerError::Build)?
        {
            return Err(ServerError::ResponseBufferTooSmall);
        }
    }
    let mut written_opt = false;
    for (section, records) in [
        (Section::Answer, query.answers()),
        (Section::Authority, query.authorities()),
        (Section::Additional, query.additionals()),
    ] {
        for rr in records {
            let written = if rr.rtype == Type::OPT {
                written_opt = true;
                builder
                    .record(section, rr.name, rr.rtype, rr.class, rr.ttl, options)
                    .map_err(ServerError::Build)?
            } else {
                let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
                builder
                    .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                        data.write(writer)
                    })
                    .map_err(ServerError::Build)?
            };
            if !written {
                return Err(ServerError::ResponseBufferTooSmall);
            }
        }
    }
    if !written_opt {
        // RFC 6891 §6.1.2: an OPT pseudo-record has a root owner and advertises UDP size.
        let root = NameRef::parse(&[0], 0).expect("root name");
        if !builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(4096),
                0,
                options,
            )
            .map_err(ServerError::Build)?
        {
            return Err(ServerError::ResponseBufferTooSmall);
        }
    }
    Ok(builder.finish().len())
}

#[inline(never)]
fn build_cname_response(
    cx: &mut Context<'_, '_>,
    lookup: Message<'_>,
    from: &NameText,
    target: &Name,
) -> Result<(), ServerError> {
    let mut scratch = [0u8; 65535];
    if cx.response.len() > scratch.len() {
        return Err(ServerError::InvalidQuery);
    }
    scratch[..cx.response.len()].copy_from_slice(cx.response);
    let response =
        Message::parse(&scratch[..cx.response.len()]).map_err(|_| ServerError::InvalidQuery)?;
    let flags = (response.flags() & !0x0200) | (lookup.flags() & 0x0200);
    let mut builder = MessageBuilder::new(
        cx.response,
        cx.max_response_size.max(512),
        response.id(),
        flags,
    )
    .map_err(ServerError::Build)?;
    for q in response.questions() {
        builder
            .question(q.name, q.qtype, q.qclass)
            .map_err(ServerError::Build)?;
    }
    for rr in response.answers() {
        let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
        if let Rdata::Cname(value) = data {
            let mut text = NameText {
                bytes: [0; 1024],
                len: 0,
            };
            let replace =
                write!(text, "{value}").is_ok() && text.bytes[..text.len] == from.bytes[..from.len];
            let value = if replace {
                NameRef::parse(target.as_wire(), 0).expect("configured name")
            } else {
                value
            };
            builder
                .record_with(Section::Answer, rr.name, rr.rtype, rr.class, rr.ttl, |w| {
                    Rdata::Cname(value).write(w)
                })
                .map_err(ServerError::Build)?;
            if replace {
                break;
            }
        }
    }
    for rr in lookup.answers() {
        let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
        builder
            .record_with(Section::Answer, rr.name, rr.rtype, rr.class, rr.ttl, |w| {
                data.write(w)
            })
            .map_err(ServerError::Build)?;
    }
    for (section, records) in [
        (Section::Authority, response.authorities()),
        (Section::Additional, response.additionals()),
    ] {
        for rr in records {
            let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
            builder
                .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |w| {
                    data.write(w)
                })
                .map_err(ServerError::Build)?;
        }
    }
    let _ = builder.finish();
    Ok(())
}

#[inline(never)]
fn revert_edns_response(
    cx: &mut Context<'_, '_>,
    original: Message<'_>,
    query_options: &[u8],
    rules: &[Rule],
    matched: &[u8],
    end: usize,
) -> Result<(), ServerError> {
    let mut scratch = [0; 65535];
    if cx.response.len() > scratch.len() {
        return Err(ServerError::InvalidQuery);
    }
    scratch[..cx.response.len()].copy_from_slice(cx.response);
    let response =
        Message::parse(&scratch[..cx.response.len()]).map_err(|_| ServerError::InvalidQuery)?;
    let response_opt = response.opt();
    if response_opt.is_none() && original.opt().is_none() {
        return Ok(());
    }
    let mut output_options = [0; 65535];
    let seed = response_opt.map_or(query_options, |opt| opt.options().as_bytes());
    let mut options = EdnsState::from_bytes(&mut output_options, seed);
    if response_opt.is_none() {
        let mut position = 0;
        while position < options.len {
            let code = u16::from_be_bytes([options.bytes[position], options.bytes[position + 1]]);
            let len = usize::from(u16::from_be_bytes([
                options.bytes[position + 2],
                options.bytes[position + 3],
            ]));
            let next = position + 4 + len;
            let registered = rules.iter().any(|rule| matches!(&rule.action, Action::Edns(candidate, EdnsValue::Local(_) | EdnsValue::Variable(_), _, _) if *candidate == code));
            if registered {
                position = next;
            } else {
                options.bytes.copy_within(next..options.len, position);
                options.len -= next - position;
            }
        }
    }
    let mut replay = [0; 65535];
    for index in (0..end).rev() {
        let Action::Edns(code, _, action, revert) = &rules[index].action else {
            continue;
        };
        if !*revert || matched[index] == 0 || options.first(*code).is_none() {
            continue;
        }
        let mut previous_options = EdnsState::new(&mut replay, &original);
        let mut previous_query = original;
        for earlier in 0..index {
            if matched[earlier] == 0 {
                continue;
            }
            if matches!(rules[earlier].action, Action::Edns(..)) {
                let _ = apply_edns(&rules[earlier], &previous_query, cx, &mut previous_options)?;
            } else {
                let _ = apply_rule(&rules[earlier], &mut previous_query, &cx.metadata)?;
            }
        }
        if *action == EdnsAction::Append {
            options.remove_first(*code);
        } else if let Some(previous) = previous_options.first(*code) {
            options.apply(*code, previous, EdnsAction::Replace, false)?;
        } else {
            options.remove_first(*code);
        }
    }
    let mut builder = MessageBuilder::new(
        cx.response,
        cx.max_response_size.max(512),
        response.id(),
        response.flags(),
    )
    .map_err(ServerError::Build)?;
    for q in response.questions() {
        builder
            .question(q.name, q.qtype, q.qclass)
            .map_err(ServerError::Build)?;
    }
    for (section, records) in [
        (Section::Answer, response.answers()),
        (Section::Authority, response.authorities()),
        (Section::Additional, response.additionals()),
    ] {
        for rr in records {
            if rr.rtype == Type::OPT {
                builder
                    .record(
                        section,
                        rr.name,
                        rr.rtype,
                        rr.class,
                        rr.ttl,
                        &options.bytes[..options.len],
                    )
                    .map_err(ServerError::Build)?;
            } else {
                let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
                builder
                    .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                        data.write(writer)
                    })
                    .map_err(ServerError::Build)?;
            }
        }
    }
    if response_opt.is_none()
        && let Some(opt) = original.opt()
    {
        let root = NameRef::parse(&[0], 0).expect("root name");
        // RFC 6891 §6.1.2: the OPT pseudo-record carries the Query's UDP payload size.
        builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(opt.udp_payload_size()),
                u32::from(opt.flags()),
                &options.bytes[..options.len],
            )
            .map_err(ServerError::Build)?;
    }
    let _ = builder.finish();
    Ok(())
}

#[inline(never)]
fn build_reverted_response(
    cx: &mut Context<'_, '_>,
    original_query: Message<'_>,
    rules: &[Rule],
    recorded: Option<&[u8]>,
    end: usize,
) -> Result<(), ServerError> {
    let mut scratch = [0u8; 65535];
    if cx.response.len() > scratch.len() {
        return Err(ServerError::InvalidQuery);
    }
    scratch[..cx.response.len()].copy_from_slice(cx.response);
    let response =
        Message::parse(&scratch[..cx.response.len()]).map_err(|_| ServerError::InvalidQuery)?;
    let original = original_query
        .questions()
        .next()
        .ok_or(ServerError::InvalidQuery)?;
    let mut builder = MessageBuilder::new(
        cx.response,
        cx.max_response_size.max(512),
        response.id(),
        response.flags(),
    )
    .map_err(ServerError::Build)?;
    builder
        .question(original.name, original.qtype, original.qclass)
        .map_err(ServerError::Build)?;
    for q in response.questions().skip(1) {
        builder
            .question(q.name, q.qtype, q.qclass)
            .map_err(ServerError::Build)?;
    }
    for (section, records) in [
        (Section::Answer, response.answers()),
        (Section::Authority, response.authorities()),
        (Section::Additional, response.additionals()),
    ] {
        for rr in records {
            let mut owner_buffer = [0; 255];
            let owner = apply_history(
                rr.name,
                original_query,
                &cx.metadata,
                (rules, recorded),
                end,
                false,
                &mut owner_buffer,
            );
            let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
            let mut value_buffer = [0; 255];
            macro_rules! map {
                ($value:expr) => {
                    apply_history(
                        $value,
                        original_query,
                        &cx.metadata,
                        (rules, recorded),
                        end,
                        true,
                        &mut value_buffer,
                    )
                };
            }
            let data = match data {
                Rdata::Cname(value) => Rdata::Cname(map!(value)),
                Rdata::Dname(value) => Rdata::Dname(map!(value)),
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
            builder
                .record_with(section, owner, rr.rtype, rr.class, rr.ttl, |writer| {
                    data.write(writer)
                })
                .map_err(ServerError::Build)?;
        }
    }
    let _ = builder.finish();
    Ok(())
}

impl Plugin for Rewrite {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let original_query = cx.query;
        let Some(_) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut end = self.rules.len();
        let mut response_rules = false;
        let mut rewrite_edns = false;
        let mut cname = None;
        // shortcut: EDNS Queries serialize per Self Lookup depth until slot-based buffers are available.
        let mut scratch = if self.edns_buffers.is_empty() {
            None
        } else {
            Some(
                self.edns_buffers[usize::from(cx.self_lookup_depth()).min(10)]
                    .lock()
                    .await,
            )
        };
        let (mut state, output, mut matches) = if let Some(scratch) = &mut scratch {
            let EdnsScratch { wire, matched } = &mut **scratch;
            matched.fill(0);
            let (options, output) = wire.split_at_mut(65535);
            (
                Some(EdnsState::new(options, &cx.query)),
                Some(output),
                Some(matched.as_mut_slice()),
            )
        } else {
            (None, None, None)
        };
        for (index, rule) in self.rules.iter().enumerate() {
            let applied = match &rule.action {
                Action::Edns(..) => match apply_edns(
                    rule,
                    &cx.query,
                    cx,
                    state.as_mut().expect("EDNS scratch allocated"),
                ) {
                    Ok(Some(matched)) => {
                        rewrite_edns = true;
                        Ok(matched)
                    }
                    Ok(None) => Ok(false),
                    Err(error) => Err(error),
                },
                _ => apply_rule(rule, &mut cx.query, &cx.metadata),
            };
            let matched = match applied {
                Ok(matched) => matched,
                Err(error) => return Outcome::Error(error),
            };
            if let Some(matches) = &mut matches {
                matches[index] = u8::from(matched);
            }
            if matched {
                match &rule.action {
                    Action::Name(_, auto, _, answers) => {
                        response_rules |= *auto || !answers.is_empty();
                    }
                    Action::Cname(matcher, to) => {
                        cname = Some((matcher, to.as_str()));
                        response_rules = true;
                    }
                    Action::Edns(_, _, _, revert) => response_rules |= *revert,
                    Action::Ttl(..) | Action::Rcode(..) => response_rules = true,
                    _ => {}
                }
            }
            if matched && rule.stop {
                response_rules = true;
                end = index + 1;
                break;
            }
        }
        let rewritten_query = cx.query;
        let outcome = if rewrite_edns {
            let state = state.as_ref().expect("EDNS state allocated");
            let wire = output.expect("EDNS output allocated");
            let len = match edns_query(cx.query, &state.bytes[..state.len], wire) {
                Ok(len) => len,
                Err(error) => return Outcome::Error(error),
            };
            cx.run_with_query(&wire[..len], next).await
        } else {
            next.run(cx).await
        };
        if outcome == Outcome::Response
            && rewrite_edns
            && let Some(matched) = matches.as_deref()
            && let Some(state) = &state
            && let Err(error) = revert_edns_response(
                cx,
                original_query,
                &state.bytes[..state.len],
                &self.rules,
                matched,
                end,
            )
        {
            return Outcome::Error(error);
        }
        if outcome == Outcome::Response
            && let Some((matcher, replacement)) = cname
        {
            let Ok(response) = Message::parse(cx.response) else {
                return outcome;
            };
            let matched = response.answers().find_map(|rr| {
                let Ok(Rdata::Cname(value)) = rr.data() else {
                    return None;
                };
                cname_replacement(matcher, replacement, value)
            });
            if let Some((from, target)) = matched {
                let Some(question) = rewritten_query.questions().next() else {
                    return outcome;
                };
                // shortcut: CNAME Self Lookup allocates; remove when issue #86 makes it allocation-free.
                if let Ok(wire) = cx.self_lookup(&target, question.qtype).await
                    && let Ok(lookup) = Message::parse(&wire)
                    && let Err(error) = build_cname_response(cx, lookup, &from, &target)
                {
                    return Outcome::Error(error);
                }
            }
        }
        let rewrite_rcode = |mut code: u16| {
            for (index, rule) in self.rules[..end].iter().enumerate().rev() {
                if !matches.as_deref().map_or_else(
                    || active_at(&self.rules, index, original_query, &cx.metadata),
                    |bits| bits[index] != 0,
                ) {
                    continue;
                }
                if let Action::Rcode(from, to) = rule.action
                    && code == from
                {
                    code = to;
                }
            }
            code
        };
        if let Outcome::Unanswered(code) = outcome {
            if !response_rules && !rewrite_edns {
                return outcome;
            }
            let code = rewrite_rcode(code.0);
            // RFC 1035 §4.1.1: a Response copies the Query opcode, RD and CD bits.
            let flags = 0x8000
                | (original_query.flags() & 0x7800)
                | if original_query.opcode() == pharos_proto::Opcode::QUERY {
                    original_query.flags() & 0x0110
                } else {
                    0
                }
                | (code & 15);
            let response_query = if response_rules {
                original_query
            } else {
                rewritten_query
            };
            let Some(question) = response_query.questions().next() else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            let Ok(mut builder) = MessageBuilder::new(
                cx.response,
                cx.max_response_size.max(512),
                original_query.id(),
                flags,
            ) else {
                return Outcome::Error(ServerError::ResponseBufferTooSmall);
            };
            if builder
                .question(question.name, question.qtype, question.qclass)
                .is_err()
            {
                return Outcome::Error(ServerError::InvalidQuery);
            }
            if code > 15 {
                let Some(opt) = original_query.opt() else {
                    return Outcome::Error(ServerError::InvalidQuery);
                };
                let root = NameRef::parse(&[0], 0).expect("root name");
                // RFC 6891 §6.1.3: extended RCODE bits are carried in the OPT TTL field.
                let ttl = (u32::from(code >> 4) << 24) | u32::from(opt.flags());
                if builder
                    .record(
                        Section::Additional,
                        root,
                        Type::OPT,
                        Class(opt.udp_payload_size()),
                        ttl,
                        &[],
                    )
                    .is_err()
                {
                    return Outcome::Error(ServerError::InvalidQuery);
                }
            }
            let _ = builder.finish();
            if rewrite_edns
                && let (Some(matched), Some(state)) = (matches.as_deref(), &state)
                && let Err(error) = revert_edns_response(
                    cx,
                    original_query,
                    &state.bytes[..state.len],
                    &self.rules,
                    matched,
                    end,
                )
            {
                return Outcome::Error(error);
            }
            return Outcome::Response;
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
                for (index, rule) in self.rules[..end].iter().enumerate().rev() {
                    if !matches.as_deref().map_or_else(
                        || active_at(&self.rules, index, original_query, &cx.metadata),
                        |bits| bits[index] != 0,
                    ) {
                        continue;
                    }
                    if let Action::Ttl(min, max) = rule.action {
                        ttl = ttl.max(min).min(max);
                    }
                }
                ttl
            });
        }
        if outcome == Outcome::Response
            && response_rules
            && let Err(error) =
                build_reverted_response(cx, original_query, &self.rules, matches.as_deref(), end)
        {
            return Outcome::Error(error);
        }
        outcome
    }
}
