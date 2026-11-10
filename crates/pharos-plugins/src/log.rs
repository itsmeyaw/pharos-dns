//! Corefile access logging rules.

use crate::log_format::{COMMON_LOG_FORMAT, Format};
use pharos_corefile::{Cursor, Error};
use pharos_proto::{Message, Name, NameRef, Opcode, Rcode, Type};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::{cell::RefCell, time::Instant};

thread_local! {
    static BUFFER: RefCell<String> = RefCell::new(String::with_capacity(512));
}

#[derive(Debug)]
struct Rule {
    scope: Option<Name>,
    format: Format,
    classes: u8,
}

#[derive(Debug)]
pub struct Log {
    rules: Vec<Rule>,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Log, Error> {
    let mut rules = Vec::new();
    while cursor.next() {
        let mut args = cursor.remaining_args();
        let format = if args.len() > 1 && args.last().is_some_and(|arg| arg.contains('{')) {
            args.pop().unwrap()
        } else {
            COMMON_LOG_FORMAT.to_owned()
        };
        if args.is_empty() {
            args.push(".".to_owned());
        }
        let mut classes = 0;
        while cursor.next_block() {
            if cursor.val() != "class" {
                return Err(cursor.error(format!("unknown property '{}'", cursor.val())));
            }
            let values = cursor.remaining_args();
            if values.is_empty() {
                return Err(cursor.arg_err());
            }
            for value in values {
                classes |= match value.as_str() {
                    "all" => 1,
                    "success" => 2,
                    "denial" => 4,
                    "error" => 8,
                    _ => return Err(cursor.error(format!("invalid Class: {value}"))),
                };
            }
        }
        if classes == 0 {
            classes = 1;
        }
        for scope in args {
            let fqdn = if scope.ends_with('.') {
                scope
            } else {
                format!("{scope}.")
            };
            rules.push(Rule {
                scope: fqdn.parse().ok(),
                format: Format::compile(&format),
                classes,
            });
        }
    }
    Ok(Log { rules })
}

impl Plugin for Log {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let rule = self.rules.iter().find(|rule| {
            let Some(scope) = &rule.scope else {
                return false;
            };
            let labels = cx
                .query
                .questions()
                .next()
                .map_or_else(|| NameRef::parse(&[0], 0).unwrap(), |q| q.name);
            let count = labels.labels().count();
            let scope_count = scope.label_count();
            count >= scope_count
                && labels
                    .labels()
                    .skip(count - scope_count)
                    .zip(NameRef::parse(scope.as_wire(), 0).unwrap().labels())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        });
        let Some(rule) = rule else {
            return next.run(cx).await;
        };
        let start = Instant::now();
        let outcome = next.run(cx).await;
        let (kind, class, bit) = classify(cx, outcome);
        cx.metadata.insert("log/type", kind);
        cx.metadata.insert("log/class", class);
        if rule.classes & (1 | bit) != 0 {
            BUFFER.with_borrow_mut(|buffer| {
                buffer.clear();
                rule.format.format(buffer, cx, outcome, start.elapsed());
                pharos_server::logging::log("INFO", "log", buffer);
            });
        }
        outcome
    }
}

fn classify(cx: &Context<'_>, outcome: Outcome) -> (&'static str, &'static str, u8) {
    let message = (outcome == Outcome::Response)
        .then(|| Message::parse(cx.response).ok())
        .flatten();
    let code = match outcome {
        Outcome::Response => message.map(|m| m.rcode()),
        Outcome::Error(_) => Some(Rcode::SERVFAIL),
        Outcome::Unanswered(code)
            if matches!(
                code,
                Rcode::SERVFAIL | Rcode::FORMERR | Rcode::REFUSED | Rcode::NOTIMP
            ) =>
        {
            Some(code)
        }
        _ => None,
    };
    let Some(code) = code else {
        return ("OTHERERROR", "error", 8);
    };
    let opcode = message.map_or(cx.query.opcode(), |m| m.opcode());
    let question = match message {
        Some(m) => m.questions().next(),
        None => cx.query.questions().next(),
    };
    if opcode == Opcode::UPDATE {
        return ("UPDATE", "error", 8);
    }
    if opcode == Opcode::NOTIFY
        || question.is_some_and(|q| matches!(q.qtype, Type::AXFR | Type::IXFR))
    {
        return ("META", "error", 8);
    }
    if let Some(msg) = message {
        if msg.opt().is_some_and(|opt| opt.dnssec_ok()) && expired_signature(msg) {
            return ("OTHERERROR", "error", 8);
        }
        if msg.answer_count() > 0 {
            if code == Rcode::NOERROR {
                return ("NOERROR", "success", 2);
            }
            if code == Rcode::NXDOMAIN {
                return ("OTHERERROR", "error", 8);
            }
        }
        if code == Rcode::NOERROR && msg.authorities().any(|r| r.rtype == Type::SOA) {
            return ("NODATA", "denial", 4);
        }
        if code == Rcode::NXDOMAIN {
            return ("NXDOMAIN", "denial", 4);
        }
        if code == Rcode::NOERROR && msg.authorities().any(|r| r.rtype == Type::NS) {
            return ("DELEGATION", "success", 2);
        }
    }
    match code {
        Rcode::NOERROR => ("NOERROR", "success", 2),
        Rcode::NXDOMAIN => ("NXDOMAIN", "denial", 4),
        Rcode::SERVFAIL | Rcode::NOTIMP => ("SERVERERROR", "error", 8),
        _ => ("OTHERERROR", "error", 8),
    }
}

fn expired_signature(message: Message<'_>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64);
    let adjust = |value: u32| {
        let value = i64::from(value);
        value + (value - now) / (1_i64 << 31) * (1_i64 << 31)
    };
    message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .any(|record| {
            if record.rtype != Type::RRSIG || record.rdata.len() < 16 {
                return false;
            }
            let expiry = u32::from_be_bytes(record.rdata[8..12].try_into().unwrap());
            let inception = u32::from_be_bytes(record.rdata[12..16].try_into().unwrap());
            adjust(inception) > now || now > adjust(expiry)
        })
}
