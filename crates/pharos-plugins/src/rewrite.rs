//! Internal Query and Response rewriting.

use std::fmt::Write;

use pharos_corefile::{Cursor, Error};
use pharos_proto::MessageMut;
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
struct Rule {
    name: String,
    min: u32,
    max: u32,
    stop: bool,
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
            let [kind, name, ttl] = args else {
                return Err(cursor.arg_err());
            };
            if !kind.eq_ignore_ascii_case("ttl") {
                return Err(cursor.error("unsupported rewrite rule"));
            }
            let (min, max) = ttl_range(ttl).ok_or_else(|| cursor.error("invalid TTL"))?;
            let mut name = name.to_ascii_lowercase();
            if !name.ends_with('.') {
                name.push('.');
            }
            rules.push(Rule {
                name,
                min,
                max,
                stop,
            });
        }
        Ok(Self { rules })
    }
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
            .position(|rule| rule.stop && rule.name == name)
            .map_or(self.rules.len(), |i| i + 1);
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response
            && let Ok(mut response) = MessageMut::parse(cx.response)
        {
            // RFC 6891 §6.1.3: OPT's TTL field contains EDNS metadata, not a TTL.
            response.rewrite_ttls(|mut ttl| {
                for rule in self.rules[..end]
                    .iter()
                    .rev()
                    .filter(|rule| rule.name == name)
                {
                    ttl = ttl.max(rule.min).min(rule.max);
                }
                ttl
            });
        }
        outcome
    }
}
