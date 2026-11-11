//! Server-side search path completion.

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Error as ServerError, Next, Outcome, Plugin, Protocol};

#[derive(Debug)]
pub struct AutoPath {
    pub(crate) domains: Vec<Name>,
    pub(crate) search: Vec<Option<Name>>,
    #[allow(dead_code)]
    pub(crate) provider: Option<String>,
}

impl AutoPath {
    pub(crate) fn parse(cursor: &mut Cursor<'_>, domains: &[&str]) -> Result<Self, Error> {
        cursor.next();
        let args = cursor.remaining_args();
        let (source, zones) = args.split_last().ok_or_else(|| cursor.arg_err())?;
        let mut search = Vec::new();
        let provider = if let Some(provider) = source.strip_prefix('@') {
            Some(provider.to_owned())
        } else {
            let file =
                std::fs::read_to_string(source).map_err(|err| cursor.error(err.to_string()))?;
            for line in file.lines() {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                match fields.first().copied() {
                    Some("domain") => {
                        search = fields.get(1).into_iter().map(|s| (*s).to_owned()).collect()
                    }
                    Some("search") => {
                        search = fields[1..].iter().map(|s| (*s).to_owned()).collect()
                    }
                    _ => {}
                }
            }
            for suffix in &mut search {
                if !suffix.ends_with('.') {
                    suffix.push('.');
                }
            }
            search.push(String::new());
            None
        };
        let domains = origins_from_args_or_server_block(
            &zones.iter().map(String::as_str).collect::<Vec<_>>(),
            domains,
        );
        Ok(Self {
            domains: domains.iter().filter_map(|d| d.parse().ok()).collect(),
            search: search.iter().map(|s| s.parse().ok()).collect(),
            provider,
        })
    }
}

impl Plugin for AutoPath {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        if cx.autopath_lookup_active()
            || self.search.is_empty()
            || self.search[0]
                .as_ref()
                .is_none_or(|first| !within(question.name, first))
            || !self.domains.iter().any(|zone| within(question.name, zone))
        {
            return next.run(cx).await;
        }
        let outcome = next.run(cx).await;
        if outcome != Outcome::Response {
            return outcome;
        }
        let Ok(first) = Message::parse(cx.response) else {
            return Outcome::Error(ServerError::InvalidQuery);
        };
        if first.rcode() != Rcode::NXDOMAIN {
            return outcome;
        }
        let original = cx.response.clone();
        let first_labels = self.search[0].as_ref().map_or(0, Name::label_count);
        let base_labels = question.name.labels().count().saturating_sub(first_labels);
        let mut wire = [0u8; 255];
        let mut used = 0;
        for label in question.name.labels().take(base_labels) {
            wire[used] = label.len() as u8;
            used += 1;
            wire[used..used + label.len()].copy_from_slice(label);
            used += label.len();
        }
        for suffix in &self.search[1..] {
            let suffix = suffix.as_ref().map_or(&[0][..], Name::as_wire);
            if used + suffix.len() > wire.len() {
                continue;
            }
            wire[used..used + suffix.len()].copy_from_slice(suffix);
            let Ok(name) = NameRef::parse(&wire[..used + suffix.len()], 0) else {
                continue;
            };
            // shortcut: search Self Lookup allocates; remove when #86 makes it allocation-free.
            let reply = match cx.autopath_lookup(&name.to_name(), question.qtype).await {
                Ok(reply) => reply,
                Err(ServerError::SelfLookupDropped) => continue,
                Err(error) => return Outcome::Error(error),
            };
            let Ok(response) = Message::parse(&reply) else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            if response.rcode() == Rcode::NXDOMAIN {
                continue;
            }
            return match rebuild(cx, &response) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            };
        }
        cx.response.clear();
        cx.response.extend_from_slice(&original);
        outcome
    }
}

fn within(name: NameRef<'_>, domain: &Name) -> bool {
    let suffix = NameRef::parse(domain.as_wire(), 0).unwrap();
    let count = name.labels().count();
    let suffix_count = suffix.labels().count();
    // RFC 4343 §3: DNS names compare ASCII case-insensitively, label by label.
    count >= suffix_count
        && name
            .labels()
            .skip(count - suffix_count)
            .zip(suffix.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn rebuild(cx: &mut Context<'_, '_>, response: &Message<'_>) -> Result<(), ServerError> {
    let question = cx
        .query
        .questions()
        .next()
        .ok_or(ServerError::InvalidQuery)?;
    let max = cx.max_response_size.max(512);
    if cx.response.capacity() < max {
        if cx.protocol == Protocol::Tcp {
            cx.response.reserve(max.saturating_sub(cx.response.len()));
        } else {
            return Err(ServerError::ResponseBufferTooSmall);
        }
    }
    // RFC 1035 §4.1.2: the Response retains the original Question.
    let mut b = MessageBuilder::new(cx.response, max, cx.query.id(), response.flags())
        .map_err(ServerError::Build)?;
    b.question(question.name, question.qtype, question.qclass)
        .map_err(ServerError::Build)?;
    if let Some(first) = response.answers().find(|rr| {
        !rr.name
            .labels()
            .zip(question.name.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
            || rr.name.labels().count() != question.name.labels().count()
    }) {
        b.record_with(
            Section::Answer,
            question.name,
            Type::CNAME,
            Class::IN,
            first.ttl,
            |w| w.write_name(first.name),
        )
        .map_err(ServerError::Build)?;
    }
    for (section, records) in [
        (Section::Answer, response.answers()),
        (Section::Authority, response.authorities()),
        (Section::Additional, response.additionals()),
    ] {
        for rr in records {
            let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
            b.record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |w| {
                data.write(w)
            })
            .map_err(ServerError::Build)?;
        }
    }
    let _ = b.finish();
    Ok(())
}
