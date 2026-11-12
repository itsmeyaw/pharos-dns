pub(crate) mod setup;

use pharos_proto::{
    MessageBuilder, Name, NameRef, Opcode, Rcode, TsigError, TsigKey, TsigRecord, Type,
};
use pharos_server::{Context, Error, Next, Outcome, Plugin};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

#[derive(Debug)]
pub struct Tsig {
    zones: Vec<Name>,
    secrets: Vec<Arc<Secret>>,
    listeners: Vec<(pharos_server::ListenerKey, SharedKeys)>,
    types: Vec<Type>,
    opcodes: Vec<Opcode>,
    all_types: bool,
    all_opcodes: bool,
}

type SharedKeys = Arc<OnceLock<Vec<Arc<Secret>>>>;

#[derive(Default)]
pub(crate) struct KeyRings(HashMap<pharos_server::ListenerKey, (SharedKeys, Vec<Arc<Secret>>)>);

impl KeyRings {
    pub(crate) fn finish(self) {
        for (_, (ring, keys)) in self.0 {
            let _ = ring.set(keys);
        }
    }
}

struct Secret {
    name: Name,
    keys: Option<[TsigKey; 5]>,
}

/// Return the normalized TSIG key name authenticated for this Query.
#[must_use]
pub fn validated_key_name<'a>(cx: &'a Context<'_, '_>) -> Option<NameRef<'a>> {
    cx.metadata.validated_tsig()
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Plugin for Tsig {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        // RFC 8945 §5.2: TSIG must be the final record in the Additional section.
        let mut tsig_seen = false;
        for rr in cx.query.additionals() {
            if tsig_seen {
                return Outcome::Unanswered(Rcode::FORMERR);
            }
            tsig_seen = rr.rtype == Type::TSIG;
        }
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 1034 §3.1: Domain membership follows the case-insensitive label suffix.
        let matches = self.zones.iter().any(|zone| {
            let zone = NameRef::parse(zone.as_wire(), 0).expect("valid Domain");
            let count = question.name.labels().count();
            let suffix = zone.labels().count();
            count >= suffix
                && question
                    .name
                    .labels()
                    .skip(count - suffix)
                    .zip(zone.labels())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        });
        if !matches {
            return next.run(cx).await;
        }
        if tsig_seen {
            return self.signed(cx, next).await;
        }
        if self.all_types
            || self.types.contains(&question.qtype)
            || self.all_opcodes
            || self.opcodes.contains(&cx.query.opcode())
        {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        next.run(cx).await
    }
}

impl Tsig {
    pub(crate) fn register(
        &mut self,
        listeners: impl Iterator<Item = pharos_server::ListenerKey>,
        rings: &mut KeyRings,
    ) {
        for listener in listeners {
            if self.listeners.iter().any(|(key, _)| *key == listener) {
                continue;
            }
            let (ring, keys) = rings.0.entry(listener).or_default();
            for secret in &self.secrets {
                if let Some(previous) = keys
                    .iter_mut()
                    .find(|previous| previous.name == secret.name)
                {
                    *previous = Arc::clone(secret);
                } else {
                    keys.push(Arc::clone(secret));
                }
            }
            self.listeners.push((listener, Arc::clone(ring)));
        }
    }

    async fn signed<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let wire = cx.query.as_wire();
        let Ok(record) = TsigRecord::parse(wire) else {
            return Outcome::Unanswered(Rcode::FORMERR);
        };
        let listener = pharos_server::ListenerKey {
            transport: cx.transport,
            address: cx.local,
        };
        let secrets = self
            .listeners
            .iter()
            .find(|(key, _)| *key == listener)
            .and_then(|(_, ring)| ring.get())
            .unwrap_or(&self.secrets);
        let Some(secret) = secrets.iter().find(|secret| record.owner == secret.name) else {
            return tsig_error(cx, &record, 17, None, 0);
        };
        let Some(keys) = &secret.keys else {
            return tsig_error(cx, &record, 16, None, 0);
        };
        let names = [
            b"\x09hmac-sha1\0".as_slice(),
            b"\x0bhmac-sha224\0",
            b"\x0bhmac-sha256\0",
            b"\x0bhmac-sha384\0",
            b"\x0bhmac-sha512\0",
        ];
        let algorithm = names
            .iter()
            .position(|name| record.algorithm == NameRef::parse(name, 0).expect("valid algorithm"));
        let Some(key) = algorithm.map(|i| &keys[i]) else {
            return tsig_error(cx, &record, 16, None, 0);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        match key.verify(wire, now, None, 0) {
            Ok(_) => {}
            Err(TsigError::BadTime) => return tsig_error(cx, &record, 18, Some(key), now),
            Err(TsigError::Format) => return Outcome::Unanswered(Rcode::FORMERR),
            Err(_) => return tsig_error(cx, &record, 16, None, 0),
        }
        cx.metadata.set_validated_tsig(&secret.name);
        let query = cx.query.without_final_tsig().expect("verified TSIG");
        let outcome = cx.run_with_message(query, next).await;
        let error_code = match outcome {
            Outcome::Response => None,
            Outcome::Unanswered(code) => Some(code),
            Outcome::Error(error) => {
                pharos_server::logging::log_error("tsig", format_args!("{error}"));
                Some(Rcode::SERVFAIL)
            }
            other => return other,
        };
        if let Some(code) = error_code {
            let flags = 0x8000 | (cx.query.flags() & 0x7910) | (code.0 & 15);
            let Ok(mut builder) = MessageBuilder::new(
                cx.response,
                cx.max_response_size.max(512),
                cx.query.id(),
                flags,
            ) else {
                return Outcome::Error(Error::ResponseBufferTooSmall);
            };
            if let Some(q) = cx.query.questions().next()
                && builder.question(q.name, q.qtype, q.qclass).is_err()
            {
                return Outcome::Error(Error::ResponseBufferTooSmall);
            }
            let _ = builder.finish();
        }
        let index = algorithm.expect("checked above");
        let size =
            secret.name.as_wire().len() + 26 + names[index].len() + [20, 28, 32, 48, 64][index];
        if let Err(error) =
            pharos_server::prepare_signed_response(cx.query, cx.protocol, size, cx.response)
        {
            return Outcome::Error(error);
        }
        let needed = cx.response.len() + size;
        if needed > cx.response.capacity() {
            if cx.protocol == pharos_server::Protocol::Tcp {
                cx.response.reserve(needed - cx.response.len());
            } else {
                return Outcome::Error(Error::ResponseBufferTooSmall);
            }
        }
        // RFC 8945 §4.3.1: the Response MAC includes the authenticated Query MAC.
        match key.sign(cx.response, now, record.fudge, Some(record.mac)) {
            Ok(()) => Outcome::Response,
            Err(_) => Outcome::Error(Error::InvalidQuery),
        }
    }
}

fn tsig_error(
    cx: &mut Context<'_, '_>,
    record: &TsigRecord<'_>,
    code: u16,
    key: Option<&TsigKey>,
    now: u64,
) -> Outcome {
    let owner_len = record.owner.labels().map(|l| l.len() + 1).sum::<usize>() + 1;
    let algorithm_len = record
        .algorithm
        .labels()
        .map(|l| l.len() + 1)
        .sum::<usize>()
        + 1;
    let size = owner_len + algorithm_len + 26 + if key.is_some() { 70 } else { 0 };
    let flags = 0x8000 | (cx.query.flags() & 0x7910) | Rcode::NOTAUTH.0;
    let Ok(mut builder) = MessageBuilder::new(
        cx.response,
        cx.max_response_size.max(512),
        cx.query.id(),
        flags,
    ) else {
        return Outcome::Error(Error::ResponseBufferTooSmall);
    };
    if let Some(q) = cx.query.questions().next()
        && builder.question(q.name, q.qtype, q.qclass).is_err()
    {
        return Outcome::Error(Error::ResponseBufferTooSmall);
    }
    let _ = builder.finish();
    if let Err(error) =
        pharos_server::prepare_signed_response(cx.query, cx.protocol, size, cx.response)
    {
        return Outcome::Error(error);
    }
    let required = cx.response.len() + size;
    if cx.response.capacity() < required {
        if cx.protocol == pharos_server::Protocol::Tcp {
            cx.response.reserve(required - cx.response.len());
        } else {
            return Outcome::Error(Error::ResponseBufferTooSmall);
        }
    }
    if let Some(key) = key {
        return match key.sign_error_response(cx.response, cx.query.as_wire(), now, 0) {
            Ok(Some(_)) => Outcome::Response,
            _ => Outcome::Error(Error::InvalidQuery),
        };
    }
    // RFC 8945 §5.3.2: BADKEY and BADSIG carry an empty MAC.
    for label in record.owner.labels() {
        cx.response.push(label.len() as u8);
        cx.response.extend_from_slice(label);
    }
    cx.response.push(0);
    cx.response.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
    cx.response
        .extend_from_slice(&((algorithm_len + 16) as u16).to_be_bytes());
    for label in record.algorithm.labels() {
        cx.response.push(label.len() as u8);
        cx.response.extend_from_slice(label);
    }
    cx.response.push(0);
    cx.response.extend_from_slice(&[0; 6]);
    cx.response.extend_from_slice(&record.fudge.to_be_bytes());
    cx.response.extend_from_slice(&[0; 2]);
    cx.response
        .extend_from_slice(&record.original_id.to_be_bytes());
    cx.response.extend_from_slice(&code.to_be_bytes());
    cx.response.extend_from_slice(&[0; 2]);
    let count = u16::from_be_bytes([cx.response[10], cx.response[11]]) + 1;
    cx.response[10..12].copy_from_slice(&count.to_be_bytes());
    Outcome::Response
}
