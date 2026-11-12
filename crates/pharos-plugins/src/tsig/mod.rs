pub(crate) mod setup;

use pharos_proto::{Name, NameRef, Opcode, Rcode, TsigKey, TsigRecord, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Tsig {
    zones: Vec<Name>,
    secrets: Vec<Secret>,
    types: Vec<Type>,
    opcodes: Vec<Opcode>,
    all_types: bool,
    all_opcodes: bool,
}

struct Secret {
    name: Name,
    keys: Option<[TsigKey; 5]>,
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
        let signed = cx.query.additionals().any(|rr| rr.rtype == Type::TSIG);
        if signed {
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
    async fn signed<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let wire = cx.query.as_wire();
        let Ok(record) = TsigRecord::parse(wire) else {
            return Outcome::Unanswered(Rcode::FORMERR);
        };
        let Some(secret) = self
            .secrets
            .iter()
            .find(|secret| record.owner == secret.name)
        else {
            return Outcome::Unanswered(Rcode::REFUSED);
        };
        let Some(keys) = &secret.keys else {
            return Outcome::Unanswered(Rcode::REFUSED);
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
            return Outcome::Unanswered(Rcode::REFUSED);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if key.verify(wire, now, None, 0).is_err() {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        let query = cx.query.without_final_tsig().expect("verified TSIG");
        let outcome = cx.run_with_message(query, next).await;
        if outcome != Outcome::Response {
            return outcome;
        }
        let index = algorithm.expect("checked above");
        let needed = cx.response.len()
            + secret.name.as_wire().len()
            + 26
            + names[index].len()
            + [20, 28, 32, 48, 64][index];
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
