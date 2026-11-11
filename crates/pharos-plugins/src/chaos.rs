//! CH-class identity Responses.

use pharos_corefile::{Cursor, Error as CorefileError};
use pharos_proto::{Class, MessageBuilder, Opcode, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol};
use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub struct Chaos {
    version: Vec<u8>,
    authors: Vec<Vec<u8>>,
    order: Mutex<Vec<usize>>,
    hostname: Vec<u8>,
}

impl Chaos {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, CorefileError> {
        cursor.next();
        let args = cursor.remaining_args();
        if cursor.next_block() {
            return Err(cursor.error("unknown chaos property"));
        }
        let default_version = format!("Pharos-{}", env!("CARGO_PKG_VERSION"));
        let version = args.first().unwrap_or(&default_version).as_bytes();
        let version = if args.len() <= 1 {
            &version[..version.len().min(255)]
        } else {
            version
        };
        let mut authors = if args.len() > 1 {
            args[1..].to_vec()
        } else {
            vec!["itsmeyaw".to_owned()]
        };
        authors.sort_unstable();
        authors.dedup();
        let mut authors = authors
            .into_iter()
            .map(|a| {
                let mut a = a.into_bytes();
                a.truncate(255);
                a
            })
            .collect::<Vec<_>>();
        authors.sort_unstable();
        let mut hostname = nix::unistd::gethostname()
            .ok()
            .map(|h| h.into_encoded_bytes())
            .unwrap_or_else(|| b"localhost".to_vec());
        hostname.truncate(255);
        let order = Mutex::new((0..authors.len()).collect());
        // Initialize platforms' lazy mutex allocation at setup, not on the first Query.
        drop(order.lock().unwrap_or_else(|e| e.into_inner()));
        Ok(Self {
            version: version.to_vec(),
            order,
            authors,
            hostname,
        })
    }
}

impl Plugin for Chaos {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        if question.qclass != Class::CH || question.qtype != Type::TXT {
            return next.run(cx).await;
        }
        // RFC 4343 §2: DNS labels are compared without ASCII case sensitivity.
        let mut labels = question.name.labels();
        let (Some(first), Some(second), None) = (labels.next(), labels.next(), labels.next())
        else {
            return next.run(cx).await;
        };
        let is_authors =
            first.eq_ignore_ascii_case(b"authors") && second.eq_ignore_ascii_case(b"bind");
        let values = if first.eq_ignore_ascii_case(b"version")
            && (second.eq_ignore_ascii_case(b"bind") || second.eq_ignore_ascii_case(b"server"))
        {
            std::slice::from_ref(&self.version)
        } else if is_authors {
            &self.authors
        } else if (first.eq_ignore_ascii_case(b"hostname") && second.eq_ignore_ascii_case(b"bind"))
            || (first.eq_ignore_ascii_case(b"id") && second.eq_ignore_ascii_case(b"server"))
        {
            std::slice::from_ref(&self.hostname)
        } else {
            return next.run(cx).await;
        };
        let result = (|| {
            let max = cx.max_response_size.max(512);
            if cx.response.capacity() < max {
                if cx.protocol == Protocol::Tcp {
                    cx.response.reserve(max.saturating_sub(cx.response.len()));
                } else {
                    return Err(Error::ResponseBufferTooSmall);
                }
            }
            // RFC 1035 §4.1.1: mark a Response and preserve the Query opcode and flags.
            let mut flags = 0x8000 | (cx.query.flags() & 0x7800);
            if cx.query.opcode() == Opcode::QUERY {
                flags |= cx.query.flags() & 0x0110;
            }
            let mut builder = MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                .map_err(Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
            let mut order =
                is_authors.then(|| self.order.lock().unwrap_or_else(|e| e.into_inner()));
            if let Some(order) = &mut order {
                for (i, index) in order.iter_mut().enumerate() {
                    *index = i;
                }
                let seed = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                shuffle(order, seed);
            }
            for i in 0..values.len() {
                let value = &values[order.as_ref().map_or(i, |order| order[i])];
                // RFC 1035 §3.3.14: TXT RDATA contains a length-prefixed character-string.
                let len = u8::try_from(value.len())
                    .map_err(|_| Error::Build(pharos_proto::BuildError::InvalidRdata))?;
                let mut rdata = [0u8; 256];
                rdata[0] = len;
                rdata[1..1 + value.len()].copy_from_slice(value);
                if !builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::TXT,
                        Class::CH,
                        0,
                        &rdata[..1 + value.len()],
                    )
                    .map_err(Error::Build)?
                {
                    break;
                }
            }
            let _ = builder.finish();
            Ok(())
        })();
        match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }
}

fn shuffle(order: &mut [usize], seed: u64) {
    let mut state = seed ^ 0x9e3779b97f4a7c15;
    for i in (1..order.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        order.swap(i, (state % (i as u64 + 1)) as usize);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn shuffles_deterministically_for_same_seed() {
        let mut first = (0..20).collect::<Vec<_>>();
        let mut second = first.clone();
        super::shuffle(&mut first, 42);
        super::shuffle(&mut second, 42);
        assert_eq!(first, second);
        assert_ne!(first, (0..20).collect::<Vec<_>>());
        first.sort_unstable();
        assert_eq!(first, (0..20).collect::<Vec<_>>());
    }
}
