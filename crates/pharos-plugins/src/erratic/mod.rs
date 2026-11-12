pub(crate) mod setup;
mod xfr;

use pharos_proto::{Class, MessageBuilder, Opcode, Rcode, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol, Readiness};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Debug)]
pub struct Erratic {
    query: AtomicU64,
    drop: u64,
    delay: u64,
    truncate: u64,
    duration: Duration,
    large: bool,
}

impl Default for Erratic {
    fn default() -> Self {
        Self {
            query: AtomicU64::new(0),
            drop: 2,
            delay: 0,
            truncate: 0,
            duration: Duration::ZERO,
            large: false,
        }
    }
}

impl Plugin for Erratic {
    async fn serve<N: Next + Send>(&self, context: &mut Context<'_, '_>, _next: N) -> Outcome {
        let number = self.query.load(Ordering::SeqCst);
        self.query.fetch_add(1, Ordering::SeqCst);
        if self.drop > 0 && number % self.drop == 0 {
            return Outcome::Drop;
        }
        if self.delay > 0 && number % self.delay == 0 {
            tokio::time::sleep(self.duration).await;
        }
        let truncated = self.truncate > 0 && number & self.truncate == 0;
        let Some(question) = context.query.questions().next() else {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        };
        if question.qtype == Type::AXFR {
            return match xfr::stream(context, truncated) {
                Ok(stream) => Outcome::Stream(stream),
                Err(error) => Outcome::Error(error),
            };
        }
        let data: &[u8] = match question.qtype {
            Type::A => &[192, 0, 2, 53],
            Type::AAAA => &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53],
            _ => return Outcome::Unanswered(Rcode::SERVFAIL),
        };
        match response(
            context,
            data,
            truncated,
            self.large && question.qtype == Type::A,
        ) {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }

    fn readiness(&self) -> Option<&dyn Readiness> {
        Some(self)
    }
}

impl Readiness for Erratic {
    fn ready(&self) -> bool {
        (3..5).contains(&self.query.load(Ordering::Relaxed))
    }
}

fn response(
    context: &mut Context<'_, '_>,
    data: &[u8],
    truncated: bool,
    large: bool,
) -> Result<(), Error> {
    let question = context
        .query
        .questions()
        .next()
        .ok_or(Error::InvalidQuery)?;
    let limit = context.max_response_size.max(512);
    if context.response.capacity() < limit {
        if context.protocol == Protocol::Tcp {
            context
                .response
                .reserve(limit.saturating_sub(context.response.len()));
        } else {
            return Err(Error::ResponseBufferTooSmall);
        }
    }
    // RFC 1035 §4.1.1: preserve the opcode and echo the request flags in the Response.
    let mut flags = 0x8400 | (context.query.flags() & 0x7800);
    if context.query.opcode() == Opcode::QUERY {
        flags |= context.query.flags() & 0x0110;
    }
    if truncated {
        flags |= 0x0200;
    }
    let mut builder = MessageBuilder::new(context.response, limit, context.query.id(), flags)
        .map_err(Error::Build)?;
    builder
        .question(question.name, question.qtype, question.qclass)
        .map_err(Error::Build)?;
    // RFC 5737 §3 and RFC 3849 §2: use documentation-only addresses.
    for _ in 0..if large { 30 } else { 1 } {
        if !builder
            .record(
                Section::Answer,
                question.name,
                question.qtype,
                Class::IN,
                0,
                data,
            )
            .map_err(Error::Build)?
        {
            break;
        }
    }
    let _ = builder.finish();
    Ok(())
}
