pub(crate) mod setup;

use pharos_proto::{Class, MessageBuilder, Opcode, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol};

/// Answers ANY Queries with a minimal HINFO Response.
#[derive(Debug)]
pub struct Any;

impl Plugin for Any {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        if question.qtype != Type::ANY {
            return next.run(cx).await;
        }
        let result = (|| {
            let max_size = cx.max_response_size.max(512);
            if cx.response.capacity() < max_size {
                if cx.protocol == Protocol::Tcp {
                    cx.response
                        .reserve(max_size.saturating_sub(cx.response.len()));
                } else {
                    return Err(Error::ResponseBufferTooSmall);
                }
            }
            let mut flags = 0x8000 | (cx.query.flags() & 0x7800);
            if cx.query.opcode() == Opcode::QUERY {
                flags |= cx.query.flags() & 0x0110;
            }
            let mut builder = MessageBuilder::new(cx.response, max_size, cx.query.id(), flags)
                .map_err(Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
            // RFC 8482 §4.2: synthesize an HINFO record for an ANY Query.
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::HINFO,
                    Class::IN,
                    8482,
                    b"\x0dANY obsoleted\x0cSee RFC 8482",
                )
                .map_err(Error::Build)?;
            let _ = builder.finish();
            Ok(())
        })();
        match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }
}
