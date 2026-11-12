pub(crate) mod setup;

use pharos_proto::{Name, NameRef, Opcode, Rcode, Type};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Tsig {
    zones: Vec<Name>,
    secrets: Vec<(Name, String)>,
    types: Vec<Type>,
    opcodes: Vec<Opcode>,
    all_types: bool,
    all_opcodes: bool,
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
        if signed
            || self.all_types
            || self.types.contains(&question.qtype)
            || self.all_opcodes
            || self.opcodes.contains(&cx.query.opcode())
        {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        next.run(cx).await
    }
}
