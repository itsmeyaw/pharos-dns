pub(crate) mod setup;

use pharos_proto::{Name, Opcode, Type};
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
    async fn serve<N: Next + Send>(&self, _cx: &mut Context<'_, '_>, _next: N) -> Outcome {
        Outcome::Unanswered(pharos_proto::Rcode::REFUSED)
    }
}
