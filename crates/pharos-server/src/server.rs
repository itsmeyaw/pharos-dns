use std::{future::Future, net::SocketAddr, sync::Arc};

use crate::{
    Action, Admission, Context, Error, Handler, Lifecycle, ListenerKey, Metadata, Outcome, Phase,
    Protocol, Router, admit, contain_panic, finish_outcome, response_limit,
};
use pharos_proto::Rcode;

/// Statically dispatched Plugin Chain supplied by the Plugin registry.
pub trait Chain: Send + Sync + 'static {
    fn serve(&self, context: &mut Context<'_>) -> impl Future<Output = Outcome> + Send;
    fn is_empty(&self) -> bool;
}

impl<C: Chain> Chain for Arc<C> {
    fn serve(&self, context: &mut Context<'_>) -> impl Future<Output = Outcome> + Send {
        self.as_ref().serve(context)
    }
    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

/// One Listener's routing, admission and Plugin Chain execution.
pub struct Server<C> {
    pub router: Router<C>,
    pub key: ListenerKey,
    pub allow_non_in: bool,
    pub debug: bool,
    pub lifecycle: Lifecycle,
    pub logger: fn(Error),
}

impl<C> Server<C> {
    pub fn new(router: Router<C>, key: ListenerKey) -> Self {
        Self {
            router,
            key,
            allow_non_in: false,
            debug: false,
            lifecycle: Lifecycle::default(),
            logger: log_error,
        }
    }

    pub async fn run_hooks(&self, phase: Phase) -> std::io::Result<()> {
        self.lifecycle.run(phase).await
    }
}

fn log_error(error: Error) {
    // shortcut: structured Plugin logging is tracked in #18.
    eprintln!("Plugin error: {error}");
}

impl<C: Chain> Handler for Server<C> {
    async fn handle(
        &self,
        wire: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        let query = match admit(wire, self.allow_non_in, response) {
            Admission::Query(query) => query,
            Admission::Respond => return Action::Respond,
            Admission::Drop => return Action::Drop,
        };
        let outcome = if let Some(block) = self.router.route(&self.key, query, peer, protocol) {
            if let Some(chain) = block.chain() {
                let mut slots = [None; 16];
                let mut context = Context {
                    query,
                    client: peer,
                    transport: self.key.transport,
                    protocol,
                    domain: block.domain(),
                    metadata: Metadata::new(&mut slots),
                    response,
                    max_response_size: response_limit(query, protocol),
                };
                contain_panic(chain.serve(&mut context), self.debug).await
            } else {
                Outcome::Unanswered(Rcode::REFUSED)
            }
        } else {
            Outcome::Unanswered(Rcode::REFUSED)
        };
        finish_outcome(query, protocol, outcome, response, self.logger)
    }

    async fn startup(&self) -> std::io::Result<()> {
        self.run_hooks(Phase::Startup).await
    }

    async fn shutdown(&self) -> std::io::Result<()> {
        self.run_hooks(Phase::Shutdown).await
    }
}
