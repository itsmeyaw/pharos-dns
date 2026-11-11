#![forbid(unsafe_code)]

use pharos_proto::{Message, Rcode};
use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport, panics_total,
};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

static LOGGED: AtomicUsize = AtomicUsize::new(0);
fn log(_: Error) {
    LOGGED.fetch_add(1, Ordering::Relaxed);
}

struct Broken {
    panic: bool,
}

struct LocalProbe;
impl Chain for LocalProbe {
    async fn serve(&self, context: &mut Context<'_>) -> Outcome {
        assert_eq!(context.local, "[::]:53".parse().unwrap());
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn wildcard_context_keeps_configured_local_address() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "[::]:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(LocalProbe), vec![]);
    let server = Server::new(router, key);
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}
impl Chain for Broken {
    async fn serve(&self, _: &mut Context<'_>) -> Outcome {
        if self.panic {
            panic!("broken plugin");
        }
        Outcome::Error(Error::InvalidQuery)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn server(panic: bool) -> Server<Broken> {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Broken { panic }), vec![]);
    let mut server = Server::new(router, key);
    server.logger = log;
    server
}

#[tokio::test]
async fn plugin_error_is_logged_and_answered_servfail() {
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let mut response = Vec::with_capacity(512);
    let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let before = LOGGED.load(Ordering::Relaxed);
    assert_eq!(
        server(false)
            .handle(&query, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(LOGGED.load(Ordering::Relaxed), before + 1);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    let before = panics_total();
    assert_eq!(
        server(true)
            .handle(&query, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(panics_total(), before + 1);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
}

#[tokio::test]
async fn debug_server_does_not_contain_plugin_panics() {
    let mut server = server(true);
    server.debug = true;
    let result = tokio::spawn(async move {
        let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let mut response = Vec::with_capacity(512);
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await
    })
    .await;
    assert!(result.unwrap_err().is_panic());
}
