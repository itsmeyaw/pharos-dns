#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rcode, Section, Type};
use pharos_server::{
    Action, Chain, Context, Handler, ListenerKey, Metadata, Outcome, Protocol, Router, Server,
    Transport,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    net::SocketAddr,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const OTHER: &[u8] = b"\x01b\x05other\0";
const THIRD: &[u8] = b"\x01c\x05third\0";

enum Zone {
    Lookup(&'static [u8]),
    Detached(&'static [u8]),
    Answer,
}

impl Chain for Zone {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        match self {
            Self::Lookup(name) => {
                let response = cx
                    .self_lookup_ref(NameRef::parse(name, 0).unwrap(), Type::A)
                    .await
                    .unwrap();
                assert!(Message::parse(&response).is_ok());
                Outcome::Unanswered(Rcode::REFUSED)
            }
            Self::Detached(name) => {
                // Mirrors the cache refresh task, which owns a handle instead of a borrowed Server.
                let handle = cx.self_lookup_handle().unwrap();
                let mut slots = [None; 8];
                let mut buffer = Vec::new();
                let detached = Context {
                    query: cx.query,
                    client: cx.client,
                    local: cx.local,
                    transport: cx.transport,
                    protocol: cx.protocol,
                    domain: cx.domain,
                    metadata: Metadata::with_self_lookup(&mut slots, Some(&handle)),
                    response: &mut buffer,
                    max_response_size: cx.max_response_size,
                };
                let response = detached
                    .self_lookup_ref(NameRef::parse(name, 0).unwrap(), Type::A)
                    .await
                    .unwrap();
                assert_eq!(Message::parse(&response).unwrap().answer_count(), 1);
                Outcome::Unanswered(Rcode::REFUSED)
            }
            Self::Answer => {
                let question = cx.query.questions().next().unwrap();
                let mut builder =
                    MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8000).unwrap();
                builder
                    .question(question.name, question.qtype, question.qclass)
                    .unwrap();
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::A,
                        Class::IN,
                        60,
                        &[192, 0, 2, 42],
                    )
                    .unwrap();
                let _ = builder.finish();
                Outcome::Response
            }
        }
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn server(first: Zone, second: Zone) -> Arc<Server<Zone>> {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, "example.".parse().unwrap(), Some(first), vec![]);
    router.add(key, "other.".parse().unwrap(), Some(second), vec![]);
    router.add(key, "third.".parse().unwrap(), Some(Zone::Answer), vec![]);
    Arc::new(Server::new(router, key))
}

/// Re-runs the named test alone in a child process and returns true in the parent.
/// The global counter sees every thread, so sibling tests and the harness would pollute a region.
fn run_isolated(name: &str) -> bool {
    if std::env::var_os("PHAROS_ALLOCATION_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("PHAROS_ALLOCATION_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
    true
}

/// Allocations over `queries` Queries after one warm-up Query. Polled without a runtime.
fn allocations(server: &Arc<Server<Zone>>, queries: usize) -> usize {
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\x07example\0\0\x01\0\x01";
    let peer: SocketAddr = "192.0.2.10:1234".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let run = |response: &mut Vec<u8>| {
        let future = Handler::handle_shared(server, query, peer, Protocol::Udp, response);
        let mut future = std::pin::pin!(future);
        assert_eq!(
            future
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Ready(Action::Respond)
        );
    };
    run(&mut response);
    let region = Region::new(GLOBAL);
    for _ in 0..queries {
        run(&mut response);
    }
    let change = region.change();
    change.allocations + change.reallocations
}

#[test]
fn self_lookup_does_not_allocate_once_warmed() {
    if run_isolated("self_lookup_does_not_allocate_once_warmed") {
        return;
    }
    let server = server(Zone::Lookup(OTHER), Zone::Answer);
    assert_eq!(allocations(&server, 100), 0);
}

#[test]
fn nested_self_lookup_does_not_allocate_once_warmed() {
    if run_isolated("nested_self_lookup_does_not_allocate_once_warmed") {
        return;
    }
    let server = server(Zone::Lookup(OTHER), Zone::Lookup(THIRD));
    assert_eq!(allocations(&server, 100), 0);
}

#[test]
fn detached_self_lookup_does_not_allocate_once_warmed() {
    if run_isolated("detached_self_lookup_does_not_allocate_once_warmed") {
        return;
    }
    let server = server(Zone::Detached(OTHER), Zone::Answer);
    assert_eq!(allocations(&server, 100), 0);
}
