//! Ported from CoreDNS v1.15.0 plugin/dnstap/handler_test.go.
use std::collections::VecDeque;

use pharos_proto::Name;
use pharos_server::{Error, Metadata, Stream, Transport};

use super::*;
use crate::dnstap::{
    msg::decode,
    testing::{Collector, Frame, config, eventually, metric, tap},
};

// example.org. IN A, id 1, RD: 29 octets, the `{size}` CoreDNS's test expects.
const QUERY: [u8; 29] = [
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'o', b'r',
    b'g', 0, 0, 1, 0, 1,
];

struct Reply(Outcome, Option<Vec<u8>>);

impl Next for Reply {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        if let Some(wire) = &self.1 {
            cx.response.extend_from_slice(wire);
        }
        self.0
    }
}

fn answer() -> Vec<u8> {
    let mut wire = QUERY.to_vec();
    wire[2] |= 0x80;
    wire
}

fn dnstap(mutate: impl FnOnce(&mut Config)) -> Dnstap {
    let mut config = config(Endpoint::Unix("/nonexistent/dnstap.sock".into()));
    mutate(&mut config);
    Dnstap::new(vec![config])
}

async fn run(dnstap: &Dnstap, outcome: Outcome, response: Option<Vec<u8>>) -> Vec<decode::Dnstap> {
    let domain: Name = ".".parse().unwrap();
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    metadata.set_enabled(true);
    metadata.insert("metadata/test", "MetadataValue");
    let mut buffer = Vec::with_capacity(512);
    let mut cx = Context {
        query: pharos_proto::Message::parse(&QUERY).unwrap(),
        client: "10.240.0.1:40212".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata,
        response: &mut buffer,
        max_response_size: 512,
    };
    let got = dnstap
        .serve(&mut cx, Reply(outcome.clone(), response))
        .await;
    assert_eq!(got, outcome);
    drain(dnstap)
}

fn drain(dnstap: &Dnstap) -> Vec<decode::Dnstap> {
    let mut batch = VecDeque::new();
    dnstap.taps()[0].0.queue.try_batch(&mut batch);
    batch
        .iter()
        .map(|payload| decode::dnstap(payload))
        .collect()
}

fn kinds(taps: &[decode::Dnstap]) -> Vec<u64> {
    taps.iter()
        .map(|tap| tap.message.as_ref().unwrap().kind.unwrap())
        .collect()
}

// TestDnstap: a Query and its Response are tapped in order with the client's address, port, family and protocol.
#[tokio::test]
async fn taps_the_query_then_the_response() {
    let taps = run(&dnstap(|_| {}), Outcome::Response, Some(answer())).await;
    assert_eq!(
        kinds(&taps),
        [
            MessageType::ClientQuery as u64,
            MessageType::ClientResponse as u64
        ]
    );
    for tap in &taps {
        let message = tap.message.as_ref().unwrap();
        assert_eq!(tap.identity.as_deref(), Some(&b"test"[..]));
        assert_eq!(message.family, Some(1));
        assert_eq!(message.protocol, Some(1));
        assert_eq!(message.query_address.as_deref(), Some(&[10, 240, 0, 1][..]));
        assert_eq!(message.query_port, Some(40212));
        assert_eq!(message.response_address, None);
        assert_eq!(tap.extra, None);
        // Without `full` neither wire message is included.
        assert_eq!(
            (&message.query_message, &message.response_message),
            (&None, &None)
        );
    }
    let response = taps[1].message.as_ref().unwrap();
    assert!(response.query_time_sec.is_some() && response.response_time_sec.is_some());
}

// TestDnstap: `extra` placeholders expand per message, for both the Query and the Response.
#[tokio::test]
async fn extra_expands_placeholders_from_the_query() {
    let format =
        "extra_field_{/metadata/test}_{type}_{name}_{class}_{proto}_{size}_{remote}_{port}_{local}";
    let taps = run(
        &dnstap(|c| c.extra = format.into()),
        Outcome::Response,
        Some(answer()),
    )
    .await;
    assert_eq!(taps.len(), 2);
    for tap in taps {
        assert_eq!(
            tap.extra.as_deref(),
            Some(
                &b"extra_field_MetadataValue_A_example.org._IN_udp_29_10.240.0.1_40212_127.0.0.1"[..]
            )
        );
    }
}

// replacer.go: Response labels have no value before a Response is recorded.
#[tokio::test]
async fn extra_has_no_response_labels() {
    let format = "{rcode}_{rsize}_{duration}_{>rflags}";
    let taps = run(
        &dnstap(|c| c.extra = format.into()),
        Outcome::Response,
        Some(answer()),
    )
    .await;
    assert!(
        taps.iter()
            .all(|tap| tap.extra.as_deref() == Some(&b"-_-_-_-"[..]))
    );
}

// TestTapMessage: a message tapped without a Context keeps `extra` exactly as configured.
#[test]
fn send_without_a_context_does_not_expand_extra() {
    let format = "extra_field_no_replacement_{/metadata/test}_{type}";
    let dnstap = dnstap(|c| c.extra = format.into());
    dnstap.taps()[0].send(&testing::query(40212));
    let taps = drain(&dnstap);
    assert_eq!(taps.len(), 1);
    assert_eq!(taps[0].extra.as_deref(), Some(format.as_bytes()));
}

// TestDnstap: `extra` without placeholders is sent as is.
#[tokio::test]
async fn literal_extra_is_sent_as_is() {
    let taps = run(
        &dnstap(|c| c.extra = "plain".into()),
        Outcome::Response,
        Some(answer()),
    )
    .await;
    assert!(
        taps.iter()
            .all(|tap| tap.extra.as_deref() == Some(&b"plain"[..]))
    );
}

// `full` includes the wire Query with the CLIENT_QUERY and the wire Response with the CLIENT_RESPONSE.
#[tokio::test]
async fn full_includes_the_wire_messages() {
    let taps = run(
        &dnstap(|c| c.full = true),
        Outcome::Response,
        Some(answer()),
    )
    .await;
    let query = taps[0].message.as_ref().unwrap();
    assert_eq!(query.query_message.as_deref(), Some(&QUERY[..]));
    assert_eq!(query.response_message, None);
    let response = taps[1].message.as_ref().unwrap();
    assert_eq!(response.response_message.as_deref(), Some(&answer()[..]));
    assert_eq!(response.query_message, None);
}

// TestDnstapDeferredError (#6532): the Server answers these after the chain returns, so dnstap taps what it will send.
#[tokio::test]
async fn deferred_error_rcodes_get_a_synthesized_response() {
    for (outcome, rcode) in [
        (Outcome::Unanswered(Rcode::SERVFAIL), 2),
        (Outcome::Unanswered(Rcode::REFUSED), 5),
        (Outcome::Unanswered(Rcode::FORMERR), 1),
        (Outcome::Unanswered(Rcode::NOTIMP), 4),
        (Outcome::Unanswered(Rcode::NOTAUTH), 9),
        (Outcome::Error(Error::NoNextPlugin), 2),
    ] {
        let taps = run(&dnstap(|c| c.full = true), outcome.clone(), None).await;
        assert_eq!(
            kinds(&taps),
            [
                MessageType::ClientQuery as u64,
                MessageType::ClientResponse as u64
            ],
            "{outcome:?}"
        );
        let wire = taps[1]
            .message
            .as_ref()
            .unwrap()
            .response_message
            .clone()
            .unwrap();
        let response = pharos_proto::Message::parse(&wire).unwrap();
        assert_eq!(response.id(), 1);
        assert_eq!(response.flags() & 0x800f, 0x8000 | rcode, "{outcome:?}");
        assert_eq!(response.flags() & 0x0100, 0x0100, "RD is copied");
        let question = response.questions().next().unwrap();
        assert_eq!(question.name.to_string(), "example.org.");
    }
}

// Without `full` the synthesized Response is not built, but the CLIENT_RESPONSE is still tapped.
#[tokio::test]
async fn deferred_error_without_full_still_taps_the_response() {
    let taps = run(&dnstap(|_| {}), Outcome::Unanswered(Rcode::SERVFAIL), None).await;
    assert_eq!(taps.len(), 2);
    assert_eq!(taps[1].message.as_ref().unwrap().response_message, None);
}

// Nothing is sent to the client for these outcomes, so no CLIENT_RESPONSE is tapped.
#[tokio::test]
async fn unanswered_queries_get_no_response_tap() {
    for outcome in [
        Outcome::Drop,
        Outcome::Unanswered(Rcode::NXDOMAIN),
        Outcome::Stream(Stream::new(|_| Ok(false))),
    ] {
        let taps = run(&dnstap(|_| {}), outcome.clone(), None).await;
        assert_eq!(
            kinds(&taps),
            [MessageType::ClientQuery as u64],
            "{outcome:?}"
        );
    }
}

// TestDnstap: every configured `dnstap` Directive receives its own copy, with its own identity and `full`.
#[tokio::test]
async fn every_directive_gets_every_message() {
    let mut first = config(Endpoint::Unix("/nonexistent/a.sock".into()));
    first.identity = b"one".to_vec();
    let mut second = config(Endpoint::Unix("/nonexistent/b.sock".into()));
    second.identity = b"two".to_vec();
    second.full = true;
    let dnstap = Dnstap::new(vec![first, second]);
    let domain: Name = ".".parse().unwrap();
    let mut slots = [];
    let mut buffer = answer();
    let mut cx = Context {
        query: pharos_proto::Message::parse(&QUERY).unwrap(),
        client: "[2001:db8::1]:5353".parse().unwrap(),
        local: "[::1]:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Tcp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut buffer,
        max_response_size: 512,
    };
    dnstap.serve(&mut cx, Reply(Outcome::Response, None)).await;
    for (index, identity, full) in [(0, "one", false), (1, "two", true)] {
        let mut batch = VecDeque::new();
        dnstap.taps()[index].0.queue.try_batch(&mut batch);
        let taps: Vec<_> = batch
            .iter()
            .map(|payload| decode::dnstap(payload))
            .collect();
        assert_eq!(taps.len(), 2);
        let message = taps[0].message.as_ref().unwrap();
        assert_eq!(taps[0].identity.as_deref(), Some(identity.as_bytes()));
        assert_eq!((message.family, message.protocol), (Some(2), Some(2)));
        assert_eq!(message.query_message.is_some(), full);
    }
}

// listener.go Dnstap: a `listen` Directive with no connected collector skips the encoding entirely.
#[tokio::test]
async fn listen_without_a_collector_queues_nothing() {
    let dnstap = dnstap(|c| c.role = Role::Listen);
    assert!(
        run(&dnstap, Outcome::Response, Some(answer()))
            .await
            .is_empty()
    );
}

// OnStartup, OnRestart and OnFinalShutdown: the Lifecycle hooks dial at Startup and close at Shutdown.
#[tokio::test]
async fn lifecycle_hooks_start_and_stop_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dnstap.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let dnstap = dnstap(|c| c.endpoint = Endpoint::Unix(path.to_string_lossy().into_owned()));
    let registry = pharos_server::metrics::Registry::default();
    dnstap.set_metrics(&registry);
    let mut lifecycle = Lifecycle::default();
    dnstap.register_hooks(&mut lifecycle);

    lifecycle.run(Phase::Startup).await.unwrap();
    let mut collector = Collector::accept(listener.accept().await.unwrap().0)
        .await
        .unwrap();
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 1).await;
    let taps = run(&dnstap, Outcome::Response, Some(answer())).await;
    // `run` drained the queue itself; the writer saw nothing to send, so the stream is idle until the stop.
    assert_eq!(taps.len(), 2);
    let stopped = tokio::spawn(async move { collector.frame().await.unwrap() });
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(stopped.await.unwrap(), Frame::Stop);

    // A failed reload resumes the old configuration.
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    let mut again = Collector::accept(listener.accept().await.unwrap().0)
        .await
        .unwrap();
    let stopped = tokio::spawn(async move { again.frame().await.unwrap() });
    lifecycle.run(Phase::Restart).await.unwrap();
    assert_eq!(stopped.await.unwrap(), Frame::Stop);
}

// A failed first dial only logs; the Query path is unaffected and messages are dropped and counted.
#[tokio::test]
async fn unreachable_collector_does_not_fail_startup() {
    let (tap, registry, _) = tap(config(Endpoint::Unix("/nonexistent/dnstap.sock".into())));
    tap.start().await;
    eventually(|| metric(&registry, "pharos_dnstap_connect_failures_total") >= 1).await;
    tap.stop().await;
}
