#![forbid(unsafe_code)]
#![cfg(feature = "plugin-etcd")]

use std::{alloc::System, time::Duration};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[path = "../support/etcd_stub.rs"]
mod etcd_stub;

use etcd_stub::EtcdStub;

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const MEASURED: usize = 100;

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    wire
}

// Pharos-owned allocations of one Query answered from the view, with the Server and the etcd stub in
// the same process. The stub is idle then: a hit makes no etcd call.
async fn per_query(name: &str, qtype: Type, answers: u16) -> (usize, usize) {
    let stub = EtcdStub::start().await;
    stub.put(
        "/skydns/test/skydns/a",
        r#"{"host":"10.0.0.1","port":8080}"#,
    );
    stub.put("/skydns/test/skydns/v6", r#"{"host":"2001:db8::1"}"#);
    stub.put(
        "/skydns/test/skydns/t",
        r#"{"host":"t.example","text":"hello"}"#,
    );
    stub.put("/skydns/test/skydns/c", r#"{"host":"other.example"}"#);
    stub.put("/skydns/test/skydns/cn", r#"{"host":"a.skydns.test."}"#);
    stub.put(
        "/skydns/test/skydns/m",
        r#"{"host":"10.0.0.3","mail":true,"priority":5}"#,
    );
    let text = format!(
        "skydns.test.:0 {{\n etcd {{\n endpoint {}\n }}\n}}",
        stub.endpoint(false)
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let (query, client) = (query(name, qtype), "127.0.0.1:1001".parse().unwrap());
    let mut response = Vec::with_capacity(65535);
    // The view is used once the watch is established; wait for a Query that reads no etcd.
    for attempt in 0.. {
        let before = stub.calls("Range");
        assert_eq!(
            server
                .handle(&query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        if stub.calls("Range") == before {
            break;
        }
        assert!(attempt < 250, "the view never got warm");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..10 {
        server
            .handle(&query, client, Protocol::Udp, &mut response)
            .await;
    }
    let range = stub.calls("Range");
    let before = GLOBAL.stats();
    for _ in 0..MEASURED {
        assert_eq!(
            server
                .handle(&query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let after = GLOBAL.stats();
    assert_eq!(stub.calls("Range"), range, "a hit read etcd");
    assert_eq!(Message::parse(&response).unwrap().answer_count(), answers);
    (
        after.allocations - before.allocations,
        after.reallocations - before.reallocations,
    )
}

// What a Query costs in Pharos on a view hit, per Query, measured with the Server and the stub in
// one process. The numbers are exact so that a regression, or an improvement, fails the test: an
// improvement should lower them. Only a host that is a name, whose CNAME chain is chased, allocates
// (see "Allocations" in the Plugin README).
async fn check(name: &str, qtype: Type, answers: u16, allocations: usize, reallocations: usize) {
    let (measured, remeasured) = per_query(name, qtype, answers).await;
    println!("{qtype:?}: {measured} allocations, {remeasured} reallocations in {MEASURED} Queries");
    assert_eq!(
        (measured, remeasured),
        (allocations * MEASURED, reallocations * MEASURED)
    );
}

macro_rules! pinned {
    ($test:ident, $name:literal, $qtype:expr, $answers:literal, $allocations:literal, $reallocations:literal) => {
        #[tokio::test]
        async fn $test() {
            if crate::run_isolated(concat!("etcd::etcd_allocations::", stringify!($test))) {
                return;
            }
            check($name, $qtype, $answers, $allocations, $reallocations).await;
        }
    };
}

pinned!(
    warmed_a_hit_allocations_are_pinned,
    "a.skydns.test.",
    Type::A,
    1,
    0,
    0
);
pinned!(
    warmed_aaaa_hit_allocations_are_pinned,
    "v6.skydns.test.",
    Type::AAAA,
    1,
    0,
    0
);
pinned!(
    warmed_srv_hit_allocations_are_pinned,
    "a.skydns.test.",
    Type::SRV,
    1,
    0,
    0
);
pinned!(
    warmed_txt_hit_allocations_are_pinned,
    "t.skydns.test.",
    Type::TXT,
    1,
    0,
    0
);
pinned!(
    warmed_cname_hit_allocations_are_pinned,
    "c.skydns.test.",
    Type::CNAME,
    1,
    0,
    0
);
pinned!(
    warmed_ptr_hit_allocations_are_pinned,
    "c.skydns.test.",
    Type::PTR,
    1,
    0,
    0
);
pinned!(
    warmed_mx_hit_allocations_are_pinned,
    "m.skydns.test.",
    Type::MX,
    1,
    0,
    0
);
pinned!(
    warmed_nodata_hit_allocations_are_pinned,
    "a.skydns.test.",
    Type::AAAA,
    0,
    0,
    0
);
pinned!(
    warmed_nxdomain_hit_allocations_are_pinned,
    "nx.skydns.test.",
    Type::A,
    0,
    0,
    0
);
pinned!(
    warmed_soa_hit_allocations_are_pinned,
    "skydns.test.",
    Type::SOA,
    1,
    0,
    0
);
pinned!(
    warmed_cname_chain_hit_allocations_are_pinned,
    "cn.skydns.test.",
    Type::A,
    2,
    15,
    3
);
