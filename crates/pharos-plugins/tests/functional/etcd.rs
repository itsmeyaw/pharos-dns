#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-etcd", feature = "plugin-whoami"))]

//! The `etcd` Plugin from a Corefile, through a running Server's UDP and TCP listeners, against an
//! in-process etcd stub. Per-key lookup cases are pinned by the unit tests of the Plugin.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, etcd::msg, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, Rcode, Rdata, Type};
use pharos_server::{ListenerRegistry, grpc::Code};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

#[path = "../support/etcd_stub.rs"]
mod etcd_stub;

use etcd_stub::{EtcdStub, FIXTURES, Mode, refused_address};

const ZONE: &str = "skydns.test";

/// A running Server for one Corefile.
struct Rig {
    address: SocketAddr,
    registry: ListenerRegistry,
}

struct Reply {
    rcode: Rcode,
    tc: bool,
    aa: bool,
    answer: Vec<String>,
    authority: Vec<String>,
    additional: Vec<String>,
}

fn show(record: &pharos_proto::Record<'_>) -> String {
    let data = match record.data().unwrap() {
        // The serial and timers of an SOA vary; CoreDNS compares the nameserver only.
        Rdata::Soa { mname, rname, .. } => format!("{mname} {rname}"),
        other => other.to_string(),
    };
    format!("{} {} {} {data}", record.name, record.ttl, record.rtype)
}

impl Reply {
    fn parse(wire: &[u8]) -> Self {
        let message = Message::parse(wire).unwrap();
        Self {
            rcode: message.rcode(),
            tc: message.tc(),
            aa: message.aa(),
            answer: message.answers().map(|r| show(&r)).collect(),
            authority: message.authorities().map(|r| show(&r)).collect(),
            additional: message.additionals().map(|r| show(&r)).collect(),
        }
    }

    /// The sections, each sorted: etcd key order is not a promise of the Plugin.
    #[track_caller]
    fn expect(&self, rcode: Rcode, answer: &[&str], authority: &[&str], additional: &[&str]) {
        assert_eq!(self.rcode, rcode, "rcode of {self:?}");
        for (what, got, want) in [
            ("answer", &self.answer, answer),
            ("authority", &self.authority, authority),
            ("additional", &self.additional, additional),
        ] {
            let mut got = got.clone();
            let mut want: Vec<_> = want.iter().map(|s| (*s).to_owned()).collect();
            got.sort();
            want.sort();
            assert_eq!(got, want, "{what} of {self:?}");
        }
    }

    // whoami answers NOERROR with the client address in Additional and nothing in Answer.
    fn is_whoami(&self) -> bool {
        self.rcode == Rcode::NOERROR && self.answer.is_empty() && !self.additional.is_empty()
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} tc={} answer={:?} authority={:?} additional={:?}",
            self.rcode, self.tc, self.answer, self.authority, self.additional
        )
    }
}

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0100).unwrap();
    builder
        .question(name.as_name_ref(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    wire
}

impl Rig {
    async fn start(corefile: &str) -> Self {
        let parsed = parse("Corefile", corefile).unwrap();
        let blocks = configure::<Chain>(&parsed, directives()).unwrap();
        let (servers, _) = servers(blocks).unwrap();
        let key = *servers.keys().next().unwrap();
        let mut registry = ListenerRegistry::default();
        registry.apply(servers).await.unwrap();
        let port = registry.get(&key).unwrap().local_addr().port();
        Self {
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            registry,
        }
    }

    /// A Server with the Directive `etcd` and `whoami` after it, for zone `skydns.test`.
    async fn zone(endpoints: &str, options: &str) -> Self {
        Self::start(&block(endpoints, options)).await
    }

    // RFC 1035 §4.2.1: a Query over UDP, in a datagram of at most 512 octets.
    async fn udp(&self, name: &str, qtype: Type) -> Reply {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&query(name, qtype), self.address)
            .await
            .unwrap();
        let mut wire = [0; 65535];
        let (len, _) = timeout(Duration::from_secs(15), socket.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        Reply::parse(&wire[..len])
    }

    // RFC 7766 §8: a Query over TCP has a two-octet length prefix.
    async fn tcp(&self, name: &str, qtype: Type) -> (Reply, usize) {
        let query = query(name, qtype);
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let len = timeout(Duration::from_secs(15), stream.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut wire = vec![0; usize::from(len)];
        stream.read_exact(&mut wire).await.unwrap();
        (Reply::parse(&wire), wire.len())
    }

    async fn shutdown(self) {
        self.registry.shutdown().await.unwrap();
    }
}

fn block(endpoints: &str, options: &str) -> String {
    format!("{ZONE}.:0 {{\n etcd {{\n endpoint {endpoints}\n {options}\n }}\n whoami\n}}",)
}

/// Store `value` under the key CoreDNS gives `name`.
fn put(stub: &EtcdStub, name: &str, value: &Value) {
    stub.put(&msg::path(name, "skydns"), &value.to_string());
}

fn put_all(stub: &EtcdStub, services: &[(&str, Value)]) {
    for (name, value) in services {
        put(stub, name, value);
    }
}

async fn stub_with(services: &[(&str, Value)]) -> EtcdStub {
    let stub = EtcdStub::start().await;
    put_all(&stub, services);
    stub
}

const SOA: &str = "skydns.test. 30 SOA ns.dns.skydns.test. hostmaster.skydns.test.";

// CoreDNS v1.15.0 plugin/etcd/lookup_test.go TestLookup: A, AAAA, TXT, CNAME.
#[tokio::test]
async fn address_text_and_alias_records_are_answered() {
    let stub = stub_with(&[
        ("a.skydns.test.", json!({"host": "10.0.0.1"})),
        ("v6.skydns.test.", json!({"host": "2001:db8::1"})),
        ("txt.skydns.test.", json!({"text": "hello"})),
        ("alias.skydns.test.", json!({"host": "target.skydns.test"})),
        ("target.skydns.test.", json!({"host": "10.0.0.9"})),
    ])
    .await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    let reply = rig.udp("a.skydns.test.", Type::A).await;
    reply.expect(Rcode::NOERROR, &["a.skydns.test. 300 A 10.0.0.1"], &[], &[]);
    // CoreDNS v1.15.0 plugin/etcd/handler.go ServeDNS: every Response is authoritative.
    assert!(reply.aa);
    rig.udp("v6.skydns.test.", Type::AAAA).await.expect(
        Rcode::NOERROR,
        &["v6.skydns.test. 300 AAAA 2001:db8::1"],
        &[],
        &[],
    );
    rig.udp("txt.skydns.test.", Type::TXT).await.expect(
        Rcode::NOERROR,
        &["txt.skydns.test. 300 TXT \"hello\""],
        &[],
        &[],
    );
    // RFC 1034 §3.6.2: an alias is answered with the CNAME and the data at its target.
    rig.udp("alias.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "alias.skydns.test. 300 CNAME target.skydns.test.",
            "target.skydns.test. 300 A 10.0.0.9",
        ],
        &[],
        &[],
    );
    rig.udp("alias.skydns.test.", Type::CNAME).await.expect(
        Rcode::NOERROR,
        &["alias.skydns.test. 300 CNAME target.skydns.test."],
        &[],
        &[],
    );
    // CoreDNS v1.15.0 plugin/backend_lookup.go BackendError: a missing name is NXDOMAIN with the SOA.
    rig.udp("missing.skydns.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
    // RFC 2308 §2.1: a name without the type is NODATA with the SOA.
    rig.udp("a.skydns.test.", Type::TXT)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/lookup_test.go TestLookup: SRV, with the address in Additional.
#[tokio::test]
async fn srv_carries_its_address_in_the_additional_section() {
    let stub = stub_with(&[
        (
            "srv.skydns.test.",
            json!({"host": "10.0.0.1", "port": 8080}),
        ),
        (
            "named.skydns.test.",
            json!({"host": "backend.skydns.test", "port": 80, "priority": 333}),
        ),
        ("backend.skydns.test.", json!({"host": "10.0.0.2"})),
    ])
    .await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    rig.udp("srv.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["srv.skydns.test. 300 SRV 10 100 8080 srv.skydns.test."],
        &[],
        &["srv.skydns.test. 300 A 10.0.0.1"],
    );
    // CoreDNS v1.15.0 plugin/etcd/etcd.go: a service `priority` is the SRV priority, else 10.
    rig.udp("named.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["named.skydns.test. 300 SRV 333 100 80 backend.skydns.test."],
        &[],
        &["backend.skydns.test. 300 A 10.0.0.2"],
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/other_test.go: MX, NS, SOA and plugin/etcd/lookup_test.go: PTR.
#[tokio::test]
async fn mx_ns_ptr_and_soa_are_answered() {
    let stub = stub_with(&[
        (
            "mail.skydns.test.",
            json!({"host": "mx.skydns.test", "priority": 20, "mail": true}),
        ),
        ("mx.skydns.test.", json!({"host": "10.0.0.7"})),
        ("a.ns.dns.skydns.test.", json!({"host": "10.0.0.2"})),
        (
            "1.0.0.10.in-addr.arpa.",
            json!({"host": "reverse.example.com"}),
        ),
    ])
    .await;
    let rig = Rig::start(&format!(
        "{ZONE}.:0 in-addr.arpa.:0 {{\n etcd {{\n endpoint {}\n }}\n whoami\n}}",
        stub.endpoint(false)
    ))
    .await;
    rig.udp("mail.skydns.test.", Type::MX).await.expect(
        Rcode::NOERROR,
        &["mail.skydns.test. 300 MX 20 mx.skydns.test."],
        &[],
        &["mx.skydns.test. 300 A 10.0.0.7"],
    );
    rig.udp("skydns.test.", Type::NS).await.expect(
        Rcode::NOERROR,
        &["skydns.test. 300 NS a.ns.dns.skydns.test."],
        &[],
        &["a.ns.dns.skydns.test. 300 A 10.0.0.2"],
    );
    rig.udp("skydns.test.", Type::SOA)
        .await
        .expect(Rcode::NOERROR, &[SOA], &[], &[]);
    // RFC 1035 §3.5: a reverse lookup is a PTR query in `in-addr.arpa`.
    rig.udp("1.0.0.10.in-addr.arpa.", Type::PTR).await.expect(
        Rcode::NOERROR,
        &["1.0.0.10.in-addr.arpa. 300 PTR reverse.example.com."],
        &[],
        &[],
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/msg/path.go PathWithWildcard: `*` and `any` match any label.
#[tokio::test]
async fn wildcard_labels_match_any_label() {
    let stub = stub_with(&[
        ("a.group.skydns.test.", json!({"host": "10.0.0.1"})),
        ("b.group.skydns.test.", json!({"host": "10.0.0.2"})),
        ("c.other.skydns.test.", json!({"host": "10.0.0.3"})),
    ])
    .await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    for wildcard in ["*", "any"] {
        let name = format!("{wildcard}.group.skydns.test.");
        rig.udp(&name, Type::A).await.expect(
            Rcode::NOERROR,
            &[
                &format!("{name} 300 A 10.0.0.1"),
                &format!("{name} 300 A 10.0.0.2"),
            ],
            &[],
            &[],
        );
    }
    let name = "*.skydns.test.";
    rig.udp(name, Type::A).await.expect(
        Rcode::NOERROR,
        &[
            &format!("{name} 300 A 10.0.0.1"),
            &format!("{name} 300 A 10.0.0.2"),
            &format!("{name} 300 A 10.0.0.3"),
        ],
        &[],
        &[],
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go TTL: a service `ttl` is the record TTL, else 300.
#[tokio::test]
async fn the_service_ttl_is_the_record_ttl() {
    let stub = stub_with(&[
        ("short.skydns.test.", json!({"host": "10.0.0.1", "ttl": 42})),
        ("plain.skydns.test.", json!({"host": "10.0.0.2"})),
    ])
    .await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    rig.udp("short.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["short.skydns.test. 42 A 10.0.0.1"],
        &[],
        &[],
    );
    rig.udp("plain.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["plain.skydns.test. 300 A 10.0.0.2"],
        &[],
        &[],
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go TTL: a lease TTL is held within `min-lease-ttl` and `max-lease-ttl`.
#[tokio::test]
async fn lease_ttls_are_held_within_the_configured_bounds() {
    let stub = stub_with(&[]).await;
    stub.set_lease(1, 10);
    stub.set_lease(2, 100_000);
    stub.set_lease(3, 100);
    for (name, lease) in [("low", 1), ("high", 2), ("mid", 3)] {
        stub.put_lease(
            &msg::path(&format!("{name}.skydns.test."), "skydns"),
            r#"{"host":"10.0.0.1"}"#,
            lease,
        );
    }
    let ttls = |rig: Rig| async move {
        let mut ttls = Vec::new();
        for name in ["low", "high", "mid"] {
            let reply = rig.udp(&format!("{name}.skydns.test."), Type::A).await;
            assert_eq!(reply.rcode, Rcode::NOERROR, "{reply:?}");
            ttls.push(reply.answer[0].split(' ').nth(1).unwrap().to_owned());
        }
        rig.shutdown().await;
        ttls
    };
    // The defaults are 30 and 86400 seconds.
    assert_eq!(
        ttls(Rig::zone(&stub.endpoint(false), "").await).await,
        ["30", "86400", "100"]
    );
    assert_eq!(
        ttls(Rig::zone(&stub.endpoint(false), "min-lease-ttl 5\n max-lease-ttl 1h").await).await,
        ["10", "3600", "100"]
    );
    assert_eq!(
        ttls(Rig::zone(&stub.endpoint(false), "min-lease-ttl 1m\n max-lease-ttl 80").await).await,
        ["60", "80", "80"]
    );
}

// CoreDNS v1.15.0 plugin/etcd/lookup_test.go TestLookupNoApexFallback.
#[tokio::test]
async fn no_apex_fallback_stops_the_zone_root_lookup() {
    let stub = stub_with(&[("x.child.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    rig.udp("skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["skydns.test. 300 A 10.0.0.1"],
        &[],
        &[],
    );
    rig.shutdown().await;
    let strict = Rig::zone(&stub.endpoint(false), "no_apex_fallback").await;
    strict
        .udp("skydns.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
    put(
        &stub,
        "x.apex.dns.skydns.test.",
        &json!({"host": "192.0.2.1"}),
    );
    strict.udp("skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["skydns.test. 300 A 192.0.2.1"],
        &[],
        &[],
    );
    strict.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: `credentials` authenticates every call with the token.
#[tokio::test]
async fn credentials_authenticate_the_client() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    stub.enable_auth("root", "secret");
    let good = Rig::zone(&stub.endpoint(false), "credentials root secret").await;
    for _ in 0..3 {
        good.udp("a.skydns.test.", Type::A).await.expect(
            Rcode::NOERROR,
            &["a.skydns.test. 300 A 10.0.0.1"],
            &[],
            &[],
        );
    }
    // The token is kept: one `Authenticate` serves every call.
    assert_eq!(stub.calls("Authenticate"), 1);
    assert!(
        stub.seen("Range")
            .iter()
            .all(|seen| seen.headers.contains_key("token"))
    );
    good.shutdown().await;
    for options in ["credentials root wrong", ""] {
        let bad = Rig::zone(&stub.endpoint(false), options).await;
        let reply = bad.udp("a.skydns.test.", Type::A).await;
        assert_eq!(reply.rcode, Rcode::SERVFAIL, "{options}: {reply:?}");
        bad.shutdown().await;
    }
}

// etcd clientv3 retry_interceptor.go: an expired token is replaced once and the call repeated.
#[tokio::test]
async fn an_expired_token_is_renewed() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    stub.enable_auth("root", "secret");
    let rig = Rig::zone(&stub.endpoint(false), "credentials root secret").await;
    assert_eq!(
        rig.udp("a.skydns.test.", Type::A).await.rcode,
        Rcode::NOERROR
    );
    stub.expire_tokens();
    put(&stub, "b.skydns.test.", &json!({"host": "10.0.0.2"}));
    assert_eq!(
        rig.udp("b.skydns.test.", Type::A).await.rcode,
        Rcode::NOERROR
    );
    rig.shutdown().await;
}

fn tls_options(args: &str) -> String {
    format!("tls {args}")
}

// CoreDNS v1.15.0 plugin/pkg/tls NewTLSConfigFromArgs: `tls CA` verifies the server against that CA.
#[tokio::test]
async fn tls_verifies_the_server_against_the_configured_ca() {
    let stub = EtcdStub::start_tls().await;
    put(&stub, "a.skydns.test.", &json!({"host": "10.0.0.1"}));
    let endpoint = stub.endpoint(true);
    let good = Rig::zone(&endpoint, &tls_options(&format!("{FIXTURES}/ca.pem"))).await;
    good.udp("a.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["a.skydns.test. 300 A 10.0.0.1"],
        &[],
        &[],
    );
    good.shutdown().await;
    // A server whose certificate does not chain to the CA fails the call, which is SERVFAIL.
    let wrong = Rig::zone(&endpoint, &tls_options(&format!("{FIXTURES}/other-ca.pem"))).await;
    let reply = wrong.udp("a.skydns.test.", Type::A).await;
    assert_eq!(reply.rcode, Rcode::SERVFAIL, "{reply:?}");
    wrong.shutdown().await;
    // etcd clientv3 endpoint.go: `https://` without `tls` verifies against the system roots, which lack the test CA.
    let system = Rig::zone(&endpoint, "").await;
    let reply = system.udp("a.skydns.test.", Type::A).await;
    assert_eq!(reply.rcode, Rcode::SERVFAIL, "{reply:?}");
    system.shutdown().await;
}

// CoreDNS v1.15.0 plugin/pkg/tls NewTLSConfigFromArgs: `tls CERT KEY CA` presents a client certificate.
#[tokio::test]
async fn tls_presents_the_client_certificate() {
    let stub = EtcdStub::start_mutual_tls().await;
    put(&stub, "a.skydns.test.", &json!({"host": "10.0.0.1"}));
    let endpoint = stub.endpoint(true);
    let ca = format!("{FIXTURES}/ca.pem");
    let with = |cert: &str| {
        tls_options(&format!(
            "{FIXTURES}/{cert}.pem {FIXTURES}/{cert}.key.pem {ca}"
        ))
    };
    let good = Rig::zone(&endpoint, &with("client")).await;
    good.udp("a.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["a.skydns.test. 300 A 10.0.0.1"],
        &[],
        &[],
    );
    good.shutdown().await;
    for (what, options) in [
        ("no client certificate", tls_options(&ca)),
        ("a certificate of another CA", with("rogue-client")),
    ] {
        let rig = Rig::zone(&endpoint, &options).await;
        let reply = rig.udp("a.skydns.test.", Type::A).await;
        assert_eq!(reply.rcode, Rcode::SERVFAIL, "{what}: {reply:?}");
        rig.shutdown().await;
    }
}

// etcd clientv3 balancer: a refused endpoint is skipped for another.
#[tokio::test]
async fn a_dead_first_endpoint_fails_over() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let dead = refused_address().await;
    let rig = Rig::zone(&format!("http://{dead} {}", stub.endpoint(false)), "").await;
    for _ in 0..3 {
        rig.udp("a.skydns.test.", Type::A).await.expect(
            Rcode::NOERROR,
            &["a.skydns.test. 300 A 10.0.0.1"],
            &[],
            &[],
        );
    }
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go `etcdTimeout`: the endpoints share one call time, and the one that hung is tried last afterwards.
#[tokio::test]
async fn a_hung_first_endpoint_fails_over_and_is_then_avoided() {
    let hung = EtcdStub::start().await;
    hung.set_mode(Mode::Hang);
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(
        &format!("{} {}", hung.endpoint(false), stub.endpoint(false)),
        "",
    )
    .await;
    let started = Instant::now();
    let reply = rig.udp("a.skydns.test.", Type::A).await;
    assert_eq!(reply.rcode, Rcode::NOERROR, "{reply:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let started = Instant::now();
    for _ in 0..5 {
        assert_eq!(
            rig.udp("a.skydns.test.", Type::A).await.rcode,
            Rcode::NOERROR
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/backend_lookup.go BackendError: an etcd that cannot be read is SERVFAIL, and promptly each time.
#[tokio::test]
async fn an_unreachable_etcd_is_servfail_without_waiting() {
    let dead = refused_address().await;
    let rig = Rig::zone(&format!("http://{dead}"), "").await;
    let started = Instant::now();
    for _ in 0..5 {
        let reply = rig.udp("a.skydns.test.", Type::A).await;
        assert_eq!(reply.rcode, Rcode::SERVFAIL, "{reply:?}");
        assert!(reply.aa);
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    rig.shutdown().await;
}

#[tokio::test]
async fn an_etcd_that_fails_is_servfail_until_it_recovers() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    stub.set_mode(Mode::Fail(Code::Unavailable));
    let started = Instant::now();
    for _ in 0..3 {
        assert_eq!(
            rig.udp("a.skydns.test.", Type::A).await.rcode,
            Rcode::SERVFAIL
        );
    }
    assert!(started.elapsed() < Duration::from_secs(3));
    stub.set_mode(Mode::Normal);
    // The failed endpoint is tried again at once when it is the only one.
    assert_eq!(
        rig.udp("a.skydns.test.", Type::A).await.rcode,
        Rcode::NOERROR
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go `etcdTimeout`: a call that is never answered ends in SERVFAIL after at most five seconds.
#[tokio::test]
async fn a_hung_etcd_is_servfail_within_the_call_time() {
    let stub = EtcdStub::start().await;
    stub.set_mode(Mode::Hang);
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    let started = Instant::now();
    let reply = rig.udp("a.skydns.test.", Type::A).await;
    assert_eq!(reply.rcode, Rcode::SERVFAIL, "{reply:?}");
    let elapsed = started.elapsed();
    assert!(
        (Duration::from_secs(4)..Duration::from_secs(8)).contains(&elapsed),
        "{elapsed:?}"
    );
    rig.shutdown().await;
}

/// Ask until a Query is answered from the view, that is, without a `Range` call.
async fn warm(rig: &Rig, stub: &EtcdStub, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let before = stub.calls("Range");
        rig.udp(name, Type::A).await;
        if stub.calls("Range") == before {
            return;
        }
        assert!(Instant::now() < deadline, "the view never got warm");
        sleep(Duration::from_millis(20)).await;
    }
}

// The view serves repeated Queries without reading etcd.
#[tokio::test]
async fn cache_hits_do_not_read_etcd() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    warm(&rig, &stub, "a.skydns.test.").await;
    let before = stub.calls("Range");
    for _ in 0..50 {
        rig.udp("a.skydns.test.", Type::A).await.expect(
            Rcode::NOERROR,
            &["a.skydns.test. 300 A 10.0.0.1"],
            &[],
            &[],
        );
    }
    assert_eq!(stub.calls("Range"), before);
    // The watch is one stream on the prefix, however many Queries there are.
    assert_eq!(stub.calls("Watch"), 1);
    rig.shutdown().await;
}

/// Ask until the answer to `name` is `address` (or none) with `rcode`; the time that took.
async fn changed(rig: &Rig, name: &str, rcode: Rcode, address: Option<&str>) -> Duration {
    let started = Instant::now();
    loop {
        let reply = rig.udp(name, Type::A).await;
        let seen = reply
            .answer
            .first()
            .map(|record| record.rsplit(' ').next().unwrap());
        if reply.rcode == rcode && seen == address {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{name} not updated: {reply:?}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

// etcd v3 api/etcdserverpb/rpc.proto Watch: a put or delete under the prefix reaches the Queries within the propagation delay, not the five second age of the entry.
#[tokio::test]
async fn a_watch_event_updates_the_answers_within_a_bounded_time() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    warm(&rig, &stub, "a.skydns.test.").await;
    warm(&rig, &stub, "new.skydns.test.").await;
    // A negative answer was held, and a put replaces it.
    put(&stub, "new.skydns.test.", &json!({"host": "10.0.0.5"}));
    let elapsed = changed(&rig, "new.skydns.test.", Rcode::NOERROR, Some("10.0.0.5")).await;
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    // An overwrite.
    put(&stub, "a.skydns.test.", &json!({"host": "10.0.0.2"}));
    changed(&rig, "a.skydns.test.", Rcode::NOERROR, Some("10.0.0.2")).await;
    // A delete.
    assert!(stub.delete(&msg::path("a.skydns.test.", "skydns")));
    changed(&rig, "a.skydns.test.", Rcode::NXDOMAIN, None).await;
    rig.shutdown().await;
}

// The view reads again when the watch is lost, and takes it up again when etcd is back.
#[tokio::test]
async fn answers_stay_current_when_the_watch_breaks() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    warm(&rig, &stub, "a.skydns.test.").await;
    stub.fail_watch(true);
    stub.drop_connections();
    put(&stub, "a.skydns.test.", &json!({"host": "10.0.0.2"}));
    // With no watch, every Query reads etcd, as CoreDNS does.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let reply = rig.udp("a.skydns.test.", Type::A).await;
        if reply.answer == ["a.skydns.test. 300 A 10.0.0.2"] {
            break;
        }
        assert!(Instant::now() < deadline, "{reply:?}");
        sleep(Duration::from_millis(20)).await;
    }
    let before = stub.calls("Range");
    rig.udp("a.skydns.test.", Type::A).await;
    rig.udp("a.skydns.test.", Type::A).await;
    // One Query reads etcd at least once (a recursive read tries the prefix, then the key itself).
    assert!(stub.calls("Range") >= before + 2);
    stub.fail_watch(false);
    warm(&rig, &stub, "a.skydns.test.").await;
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/handler.go ServeDNS: a name error goes to the next Plugin inside `fallthrough`.
#[tokio::test]
async fn fallthrough_runs_the_next_plugin_on_a_name_error() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let endpoint = stub.endpoint(false);
    let without = Rig::zone(&endpoint, "").await;
    without
        .udp("missing.skydns.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
    without.shutdown().await;

    let all = Rig::zone(&endpoint, "fallthrough").await;
    assert!(all.udp("missing.skydns.test.", Type::A).await.is_whoami());
    // Found names, and NODATA, are still answered by the Plugin.
    assert_eq!(
        all.udp("a.skydns.test.", Type::A).await.answer,
        ["a.skydns.test. 300 A 10.0.0.1"]
    );
    all.udp("a.skydns.test.", Type::TXT)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
    all.shutdown().await;

    let some = Rig::zone(&endpoint, "fallthrough sub.skydns.test").await;
    assert!(some.udp("x.sub.skydns.test.", Type::A).await.is_whoami());
    some.udp("missing.skydns.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
    some.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go `upstream`: a CNAME or SRV target outside the zones is looked up through the Server.
#[cfg(feature = "plugin-hosts")]
#[tokio::test]
async fn a_target_outside_the_zones_is_resolved_through_the_chain() {
    let stub = stub_with(&[
        ("x.skydns.test.", json!({"host": "b.other"})),
        ("srv.skydns.test.", json!({"host": "b.other", "port": 80})),
    ])
    .await;
    let rig = Rig::start(&format!(
        "{ZONE}.:0 {{\n etcd {{\n endpoint {}\n }}\n}}\nother.:0 {{\n hosts /nonexistent other. {{\n 192.0.2.42 b.other.\n }}\n}}",
        stub.endpoint(false)
    ))
    .await;
    rig.udp("x.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "x.skydns.test. 300 CNAME b.other.",
            "b.other. 3600 A 192.0.2.42",
        ],
        &[],
        &[],
    );
    rig.udp("srv.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["srv.skydns.test. 300 SRV 10 100 80 b.other."],
        &[],
        &["b.other. 3600 A 192.0.2.42"],
    );
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/normalize.go Zones: each Server Block, and each zone of a Directive, has its own etcd and path.
#[tokio::test]
async fn server_blocks_and_zones_are_served_from_their_own_etcd() {
    let first = EtcdStub::start().await;
    let second = EtcdStub::start().await;
    first.put("/skydns/test/one/a", r#"{"host":"10.0.0.1"}"#);
    first.put("/skydns/test/two/a", r#"{"host":"10.0.0.2"}"#);
    second.put("/other/test/three/a", r#"{"host":"10.0.0.3"}"#);
    let rig = Rig::start(&format!(
        "one.test.:0 two.test.:0 {{\n etcd {{\n endpoint {}\n }}\n}}\nthree.test.:0 {{\n etcd {{\n endpoint {}\n path other\n }}\n}}",
        first.endpoint(false),
        second.endpoint(false)
    ))
    .await;
    for (name, address) in [
        ("a.one.test.", "10.0.0.1"),
        ("a.two.test.", "10.0.0.2"),
        ("a.three.test.", "10.0.0.3"),
    ] {
        rig.udp(name, Type::A).await.expect(
            Rcode::NOERROR,
            &[&format!("{name} 300 A {address}")],
            &[],
            &[],
        );
    }
    // Each zone has its own SOA.
    rig.udp("two.test.", Type::SOA).await.expect(
        Rcode::NOERROR,
        &["two.test. 30 SOA ns.dns.two.test. hostmaster.two.test."],
        &[],
        &[],
    );
    // A name in one zone is not looked up under another's etcd or path.
    rig.udp("a.three.test.", Type::TXT).await.expect(
        Rcode::NOERROR,
        &[],
        &["three.test. 30 SOA ns.dns.three.test. hostmaster.three.test."],
        &[],
    );
    assert!(second.calls("Range") > 0);
    rig.shutdown().await;
}

// RFC 1035 §4.2.1, RFC 7766 §8: a Response too large for UDP is truncated there and whole over TCP.
#[tokio::test]
async fn a_large_response_is_truncated_over_udp_and_whole_over_tcp() {
    let stub = EtcdStub::start().await;
    for i in 0..60 {
        stub.put(
            &format!("/skydns/test/skydns/many/h{i}"),
            &json!({"host": format!("10.1.0.{i}")}).to_string(),
        );
    }
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    let udp = rig.udp("many.skydns.test.", Type::A).await;
    assert!(udp.tc, "{udp:?}");
    assert!(
        !udp.answer.is_empty() && udp.answer.len() < 60,
        "{}",
        udp.answer.len()
    );
    let (tcp, len) = rig.tcp("many.skydns.test.", Type::A).await;
    assert!(!tcp.tc);
    assert_eq!(tcp.answer.len(), 60);
    assert!(len > 512);
    rig.shutdown().await;
}

// RFC 1035 §4.2.2: a message over TCP is at most 65535 octets, so a larger answer is truncated there too.
#[tokio::test]
async fn a_response_over_the_tcp_limit_is_truncated() {
    let stub = EtcdStub::start().await;
    for i in 0..5000 {
        stub.put(
            &format!("/skydns/test/skydns/huge/h{i:04}"),
            &json!({"host": format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)})
                .to_string(),
        );
    }
    let rig = Rig::zone(&stub.endpoint(false), "").await;
    let (tcp, len) = rig.tcp("huge.skydns.test.", Type::A).await;
    assert!(tcp.tc, "{} records", tcp.answer.len());
    assert!(len <= 65535);
    assert!(tcp.answer.len() > 4000 && tcp.answer.len() < 5000);
    rig.shutdown().await;
}

fn setup_error(corefile: &str) -> String {
    let blocks = parse("Corefile", corefile).unwrap();
    configure::<Chain>(&blocks, directives())
        .err()
        .unwrap_or_else(|| panic!("{corefile} was accepted"))
        .to_string()
}

// CoreDNS v1.15.0 plugin/etcd/setup_test.go TestSetupEtcd and plugin/etcd/setup.go etcdParse.
#[test]
fn corefile_errors_fail_setup() {
    for (corefile, expected) in [
        (
            ".:0 {\n etcd {\n endpoints localhost:300\n }\n}",
            "unknown property 'endpoints'",
        ),
        (
            ".:0 {\n etcd {\n credentials username\n }\n}",
            "credentials requires 2 arguments",
        ),
        (
            ".:0 {\n etcd {\n credentials\n }\n}",
            "Wrong argument count",
        ),
        (
            ".:0 {\n etcd {\n min-lease-ttl abc\n }\n}",
            "invalid min-lease-ttl value: invalid TTL format",
        ),
        (
            ".:0 {\n etcd {\n max-lease-ttl -5s\n }\n}",
            "invalid max-lease-ttl value: TTL must be non-negative",
        ),
        (".:0 {\n etcd {\n path\n }\n}", "Wrong argument count"),
        (
            ".:0 {\n etcd {\n tls a b c d\n }\n}",
            "maximum of three arguments allowed for TLS config, found 4",
        ),
        (
            ".:0 {\n etcd {\n tls /nonexistent/ca.pem\n }\n}",
            "/nonexistent/ca.pem",
        ),
        (
            ".:0 {\n etcd {\n endpoint ftp://localhost:2379\n }\n}",
            "unsupported etcd endpoint",
        ),
        (
            ".:0 {\n etcd\n etcd\n}",
            "this plugin can only be used once per Server Block",
        ),
    ] {
        let error = setup_error(corefile);
        assert!(error.contains(expected), "{corefile}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: setup does not connect, so an unreachable etcd is accepted.
#[tokio::test]
async fn setup_accepts_an_unreachable_etcd() {
    let dead = refused_address().await;
    let rig = Rig::zone(&format!("http://{dead}"), "").await;
    rig.shutdown().await;
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: the accepted options, including those that do nothing.
#[tokio::test]
async fn ignored_options_are_accepted() {
    let stub = stub_with(&[("a.skydns.test.", json!({"host": "10.0.0.1"}))]).await;
    let rig = Rig::zone(
        &stub.endpoint(false),
        "stubzones\n debug\n upstream 1.1.1.1\n",
    )
    .await;
    rig.udp("a.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["a.skydns.test. 300 A 10.0.0.1"],
        &[],
        &[],
    );
    rig.shutdown().await;
}
