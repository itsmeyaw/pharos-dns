//! Ported from CoreDNS v1.15.0 plugin/etcd lookup_test.go, cname_test.go, group_test.go,
//! multi_test.go and other_test.go. CoreDNS compares each section after sorting it, ignores the
//! serial and timers of an SOA, and treats a TTL of 303 as "any"; the checks here do the same.

use std::net::SocketAddr;

use pharos_proto::{Class, Message, MessageBuilder, Name, Rcode, Rdata, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use serde_json::{Value, json};

use super::{Config, Endpoint, Etcd, etcd_stub::EtcdStub, msg};

mod served;

struct Passed;

impl Next for Passed {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
}

struct Reply {
    outcome: Outcome,
    rcode: Rcode,
    tc: bool,
    aa: bool,
    answer: Vec<String>,
    authority: Vec<String>,
    additional: Vec<String>,
}

impl Reply {
    fn answered(&self) -> bool {
        self.outcome == Outcome::Response
    }

    /// The sections sorted, as CoreDNS `SortAndCheck` does.
    #[track_caller]
    fn expect(&self, rcode: Rcode, answer: &[&str], authority: &[&str], additional: &[&str]) {
        assert!(self.answered(), "no Response: {:?}", self.outcome);
        assert_eq!(self.rcode, rcode, "rcode");
        for (what, got, want) in [
            ("answer", &self.answer, answer),
            ("authority", &self.authority, authority),
            ("additional", &self.additional, additional),
        ] {
            let mut got = got.clone();
            let mut want: Vec<_> = want.iter().map(|s| (*s).to_owned()).collect();
            got.sort();
            want.sort();
            assert_eq!(got, want, "{what}");
        }
    }

    /// The sections in order, as CoreDNS `test.Section` does without sorting.
    #[track_caller]
    fn expect_ordered(&self, answer: &[&str], additional: &[&str]) {
        assert!(self.answered(), "no Response: {:?}", self.outcome);
        assert_eq!(self.rcode, Rcode::NOERROR, "rcode");
        assert_eq!(self.answer, answer, "answer");
        assert_eq!(self.additional, additional, "additional");
    }
}

fn show(record: &pharos_proto::Record<'_>) -> String {
    let data = match record.data().unwrap() {
        // The serial and timers of an SOA vary; CoreDNS compares the nameserver only.
        Rdata::Soa { mname, rname, .. } => format!("{mname} {rname}"),
        other => other.to_string(),
    };
    format!("{} {} {} {data}", record.name, record.ttl, record.rtype)
}

fn config(address: SocketAddr, zones: &[&str]) -> Config {
    Config {
        zones: zones.iter().map(|zone| zone.parse().unwrap()).collect(),
        fallthrough: Vec::new(),
        path_prefix: "skydns".into(),
        endpoints: vec![Endpoint {
            text: address.to_string(),
            host: address.ip().to_string(),
            port: address.port(),
            tls: false,
        }],
        tls: None,
        credentials: None,
        min_lease_ttl: 0,
        max_lease_ttl: 0,
        no_apex_fallback: false,
    }
}

/// Zones of CoreDNS lookup_test.go `newEtcdPlugin`.
const ZONES: &[&str] = &[
    "skydns.test.",
    "skydns_extra.test.",
    "skydns_zonea.test.",
    "skydns_zoneb.test.",
    "skydns_zonec.test.",
    "skydns_zoned.test.",
    "in-addr.arpa.",
];

struct Fixture {
    stub: EtcdStub,
    etcd: Etcd,
}

impl Fixture {
    /// CoreDNS names each key as a DNS name; etcd holds the path.
    async fn new(zones: &[&str], services: &[(&str, Value)]) -> Self {
        Self::with(zones, services, |_| {}).await
    }

    async fn with(
        zones: &[&str],
        services: &[(&str, Value)],
        edit: impl FnOnce(&mut Config),
    ) -> Self {
        let stub = EtcdStub::start().await;
        for (key, value) in services {
            stub.put(
                &msg::path_with_wildcard(key, "skydns").0,
                &value.to_string(),
            );
        }
        let mut config = config(stub.address, zones);
        edit(&mut config);
        Self {
            stub,
            etcd: Etcd::new(config),
        }
    }

    /// Serve one Query; the Response, if the Plugin wrote one.
    async fn exchange(&self, qname: &str, qtype: Type) -> (Outcome, Vec<u8>) {
        let name: Name = qname.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder
            .question(name.as_name_ref(), qtype, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let root: Name = ".".parse().unwrap();
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = self.etcd.serve(&mut cx, Passed).await;
        (outcome, response)
    }

    async fn ask(&self, qname: &str, qtype: Type) -> Reply {
        let (outcome, response) = self.exchange(qname, qtype).await;
        if outcome != Outcome::Response {
            return Reply {
                outcome,
                rcode: Rcode::NOERROR,
                tc: false,
                aa: false,
                answer: Vec::new(),
                authority: Vec::new(),
                additional: Vec::new(),
            };
        }
        let message = Message::parse(&response).unwrap();
        Reply {
            outcome,
            rcode: message.rcode(),
            tc: message.tc(),
            aa: message.aa(),
            answer: message.answers().map(|r| show(&r)).collect(),
            authority: message.authorities().map(|r| show(&r)).collect(),
            additional: message.additionals().map(|r| show(&r)).collect(),
        }
    }
}

const SOA: &str = "skydns.test. 30 SOA ns.dns.skydns.test. hostmaster.skydns.test.";

/// CoreDNS lookup_test.go `services`.
fn lookup_services() -> Vec<(&'static str, Value)> {
    vec![
        (
            "a.server1.dev.region1.skydns.test.",
            json!({"host": "dev.server1", "port": 8080}),
        ),
        (
            "a.server1.prod.region1.skydns.test.",
            json!({"host": "10.0.0.1", "port": 8080}),
        ),
        (
            "b.server1.prod.region1.skydns.test.",
            json!({"host": "10.0.0.2", "port": 8080}),
        ),
        (
            "b.server6.prod.region1.skydns.test.",
            json!({"host": "::1", "port": 8080}),
        ),
        (
            "a.txt.server1.prod.region1.skydns.test.",
            json!({"text": "sometext"}),
        ),
        (
            "b.txt.server1.prod.region1.skydns.test.",
            json!({"text": "moretext"}),
        ),
        (
            "cname.prod.region1.skydns.test.",
            json!({"host": "unresolvable.skydns.test"}),
        ),
        (
            "priority.skydns.test.",
            json!({"host": "priority.server1", "priority": 333, "port": 8080}),
        ),
        (
            "a.sub.region1.skydns.test.",
            json!({"host": "sub.server1", "port": 0}),
        ),
        (
            "b.sub.region1.skydns.test.",
            json!({"host": "sub.server2", "port": 80}),
        ),
        (
            "c.sub.region1.skydns.test.",
            json!({"host": "10.0.0.1", "port": 8080}),
        ),
        (
            "a.targetstrip.skydns.test.",
            json!({"host": "10.0.0.1", "port": 8080, "targetstrip": 1}),
        ),
        (
            "b.cname.skydns.test.",
            json!({"host": "a.cname.skydns.test"}),
        ),
        (
            "a.cname.skydns.test.",
            json!({"host": "b.cname.skydns.test"}),
        ),
        ("a.ns.dns.skydns.test.", json!({"host": "10.0.0.2"})),
        ("b.ns.dns.skydns.test.", json!({"host": "10.0.0.3"})),
        (
            "ns1.c.ns.dns.skydns.test.",
            json!({"host": "10.0.0.4", "targetstrip": 1}),
        ),
        (
            "ns2.c.ns.dns.skydns.test.",
            json!({"host": "10.0.0.5", "targetstrip": 1}),
        ),
        ("x.skydns_zonea.test.", json!({"host": "10.0.0.2"})),
        ("y.skydns_zonea.test.", json!({"host": "10.0.0.3"})),
        ("x.skydns_zoneb.test.", json!({"host": "10.0.0.2"})),
        ("y.skydns_zoneb.test.", json!({"host": "10.0.0.3"})),
        ("apex.dns.skydns_zoneb.test.", json!({"host": "10.0.0.4"})),
        ("x.skydns_zonec.test.", json!({"host": "10.0.0.2"})),
        ("y.skydns_zonec.test.", json!({"host": "10.0.0.3"})),
        (
            "a1.apex.dns.skydns_zonec.test.",
            json!({"host": "10.0.0.4"}),
        ),
        (
            "a2.apex.dns.skydns_zonec.test.",
            json!({"host": "10.0.0.5"}),
        ),
        ("x.skydns_zoned.test.", json!({"host": "10.0.0.2"})),
        ("y.skydns_zoned.test.", json!({"host": "10.0.0.3"})),
        (
            "a1.apex.dns.skydns_zoned.test.",
            json!({"host": "10.0.0.4"}),
        ),
        (
            "a2.apex.dns.skydns_zoned.test.",
            json!({"host": "10.0.0.5"}),
        ),
        (
            "a3.apex.dns.skydns_zoned.test.",
            json!({"host": "2003::8:1"}),
        ),
        (
            "a4.apex.dns.skydns_zoned.test.",
            json!({"host": "2003::8:2"}),
        ),
        (
            "1.0.0.10.in-addr.arpa.",
            json!({"host": "reverse.example.com"}),
        ),
    ]
}

async fn lookup() -> Fixture {
    Fixture::new(ZONES, &lookup_services()).await
}

// CoreDNS v1.15.0 plugin/etcd/lookup_test.go TestLookup: SRV.
#[tokio::test]
async fn srv_of_a_name() {
    let f = lookup().await;
    f.ask("a.server1.dev.region1.skydns.test.", Type::SRV)
        .await
        .expect(
            Rcode::NOERROR,
            &["a.server1.dev.region1.skydns.test. 300 SRV 10 100 8080 dev.server1."],
            &[],
            &[],
        );
}

// RFC 4343 §4.1: the answer keeps the case of the question.
#[tokio::test]
async fn srv_keeps_the_case_of_the_question() {
    let f = lookup().await;
    f.ask("a.SERVer1.dEv.region1.skydns.tEst.", Type::SRV)
        .await
        .expect(
            Rcode::NOERROR,
            &["a.SERVer1.dEv.region1.skydns.tEst. 300 SRV 10 100 8080 dev.server1."],
            &[],
            &[],
        );
}

#[tokio::test]
async fn a_of_a_missing_name_is_nxdomain_with_soa() {
    let f = lookup().await;
    f.ask("doesnotexist.skydns.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
}

#[tokio::test]
async fn a_of_a_name() {
    let f = lookup().await;
    f.ask("a.server1.prod.region1.skydns.test.", Type::A)
        .await
        .expect(
            Rcode::NOERROR,
            &["a.server1.prod.region1.skydns.test. 300 A 10.0.0.1"],
            &[],
            &[],
        );
}

#[tokio::test]
async fn srv_with_an_address_names_the_key_and_adds_the_address() {
    let f = lookup().await;
    f.ask("a.server1.prod.region1.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["a.server1.prod.region1.skydns.test. 300 SRV 10 100 8080 a.server1.prod.region1.skydns.test."],
        &[],
        &["a.server1.prod.region1.skydns.test. 300 A 10.0.0.1"],
    );
}

#[tokio::test]
async fn aaaa_of_a_name() {
    let f = lookup().await;
    f.ask("b.server6.prod.region1.skydns.test.", Type::AAAA)
        .await
        .expect(
            Rcode::NOERROR,
            &["b.server6.prod.region1.skydns.test. 300 AAAA ::1"],
            &[],
            &[],
        );
}

#[tokio::test]
async fn a_of_a_directory_lists_every_key_under_it() {
    let f = lookup().await;
    f.ask("server1.prod.region1.skydns.test.", Type::A)
        .await
        .expect(
            Rcode::NOERROR,
            &[
                "server1.prod.region1.skydns.test. 300 A 10.0.0.1",
                "server1.prod.region1.skydns.test. 300 A 10.0.0.2",
            ],
            &[],
            &[],
        );
}

#[tokio::test]
async fn srv_priority() {
    let f = lookup().await;
    f.ask("priority.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["priority.skydns.test. 300 SRV 333 100 8080 priority.server1."],
        &[],
        &[],
    );
}

#[tokio::test]
async fn srv_of_a_subdomain_shares_the_weight() {
    let f = lookup().await;
    f.ask("sub.region1.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &[
            "sub.region1.skydns.test. 300 SRV 10 33 0 sub.server1.",
            "sub.region1.skydns.test. 300 SRV 10 33 80 sub.server2.",
            "sub.region1.skydns.test. 300 SRV 10 33 8080 c.sub.region1.skydns.test.",
        ],
        &[],
        &["c.sub.region1.skydns.test. 300 A 10.0.0.1"],
    );
}

#[tokio::test]
async fn srv_target_strip() {
    let f = lookup().await;
    f.ask("targetstrip.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["targetstrip.skydns.test. 300 SRV 10 100 8080 targetstrip.skydns.test."],
        &[],
        &["targetstrip.skydns.test. 300 A 10.0.0.1"],
    );
}

#[tokio::test]
async fn a_of_an_unresolvable_cname_is_nodata() {
    let f = lookup().await;
    f.ask("cname.prod.region1.skydns.test.", Type::A)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
}

#[tokio::test]
async fn txt_of_a_directory() {
    let f = lookup().await;
    f.ask("txt.server1.prod.region1.skydns.test.", Type::TXT)
        .await
        .expect(
            Rcode::NOERROR,
            &[
                "txt.server1.prod.region1.skydns.test. 300 TXT \"moretext\"",
                "txt.server1.prod.region1.skydns.test. 300 TXT \"sometext\"",
            ],
            &[],
            &[],
        );
}

const WILDCARD_EXTRA: [&str; 3] = [
    "a.server1.prod.region1.skydns.test. 300 A 10.0.0.1",
    "b.server1.prod.region1.skydns.test. 300 A 10.0.0.2",
    "b.server6.prod.region1.skydns.test. 300 AAAA ::1",
];

#[tokio::test]
async fn srv_with_a_wildcard_at_the_end() {
    let f = lookup().await;
    let mut extra = WILDCARD_EXTRA.to_vec();
    extra.push("c.sub.region1.skydns.test. 300 A 10.0.0.1");
    f.ask("*.region1.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &[
            "*.region1.skydns.test. 300 SRV 10 12 0 sub.server1.",
            "*.region1.skydns.test. 300 SRV 10 12 0 unresolvable.skydns.test.",
            "*.region1.skydns.test. 300 SRV 10 12 80 sub.server2.",
            "*.region1.skydns.test. 300 SRV 10 12 8080 a.server1.prod.region1.skydns.test.",
            "*.region1.skydns.test. 300 SRV 10 12 8080 b.server1.prod.region1.skydns.test.",
            "*.region1.skydns.test. 300 SRV 10 12 8080 b.server6.prod.region1.skydns.test.",
            "*.region1.skydns.test. 300 SRV 10 12 8080 c.sub.region1.skydns.test.",
            "*.region1.skydns.test. 300 SRV 10 12 8080 dev.server1.",
        ],
        &[],
        &extra,
    );
}

#[tokio::test]
async fn srv_with_a_wildcard_in_the_middle() {
    let f = lookup().await;
    for wildcard in ["*", "any"] {
        let name = format!("prod.{wildcard}.skydns.test.");
        let owner = |rest: &str| format!("{name} 300 SRV 10 25 {rest}");
        f.ask(&name, Type::SRV).await.expect(
            Rcode::NOERROR,
            &[
                &owner("0 unresolvable.skydns.test."),
                &owner("8080 a.server1.prod.region1.skydns.test."),
                &owner("8080 b.server1.prod.region1.skydns.test."),
                &owner("8080 b.server6.prod.region1.skydns.test."),
            ],
            &[],
            &WILDCARD_EXTRA,
        );
    }
}

#[tokio::test]
async fn a_cname_loop_is_nodata() {
    let f = lookup().await;
    f.ask("a.cname.skydns.test.", Type::A)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
}

#[tokio::test]
async fn txt_and_other_types_of_a_service_without_them_are_nodata() {
    let f = lookup().await;
    for qtype in [Type::TXT, Type::HINFO] {
        f.ask("a.server1.dev.region1.skydns.test.", qtype)
            .await
            .expect(Rcode::NOERROR, &[], &[SOA], &[]);
    }
}

#[tokio::test]
async fn other_types_of_a_missing_name_are_nxdomain() {
    let f = lookup().await;
    f.ask("a.server1.nonexistent.region1.skydns.test.", Type::HINFO)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
}

#[tokio::test]
async fn soa_of_the_zone() {
    let f = lookup().await;
    f.ask("skydns.test.", Type::SOA)
        .await
        .expect(Rcode::NOERROR, &[SOA], &[], &[]);
    f.ask("skydns_extra.test.", Type::SOA).await.expect(
        Rcode::NOERROR,
        &["skydns_extra.test. 30 SOA ns.dns.skydns_extra.test. hostmaster.skydns_extra.test."],
        &[],
        &[],
    );
}

// CoreDNS v1.15.0 plugin/backend_lookup.go SOA.
#[tokio::test]
async fn soa_timers() {
    let f = lookup().await;
    let (outcome, response) = f.exchange("skydns.test.", Type::SOA).await;
    assert_eq!(outcome, Outcome::Response);
    let message = Message::parse(&response).unwrap();
    let Rdata::Soa {
        serial,
        refresh,
        retry,
        expire,
        minimum,
        ..
    } = message.answers().next().unwrap().data().unwrap()
    else {
        panic!("expected SOA")
    };
    assert!(serial > 1_700_000_000);
    assert_eq!((refresh, retry, expire, minimum), (7200, 1800, 86400, 30));
}

#[tokio::test]
async fn ns_of_the_zone_apex() {
    let f = lookup().await;
    f.ask("skydns.test.", Type::NS).await.expect(
        Rcode::NOERROR,
        &[
            "skydns.test. 300 NS a.ns.dns.skydns.test.",
            "skydns.test. 300 NS b.ns.dns.skydns.test.",
            "skydns.test. 300 NS c.ns.dns.skydns.test.",
        ],
        &[],
        &[
            "a.ns.dns.skydns.test. 300 A 10.0.0.2",
            "b.ns.dns.skydns.test. 300 A 10.0.0.3",
            "c.ns.dns.skydns.test. 300 A 10.0.0.4",
            "c.ns.dns.skydns.test. 300 A 10.0.0.5",
        ],
    );
}

#[tokio::test]
async fn ns_below_the_apex_is_nxdomain() {
    let f = lookup().await;
    f.ask("a.skydns.test.", Type::NS)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
}

#[tokio::test]
async fn a_of_the_nameserver_name() {
    let f = lookup().await;
    f.ask("ns.dns.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "ns.dns.skydns.test. 300 A 10.0.0.2",
            "ns.dns.skydns.test. 300 A 10.0.0.3",
            "ns.dns.skydns.test. 300 A 10.0.0.4",
            "ns.dns.skydns.test. 300 A 10.0.0.5",
        ],
        &[],
        &[],
    );
}

#[tokio::test]
async fn zone_name_as_a_without_apex_returns_all() {
    let f = lookup().await;
    f.ask("skydns_zonea.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "skydns_zonea.test. 300 A 10.0.0.2",
            "skydns_zonea.test. 300 A 10.0.0.3",
        ],
        &[],
        &[],
    );
}

#[tokio::test]
async fn zone_name_as_a_with_one_apex_entry() {
    let f = lookup().await;
    f.ask("skydns_zoneb.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["skydns_zoneb.test. 300 A 10.0.0.4"],
        &[],
        &[],
    );
}

#[tokio::test]
async fn zone_name_as_a_with_several_apex_entries() {
    let f = lookup().await;
    f.ask("skydns_zonec.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "skydns_zonec.test. 300 A 10.0.0.4",
            "skydns_zonec.test. 300 A 10.0.0.5",
        ],
        &[],
        &[],
    );
}

#[tokio::test]
async fn zone_name_with_mixed_apex_entries() {
    let f = lookup().await;
    f.ask("skydns_zoned.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "skydns_zoned.test. 300 A 10.0.0.4",
            "skydns_zoned.test. 300 A 10.0.0.5",
        ],
        &[],
        &[],
    );
    f.ask("skydns_zoned.test.", Type::AAAA).await.expect(
        Rcode::NOERROR,
        &[
            "skydns_zoned.test. 300 AAAA 2003::8:1",
            "skydns_zoned.test. 300 AAAA 2003::8:2",
        ],
        &[],
        &[],
    );
}

#[tokio::test]
async fn ptr_lookup() {
    let f = lookup().await;
    f.ask("1.0.0.10.in-addr.arpa.", Type::PTR).await.expect(
        Rcode::NOERROR,
        &["1.0.0.10.in-addr.arpa. 300 PTR reverse.example.com."],
        &[],
        &[],
    );
}

// CoreDNS v1.15.0 plugin/etcd/lookup_test.go TestLookupNoApexFallback.
#[tokio::test]
async fn no_apex_fallback() {
    let child = [("x.child.strict.test.", json!({"host": "10.0.0.1"}))];
    let f = Fixture::new(&["strict.test."], &child).await;
    f.ask("strict.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["strict.test. 300 A 10.0.0.1"],
        &[],
        &[],
    );

    let strict = Fixture::with(&["strict.test."], &child, |c| c.no_apex_fallback = true).await;
    let soa = ["strict.test. 30 SOA ns.dns.strict.test. hostmaster.strict.test."];
    strict
        .ask("strict.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &soa, &[]);

    strict
        .stub
        .put("/skydns/test/strict/dns/apex/x", r#"{"host":"192.0.2.1"}"#);
    strict.ask("strict.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["strict.test. 300 A 192.0.2.1"],
        &[],
        &[],
    );
}

const CNAME_SERVICES: &[(&str, &str)] = &[
    (
        "a.server1.dev.region1.skydns.test.",
        "cname1.region2.skydns.test",
    ),
    ("cname1.region2.skydns.test.", "cname2.region2.skydns.test"),
    ("cname2.region2.skydns.test.", "cname3.region2.skydns.test"),
    ("cname3.region2.skydns.test.", "cname4.region2.skydns.test"),
    ("cname4.region2.skydns.test.", "cname5.region2.skydns.test"),
    ("cname5.region2.skydns.test.", "cname6.region2.skydns.test"),
    (
        "cname6.region2.skydns.test.",
        "endpoint.region2.skydns.test",
    ),
    ("endpoint.region2.skydns.test.", "10.240.0.1"),
    ("region2.skydns.test.", "mainendpoint.region2.skydns.test"),
    ("cname3.region3.skydns.test.", "cname2.region3.skydns.test"),
    ("cname2.region3.skydns.test.", "cname1.region3.skydns.test"),
    (
        "cname1.region3.skydns.test.",
        "endpoint.region3.skydns.test",
    ),
];

async fn cnames() -> Fixture {
    let mut services: Vec<_> = CNAME_SERVICES
        .iter()
        .map(|(key, host)| (*key, json!({ "host": host })))
        .collect();
    services.push((
        "endpoint.region3.skydns.test.",
        json!({"host": "", "text": "SOME-RECORD-TEXT"}),
    ));
    Fixture::new(ZONES, &services).await
}

// CoreDNS v1.15.0 plugin/etcd/cname_test.go TestCnameLookup, test 0.
#[tokio::test]
async fn srv_target_chain_is_added_in_order() {
    let f = cnames().await;
    f.ask("a.server1.dev.region1.skydns.test.", Type::SRV)
        .await
        .expect_ordered(
            &["a.server1.dev.region1.skydns.test. 300 SRV 10 100 0 cname1.region2.skydns.test."],
            &[
                "cname1.region2.skydns.test. 300 CNAME cname2.region2.skydns.test.",
                "cname2.region2.skydns.test. 300 CNAME cname3.region2.skydns.test.",
                "cname3.region2.skydns.test. 300 CNAME cname4.region2.skydns.test.",
                "cname4.region2.skydns.test. 300 CNAME cname5.region2.skydns.test.",
                "cname5.region2.skydns.test. 300 CNAME cname6.region2.skydns.test.",
                "cname6.region2.skydns.test. 300 CNAME endpoint.region2.skydns.test.",
                "endpoint.region2.skydns.test. 300 A 10.240.0.1",
            ],
        );
}

#[tokio::test]
async fn cname_query() {
    let f = cnames().await;
    f.ask("region2.skydns.test.", Type::CNAME)
        .await
        .expect_ordered(
            &["region2.skydns.test. 300 CNAME mainendpoint.region2.skydns.test."],
            &[],
        );
}

#[tokio::test]
async fn cname_query_of_a_service_without_a_host_is_nodata() {
    let f = cnames().await;
    f.ask("endpoint.region3.skydns.test.", Type::CNAME)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
}

#[tokio::test]
async fn txt_follows_cnames() {
    let f = cnames().await;
    f.ask("cname3.region3.skydns.test.", Type::TXT)
        .await
        .expect_ordered(
            &[
                "cname3.region3.skydns.test. 300 CNAME cname2.region3.skydns.test.",
                "cname2.region3.skydns.test. 300 CNAME cname1.region3.skydns.test.",
                "cname1.region3.skydns.test. 300 CNAME endpoint.region3.skydns.test.",
                "endpoint.region3.skydns.test. 300 TXT \"SOME-RECORD-TEXT\"",
            ],
            &[],
        );
}

// CoreDNS v1.15.0 plugin/backend_lookup.go: a chain is at most `maxCnameChainLength` long.
#[tokio::test]
async fn a_long_cname_chain_is_cut() {
    let mut services = vec![("end.skydns.test.", json!({"host": "10.0.0.9"}))];
    let mut keys = Vec::new();
    for n in 0..13 {
        keys.push(format!("c{n}.skydns.test."));
    }
    for (n, key) in keys.iter().enumerate() {
        let next = keys.get(n + 1).map_or("end.skydns.test".to_owned(), |k| {
            k.trim_end_matches('.').to_owned()
        });
        services.push((key.as_str(), json!({ "host": next })));
    }
    let f = Fixture::new(ZONES, &services).await;
    f.ask("c12.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "c12.skydns.test. 300 CNAME end.skydns.test.",
            "end.skydns.test. 300 A 10.0.0.9",
        ],
        &[],
        &[],
    );
    let reply = f.ask("c0.skydns.test.", Type::A).await;
    reply.expect(Rcode::NOERROR, &[], &[SOA], &[]);
}

fn group_services() -> Vec<(&'static str, Value)> {
    vec![
        (
            "a.dom.skydns.test.",
            json!({"host": "127.0.0.1", "group": "g1"}),
        ),
        (
            "b.sub.dom.skydns.test.",
            json!({"host": "127.0.0.2", "group": "g1"}),
        ),
        (
            "a.dom2.skydns.test.",
            json!({"host": "127.0.0.1", "group": "g1"}),
        ),
        (
            "b.sub.dom2.skydns.test.",
            json!({"host": "127.0.0.2", "group": ""}),
        ),
        (
            "a.dom1.skydns.test.",
            json!({"host": "127.0.0.1", "group": "g1"}),
        ),
        (
            "b.sub.dom1.skydns.test.",
            json!({"host": "127.0.0.2", "group": "g2"}),
        ),
        ("a.dom3.skydns.test.", json!({"text": "foo", "group": "g1"})),
        (
            "b.sub.dom3.skydns.test.",
            json!({"text": "bar", "group": "g1"}),
        ),
    ]
}

// CoreDNS v1.15.0 plugin/etcd/group_test.go TestGroupLookup.
#[tokio::test]
async fn group_lookup() {
    let f = Fixture::new(ZONES, &group_services()).await;
    // The group of the shortest key holds both.
    f.ask("dom.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "dom.skydns.test. 300 A 127.0.0.1",
            "dom.skydns.test. 300 A 127.0.0.2",
        ],
        &[],
        &[],
    );
    // One has a group, the other has not: the one without stays.
    f.ask("dom2.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &[
            "dom2.skydns.test. 300 A 127.0.0.1",
            "dom2.skydns.test. 300 A 127.0.0.2",
        ],
        &[],
        &[],
    );
    // The groups differ: the shortest key's group wins.
    f.ask("dom1.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["dom1.skydns.test. 300 A 127.0.0.1"],
        &[],
        &[],
    );
    f.ask("dom3.skydns.test.", Type::TXT).await.expect(
        Rcode::NOERROR,
        &[
            "dom3.skydns.test. 300 TXT \"bar\"",
            "dom3.skydns.test. 300 TXT \"foo\"",
        ],
        &[],
        &[],
    );
}

// CoreDNS v1.15.0 plugin/etcd/multi_test.go TestMultiLookup.
#[tokio::test]
async fn several_zones_and_a_name_outside_them() {
    let services = [
        (
            "a.server1.dev.region1.skydns.test.",
            json!({"host": "dev.server1", "port": 8080}),
        ),
        (
            "a.server1.dev.region1.miek.nl.",
            json!({"host": "dev.server1", "port": 8080}),
        ),
        (
            "a.server1.dev.region1.example.org.",
            json!({"host": "dev.server1", "port": 8080}),
        ),
    ];
    let f = Fixture::new(&["skydns.test.", "miek.nl."], &services).await;
    for zone in ["skydns.test.", "miek.nl."] {
        let name = format!("a.server1.dev.region1.{zone}");
        f.ask(&name, Type::SRV).await.expect(
            Rcode::NOERROR,
            &[&format!("{name} 300 SRV 10 100 8080 dev.server1.")],
            &[],
            &[],
        );
    }
    // CoreDNS v1.15.0 plugin/etcd/handler.go: a name outside the zones goes to the next Plugin.
    let reply = f.ask("a.server1.dev.region1.example.org.", Type::SRV).await;
    assert_eq!(reply.outcome, Outcome::Unanswered(Rcode::REFUSED));
}

fn other_services() -> Vec<(&'static str, Value)> {
    vec![
        (
            "a.server1.dev.region1.skydns.test.",
            json!({"host": "dev.server1", "port": 8080}),
        ),
        (
            "a.mail.skydns.test.",
            json!({"host": "mx.skydns.test", "priority": 50, "mail": true}),
        ),
        (
            "b.mail.skydns.test.",
            json!({"host": "mx.miek.nl", "priority": 50, "mail": true}),
        ),
        (
            "a.mx.skydns.test.",
            json!({"host": "a.ipaddr.skydns.test", "priority": 30, "mail": true}),
        ),
        (
            "a.mx2.skydns.test.",
            json!({"host": "a.ipaddr.skydns.test", "mail": true}),
        ),
        (
            "b.mx2.skydns.test.",
            json!({"host": "b.ipaddr.skydns.test", "mail": true}),
        ),
        (
            "a.mx3.skydns.test.",
            json!({"host": "a.ipaddr.skydns.test", "priority": 20, "mail": true}),
        ),
        (
            "b.mx3.skydns.test.",
            json!({"host": "a.ipaddr.skydns.test", "priority": 30, "mail": true}),
        ),
        ("a.ipaddr.skydns.test.", json!({"host": "172.16.1.1"})),
        ("b.ipaddr.skydns.test.", json!({"host": "172.16.1.2"})),
        ("a1.txt.skydns.test.", json!({"text": "abc"})),
        ("a2.txt.skydns.test.", json!({"text": "abc abc"})),
        ("large400.skydns.test.", json!({"text": "0".repeat(400)})),
        ("large600.skydns.test.", json!({"text": "0".repeat(600)})),
        (
            "http.multiport.http.skydns.test.",
            json!({"host": "10.11.11.10", "port": 80}),
        ),
        (
            "https.multiport.http.skydns.test.",
            json!({"host": "10.11.11.10", "port": 443}),
        ),
    ]
}

// CoreDNS v1.15.0 plugin/etcd/other_test.go TestOtherLookup.
#[tokio::test]
async fn mx_of_a_service_that_is_not_mail_is_nodata() {
    let f = Fixture::new(ZONES, &other_services()).await;
    f.ask("a.server1.dev.region1.skydns.test.", Type::MX)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
}

#[tokio::test]
async fn mx_with_a_name_in_the_zone() {
    let f = Fixture::new(ZONES, &other_services()).await;
    f.ask("a.mail.skydns.test.", Type::MX).await.expect(
        Rcode::NOERROR,
        &["a.mail.skydns.test. 300 MX 50 mx.skydns.test."],
        &[],
        &[
            "a.ipaddr.skydns.test. 300 A 172.16.1.1",
            "mx.skydns.test. 300 CNAME a.ipaddr.skydns.test.",
        ],
    );
}

#[tokio::test]
async fn mx_with_two_hosts_and_the_default_preference() {
    let f = Fixture::new(ZONES, &other_services()).await;
    f.ask("mx2.skydns.test.", Type::MX).await.expect(
        Rcode::NOERROR,
        &[
            "mx2.skydns.test. 300 MX 10 a.ipaddr.skydns.test.",
            "mx2.skydns.test. 300 MX 10 b.ipaddr.skydns.test.",
        ],
        &[],
        &[
            "a.ipaddr.skydns.test. 300 A 172.16.1.1",
            "b.ipaddr.skydns.test. 300 A 172.16.1.2",
        ],
    );
}

#[tokio::test]
async fn mx_with_the_same_host_and_different_preferences() {
    let f = Fixture::new(ZONES, &other_services()).await;
    f.ask("mx3.skydns.test.", Type::MX).await.expect(
        Rcode::NOERROR,
        &[
            "mx3.skydns.test. 300 MX 20 a.ipaddr.skydns.test.",
            "mx3.skydns.test. 300 MX 30 a.ipaddr.skydns.test.",
        ],
        &[],
        &["a.ipaddr.skydns.test. 300 A 172.16.1.1"],
    );
}

#[tokio::test]
async fn txt_lookups() {
    let f = Fixture::new(ZONES, &other_services()).await;
    f.ask("a1.txt.skydns.test.", Type::TXT).await.expect(
        Rcode::NOERROR,
        &["a1.txt.skydns.test. 300 TXT \"abc\""],
        &[],
        &[],
    );
    f.ask("a2.txt.skydns.test.", Type::TXT).await.expect(
        Rcode::NOERROR,
        &["a2.txt.skydns.test. 300 TXT \"abc abc\""],
        &[],
        &[],
    );
    // RFC 1035 §3.3.14: a character-string holds at most 255 octets, so 400 are two strings.
    let (first, second) = ("0".repeat(255), "0".repeat(145));
    f.ask("large400.skydns.test.", Type::TXT).await.expect(
        Rcode::NOERROR,
        &[&format!(
            "large400.skydns.test. 300 TXT \"{first}\" \"{second}\""
        )],
        &[],
        &[],
    );
}

// RFC 7766 §3: a Response that does not fit in UDP is truncated, here the 600-octet TXT in 512.
#[tokio::test]
async fn a_large_txt_sets_tc() {
    let f = Fixture::new(ZONES, &other_services()).await;
    let reply = f.ask("large600.skydns.test.", Type::TXT).await;
    assert!(reply.answered());
    assert!(reply.tc);
    assert!(reply.answer.is_empty());
}

#[tokio::test]
async fn an_address_shared_by_two_ports_is_answered_once() {
    let f = Fixture::new(ZONES, &other_services()).await;
    f.ask("multiport.http.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["multiport.http.skydns.test. 300 A 10.11.11.10"],
        &[],
        &[],
    );
}

// CoreDNS v1.15.0 plugin/etcd/handler.go ServeDNS and plugin/backend_lookup.go BackendError.
#[tokio::test]
async fn every_response_is_authoritative() {
    let f = lookup().await;
    for (name, qtype) in [
        ("a.server1.prod.region1.skydns.test.", Type::A),
        ("doesnotexist.skydns.test.", Type::A),
        ("a.server1.dev.region1.skydns.test.", Type::TXT),
    ] {
        assert!(f.ask(name, qtype).await.aa, "{name}");
    }
}

#[tokio::test]
async fn a_name_error_falls_through_where_configured() {
    let f = Fixture::with(ZONES, &lookup_services(), |c| {
        c.fallthrough = vec!["region1.skydns.test.".parse().unwrap()];
    })
    .await;
    // Inside the fallthrough zone a name error goes to the next Plugin.
    let reply = f
        .ask("a.server1.nonexistent.region1.skydns.test.", Type::A)
        .await;
    assert_eq!(reply.outcome, Outcome::Unanswered(Rcode::REFUSED));
    // Outside it, and for NODATA, the Plugin answers.
    f.ask("doesnotexist.skydns.test.", Type::A)
        .await
        .expect(Rcode::NXDOMAIN, &[], &[SOA], &[]);
    f.ask("a.server1.dev.region1.skydns.test.", Type::TXT)
        .await
        .expect(Rcode::NOERROR, &[], &[SOA], &[]);
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go loopNodes: a value that is not a service fails the lookup.
#[tokio::test]
async fn an_invalid_value_is_servfail_with_soa() {
    let f = lookup().await;
    f.stub.put("/skydns/test/skydns/broken/x", "not json");
    f.ask("broken.skydns.test.", Type::A)
        .await
        .expect(Rcode::SERVFAIL, &[], &[SOA], &[]);
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go get: an etcd that cannot be read fails the lookup.
#[tokio::test]
async fn an_unreachable_etcd_is_servfail() {
    let f = lookup().await;
    let address = super::etcd_stub::refused_address().await;
    let down = Etcd::new(config(address, ZONES));
    let f = Fixture {
        stub: f.stub,
        etcd: down,
    };
    f.ask("a.server1.prod.region1.skydns.test.", Type::A)
        .await
        .expect(Rcode::SERVFAIL, &[], &[SOA], &[]);
}

// CoreDNS v1.15.0 plugin/backend_lookup.go NS: a nameserver must be an address.
#[tokio::test]
async fn a_nameserver_that_is_a_name_is_servfail() {
    let services = [("a.ns.dns.skydns.test.", json!({"host": "ns.example.org"}))];
    let f = Fixture::new(ZONES, &services).await;
    f.ask("skydns.test.", Type::NS)
        .await
        .expect(Rcode::SERVFAIL, &[], &[SOA], &[]);
}

// CoreDNS v1.15.0 plugin/backend_lookup.go SRV: port -1 marks a service without a port, which still counts in the weights.
#[tokio::test]
async fn srv_skips_port_minus_one() {
    let services = [
        ("a.s.skydns.test.", json!({"host": "10.0.0.1", "port": -1})),
        ("b.s.skydns.test.", json!({"host": "10.0.0.2", "port": 80})),
    ];
    let f = Fixture::new(ZONES, &services).await;
    f.ask("s.skydns.test.", Type::SRV).await.expect(
        Rcode::NOERROR,
        &["s.skydns.test. 300 SRV 10 50 80 b.s.skydns.test."],
        &[],
        &["b.s.skydns.test. 300 A 10.0.0.2"],
    );
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go: the TTL is the service's, else the default.
#[tokio::test]
async fn the_service_ttl_is_the_record_ttl() {
    let services = [("a.skydns.test.", json!({"host": "10.0.0.1", "ttl": 7}))];
    let f = Fixture::new(ZONES, &services).await;
    f.ask("a.skydns.test.", Type::A).await.expect(
        Rcode::NOERROR,
        &["a.skydns.test. 7 A 10.0.0.1"],
        &[],
        &[],
    );
}
