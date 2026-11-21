use super::{
    Api, Config, Page, RecordSet, StartRecord,
    serve::{Route53, Stanza},
    setup::parse,
    zones::{initialize, update_zones},
};
use pharos_corefile::{Cursor, lex};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Records, Section, Type};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol, Transport};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

const SOA_1536: &str =
    "ns-1536.awsdns-00.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400";
const SOA_15: &str =
    "ns-15.awsdns-00.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400";

fn set(name: &str, rtype: &str, values: &[&str]) -> RecordSet {
    RecordSet {
        name: name.to_owned(),
        rtype: rtype.to_owned(),
        ttl: 300,
        values: values.iter().map(|value| (*value).to_owned()).collect(),
    }
}

/// A fake Route 53 API: record sets per hosted zone ID, optional paging, and hosted zones that fail.
#[derive(Default)]
struct Fake {
    sets: Mutex<HashMap<String, Vec<RecordSet>>>,
    failing: Mutex<HashSet<String>>,
    page_size: usize,
    pages: Mutex<Vec<(String, Option<StartRecord>)>>,
}

impl Fake {
    fn with(self, id: &str, sets: Vec<RecordSet>) -> Self {
        self.sets.lock().unwrap().insert(id.to_owned(), sets);
        self
    }

    fn replace(&self, id: &str, sets: Vec<RecordSet>) {
        self.sets.lock().unwrap().insert(id.to_owned(), sets);
    }

    fn fail(&self, id: &str, failing: bool) {
        let mut ids = self.failing.lock().unwrap();
        if failing {
            ids.insert(id.to_owned());
        } else {
            ids.remove(id);
        }
    }
}

impl Api for Fake {
    async fn check_hosted_zone(&self, _dns: &str, _hosted_zone_id: &str) -> Result<(), String> {
        Ok(())
    }

    async fn list_record_sets(
        &self,
        hosted_zone_id: &str,
        start: Option<&StartRecord>,
    ) -> Result<Page, String> {
        self.pages
            .lock()
            .unwrap()
            .push((hosted_zone_id.to_owned(), start.cloned()));
        if self.failing.lock().unwrap().contains(hosted_zone_id) {
            return Err("bad. zone is bad".to_owned());
        }
        let sets = self
            .sets
            .lock()
            .unwrap()
            .get(hosted_zone_id)
            .cloned()
            .unwrap_or_default();
        // The fake's StartRecord name is the index of the first record set of the page.
        let from = start.map_or(0, |start| start.name.parse::<usize>().unwrap());
        let size = if self.page_size == 0 {
            sets.len().max(1)
        } else {
            self.page_size
        };
        let end = (from + size).min(sets.len());
        let next = (end < sets.len()).then(|| StartRecord {
            name: end.to_string(),
            rtype: "A".to_owned(),
            identifier: None,
        });
        Ok(Page {
            sets: sets[from..end].to_vec(),
            next,
        })
    }
}

// CoreDNS v1.15.0 plugin/route53/route53_test.go fakeRoute53, with an apex SOA and NS for each hosted zone and the
// records that CoreDNS inserts but never serves (`com.` NS, `swag.` YOLO, org. data in a gov. zone) still present.
fn coredns_fake() -> Fake {
    Fake::default()
        .with(
            "1234567890",
            vec![
                set("example.org.", "A", &["1.2.3.4"]),
                set("www.example.org", "A", &["1.2.3.4"]),
                set(r"\052.www.example.org", "CNAME", &["www.example.org"]),
                set("example.org.", "AAAA", &["2001:db8:85a3::8a2e:370:7334"]),
                set("sample.example.org.", "CNAME", &["example.org"]),
                set("example.org.", "PTR", &["ptr.example.org."]),
                set("org.", "SOA", &[SOA_1536]),
                set("org.", "NS", &["ns-1536.awsdns-00.co.uk."]),
                set("com.", "NS", &["ns-1536.awsdns-00.co.uk."]),
                set("split-example.gov.", "A", &["1.2.3.4"]),
                set("gov.", "SOA", &[SOA_1536]),
                set("gov.", "NS", &["ns-1536.awsdns-00.co.uk."]),
                set("swag.", "YOLO", &["foobar"]),
            ],
        )
        .with(
            "1357986420",
            vec![
                set("other-example.org.", "A", &["3.5.7.9"]),
                set("split-example.org.", "A", &["1.2.3.4"]),
                set("org.", "SOA", &[SOA_15]),
                set("org.", "NS", &["ns-15.awsdns-00.co.uk."]),
            ],
        )
        .with(
            "Z098765432",
            vec![
                set("gov.", "SOA", &[SOA_1536]),
                set("gov.", "NS", &["ns-1536.awsdns-00.co.uk."]),
            ],
        )
}

fn configs(text: &str) -> Vec<Config> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), false).unwrap()
}

async fn load_with(text: &str, fake: &Arc<Fake>) -> Route53 {
    let mut stanzas = Vec::new();
    for config in configs(text) {
        let stanza = Stanza::new(config).unwrap();
        initialize(fake, &stanza.groups).await.unwrap();
        stanzas.push(Arc::new(stanza));
    }
    Route53 { stanzas }
}

async fn load(text: &str, fake: Fake) -> (Route53, Arc<Fake>) {
    let fake = Arc::new(fake);
    (load_with(text, &fake).await, fake)
}

/// Stands in for the rest of the Chain: it answers `example.gov.` and fails everything else, like CoreDNS's test handler.
struct GovNext;

impl Next for GovNext {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        if question.name.to_string() != "example.gov." {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        }
        let mut builder = MessageBuilder::new(cx.response, 1232, cx.query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::A,
                Class::IN,
                300,
                &[2, 4, 6, 8],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

async fn ask(plugin: &Route53, qname: &str, qtype: Type) -> (Outcome, Vec<u8>) {
    let name: Name = qname.parse().unwrap();
    let mut query = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut query, 1232, 1, 0).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let root: Name = ".".parse().unwrap();
    let mut context = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = plugin.serve(&mut context, GovNext).await;
    drop(context);
    (outcome, response)
}

fn lines(records: Records<'_>) -> Vec<String> {
    records
        .map(|record| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                record.name,
                record.ttl,
                record.class,
                record.rtype,
                record.data().unwrap()
            )
        })
        .collect()
}

struct Reply {
    rcode: Rcode,
    authoritative: bool,
    answer: Vec<String>,
    authority: Vec<String>,
}

async fn reply(plugin: &Route53, qname: &str, qtype: Type) -> Reply {
    let (outcome, response) = ask(plugin, qname, qtype).await;
    assert_eq!(outcome, Outcome::Response, "{qname} {qtype}");
    let message = Message::parse(&response).unwrap();
    Reply {
        rcode: message.rcode(),
        authoritative: message.aa(),
        answer: lines(message.answers()),
        authority: lines(message.authorities()),
    }
}

fn soa_line(owner: &str, soa: &str) -> String {
    format!("{owner}\t300\tIN\tSOA\t{soa}")
}

fn ns_line(owner: &str, ns: &str) -> String {
    format!("{owner}\t300\tIN\tNS\t{ns}")
}

const COREDNS_CONFIG: &str = "route53 org.:1357986420 org.:1234567890 gov.:Z098765432 gov.:1234567890 {\n  fallthrough gov.\n  refresh 90\n}";

// CoreDNS v1.15.0 plugin/route53/route53_test.go TestRoute53: the hosted zone "bad." fails its first update.
#[tokio::test]
async fn a_failing_hosted_zone_fails_the_first_load() {
    let fake = Arc::new(Fake::default());
    fake.fail("0987654321", true);
    let stanza = Stanza::new(configs("route53 bad.:0987654321").remove(0)).unwrap();
    let error = initialize(&fake, &stanza.groups).await.unwrap_err();
    assert_eq!(
        error,
        "failed to initialize route53 plugin: errors updating zones: [failed to list resource records for bad.:0987654321 from route53: bad. zone is bad]"
    );
}

// CoreDNS v1.15.0 plugin/route53/route53_test.go TestRoute53: the table of Queries against the fake hosted zones.
#[tokio::test]
async fn coredns_query_table() {
    let (plugin, _) = load(COREDNS_CONFIG, coredns_fake()).await;
    let ns_1536 = ns_line("org.", "ns-1536.awsdns-00.co.uk.");
    let ns_15 = ns_line("org.", "ns-15.awsdns-00.co.uk.");
    let soa_org_1536 = soa_line("org.", SOA_1536);
    // (qname, qtype, answer, authority, rcode)
    type Row<'a> = (&'a str, Type, Vec<&'a str>, Vec<&'a String>, Rcode);
    let table: Vec<Row<'_>> = vec![
        // 0. example.org A found.
        (
            "example.org.",
            Type::A,
            vec!["example.org.\t300\tIN\tA\t1.2.3.4"],
            vec![&ns_1536],
            Rcode::NOERROR,
        ),
        // 1. example.org AAAA found.
        (
            "example.org.",
            Type::AAAA,
            vec!["example.org.\t300\tIN\tAAAA\t2001:db8:85a3::8a2e:370:7334"],
            vec![&ns_1536],
            Rcode::NOERROR,
        ),
        // 2. example.org PTR found.
        (
            "example.org.",
            Type::PTR,
            vec!["example.org.\t300\tIN\tPTR\tptr.example.org."],
            vec![&ns_1536],
            Rcode::NOERROR,
        ),
        // 3. sample.example.org CNAME to example.org: the CNAME and the A record.
        (
            "sample.example.org.",
            Type::A,
            vec![
                "sample.example.org.\t300\tIN\tCNAME\texample.org.",
                "example.org.\t300\tIN\tA\t1.2.3.4",
            ],
            vec![&ns_1536],
            Rcode::NOERROR,
        ),
        // 4. Explicit CNAME query: just the CNAME.
        (
            "sample.example.org.",
            Type::CNAME,
            vec!["sample.example.org.\t300\tIN\tCNAME\texample.org."],
            vec![&ns_1536],
            Rcode::NOERROR,
        ),
        // 5. example.org NS: NODATA with the SOA of the last hosted zone that was tried.
        (
            "example.org.",
            Type::NS,
            vec![],
            vec![&soa_org_1536],
            Rcode::NOERROR,
        ),
        // 12. *.www.example.org is a wildcard CNAME to www.example.org.
        (
            "a.www.example.org.",
            Type::A,
            vec![
                "a.www.example.org.\t300\tIN\tCNAME\twww.example.org.",
                "www.example.org.\t300\tIN\tA\t1.2.3.4",
            ],
            vec![&ns_1536],
            Rcode::NOERROR,
        ),
        // 8. No record found: NXDOMAIN with the SOA of the last hosted zone.
        (
            "bad.org.",
            Type::A,
            vec![],
            vec![&soa_org_1536],
            Rcode::NXDOMAIN,
        ),
        // 10. other-example.org is in the first hosted zone of org.
        (
            "other-example.org.",
            Type::A,
            vec!["other-example.org.\t300\tIN\tA\t3.5.7.9"],
            vec![&ns_15],
            Rcode::NOERROR,
        ),
    ];
    for (qname, qtype, answer, authority, rcode) in table {
        let got = reply(&plugin, qname, qtype).await;
        assert_eq!(got.answer, answer, "{qname} {qtype}");
        assert_eq!(
            got.authority,
            authority.into_iter().cloned().collect::<Vec<_>>(),
            "{qname} {qtype}"
        );
        assert_eq!(got.rcode, rcode, "{qname} {qtype}");
        assert!(got.authoritative, "{qname} {qtype}");
    }

    // 11. split-example.org only has an A record in the first hosted zone: NODATA with its SOA, no second try.
    let got = reply(&plugin, "split-example.org.", Type::AAAA).await;
    assert!(got.answer.is_empty());
    assert_eq!(got.authority, [soa_line("org.", SOA_15)]);
    assert_eq!(got.rcode, Rcode::NOERROR);

    // 6. split-example.gov only has an A record: NODATA. CoreDNS answers with the org. SOA that the fixture
    // inserted into the gov. hosted zone; Pharos serves the gov. SOA, because a Zone's SOA owner is its apex.
    let got = reply(&plugin, "split-example.gov.", Type::AAAA).await;
    assert!(got.answer.is_empty());
    assert_eq!(got.authority, [soa_line("gov.", SOA_1536)]);
    assert_eq!(got.rcode, Rcode::NOERROR);

    // 9. example.gov has no record, and fallthrough gov. hands it to the next Plugin.
    let got = reply(&plugin, "example.gov.", Type::A).await;
    assert_eq!(got.answer, ["example.gov.\t300\tIN\tA\t2.4.6.8"]);
    assert!(got.authority.is_empty());

    // 7. A name outside every ZONE goes to the next Plugin, which fails it.
    let (outcome, _) = ask(&plugin, "badexample.com.", Type::A).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
}

// CoreDNS v1.15.0 plugin/route53/route53_test.go TestRoute53: records outside a hosted zone's ZONE are not served.
#[tokio::test]
async fn records_outside_the_zone_are_dropped() {
    let (plugin, _) = load(COREDNS_CONFIG, coredns_fake()).await;
    // `com.` NS sits in a hosted zone of org. and gov.; and the org. data sits in the gov. zone too.
    let (outcome, _) = ask(&plugin, "com.", Type::NS).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
    let got = reply(&plugin, "example.gov.", Type::A).await;
    assert_eq!(got.answer, ["example.gov.\t300\tIN\tA\t2.4.6.8"]);
}

// CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: `plugin.Zones.Matches` takes the longest ZONE.
#[tokio::test]
async fn the_longest_zone_wins() {
    let fake = Fake::default()
        .with(
            "P",
            vec![
                set("example.org.", "SOA", &[SOA_1536]),
                set("example.org.", "NS", &["ns.example.org."]),
                set("www.example.org.", "A", &["1.1.1.1"]),
                set("a.sub.example.org.", "A", &["1.1.1.2"]),
            ],
        )
        .with(
            "C",
            vec![
                set("sub.example.org.", "SOA", &[SOA_15]),
                set("sub.example.org.", "NS", &["ns.sub.example.org."]),
                set("a.sub.example.org.", "A", &["2.2.2.2"]),
            ],
        );
    let (plugin, _) = load("route53 example.org.:P sub.example.org.:C", fake).await;
    let got = reply(&plugin, "a.sub.example.org.", Type::A).await;
    assert_eq!(got.answer, ["a.sub.example.org.\t300\tIN\tA\t2.2.2.2"]);
    let got = reply(&plugin, "www.example.org.", Type::A).await;
    assert_eq!(got.answer, ["www.example.org.\t300\tIN\tA\t1.1.1.1"]);
    // RFC 4343 §3: names compare without regard to case.
    let got = reply(&plugin, "A.SUB.Example.ORG.", Type::A).await;
    assert_eq!(got.answer.len(), 1);
}

fn base(apex: &str) -> Vec<RecordSet> {
    vec![
        set(apex, "SOA", &[SOA_1536]),
        set(apex, "NS", &["ns.example.org."]),
    ]
}

fn with(mut sets: Vec<RecordSet>, more: Vec<RecordSet>) -> Vec<RecordSet> {
    sets.extend(more);
    sets
}

// CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: `len(Answer) == 0 && result != NoData && Fall.Through(qname)`.
#[tokio::test]
async fn fallthrough_follows_the_coredns_rule() {
    let sets = with(
        base("example.org."),
        vec![
            set("www.example.org.", "A", &["1.1.1.1"]),
            set("a.b.example.org.", "A", &["1.1.1.2"]),
            set("sub.example.org.", "NS", &["ns.other.net."]),
        ],
    );
    let on = "route53 example.org.:Z {\n  fallthrough\n}";
    let off = "route53 example.org.:Z";
    let narrow = "route53 example.org.:Z {\n  fallthrough sub.example.org.\n}";
    let (on, _) = load(on, Fake::default().with("Z", sets.clone())).await;
    let (off, _) = load(off, Fake::default().with("Z", sets.clone())).await;
    let (narrow, _) = load(narrow, Fake::default().with("Z", sets)).await;

    for (plugin, label, falls) in [(&on, "on", true), (&off, "off", false)] {
        // NXDOMAIN falls through.
        let (outcome, response) = ask(plugin, "nope.example.org.", Type::A).await;
        if falls {
            assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL), "{label}");
        } else {
            assert_eq!(outcome, Outcome::Response, "{label}");
            assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NXDOMAIN);
        }
        // An empty non-terminal is a Success without an Answer in CoreDNS, so it falls through too.
        let (outcome, response) = ask(plugin, "b.example.org.", Type::A).await;
        if falls {
            assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL), "{label}");
        } else {
            assert_eq!(outcome, Outcome::Response, "{label}");
            let message = Message::parse(&response).unwrap();
            assert_eq!(message.rcode(), Rcode::NOERROR);
            assert!(message.aa());
            assert_eq!(message.answer_count(), 0);
        }
        // A delegation without an Answer falls through as well.
        let (outcome, response) = ask(plugin, "x.sub.example.org.", Type::A).await;
        if falls {
            assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL), "{label}");
        } else {
            assert_eq!(outcome, Outcome::Response, "{label}");
            let message = Message::parse(&response).unwrap();
            assert!(!message.aa());
            assert_eq!(message.authority_count(), 1);
        }
        // NODATA and a found record never fall through.
        let got = reply(plugin, "www.example.org.", Type::AAAA).await;
        assert!(got.answer.is_empty() && got.rcode == Rcode::NOERROR && got.authoritative);
        let got = reply(plugin, "www.example.org.", Type::A).await;
        assert_eq!(got.answer.len(), 1);
    }

    // Only names under the listed fallthrough zones fall through.
    let got = reply(&narrow, "nope.example.org.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NXDOMAIN);
    let (outcome, _) = ask(&narrow, "x.sub.example.org.", Type::A).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
}

// CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: hosted zones of one ZONE are tried in order; NODATA stops the loop.
#[tokio::test]
async fn hosted_zones_of_one_zone_are_tried_in_order() {
    let first = with(
        base("example.org."),
        vec![
            set("both.example.org.", "A", &["1.1.1.1"]),
            set("nodata.example.org.", "TXT", &["\"one\""]),
            set("empty.nonterminal.example.org.", "A", &["1.1.1.9"]),
        ],
    );
    let second = with(
        base("example.org."),
        vec![
            set("both.example.org.", "A", &["2.2.2.2"]),
            set("nodata.example.org.", "AAAA", &["2001:db8::2"]),
            set("only2.example.org.", "A", &["2.2.2.3"]),
        ],
    );
    let fake = Fake::default().with("one", first).with("two", second);
    let (plugin, _) = load("route53 example.org.:one example.org.:two", fake).await;

    // The first hosted zone with an Answer wins, even if the second also has one.
    let got = reply(&plugin, "both.example.org.", Type::A).await;
    assert_eq!(got.answer, ["both.example.org.\t300\tIN\tA\t1.1.1.1"]);
    // NXDOMAIN in the first hosted zone moves on to the second.
    let got = reply(&plugin, "only2.example.org.", Type::A).await;
    assert_eq!(got.answer, ["only2.example.org.\t300\tIN\tA\t2.2.2.3"]);
    // NODATA in the first hosted zone ends the search, although the second one has an AAAA.
    let got = reply(&plugin, "nodata.example.org.", Type::AAAA).await;
    assert!(got.answer.is_empty());
    assert_eq!(got.rcode, Rcode::NOERROR);
    // An empty non-terminal in the first hosted zone is not NODATA: the second one is tried.
    let got = reply(&plugin, "nonterminal.example.org.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NXDOMAIN);
    // NXDOMAIN everywhere answers with the SOA of the last hosted zone.
    let got = reply(&plugin, "nothing.example.org.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NXDOMAIN);
    assert_eq!(got.authority, [soa_line("example.org.", SOA_1536)]);
}

#[tokio::test]
async fn the_last_hosted_zone_decides_the_negative_answer() {
    let mut second = base("example.org.");
    second[0] = set("example.org.", "SOA", &[SOA_15]);
    let fake = Fake::default()
        .with("one", base("example.org."))
        .with("two", second);
    let (plugin, _) = load("route53 example.org.:one example.org.:two", fake).await;
    let got = reply(&plugin, "nothing.example.org.", Type::A).await;
    assert_eq!(got.authority, [soa_line("example.org.", SOA_15)]);
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: each Directive line is its own handler and passes the Query on.
#[tokio::test]
async fn stanzas_are_chained_in_order() {
    let fake = Fake::default()
        .with(
            "A",
            with(
                base("example.org."),
                vec![set("a.example.org.", "A", &["1.1.1.1"])],
            ),
        )
        .with(
            "B",
            with(
                base("example.org."),
                vec![set("b.example.org.", "A", &["2.2.2.2"])],
            ),
        )
        .with(
            "C",
            with(
                base("example.net."),
                vec![set("c.example.net.", "A", &["3.3.3.3"])],
            ),
        );
    let text = "route53 example.org.:A\nroute53 example.org.:B {\n  fallthrough\n}\nroute53 example.net.:C";
    let (plugin, _) = load(text, fake).await;
    assert_eq!(plugin.stanzas.len(), 3);
    // The first stanza answers NXDOMAIN without fallthrough: the later stanzas never see it.
    assert_eq!(
        reply(&plugin, "b.example.org.", Type::A).await.rcode,
        Rcode::NXDOMAIN
    );
    let got = reply(&plugin, "a.example.org.", Type::A).await;
    assert_eq!(got.answer, ["a.example.org.\t300\tIN\tA\t1.1.1.1"]);
    // A ZONE that does not match passes the Query to the next stanza.
    let got = reply(&plugin, "c.example.net.", Type::A).await;
    assert_eq!(got.answer, ["c.example.net.\t300\tIN\tA\t3.3.3.3"]);
}

#[tokio::test]
async fn a_stanza_that_falls_through_hands_over_to_the_next_stanza() {
    let fake = Fake::default().with("A", base("example.org.")).with(
        "B",
        with(
            base("example.org."),
            vec![set("b.example.org.", "A", &["2.2.2.2"])],
        ),
    );
    let text = "route53 example.org.:A {\n  fallthrough\n}\nroute53 example.org.:B";
    let (plugin, _) = load(text, fake).await;
    let got = reply(&plugin, "b.example.org.", Type::A).await;
    assert_eq!(got.answer, ["b.example.org.\t300\tIN\tA\t2.2.2.2"]);
}

// CoreDNS v1.15.0 plugin/route53/route53.go updateZones: every page is read until IsTruncated is false.
#[tokio::test]
async fn pagination_reads_every_page() {
    let mut sets = base("example.org.");
    for index in 0..10 {
        sets.push(set(
            &format!("h{index}.example.org."),
            "A",
            &[&format!("10.0.0.{index}")],
        ));
    }
    let fake = Fake {
        page_size: 3,
        ..Fake::default()
    }
    .with("Z", sets);
    let (plugin, fake) = load("route53 example.org.:Z", fake).await;
    for index in 0..10 {
        let got = reply(&plugin, &format!("h{index}.example.org."), Type::A).await;
        assert_eq!(got.answer.len(), 1, "h{index}");
    }
    // 12 record sets in pages of 3, each page asking from the previous Next* record.
    let pages = fake.pages.lock().unwrap();
    let starts = pages
        .iter()
        .map(|(_, start)| start.as_ref().map(|start| start.name.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        starts,
        [
            None,
            Some("3".to_owned()),
            Some("6".to_owned()),
            Some("9".to_owned())
        ]
    );
}

// CoreDNS v1.15.0 plugin/route53/route53.go updateZones: a failing hosted zone keeps its snapshot, the others still update.
#[tokio::test]
async fn a_failed_refresh_keeps_the_last_good_data_and_other_zones_update() {
    let fake = Fake::default()
        .with(
            "A",
            with(
                base("a.example."),
                vec![set("www.a.example.", "A", &["1.1.1.1"])],
            ),
        )
        .with(
            "B",
            with(
                base("b.example."),
                vec![set("www.b.example.", "A", &["2.2.2.2"])],
            ),
        );
    let (plugin, fake) = load("route53 a.example.:A b.example.:B", fake).await;
    fake.replace(
        "A",
        with(
            base("a.example."),
            vec![set("www.a.example.", "A", &["1.1.1.9"])],
        ),
    );
    fake.replace(
        "B",
        with(
            base("b.example."),
            vec![set("www.b.example.", "A", &["2.2.2.9"])],
        ),
    );
    fake.fail("A", true);
    let groups = &plugin.stanzas[0].groups;
    let error = update_zones(&fake, groups).await.unwrap_err();
    assert_eq!(
        error,
        "errors updating zones: [failed to list resource records for a.example.:A from route53: bad. zone is bad]"
    );
    let got = reply(&plugin, "www.a.example.", Type::A).await;
    assert_eq!(got.answer, ["www.a.example.\t300\tIN\tA\t1.1.1.1"]);
    let got = reply(&plugin, "www.b.example.", Type::A).await;
    assert_eq!(got.answer, ["www.b.example.\t300\tIN\tA\t2.2.2.9"]);
    fake.fail("A", false);
    update_zones(&fake, groups).await.unwrap();
    let got = reply(&plugin, "www.a.example.", Type::A).await;
    assert_eq!(got.answer, ["www.a.example.\t300\tIN\tA\t1.1.1.9"]);
}

// CoreDNS v1.15.0 plugin/route53/route53.go updateZones: the first failing hosted zone ends that ZONE's update.
#[tokio::test]
async fn a_failing_hosted_zone_stops_later_zones_of_the_same_name() {
    let fake = Fake::default().with("one", base("example.org.")).with(
        "two",
        with(
            base("example.org."),
            vec![set("a.example.org.", "A", &["1.1.1.1"])],
        ),
    );
    let (plugin, fake) = load("route53 example.org.:one example.org.:two", fake).await;
    fake.fail("one", true);
    fake.replace(
        "two",
        with(
            base("example.org."),
            vec![set("a.example.org.", "A", &["1.1.1.9"])],
        ),
    );
    update_zones(&fake, &plugin.stanzas[0].groups)
        .await
        .unwrap_err();
    let got = reply(&plugin, "a.example.org.", Type::A).await;
    assert_eq!(got.answer, ["a.example.org.\t300\tIN\tA\t1.1.1.1"]);
}

// CoreDNS v1.15.0 plugin/route53/route53.go updateZoneFromRRS: an alias record set has no ResourceRecords and is skipped.
#[tokio::test]
async fn alias_record_sets_are_skipped() {
    let sets = with(
        base("example.org."),
        vec![
            set("alias.example.org.", "A", &[]),
            set("www.example.org.", "A", &["1.1.1.1"]),
        ],
    );
    let (plugin, _) = load("route53 example.org.:Z", Fake::default().with("Z", sets)).await;
    let got = reply(&plugin, "alias.example.org.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NXDOMAIN);
    let got = reply(&plugin, "www.example.org.", Type::A).await;
    assert_eq!(got.answer.len(), 1);
}

// A hosted zone with no SOA or apex NS cannot become a Zone: the load fails and the last good Zone keeps serving.
#[tokio::test]
async fn a_hosted_zone_without_soa_fails_to_load() {
    let fake = Fake::default().with("Z", vec![set("www.example.org.", "A", &["1.1.1.1"])]);
    let fake = Arc::new(fake);
    let stanza = Stanza::new(configs("route53 example.org.:Z").remove(0)).unwrap();
    let error = initialize(&fake, &stanza.groups).await.unwrap_err();
    assert!(error.contains("Zone has no SOA"), "{error}");
    fake.replace(
        "Z",
        with(
            base("example.org."),
            vec![set("www.example.org.", "A", &["1.1.1.1"])],
        ),
    );
    initialize(&fake, &stanza.groups).await.unwrap();
    fake.replace("Z", vec![set("www.example.org.", "A", &["1.1.1.1"])]);
    update_zones(&fake, &stanza.groups).await.unwrap_err();
    let plugin = Route53 {
        stanzas: vec![Arc::new(stanza)],
    };
    let got = reply(&plugin, "www.example.org.", Type::A).await;
    assert_eq!(got.answer.len(), 1);
}

// CoreDNS v1.15.0 plugin/route53/lock_repro_test.go: no lock is held during a lookup, and a swap never waits for one.
// A Zone snapshot sits behind an ArcSwap, so a reader keeps its snapshot and a swap is wait-free by construction.
#[tokio::test]
async fn swapping_a_snapshot_does_not_wait_for_readers() {
    let (plugin, fake) = load(
        "route53 example.org.:Z",
        Fake::default().with(
            "Z",
            with(
                base("example.org."),
                vec![set("www.example.org.", "A", &["1.1.1.1"])],
            ),
        ),
    )
    .await;
    let hosted = &plugin.stanzas[0].groups[0].hosted[0];
    let reader = hosted.current.load();
    fake.replace(
        "Z",
        with(
            base("example.org."),
            vec![set("www.example.org.", "A", &["1.1.1.9"])],
        ),
    );
    update_zones(&fake, &plugin.stanzas[0].groups)
        .await
        .unwrap();
    // The reader still sees the old snapshot while new Queries see the new one.
    let old = reader
        .as_ref()
        .unwrap()
        .rrset(
            NameRef::parse(name("www.example.org.").as_wire(), 0).unwrap(),
            Type::A,
        )
        .next()
        .unwrap()
        .rdata
        .clone();
    assert_eq!(old, [1, 1, 1, 1]);
    let got = reply(&plugin, "www.example.org.", Type::A).await;
    assert_eq!(got.answer, ["www.example.org.\t300\tIN\tA\t1.1.1.9"]);
}

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

// CoreDNS v1.15.0 plugin/route53/route53.go New: a non-fully-qualified ZONE is made absolute, as file.NewZone does.
#[tokio::test]
async fn a_zone_without_a_trailing_dot_is_made_absolute() {
    let sets = with(
        base("example.org."),
        vec![set("www.example.org.", "A", &["1.1.1.1"])],
    );
    let (plugin, _) = load("route53 example.org:Z", Fake::default().with("Z", sets)).await;
    let got = reply(&plugin, "www.example.org.", Type::A).await;
    assert_eq!(got.answer.len(), 1);
}

// RFC 1035 §3.2.4: QCLASS CH is not served by an IN Zone, so the Query goes on.
#[tokio::test]
async fn a_query_for_another_class_goes_to_the_next_plugin() {
    let (plugin, _) = load(
        "route53 example.org.:Z",
        Fake::default().with("Z", base("example.org.")),
    )
    .await;
    let name: Name = "example.org.".parse().unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::TXT,
            Class::CH,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut context = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &name,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        plugin.serve(&mut context, GovNext).await,
        Outcome::Unanswered(Rcode::SERVFAIL)
    );
}
