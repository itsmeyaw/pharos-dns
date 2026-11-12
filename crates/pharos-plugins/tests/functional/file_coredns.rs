#![forbid(unsafe_code)]

use pharos_plugins::file::Zone;
use pharos_proto::{
    Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type, zone::ZoneParser,
};
use pharos_server::{Context, Metadata, Next, Outcome, Protocol, Transport};

struct ErrorNext;
impl Next for ErrorNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::SERVFAIL)
    }
}

async fn query(
    zone: &Zone,
    name: &str,
    kind: Type,
    dnssec: bool,
    fallthrough: &[Name],
) -> (Outcome, Vec<u8>) {
    let name: Name = name.parse().unwrap();
    let mut query = Vec::with_capacity(4096);
    let mut builder = MessageBuilder::new(&mut query, 4096, 1, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    if dnssec {
        builder
            .record(
                Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(4096),
                0x8000,
                &[],
            )
            .unwrap();
    }
    let _ = builder.finish();
    let mut response = Vec::with_capacity(4096);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: zone.apex(),
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 4096,
    };
    let outcome = zone.lookup(&mut cx, ErrorNext, fallthrough).await;
    (outcome, response)
}

fn zone(origin: &str, text: &str) -> Result<Zone, String> {
    let origin: Name = origin
        .parse()
        .map_err(|error: pharos_proto::NameError| error.to_string())?;
    let records = ZoneParser::new(text.as_bytes(), origin.clone(), "db.test")
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Zone::from_records(origin, records)
}

// Derived from CoreDNS file_test.go TestParseNoSOA, TestParseSyntaxError,
// TestParseMalformedSOA, and TestParseSOASerialTooLarge.
#[test]
fn coredns_rejects_invalid_zone_input() {
    for input in [
        "$ORIGIN example.org.\nwww 60 IN A 192.168.0.14\n",
        "$ORIGIN example.org.\n@ 60 IN SOA ns.example. admin.example. 1 2 3 4 5\n# invalid comment\n",
        "$ORIGIN example.org.\n@ 60 IN SOA ns.example. admin.example. abc 2 3 4 5\n",
        "$ORIGIN example.org.\n@ 60 IN SOA ns.example. admin.example. 202512200817 2 3 4 5\n",
        "@ 500 IN SOA ns.example. hostmaster.example. 3 3600 600 86400 300\nchild 500 IN SOA ns.example. hostmaster.example. 4 3600 600 86400 300\n",
    ] {
        assert!(zone("example.org.", input).is_err(), "{input}");
    }
}

// Derived from CoreDNS file_test.go TestParseSOAOrigin.
#[test]
fn coredns_soa_owner_origin_cases() {
    for (origin, prefix, owner, valid) in [
        ("example.org.", "", "@", true),
        ("example.org.", "", "example.org.", true),
        ("example.org.", "", "ExAmPlE.OrG.", true),
        ("ExAmPlE.OrG.", "", "example.org.", true),
        ("example.org.", "$ORIGIN org.\n", "example", true),
        ("example.org.", "", r"\101xample.org.", true),
        (r"has\.dot.example.", "", r"has\046dot.example.", true),
        (".", "", "@", true),
        ("test.", "", "test", false),
        ("example.org.", "", "child.example.org.", false),
        ("example.org.", "", "org.", false),
        ("example.org.", "", "example.net.", false),
        ("example.org.", "$ORIGIN example.net.\n", "@", false),
        (".", "", "example.org.", false),
    ] {
        let input = format!(
            "{prefix}{owner} 500 IN SOA ns.example. hostmaster.example. 3 3600 600 86400 300\n"
        );
        assert_eq!(zone(origin, &input).is_ok(), valid, "{origin} {owner}");
    }
}

// Derived from CoreDNS include_test.go TestInclude.
#[test]
fn coredns_include_loads_relative_zone_file() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-include-{}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).unwrap();
    let child = dir.join("included.zone");
    let parent = dir.join("parent.zone");
    std::fs::write(&child, "foo 60 IN A 127.0.0.1\n").unwrap();
    std::fs::write(&parent, "$ORIGIN example.org.\n@ 60 IN SOA sns.dns.icann.org. noc.dns.icann.org. 2017042766 7200 3600 1209600 3600\n$INCLUDE included.zone\n").unwrap();
    let zone = Zone::load("example.org.".parse().unwrap(), &parent).unwrap();
    let owner: Name = "foo.example.org.".parse().unwrap();
    assert_eq!(
        zone.rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::A)
            .next()
            .unwrap()
            .rdata,
        [127, 0, 0, 1]
    );
    std::fs::remove_file(child).unwrap();
    std::fs::remove_file(parent).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

// Derived from CoreDNS escape_test.go TestLookupOwnerNameWithDecimalEscape and TestCanonicalEscape.
#[tokio::test]
async fn coredns_decimal_escape_lookup() {
    let input = "campus.edu. 500 IN SOA ns1.outside.edu. root.campus.edu. 8 6048 4000 2419200 6048\ncampus.edu. 500 IN NS ns1.outside.edu.\nhas\\046dot.campus.edu. 500 IN A 192.0.2.2\n";
    let zone = zone("campus.edu.", input).unwrap();
    let (outcome, response) = query(&zone, r"has\.dot.campus.edu.", Type::A, false, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    let rr = response.answers().next().unwrap();
    assert_eq!(
        rr.name.to_name(),
        r"has\046dot.campus.edu.".parse::<Name>().unwrap()
    );
    assert_eq!(rr.rdata, [192, 0, 2, 2]);
    for (left, right) in [
        (r"has\046dot.campus.edu.", r"has\.dot.campus.edu."),
        (r"a\009b.campus.edu.", r"a\009b.campus.edu."),
        ("plain.campus.edu.", "plain.campus.edu."),
    ] {
        assert_eq!(
            left.parse::<Name>().unwrap(),
            right.parse::<Name>().unwrap()
        );
    }
}

// Derived from CoreDNS zone_test.go TestInsertPreservesSRVCase.
#[test]
fn coredns_srv_owner_and_target_keep_case() {
    let input = "@ 60 IN SOA ns.home.arpa. hostmaster.home.arpa. 1 2 3 4 5\nHome\\032Media._smb._tcp.home.arpa. 5 IN SRV 0 0 445 samba.home.arpa.\n";
    let zone = zone("home.arpa.", input).unwrap();
    let owner: Name = r"home\032media._smb._tcp.home.arpa.".parse().unwrap();
    let record = zone
        .rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::SRV)
        .next()
        .unwrap();
    assert_eq!(
        NameRef::parse(record.owner.as_wire(), 0)
            .unwrap()
            .labels()
            .next()
            .unwrap(),
        b"Home Media"
    );
    assert_eq!(
        NameRef::parse(&record.rdata, 6).unwrap().to_string(),
        "samba.home.arpa."
    );
}
