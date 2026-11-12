#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, file::Zone};
use pharos_proto::{
    Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type, zone::ZoneParser,
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

async fn query_chain(chain: &Chain, domain: &Name, name: &str, kind: Type) -> (Outcome, Vec<u8>) {
    let name: Name = name.parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = chain.serve(&mut cx).await;
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

fn assert_records<'a>(records: impl Iterator<Item = pharos_proto::Record<'a>>, expected: &[&str]) {
    let mut actual = records
        .map(|rr| {
            (
                rr.name.to_name().canonical(),
                rr.rtype.0,
                rr.class.0,
                rr.ttl,
                rr.rdata.to_vec(),
            )
        })
        .collect::<Vec<_>>();
    let mut expected = expected
        .iter()
        .map(|text| {
            let mut parser = ZoneParser::new(text.as_bytes(), ".".parse().unwrap(), "expected");
            let rr = parser.next().unwrap().unwrap();
            (
                rr.owner.canonical(),
                rr.rtype.0,
                rr.class.0,
                rr.ttl,
                rr.rdata,
            )
        })
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
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

// Derived from CoreDNS setup_test.go TestFileParse and TestFileParseRelativeZones.
#[tokio::test]
async fn coredns_setup_accepts_origins_and_rejects_bad_directives() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-setup-{}.zone",
        std::process::id()
    ));
    std::fs::write(&path, "@ 500 IN SOA ns.example. hostmaster.example. 3 3600 600 86400 300\n@ 500 IN NS ns.example.\nfoo 500 IN A 192.0.2.1\n").unwrap();
    for (args, option, name) in [
        ("example.org.", "", "foo.example.org."),
        ("10.0.0.0/8", "", "foo.10.in-addr.arpa."),
        ("example.org.", "fallthrough", "foo.example.org."),
        (
            "example.org.",
            "fallthrough www.example.org",
            "foo.example.org.",
        ),
        ("example.org example.net", "", "foo.example.net."),
    ] {
        let block = if option.is_empty() {
            String::new()
        } else {
            format!(" {{\n {option}\n }}")
        };
        let text = format!(".:53 {{\n file {} {args}{block}\n}}", path.display());
        let configured =
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let (outcome, wire) =
            query_chain(&configured[0].config, &".".parse().unwrap(), name, Type::A).await;
        assert_eq!(outcome, Outcome::Response, "{text}");
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            [192, 0, 2, 1]
        );
    }
    for directive in [
        "file".to_string(),
        format!(
            "file {} example.org {{\n transfer from 127.0.0.1\n }}",
            path.display()
        ),
        format!("file {} example.net {{\n no_reload\n }}", path.display()),
        format!("file {} example.net {{\n no_rebloat\n }}", path.display()),
    ] {
        let text = format!(".:53 {{\n {directive}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert!(configure::<Chain>(&blocks, directives()).is_err(), "{text}");
    }
    for (fixture, origin, name) in [
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/file/coredns-miek.zone"
            ),
            "miek.nl.",
            "a.miek.nl.",
        ),
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/file/dnssex-signed.zone"
            ),
            "dnssex.nl.",
            "a.dnssex.nl.",
        ),
    ] {
        let text = format!(".:53 {{\n file {fixture} {origin}\n}}");
        let configured =
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let (outcome, wire) =
            query_chain(&configured[0].config, &".".parse().unwrap(), name, Type::A).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(Message::parse(&wire).unwrap().answer_count(), 1);
    }
    std::fs::remove_file(path).unwrap();
}

// Derived from CoreDNS setup_test.go TestFileParseSOAOrigin.
#[tokio::test]
async fn coredns_setup_soa_owner_with_implicit_and_explicit_origin() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-origin-{}.zone",
        std::process::id()
    ));
    for owner in ["test", "@", "test."] {
        let contents = format!(
            "{owner} 500 IN SOA ns1.outside.com. root.test 3 604800 86400 2419200 604800\n{owner} 500 IN NS ns1.outside.com.\nfoo 500 IN A 1.1.1.1\n"
        );
        std::fs::write(&path, contents).unwrap();
        for explicit in [false, true] {
            let text = format!(
                "test:53 {{\n file {} {}\n}}",
                path.display(),
                if explicit { "test" } else { "" }
            );
            let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives());
            if owner == "test" {
                assert!(configured.is_err());
                continue;
            }
            let configured = configured.unwrap();
            for (name, expected) in [
                ("foo.test.", Rcode::NOERROR),
                ("bar.test.", Rcode::NXDOMAIN),
            ] {
                let (outcome, wire) = query_chain(
                    &configured[0].config,
                    &"test.".parse().unwrap(),
                    name,
                    Type::A,
                )
                .await;
                assert_eq!(outcome, Outcome::Response);
                let response = Message::parse(&wire).unwrap();
                assert_eq!(response.rcode(), expected);
                if expected == Rcode::NOERROR {
                    assert_records(response.answers(), &["foo.test. 500 IN A 1.1.1.1"]);
                    assert_records(
                        response.authorities(),
                        &["test. 500 IN NS ns1.outside.com."],
                    );
                } else {
                    assert_records(
                        response.authorities(),
                        &[
                            "test. 500 IN SOA ns1.outside.com. root.test.test. 3 604800 86400 2419200 604800",
                        ],
                    );
                }
            }
        }
    }
    std::fs::remove_file(path).unwrap();
}

// CoreDNS file README: the root Server Block without an explicit Zone rejects this SOA.
#[test]
fn coredns_readme_root_without_zone_is_invalid() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let config = format!(".:53 {{\n file {path}\n}}");
    assert!(configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).is_err());
}

// Derived from CoreDNS setup_test.go TestParseReload and reload_test.go TestZoneReload.
#[tokio::test(start_paused = true)]
async fn coredns_default_and_configured_reload_intervals() {
    use std::time::{Duration, Instant};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-interval-{}.zone",
        std::process::id()
    ));
    let original = "@ 500 IN SOA ns.example. hostmaster.example. 3 3600 600 86400 300\n@ 500 IN NS ns.example.\nfoo 500 IN A 192.0.2.1\n";
    for (option, interval) in [("", 60), (" {\n reload 5s\n }", 5)] {
        std::fs::write(&path, original).unwrap();
        let text = format!("example.org:53 {{\n file {}{option}\n}}", path.display());
        let configured =
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let chain = &configured[0].config;
        chain
            .lifecycle
            .run(pharos_server::Phase::Startup)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        std::fs::write(
            &path,
            original
                .replace(" 3 3600", " 4 3600")
                .replace("192.0.2.1", "192.0.2.2"),
        )
        .unwrap();
        tokio::time::advance(Duration::from_secs(interval - 1)).await;
        let (_, wire) = query_chain(
            chain,
            &"example.org.".parse().unwrap(),
            "foo.example.org.",
            Type::A,
        )
        .await;
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            [192, 0, 2, 1]
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (_, wire) = query_chain(
                chain,
                &"example.org.".parse().unwrap(),
                "foo.example.org.",
                Type::A,
            )
            .await;
            if Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata
                == [192, 0, 2, 2]
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "reload did not run after {interval}s"
            );
            tokio::task::yield_now().await;
        }
        chain
            .lifecycle
            .run(pharos_server::Phase::Shutdown)
            .await
            .unwrap();
    }
    std::fs::remove_file(path).unwrap();
}

async fn wait_for_address(chain: &Chain, domain: &Name, name: &str, expected: [u8; 4]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let (outcome, wire) = query_chain(chain, domain, name, Type::A).await;
        if outcome == Outcome::Response
            && Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .is_some_and(|record| record.rdata == expected)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Zone did not serve {expected:?}"
        );
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
    }
}

// Derived from CoreDNS reload_test.go TestZoneReloadByMtime and TestZoneReloadSOAOrigin.
#[tokio::test(start_paused = true)]
async fn coredns_mtime_reload_keeps_last_valid_zone_and_recovers() {
    use std::time::{Duration, SystemTime};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-mtime-{}.zone",
        std::process::id()
    ));
    let original = "@ 500 IN SOA ns.example. hostmaster.example. 3 3600 600 86400 300\n@ 500 IN NS ns.example.\nfoo 500 IN A 192.0.2.1\n";
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let set_time = |time| {
        std::fs::File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(time))
            .unwrap()
    };
    std::fs::write(&path, original).unwrap();
    set_time(old);
    let config = format!(
        "example.org:53 {{\n file {} {{\n reload 5s\n reload_by_mtime\n }}\n}}",
        path.display()
    );
    let configured =
        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
    let chain = &configured[0].config;
    let apex: Name = "example.org.".parse().unwrap();
    chain
        .lifecycle
        .run(pharos_server::Phase::Startup)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    std::fs::write(&path, original.replace("192.0.2.1", "192.0.2.2")).unwrap();
    set_time(old);
    tokio::time::advance(Duration::from_secs(5)).await;
    let (_, wire) = query_chain(chain, &apex, "foo.example.org.", Type::A).await;
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
    set_time(old + Duration::from_secs(10));
    tokio::time::advance(Duration::from_secs(5)).await;
    wait_for_address(chain, &apex, "foo.example.org.", [192, 0, 2, 2]).await;
    std::fs::remove_file(&path).unwrap();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    let (_, wire) = query_chain(chain, &apex, "foo.example.org.", Type::A).await;
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
    std::fs::write(
        &path,
        original
            .replace("@ 500 IN SOA", "child 500 IN SOA")
            .replace(" 3 3600", " 4 3600"),
    )
    .unwrap();
    set_time(old + Duration::from_secs(20));
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    let (_, wire) = query_chain(chain, &apex, "foo.example.org.", Type::A).await;
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
    std::fs::write(
        &path,
        original
            .replace(" 3 3600", " 4 3600")
            .replace("192.0.2.1", "192.0.2.3"),
    )
    .unwrap();
    set_time(old + Duration::from_secs(30));
    tokio::time::advance(Duration::from_secs(5)).await;
    wait_for_address(chain, &apex, "foo.example.org.", [192, 0, 2, 3]).await;
    chain
        .lifecycle
        .run(pharos_server::Phase::Shutdown)
        .await
        .unwrap();
    std::fs::remove_file(path).unwrap();
}

// Derived from CoreDNS reload_test.go TestZoneReload, TestZoneReloadSOAChange, and TestZoneReloadByMtime.
#[tokio::test(start_paused = true)]
async fn coredns_reload_updates_apex_records() {
    use std::time::{Duration, Instant, SystemTime};
    let first = "miek.nl. 1627 IN SOA linode.atoom.net. miek.miek.nl. 1460175181 14400 3600 604800 14400\nmiek.nl. 1627 IN NS ext.ns.whyscream.net.\nmiek.nl. 1627 IN NS omval.tednet.nl.\nmiek.nl. 1627 IN NS linode.atoom.net.\nmiek.nl. 1627 IN NS ns-ext.nlnetlabs.nl.\n";
    let second = "miek.nl. 1627 IN SOA linode.atoom.net. miek.miek.nl. 1460175182 14400 3600 604800 14400\nmiek.nl. 1627 IN NS ext.ns.whyscream.net.\nmiek.nl. 1627 IN NS omval.tednet.nl.\n";
    let apex: Name = "miek.nl.".parse().unwrap();
    for mtime in [false, true] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../target/file-p75-apex-{mtime}-{}.zone",
            std::process::id()
        ));
        let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        std::fs::write(&path, first).unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        let config = format!(
            "miek.nl:53 {{\n file {} {{\n reload 1s\n {}\n }}\n}}",
            path.display(),
            if mtime { "reload_by_mtime" } else { "" }
        );
        let configured =
            configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
        let chain = &configured[0].config;
        chain
            .lifecycle
            .run(pharos_server::Phase::Startup)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        let (outcome, wire) = query_chain(chain, &apex, "miek.nl.", Type::NS).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(Message::parse(&wire).unwrap().answer_count(), 4);
        let same_serial = second.replace("1460175182", "1460175181");
        std::fs::write(&path, &same_serial).unwrap();
        std::fs::File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time + Duration::from_secs(10)))
            .unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        if !mtime {
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            let (_, wire) = query_chain(chain, &apex, "miek.nl.", Type::NS).await;
            assert_eq!(Message::parse(&wire).unwrap().answer_count(), 4);
            std::fs::write(&path, second).unwrap();
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (outcome, wire) = query_chain(chain, &apex, "miek.nl.", Type::NS).await;
            assert_eq!(outcome, Outcome::Response);
            if Message::parse(&wire).unwrap().answer_count() == 2 {
                break;
            }
            assert!(Instant::now() < deadline, "apex records were not reloaded");
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(100)).await;
        }
        chain
            .lifecycle
            .run(pharos_server::Phase::Shutdown)
            .await
            .unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

// Derived from CoreDNS setup_test.go TestFileParseReloadByMtimeMissingFileLeavesBaselineUnset
// and TestFileParseReloadByMtimeRecoversLaterZoneAfterMissingFile.
#[tokio::test(start_paused = true)]
async fn coredns_missing_zone_and_later_zone_recover_by_mtime() {
    use std::time::Duration;
    let missing = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-missing-{}.zone",
        std::process::id()
    ));
    assert!(!missing.exists());
    let existing = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/external.zone"
    );
    let config = format!(
        ".:53 {{\n file {} example.org {{\n reload 5s\n reload_by_mtime\n }}\n file {existing} external.test {{\n reload 5s\n reload_by_mtime\n }}\n}}",
        missing.display()
    );
    let configured =
        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
    let chain = &configured[0].config;
    let apex: Name = ".".parse().unwrap();
    assert_eq!(
        query_chain(chain, &apex, "leaf.external.test.", Type::A)
            .await
            .0,
        Outcome::Unanswered(Rcode::SERVFAIL)
    );
    chain
        .lifecycle
        .run(pharos_server::Phase::Startup)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    wait_for_address(chain, &apex, "leaf.external.test.", [192, 0, 2, 88]).await;
    std::fs::write(
        &missing,
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\nfoo 60 IN A 192.0.2.10\n",
    )
    .unwrap();
    tokio::time::advance(Duration::from_secs(5)).await;
    wait_for_address(chain, &apex, "foo.example.org.", [192, 0, 2, 10]).await;
    chain
        .lifecycle
        .run(pharos_server::Phase::Shutdown)
        .await
        .unwrap();
    std::fs::remove_file(missing).unwrap();
}

// Derived from CoreDNS ent_test.go TestLookupEnt and closest_test.go TestClosestEncloser.
#[tokio::test]
async fn coredns_empty_nonterminal_and_closest_encloser_proofs() {
    let zone = zone(
        "miek.nl.",
        include_str!("../fixtures/file/coredns-ent.zone"),
    )
    .unwrap();
    for dnssec in [false, true] {
        let (outcome, response) = query(&zone, "b.c.miek.nl.", Type::A, dnssec, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert_eq!(response.answer_count(), 0);
        let authority = response.authorities().collect::<Vec<_>>();
        assert_eq!(authority.len(), if dnssec { 4 } else { 1 });
        assert!(authority.iter().any(|rr| matches!(
            rr.data(),
            Ok(Rdata::Soa {
                serial: 1282630057,
                ..
            })
        )));
        if dnssec {
            assert!(
                authority
                    .iter()
                    .any(|rr| rr.rtype == Type::NSEC && rr.name.to_string() == "a.miek.nl.")
            );
            assert!(authority.iter().any(|rr| matches!(
                rr.data(),
                Ok(Rdata::Rrsig {
                    type_covered: Type::NSEC,
                    ..
                })
            )));
            assert!(authority.iter().any(|rr| matches!(
                rr.data(),
                Ok(Rdata::Rrsig {
                    type_covered: Type::SOA,
                    ..
                })
            )));
        }
    }
    for (name, expected_nsec) in [
        ("blaat.a.miek.nl.", vec!["a.miek.nl."]),
        ("blaat.z.a.miek.nl.", vec!["a.miek.nl."]),
        ("blaat.miek.nl.", vec!["a.miek.nl.", "miek.nl."]),
    ] {
        let (outcome, response) = query(&zone, name, Type::A, true, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
        assert_eq!(
            response
                .authorities()
                .filter(|rr| rr.rtype == Type::NSEC)
                .map(|rr| rr.name.to_string())
                .collect::<Vec<_>>(),
            expected_nsec,
            "{name}"
        );
    }
}

// Adapted from CoreDNS closest_test.go TestClosestEncloser through signed wire proofs.
#[tokio::test]
async fn coredns_closest_encloser_cases_through_signed_denial() {
    let zone = zone(
        "miek.nl.",
        include_str!("../fixtures/file/coredns-miek-signed.zone"),
    )
    .unwrap();
    for (name, kind) in [("miek.nl.", Type::A), ("www.miek.nl.", Type::CNAME)] {
        let (outcome, wire) = query(&zone, name, kind, true, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .name
                .to_string(),
            name
        );
    }
    for (name, encloser) in [
        ("blaat.miek.nl.", "miek.nl."),
        ("blaat.www.miek.nl.", "www.miek.nl."),
        ("www.blaat.miek.nl.", "miek.nl."),
        ("blaat.a.miek.nl.", "a.miek.nl."),
        ("blaat.z.a.miek.nl.", "a.miek.nl."),
    ] {
        let (outcome, wire) = query(&zone, name, Type::A, true, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
        assert!(
            response
                .authorities()
                .any(|rr| rr.rtype == Type::NSEC && rr.name.to_string() == encloser),
            "{name} {encloser}"
        );
    }
}

// Derived from CoreDNS apex_test.go TestLookupApex.
#[tokio::test]
async fn coredns_apex_only_zone_returns_nxdomain_for_missing_type() {
    let input = "$ORIGIN example.com.\n@ 60 IN SOA ns1.example.com. admin.example.com. 2005011437 1200 144 1814400 7200\n@ 60 IN NS ns1.example.com.\n";
    let zone = zone("example.com.", input).unwrap();
    let (outcome, wire) = query(&zone, "example.com.", Type::A, false, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&wire).unwrap().rcode(), Rcode::NXDOMAIN);
}

// Derived from CoreDNS delegation_test.go TestLookupDelegation and ds_test.go TestLookupDS.
#[tokio::test]
async fn coredns_unsigned_delegation_and_ds_queries() {
    let zone = zone(
        "miek.nl.",
        include_str!("../fixtures/file/coredns-delegation.zone"),
    )
    .unwrap();
    for (name, kind) in [
        ("a.delegated.miek.nl.", Type::TXT),
        ("delegated.miek.nl.", Type::NS),
        ("foo.delegated.miek.nl.", Type::A),
        ("foo.delegated.miek.nl.", Type::TXT),
        ("foo.delegated.miek.nl.", Type::SOA),
        ("a.delegated.miek.nl.", Type::DS),
        ("_udp.delegated.miek.nl.", Type::DS),
    ] {
        let (outcome, wire) = query(&zone, name, kind, false, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert!(!response.aa());
        assert_eq!(response.answer_count(), 0);
        assert_eq!(
            response
                .authorities()
                .filter(|rr| rr.rtype == Type::NS && rr.name.to_string() == "delegated.miek.nl.")
                .count(),
            2
        );
        assert_eq!(
            response
                .additionals()
                .filter(|rr| rr.rtype == Type::A || rr.rtype == Type::AAAA)
                .count(),
            2
        );
    }
    for (name, expected) in [
        ("_udp.miek.nl.", Rcode::NXDOMAIN),
        ("miek.nl.", Rcode::NOERROR),
    ] {
        let (outcome, wire) = query(&zone, name, Type::DS, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), expected);
        assert_eq!(response.authorities().next().unwrap().rtype, Type::SOA);
    }
}

// Derived from CoreDNS delegation_test.go TestLookupSecureDelegation.
#[tokio::test]
async fn coredns_secure_delegation_and_ds_at_cut() {
    let zone = zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-signed-delegation.zone"),
    )
    .unwrap();
    for (name, kind) in [
        ("a.delegated.example.org.", Type::TXT),
        ("delegated.example.org.", Type::NS),
        ("foo.delegated.example.org.", Type::A),
        ("foo.delegated.example.org.", Type::DS),
    ] {
        let (outcome, wire) = query(&zone, name, kind, true, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert!(!response.aa());
        let authority = response.authorities().collect::<Vec<_>>();
        assert_eq!(
            authority.iter().filter(|rr| rr.rtype == Type::NS).count(),
            2
        );
        assert_eq!(
            authority.iter().filter(|rr| rr.rtype == Type::DS).count(),
            2
        );
        assert!(authority.iter().any(|rr| matches!(
            rr.data(),
            Ok(Rdata::Rrsig {
                type_covered: Type::DS,
                key_tag: 49035,
                ..
            })
        )));
        assert_eq!(
            response
                .additionals()
                .filter(|rr| rr.rtype == Type::A || rr.rtype == Type::AAAA)
                .count(),
            2
        );
    }
    let (outcome, wire) = query(&zone, "delegated.example.org.", Type::DS, true, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert!(response.aa());
    assert_eq!(
        response.answers().filter(|rr| rr.rtype == Type::DS).count(),
        2
    );
    assert!(response.answers().any(|rr| matches!(
        rr.data(),
        Ok(Rdata::Rrsig {
            type_covered: Type::DS,
            key_tag: 49035,
            ..
        })
    )));
    assert_eq!(
        response
            .authorities()
            .filter(|rr| rr.rtype == Type::NS)
            .count(),
        2
    );
}

// Derived from CoreDNS wildcard_test.go TestLookupApexWildcard and TestLookupMultiWildcard.
#[tokio::test]
async fn coredns_apex_and_nested_wildcards() {
    for (fixture, cases) in [
        (
            include_str!("../fixtures/file/coredns-apex-wildcard.zone"),
            vec![
                ("foo.example.org.", [127, 0, 0, 54]),
                ("bar.example.org.", [127, 0, 0, 53]),
            ],
        ),
        (
            include_str!("../fixtures/file/coredns-multi-wildcard.zone"),
            vec![
                ("foo.example.org.", [127, 0, 0, 54]),
                ("bar.example.org.", [127, 0, 0, 53]),
                ("bar.intern.example.org.", [127, 0, 1, 52]),
            ],
        ),
    ] {
        let zone = zone("example.org.", fixture).unwrap();
        for (name, expected) in cases {
            let (outcome, wire) = query(&zone, name, Type::A, false, &[]).await;
            assert_eq!(outcome, Outcome::Response);
            let response = Message::parse(&wire).unwrap();
            let rr = response.answers().next().unwrap();
            assert_eq!(rr.name.to_string(), name);
            assert_eq!(rr.rdata, expected);
            assert_eq!(response.authorities().next().unwrap().rtype, Type::NS);
        }
    }
}

// Derived from CoreDNS svcb_test.go TestSVCBTargetNormalization.
#[tokio::test]
async fn coredns_svcb_target_is_normalized_and_has_glue() {
    let input = "$TTL 30M\n$ORIGIN example.com.\n@ IN SOA ns.example.com. admin.example.com. 2024010100 14400 3600 604800 14400\n@ IN NS ns.example.com.\nns IN A 192.0.2.1\nsvc IN A 192.0.2.10\n_foo IN SVCB 1 SVC.Example.COM. alpn=h2\n";
    let zone = zone("example.com.", input).unwrap();
    let (outcome, wire) = query(&zone, "_foo.example.com.", Type::SVCB, false, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert!(
        matches!(response.answers().next().unwrap().data(), Ok(Rdata::Svcb { target, .. }) if target.to_string() == "svc.example.com.")
    );
    let glue = response.additionals().next().unwrap();
    assert_eq!(glue.name.to_string(), "svc.example.com.");
    assert_eq!(glue.rdata, [192, 0, 2, 10]);
}

// Derived from CoreDNS lookup_test.go TestLookUpNoDataResult and TestLookupFallthrough.
#[tokio::test]
async fn coredns_nodata_and_scoped_fallthrough() {
    let zone = zone(
        "miek.nl.",
        include_str!("../fixtures/file/coredns-miek.zone"),
    )
    .unwrap();
    for name in ["a.miek.nl.", "wildcard.nodata.miek.nl."] {
        let (outcome, wire) = query(&zone, name, Type::MX, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert_eq!(response.answer_count(), 0);
        assert_eq!(response.authorities().next().unwrap().rtype, Type::SOA);
    }
    for (fall, name, expected) in [
        (
            ".",
            "doesnotexist.miek.nl.",
            Outcome::Unanswered(Rcode::SERVFAIL),
        ),
        (".", "x.miek.nl.", Outcome::Unanswered(Rcode::SERVFAIL)),
        ("a.miek.nl.", "a.miek.nl.", Outcome::Response),
        ("a.miek.nl.", "doesnotexist.miek.nl.", Outcome::Response),
        (
            "a.miek.nl.",
            "passthrough.a.miek.nl.",
            Outcome::Unanswered(Rcode::SERVFAIL),
        ),
        (
            "x.miek.nl.",
            "x.miek.nl.",
            Outcome::Unanswered(Rcode::SERVFAIL),
        ),
        ("x.miek.nl.", "wildcard.x.miek.nl.", Outcome::Response),
    ] {
        let (outcome, wire) = query(&zone, name, Type::A, false, &[fall.parse().unwrap()]).await;
        assert_eq!(outcome, expected, "{fall} {name}");
        if name == "doesnotexist.miek.nl." && fall == "a.miek.nl." {
            assert_eq!(Message::parse(&wire).unwrap().rcode(), Rcode::NXDOMAIN);
        }
    }
}

// Derived from CoreDNS lookup_test.go TestLookupNil.
#[tokio::test]
async fn coredns_missing_zone_is_servfail() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-nil-{}.zone",
        std::process::id()
    ));
    assert!(!path.exists());
    let config = format!("miek.nl:53 {{\n file {}\n}}", path.display());
    let configured =
        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
    assert_eq!(
        query_chain(
            &configured[0].config,
            &"miek.nl.".parse().unwrap(),
            "www.miek.nl.",
            Type::A
        )
        .await
        .0,
        Outcome::Unanswered(Rcode::SERVFAIL)
    );
}

// Derived from CoreDNS lookup_test.go TestLookup.
#[tokio::test]
async fn coredns_lookup_records_and_negative_responses() {
    let zone = zone(
        "miek.nl.",
        include_str!("../fixtures/file/coredns-miek.zone"),
    )
    .unwrap();
    let ns = [
        "miek.nl. 1800 IN NS ext.ns.whyscream.net.",
        "miek.nl. 1800 IN NS linode.atoom.net.",
        "miek.nl. 1800 IN NS ns-ext.nlnetlabs.nl.",
        "miek.nl. 1800 IN NS omval.tednet.nl.",
    ];
    let soa =
        ["miek.nl. 1800 IN SOA linode.atoom.net. miek.miek.nl. 1282630057 14400 3600 604800 14400"];
    let cases: &[(&str, Type, Rcode, &[&str], &[&str], &[&str])] = &[
        (
            "www.miek.nl.",
            Type::A,
            Rcode::NOERROR,
            &[
                "www.miek.nl. 1800 IN CNAME a.miek.nl.",
                "a.miek.nl. 1800 IN A 139.162.196.78",
            ],
            &ns,
            &[],
        ),
        (
            "www.miek.nl.",
            Type::AAAA,
            Rcode::NOERROR,
            &[
                "www.miek.nl. 1800 IN CNAME a.miek.nl.",
                "a.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735",
            ],
            &ns,
            &[],
        ),
        ("miek.nl.", Type::SOA, Rcode::NOERROR, &soa, &ns, &[]),
        (
            "miek.nl.",
            Type::AAAA,
            Rcode::NOERROR,
            &["miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"],
            &ns,
            &[],
        ),
        (
            "mIeK.NL.",
            Type::AAAA,
            Rcode::NOERROR,
            &["miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735"],
            &ns,
            &[],
        ),
        (
            "miek.nl.",
            Type::MX,
            Rcode::NOERROR,
            &[
                "miek.nl. 1800 IN MX 1 aspmx.l.google.com.",
                "miek.nl. 1800 IN MX 5 alt1.aspmx.l.google.com.",
                "miek.nl. 1800 IN MX 5 alt2.aspmx.l.google.com.",
                "miek.nl. 1800 IN MX 10 aspmx2.googlemail.com.",
                "miek.nl. 1800 IN MX 10 aspmx3.googlemail.com.",
            ],
            &ns,
            &[],
        ),
        ("a.miek.nl.", Type::SRV, Rcode::NOERROR, &[], &soa, &[]),
        ("b.miek.nl.", Type::A, Rcode::NXDOMAIN, &[], &soa, &[]),
        (
            "srv.miek.nl.",
            Type::SRV,
            Rcode::NOERROR,
            &["srv.miek.nl. 1800 IN SRV 10 10 8080 a.miek.nl."],
            &ns,
            &[
                "a.miek.nl. 1800 IN A 139.162.196.78",
                "a.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735",
            ],
        ),
        (
            "mx.miek.nl.",
            Type::MX,
            Rcode::NOERROR,
            &["mx.miek.nl. 1800 IN MX 10 a.miek.nl."],
            &ns,
            &[
                "a.miek.nl. 1800 IN A 139.162.196.78",
                "a.miek.nl. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735",
            ],
        ),
        (
            "asterisk.x.miek.nl.",
            Type::CNAME,
            Rcode::NOERROR,
            &["asterisk.x.miek.nl. 1800 IN CNAME www.miek.nl."],
            &ns,
            &[],
        ),
        (
            "a.b.x.miek.nl.",
            Type::CNAME,
            Rcode::NXDOMAIN,
            &[],
            &soa,
            &[],
        ),
        (
            "asterisk.y.miek.nl.",
            Type::A,
            Rcode::NOERROR,
            &["asterisk.y.miek.nl. 1800 IN A 139.162.196.78"],
            &ns,
            &[],
        ),
        (
            "foo.dname.miek.nl.",
            Type::CNAME,
            Rcode::NOERROR,
            &[
                "dname.miek.nl. 1800 IN DNAME x.miek.nl.",
                "foo.dname.miek.nl. 1800 IN CNAME foo.x.miek.nl.",
            ],
            &ns,
            &[],
        ),
        (
            "ext-cname.miek.nl.",
            Type::A,
            Rcode::SERVFAIL,
            &["ext-cname.miek.nl. 1800 IN CNAME example.com."],
            &ns,
            &[],
        ),
        (
            "txt.miek.nl.",
            Type::TXT,
            Rcode::NOERROR,
            &["txt.miek.nl. 1800 IN TXT \"v=spf1 a mx ~all\""],
            &ns,
            &[],
        ),
        (
            "caa.miek.nl.",
            Type::CAA,
            Rcode::NOERROR,
            &["caa.miek.nl. 1800 IN CAA 0 issue letsencrypt.org"],
            &ns,
            &[],
        ),
    ];
    for (name, kind, rcode, answer, authority, additional) in cases {
        let (outcome, wire) = query(&zone, name, *kind, false, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), *rcode, "{name}");
        assert_records(response.answers(), answer);
        assert_records(response.authorities(), authority);
        assert_records(response.additionals(), additional);
    }
}

// Derived from CoreDNS lookup_test.go TestLookupRefusedUpstream.
#[test]
fn coredns_refused_target_keeps_alias_and_noerror() {
    // Debug Plugin Chain futures exceed 2 MiB; see #90.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    use pharos_server::{Action, Handler};
                    let path = concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/fixtures/file/coredns-outside.zone"
                    );
                    let config = format!(".:0 {{\n file {path} example.org\n}}");
                    let (mut servers, _) = pharos_plugins::servers(
                        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
                            .unwrap(),
                    )
                    .unwrap();
                    let (_, server) = servers.drain().next().unwrap();
                    let name: Name = "www.example.org.".parse().unwrap();
                    let mut wire = Vec::with_capacity(512);
                    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
                    builder
                        .question(
                            NameRef::parse(name.as_wire(), 0).unwrap(),
                            Type::A,
                            Class::IN,
                        )
                        .unwrap();
                    let _ = builder.finish();
                    let mut response = Vec::with_capacity(65535);
                    assert_eq!(
                        server
                            .handle(
                                &wire,
                                "127.0.0.1:1234".parse().unwrap(),
                                Protocol::Udp,
                                &mut response
                            )
                            .await,
                        Action::Respond
                    );
                    let response = Message::parse(&response).unwrap();
                    assert_eq!(response.rcode(), Rcode::NOERROR);
                    assert_records(
                        response.answers(),
                        &["www.example.org. 3600 IN CNAME www.example.net."],
                    );
                    assert_records(
                        response.authorities(),
                        &["example.org. 3600 IN NS a.iana-servers.net."],
                    );
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

// Derived from CoreDNS xfr_test.go TestAXFRWithOutTransferPlugin and TestTransferRequiresExactZone.
#[tokio::test]
async fn coredns_axfr_requires_transfer_and_exact_apex() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/coredns-miek.zone"
    );
    let text = format!("miek.nl:53 {{\n file {path}\n}}");
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let (outcome, _) = query_chain(&configured[0].config, &apex, "miek.nl.", Type::AXFR).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::REFUSED));
    #[cfg(feature = "plugin-transfer")]
    {
        use pharos_plugins::transfer::{TransferRequest, Transferer};
        let child: Name = "www.miek.nl.".parse().unwrap();
        let outcome = configured[0]
            .config
            .file
            .as_ref()
            .unwrap()
            .transfer(TransferRequest {
                zone: NameRef::parse(child.as_wire(), 0).unwrap(),
                serial: 0,
                id: 1,
                flags: 0,
                protocol: Protocol::Tcp,
                qtype: Type::AXFR,
                qclass: Class::IN,
            })
            .unwrap();
        assert!(outcome.is_none());
    }
}

// Adapted from CoreDNS closest_test.go TestClosestEncloserConcurrentSetData.
#[tokio::test(start_paused = true)]
async fn coredns_reload_and_lookup_keep_one_zone_generation() {
    use std::{fmt::Write, sync::Arc, time::Duration};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-p75-concurrent-{}.zone",
        std::process::id()
    ));
    let replacement = path.with_extension("new");
    let content = |serial: u32| {
        let version = 1 + serial % 2;
        let mut text = String::new();
        writeln!(
            text,
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. {serial} 2 3 4 5"
        )
        .unwrap();
        writeln!(text, "@ 60 IN NS ns{version}.example.org.").unwrap();
        writeln!(text, "www 60 IN A 192.0.2.{version}").unwrap();
        text
    };
    std::fs::write(&path, content(1)).unwrap();
    let config = format!(
        "example.org:53 {{\n file {} {{\n reload 1ms\n }}\n}}",
        path.display()
    );
    let chain = Arc::new(
        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config,
    );
    chain
        .lifecycle
        .run(pharos_server::Phase::Startup)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    let reader = Arc::clone(&chain);
    let (ready, started) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let reads = tokio::spawn(async move {
        let domain: Name = "example.org.".parse().unwrap();
        let mut ready = Some(ready);
        let mut seen = [false; 2];
        loop {
            let (outcome, wire) = query_chain(&reader, &domain, "www.example.org.", Type::A).await;
            assert_eq!(outcome, Outcome::Response);
            let response = Message::parse(&wire).unwrap();
            let address = response.answers().next().unwrap().rdata[3];
            let ns = response.authorities().next().unwrap();
            assert!(
                matches!(ns.data(), Ok(Rdata::Ns(target)) if target.to_string() == format!("ns{address}.example.org."))
            );
            seen[usize::from(address - 1)] = true;
            if let Some(ready) = ready.take() {
                ready.send(()).unwrap();
            }
            if *stopped.borrow() {
                return seen;
            }
            tokio::task::yield_now().await;
        }
    });
    started.await.unwrap();
    for serial in 2..=20 {
        std::fs::write(&replacement, content(serial)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
    }
    wait_for_address(
        &chain,
        &"example.org.".parse().unwrap(),
        "www.example.org.",
        [192, 0, 2, 1],
    )
    .await;
    stop.send(true).unwrap();
    assert_eq!(reads.await.unwrap(), [true, true]);
    chain
        .lifecycle
        .run(pharos_server::Phase::Shutdown)
        .await
        .unwrap();
    std::fs::remove_file(path).unwrap();
}

// Derived from CoreDNS dnssec_test.go TestLookupDNSSEC.
#[tokio::test]
async fn coredns_signed_lookup_and_denial_cases() {
    let zone = zone(
        "miek.nl.",
        include_str!("../fixtures/file/coredns-miek-signed.zone"),
    )
    .unwrap();
    let cases: &[(&str, Type, Rcode, &[Type], &[Type], &[&str])] = &[
        (
            "miek.nl.",
            Type::SOA,
            Rcode::NOERROR,
            &[Type::SOA, Type::RRSIG],
            &[Type::NS, Type::NS, Type::NS, Type::NS, Type::RRSIG],
            &[],
        ),
        (
            "miek.nl.",
            Type::AAAA,
            Rcode::NOERROR,
            &[Type::AAAA, Type::RRSIG],
            &[Type::NS, Type::NS, Type::NS, Type::NS, Type::RRSIG],
            &[],
        ),
        (
            "miek.nl.",
            Type::NS,
            Rcode::NOERROR,
            &[Type::NS, Type::NS, Type::NS, Type::NS, Type::RRSIG],
            &[],
            &[],
        ),
        (
            "miek.nl.",
            Type::MX,
            Rcode::NOERROR,
            &[
                Type::MX,
                Type::MX,
                Type::MX,
                Type::MX,
                Type::MX,
                Type::RRSIG,
            ],
            &[Type::NS, Type::NS, Type::NS, Type::NS, Type::RRSIG],
            &[],
        ),
        (
            "www.miek.nl.",
            Type::A,
            Rcode::NOERROR,
            &[Type::CNAME, Type::RRSIG, Type::A, Type::RRSIG],
            &[Type::NS, Type::NS, Type::NS, Type::NS, Type::RRSIG],
            &[],
        ),
        (
            "a.miek.nl.",
            Type::SRV,
            Rcode::NOERROR,
            &[],
            &[Type::SOA, Type::RRSIG, Type::NSEC, Type::RRSIG],
            &["a.miek.nl."],
        ),
        (
            "b.miek.nl.",
            Type::A,
            Rcode::NXDOMAIN,
            &[],
            &[
                Type::SOA,
                Type::RRSIG,
                Type::NSEC,
                Type::RRSIG,
                Type::NSEC,
                Type::RRSIG,
            ],
            &["archive.miek.nl.", "miek.nl."],
        ),
        (
            "b.blaat.miek.nl.",
            Type::A,
            Rcode::NXDOMAIN,
            &[],
            &[
                Type::SOA,
                Type::RRSIG,
                Type::NSEC,
                Type::RRSIG,
                Type::NSEC,
                Type::RRSIG,
            ],
            &["archive.miek.nl.", "miek.nl."],
        ),
        (
            "b.a.miek.nl.",
            Type::A,
            Rcode::NXDOMAIN,
            &[],
            &[Type::SOA, Type::RRSIG, Type::NSEC, Type::RRSIG],
            &["a.miek.nl."],
        ),
    ];
    for (name, kind, rcode, answer, authority, nsec_names) in cases {
        let (outcome, wire) = query(&zone, name, *kind, true, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), *rcode, "{name}");
        assert_eq!(
            response.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
            *answer,
            "{name}"
        );
        assert_eq!(
            response
                .authorities()
                .map(|rr| rr.rtype)
                .collect::<Vec<_>>(),
            *authority,
            "{name}"
        );
        assert_eq!(
            response
                .authorities()
                .filter(|rr| rr.rtype == Type::NSEC)
                .map(|rr| rr.name.to_string())
                .collect::<Vec<_>>(),
            *nsec_names,
            "{name}"
        );
        assert!(
            response
                .answers()
                .chain(response.authorities())
                .filter(|rr| rr.rtype == Type::RRSIG)
                .all(|rr| matches!(
                    rr.data(),
                    Ok(Rdata::Rrsig {
                        algorithm: 8,
                        key_tag: 12051,
                        ..
                    })
                ))
        );
    }
}

// Derived from CoreDNS glue_test.go TestLookupGlue.
#[tokio::test]
async fn coredns_apex_ns_includes_signed_glue() {
    let zone = zone(
        "atoom.net.",
        include_str!("../fixtures/file/coredns-atoom-signed.zone"),
    )
    .unwrap();
    let (outcome, wire) = query(&zone, "atoom.net.", Type::NS, true, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(
        response.answers().filter(|rr| rr.rtype == Type::NS).count(),
        3
    );
    assert!(response.answers().any(|rr| matches!(
        rr.data(),
        Ok(Rdata::Rrsig {
            type_covered: Type::NS,
            key_tag: 53289,
            ..
        })
    )));
    let extra = response.additionals().collect::<Vec<_>>();
    assert_eq!(
        extra.iter().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::A, Type::RRSIG, Type::AAAA, Type::RRSIG]
    );
    assert!(
        extra
            .iter()
            .all(|rr| rr.name.to_string() == "linode.atoom.net.")
    );
    assert!(extra.iter().any(|rr| matches!(rr.data(), Ok(Rdata::A(address)) if address == std::net::Ipv4Addr::new(176, 58, 119, 54))));
    assert!(extra.iter().any(|rr| matches!(rr.data(), Ok(Rdata::Aaaa(address)) if address == "2a01:7e00::f03c:91ff:fe79:234c".parse::<std::net::Ipv6Addr>().unwrap())));
}

// Derived from CoreDNS alias_delegation_test.go TestAliasToDelegation.
#[tokio::test]
async fn coredns_aliases_to_delegated_zones() {
    let zone = zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-alias-cut.zone"),
    )
    .unwrap();
    let child_ns = ["child.example.org. 300 IN NS ns.child.example.org."];
    let child_glue = [
        "ns.child.example.org. 300 IN A 192.0.2.2",
        "ns.child.example.org. 300 IN AAAA 2001:db8::2",
    ];
    let host_ns = ["host.example.org. 300 IN NS ns.host.example.org."];
    let host_glue = [
        "ns.host.example.org. 300 IN A 192.0.2.3",
        "ns.host.example.org. 300 IN AAAA 2001:db8::3",
    ];
    let cases: &[(&str, Type, bool, &[&str], &[&str], &[&str])] = &[
        (
            "alias.example.org.",
            Type::A,
            true,
            &["alias.example.org. 300 IN CNAME host.child.example.org."],
            &child_ns,
            &child_glue,
        ),
        (
            "chain.example.org.",
            Type::A,
            true,
            &[
                "chain.example.org. 300 IN CNAME alias.example.org.",
                "alias.example.org. 300 IN CNAME host.child.example.org.",
            ],
            &child_ns,
            &child_glue,
        ),
        (
            "name.wild.example.org.",
            Type::A,
            true,
            &["name.wild.example.org. 300 IN CNAME host.child.example.org."],
            &child_ns,
            &child_glue,
        ),
        (
            "host.mapped.example.org.",
            Type::A,
            true,
            &[
                "mapped.example.org. 300 IN DNAME example.org.",
                "host.mapped.example.org. 300 IN CNAME host.example.org.",
            ],
            &host_ns,
            &host_glue,
        ),
        (
            "host.mapped.example.org.",
            Type::NS,
            true,
            &[
                "mapped.example.org. 300 IN DNAME example.org.",
                "host.mapped.example.org. 300 IN CNAME host.example.org.",
            ],
            &host_ns,
            &host_glue,
        ),
        (
            "host.child.example.org.",
            Type::A,
            false,
            &[],
            &child_ns,
            &child_glue,
        ),
    ];
    for (name, kind, authoritative, answer, authority, additional) in cases {
        let (outcome, wire) = query(&zone, name, *kind, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.aa(), *authoritative, "{name}");
        assert_records(response.answers(), answer);
        assert_records(response.authorities(), authority);
        assert_records(response.additionals(), additional);
    }
}

// Derived from CoreDNS alias_delegation_test.go TestSignedAliasToDelegation.
#[tokio::test]
async fn coredns_signed_aliases_to_delegated_zones() {
    let zone = zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-signed-delegation.zone"),
    )
    .unwrap();
    let (outcome, wire) = query(&zone, "alias.example.org.", Type::A, true, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert!(response.aa());
    assert_records(
        response.answers(),
        &["alias.example.org. 1800 IN CNAME a.delegated.example.org."],
    );
    assert_eq!(
        response
            .authorities()
            .filter(|rr| rr.rtype == Type::NS)
            .count(),
        2
    );
    assert_eq!(
        response
            .authorities()
            .filter(|rr| rr.rtype == Type::DS)
            .count(),
        2
    );
    assert!(response.authorities().any(|rr| matches!(
        rr.data(),
        Ok(Rdata::Rrsig {
            type_covered: Type::DS,
            ..
        })
    )));
    assert_records(
        response.additionals(),
        &[
            "a.delegated.example.org. 1800 IN A 139.162.196.78",
            "a.delegated.example.org. 1800 IN AAAA 2a01:7e00::f03c:91ff:fef1:6735",
        ],
    );
    let (outcome, wire) = query(&zone, "ds-alias.example.org.", Type::DS, true, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert!(response.aa());
    assert_eq!(
        response
            .answers()
            .filter(|rr| rr.rtype == Type::CNAME)
            .count(),
        1
    );
    assert_eq!(
        response.answers().filter(|rr| rr.rtype == Type::DS).count(),
        2
    );
    assert!(response.answers().any(|rr| matches!(
        rr.data(),
        Ok(Rdata::Rrsig {
            type_covered: Type::DS,
            ..
        })
    )));
    assert_eq!(
        response
            .authorities()
            .filter(|rr| rr.rtype == Type::NS)
            .count(),
        2
    );
    assert!(response.authorities().any(|rr| matches!(
        rr.data(),
        Ok(Rdata::Rrsig {
            type_covered: Type::NS,
            ..
        })
    )));
}

// Derived from CoreDNS wildcard_test.go TestLookupWildcard.
#[tokio::test]
async fn coredns_signed_wildcard_and_nodata_cases() {
    let zone = zone(
        "dnssex.nl.",
        include_str!("../fixtures/file/dnssex-signed.zone"),
    )
    .unwrap();
    for name in ["wild.dnssex.nl.", "a.wild.dnssex.nl."] {
        for dnssec in [false, true] {
            let (outcome, wire) = query(&zone, name, Type::TXT, dnssec, &[]).await;
            assert_eq!(outcome, Outcome::Response);
            let response = Message::parse(&wire).unwrap();
            let expected = format!("{name} 1800 IN TXT \"Doing It Safe Is Better\"");
            assert_records(
                response.answers().filter(|rr| rr.rtype == Type::TXT),
                &[&expected],
            );
            assert_eq!(
                response
                    .answers()
                    .filter(|rr| rr.rtype == Type::RRSIG)
                    .count(),
                usize::from(dnssec)
            );
            assert_eq!(
                response
                    .authorities()
                    .filter(|rr| rr.rtype == Type::NS)
                    .count(),
                3
            );
            if dnssec {
                assert!(response.answers().any(|rr| matches!(
                    rr.data(),
                    Ok(Rdata::Rrsig {
                        type_covered: Type::TXT,
                        ..
                    })
                ) && rr.name.to_string() == name));
                assert!(
                    response
                        .authorities()
                        .any(|rr| rr.rtype == Type::NSEC && rr.name.to_string() == "a.dnssex.nl.")
                );
            }
        }
    }
    for dnssec in [false, true] {
        let (outcome, wire) = query(&zone, "wild.dnssex.nl.", Type::SRV, dnssec, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert_eq!(response.answer_count(), 0);
        assert!(response.authorities().any(|rr| rr.rtype == Type::SOA));
        if dnssec {
            assert!(
                response
                    .authorities()
                    .any(|rr| rr.rtype == Type::NSEC && rr.name.to_string() == "*.dnssex.nl.")
            );
        }
    }
}

// Derived from CoreDNS wildcard_test.go TestLookupDoubleWildcard and TestLookupWildcardAdditional.
#[tokio::test]
async fn coredns_wildcard_alias_and_additional_cases() {
    let zone = zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-wildcard-alias.zone"),
    )
    .unwrap();
    for (name, answer) in [
        (
            "wild.w.example.org.",
            vec!["wild.w.example.org. 3600 IN TXT \"Wildcard\""],
        ),
        (
            "wild.c.example.org.",
            vec!["wild.c.example.org. 3600 IN TXT \"c Wildcard\""],
        ),
        (
            "wild.d.example.org.",
            vec![
                "wild.d.example.org. 3600 IN CNAME alias.example.org.",
                "alias.example.org. 3600 IN TXT \"Wildcard CNAME expansion\"",
            ],
        ),
        (
            "alias.example.org.",
            vec!["alias.example.org. 3600 IN TXT \"Wildcard CNAME expansion\""],
        ),
    ] {
        let (outcome, wire) = query(&zone, name, Type::TXT, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        assert_records(Message::parse(&wire).unwrap().answers(), &answer);
    }
    let zone = self::zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-wildcard-glue.zone"),
    )
    .unwrap();
    let (outcome, wire) = query(&zone, "foo.wild.example.org.", Type::MX, false, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_records(
        response.answers(),
        &["foo.wild.example.org. 1800 IN MX 10 mail.example.org."],
    );
    assert_records(
        response.additionals(),
        &[
            "mail.example.org. 1800 IN A 192.0.2.10",
            "mail.example.org. 1800 IN AAAA 2001:db8::10",
        ],
    );
}

// Derived from CoreDNS wildcard_test.go TestLookupEmptyNonTerminalWildcard and TestLookupWildcardRespectsCloserEmptyNonTerminal.
#[tokio::test]
async fn coredns_empty_nonterminal_wildcard_cases() {
    let zone = zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-wildcard-ent.zone"),
    )
    .unwrap();
    for (name, kind, code, answer) in [
        ("something.e.example.org.", Type::A, Rcode::NOERROR, None),
        ("something.e.example.org.", Type::AAAA, Rcode::NOERROR, None),
        (
            "something.somewhere.e.example.org.",
            Type::A,
            Rcode::NOERROR,
            None,
        ),
        (
            "f.*.e.example.org.",
            Type::A,
            Rcode::NOERROR,
            Some([192, 0, 2, 1]),
        ),
        ("missing.*.e.example.org.", Type::A, Rcode::NXDOMAIN, None),
        (
            "missing.deep.e.example.org.",
            Type::A,
            Rcode::NXDOMAIN,
            None,
        ),
        (
            "something.ordinary.example.org.",
            Type::A,
            Rcode::NOERROR,
            Some([192, 0, 2, 4]),
        ),
    ] {
        let (outcome, wire) = query(&zone, name, kind, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), code, "{name}");
        assert_eq!(
            response.answers().next().map(|rr| rr.rdata.to_vec()),
            answer.map(|address| address.to_vec()),
            "{name}"
        );
    }
    let zone = self::zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-closer-ent.zone"),
    )
    .unwrap();
    for (name, code, answer) in [
        ("nonexistent.deeper.example.org.", Rcode::NXDOMAIN, None),
        (
            "nonexistent.example.org.",
            Rcode::NOERROR,
            Some([127, 0, 0, 53]),
        ),
    ] {
        let (outcome, wire) = query(&zone, name, Type::A, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), code);
        assert_eq!(
            response.answers().next().map(|rr| rr.rdata.to_vec()),
            answer.map(|address| address.to_vec())
        );
    }
}

// Derived from CoreDNS svcb_test.go TestLookupSVCB and TestSVCBPrivateKeys.
#[tokio::test]
async fn coredns_svcb_and_https_cases() {
    let zone = zone(
        "example.com.",
        include_str!("../fixtures/file/coredns-svcb.zone"),
    )
    .unwrap();
    for (name, kind, record) in [
        (
            "_8443._foo.example.com.",
            Type::SVCB,
            "_8443._foo.example.com. 1800 IN SVCB 1 svc-target.example.com. alpn=h2,h3 port=8443",
        ),
        (
            "www.example.com.",
            Type::HTTPS,
            "www.example.com. 1800 IN HTTPS 1 svc-target.example.com. alpn=h2,h3",
        ),
        (
            "_alias._foo.example.com.",
            Type::SVCB,
            "_alias._foo.example.com. 1800 IN SVCB 0 svc-target.example.com.",
        ),
        (
            "_http._tcp.example.com.",
            Type::SVCB,
            "_http._tcp.example.com. 1800 IN SVCB 1 svc-target.example.com. port=443",
        ),
    ] {
        let (outcome, wire) = query(&zone, name, kind, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_records(response.answers(), &[record]);
        assert_records(
            response.authorities(),
            &["example.com. 1800 IN NS ns.example.com."],
        );
        assert_records(
            response.additionals(),
            &[
                "svc-target.example.com. 1800 IN A 192.0.2.10",
                "svc-target.example.com. 1800 IN AAAA 2001:db8::10",
            ],
        );
    }
    for (name, expected) in [
        ("svc-target.example.com.", Rcode::NOERROR),
        ("nonexistent.example.com.", Rcode::NXDOMAIN),
    ] {
        let (outcome, wire) = query(&zone, name, Type::SVCB, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), expected);
        assert_records(
            response.authorities(),
            &[
                "example.com. 1800 IN SOA ns.example.com. admin.example.com. 2024010100 14400 3600 604800 14400",
            ],
        );
    }
    let (outcome, wire) = query(&zone, "_dnsaid.example.com.", Type::HTTPS, false, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    let value = response
        .answers()
        .next()
        .unwrap()
        .data()
        .unwrap()
        .to_string();
    for key in ["key65400=", "key65401=", "key65406="] {
        assert!(value.contains(key), "{value}");
    }
}

// Derived from CoreDNS lookup_test.go TestAdditionalSectionDeduplication and TestAdditionalSectionDeduplicationMixedCase.
#[tokio::test]
async fn coredns_additional_processing_deduplicates_targets() {
    let zone = zone(
        "example.org.",
        include_str!("../fixtures/file/coredns-additional.zone"),
    )
    .unwrap();
    let host = [
        "host.example.org. 1800 IN A 192.0.2.10",
        "host.example.org. 1800 IN AAAA 2001:db8::10",
    ];
    let two = [
        "host.example.org. 1800 IN A 192.0.2.10",
        "host.example.org. 1800 IN AAAA 2001:db8::10",
        "other.example.org. 1800 IN A 192.0.2.20",
        "other.example.org. 1800 IN AAAA 2001:db8::20",
    ];
    let cases: &[(&str, Type, &[&str], &[&str])] = &[
        (
            "mx.example.org.",
            Type::MX,
            &[
                "mx.example.org. 1800 IN MX 10 host.example.org.",
                "mx.example.org. 1800 IN MX 20 host.example.org.",
            ],
            &host,
        ),
        (
            "srv.example.org.",
            Type::SRV,
            &[
                "srv.example.org. 1800 IN SRV 10 50 8080 host.example.org.",
                "srv.example.org. 1800 IN SRV 20 50 8080 host.example.org.",
            ],
            &host,
        ),
        (
            "mixed.example.org.",
            Type::SRV,
            &[
                "mixed.example.org. 1800 IN SRV 10 50 8080 host.example.org.",
                "mixed.example.org. 1800 IN SRV 20 50 8080 HOST.EXAMPLE.ORG.",
            ],
            &host,
        ),
        (
            "two.example.org.",
            Type::MX,
            &[
                "two.example.org. 1800 IN MX 10 host.example.org.",
                "two.example.org. 1800 IN MX 20 other.example.org.",
            ],
            &two,
        ),
        (
            "cname-srv.example.org.",
            Type::SRV,
            &[
                "cname-srv.example.org. 1800 IN CNAME srv.example.org.",
                "srv.example.org. 1800 IN SRV 10 50 8080 host.example.org.",
                "srv.example.org. 1800 IN SRV 20 50 8080 host.example.org.",
            ],
            &host,
        ),
        (
            "foo.wild.example.org.",
            Type::SRV,
            &[
                "foo.wild.example.org. 1800 IN CNAME srv.example.org.",
                "srv.example.org. 1800 IN SRV 10 50 8080 host.example.org.",
                "srv.example.org. 1800 IN SRV 20 50 8080 host.example.org.",
            ],
            &host,
        ),
        (
            "srv.dname.example.org.",
            Type::SRV,
            &[
                "dname.example.org. 1800 IN DNAME dsub.example.org.",
                "srv.dname.example.org. 1800 IN CNAME srv.dsub.example.org.",
                "srv.dsub.example.org. 1800 IN SRV 10 50 8080 host.example.org.",
            ],
            &host,
        ),
    ];
    for (name, kind, answer, additional) in cases {
        let (outcome, wire) = query(&zone, name, *kind, false, &[]).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_records(response.answers(), answer);
        assert_records(
            response.authorities(),
            &["example.org. 1800 IN NS ns.example.org."],
        );
        assert_records(response.additionals(), additional);
    }
}

// CoreDNS tsig README: require signatures for IXFR as well as AXFR.
#[cfg(all(feature = "plugin-transfer", feature = "plugin-tsig"))]
#[test]
fn coredns_tsig_readme_requires_signed_ixfr() {
    // Debug Plugin Chain futures exceed 2 MiB; see #90.
    std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(|| {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            use pharos_server::Listener;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/file/coredns-tsig-zone.zone");
            let config = format!("example.zone:0 {{\n tsig {{\n secret example.zone.key. NoTCJU+DMqFWywaPyxSijrDEA/eC3nK0xi3AMEZuPVk=\n require AXFR IXFR\n }}\n transfer {{\n to *\n }}\n file {path}\n}}");
            let (mut servers, lifecycle) = pharos_plugins::servers(configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap()).unwrap();
            lifecycle.run(pharos_server::Phase::Startup).await.unwrap();
            let (_, server) = servers.drain().next().unwrap();
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), server).await.unwrap();
            let apex: Name = "example.zone.".parse().unwrap();
            let records = ZoneParser::new(include_str!("../fixtures/file/coredns-tsig-zone.zone").as_bytes(), apex.clone(), "test").collect::<Result<Vec<_>, _>>().unwrap();
            let soa = records.iter().find(|record| record.rtype == Type::SOA).unwrap();
            let make_query = || {
                let mut wire = Vec::with_capacity(512);
                let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
                let owner = NameRef::parse(apex.as_wire(), 0).unwrap();
                builder.question(owner, Type::IXFR, Class::IN).unwrap();
                builder.record(Section::Authority, owner, Type::SOA, Class::IN, soa.ttl, &soa.rdata).unwrap();
                let _ = builder.finish();
                wire
            };
            let secret = [54, 132, 194, 37, 79, 131, 50, 161, 86, 203, 6, 143, 203, 20, 162, 142, 176, 196, 3, 247, 130, 222, 114, 180, 198, 45, 192, 48, 70, 110, 61, 89];
            let key = pharos_proto::TsigKey::new("example.zone.key.".parse().unwrap(), pharos_proto::TsigAlgorithm::Sha256, &secret);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            for signed in [false, true] {
                let mut query = make_query();
                if signed { key.sign(&mut query, now, 300, None).unwrap(); }
                let mac = signed.then(|| pharos_proto::TsigRecord::parse(&query).unwrap().mac.to_vec());
                let mut socket = tokio::net::TcpStream::connect(listener.local_addr()).await.unwrap();
                socket.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
                socket.write_all(&query).await.unwrap();
                let len = tokio::time::timeout(std::time::Duration::from_secs(3), socket.read_u16()).await.unwrap().unwrap();
                let mut response = vec![0; usize::from(len)];
                socket.read_exact(&mut response).await.unwrap();
                let message = Message::parse(&response).unwrap();
                if signed {
                    assert_eq!(message.rcode(), Rcode::NOERROR);
                    assert_eq!(message.answer_count(), 1);
                    assert_eq!(message.answers().next().unwrap().rtype, Type::SOA);
                    let mut verifier = pharos_proto::TsigStream::new(&key, mac.as_deref().unwrap());
                    assert!(verifier.verify(&response, now, 0).unwrap().is_some());
                    verifier.finish().unwrap();
                } else {
                    assert_eq!(message.rcode(), Rcode::REFUSED);
                }
            }
            listener.shutdown().await.unwrap();
            lifecycle.run(pharos_server::Phase::Shutdown).await.unwrap();
        });
    }).unwrap().join().unwrap();
}
