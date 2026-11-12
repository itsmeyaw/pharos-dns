#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, file::Zone};
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
                assert_eq!(Message::parse(&wire).unwrap().rcode(), expected);
            }
        }
    }
    std::fs::remove_file(path).unwrap();
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
