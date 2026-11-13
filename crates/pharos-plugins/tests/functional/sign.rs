use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_sign_setup_accepts_key_and_directory() {
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text =
        format!("miek.nl {{\n sign db.miek.nl miek.nl {{\n key file {key}\n directory .\n }}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    assert!(configure::<Chain>(&blocks, directives()).is_ok());
}

#[test]
fn coredns_sign_setup_accepts_and_rejects_documented_options() {
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    for (directive, accepted) in [
        (
            format!("sign db.miek.nl miek.nl {{\n key file {key}.key\n directory .\n}}"),
            true,
        ),
        (
            format!("sign db.miek.nl example.org {{\n key file {key}.private\n}}"),
            true,
        ),
        (
            "sign db.miek.nl {\n key directory /missing\n}".to_owned(),
            false,
        ),
        ("sign db.miek.nl {\n key file /missing\n}".to_owned(), false),
        ("sign db.miek.nl {\n key file\n}".to_owned(), false),
        ("sign db.miek.nl {\n directory a b\n}".to_owned(), false),
        ("sign db.miek.nl {\n unknown x\n}".to_owned(), false),
        ("sign db.� miek.nl".to_owned(), false),
    ] {
        let text = format!("miek.nl {{\n {directive}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            accepted,
            "{directive}"
        );
    }
}

#[tokio::test]
async fn startup_writes_a_signed_zone_that_file_can_load() {
    use pharos_proto::{Name, Type};
    use pharos_server::Phase;

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/sign-functional-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/coredns-miek.zone"
    );
    let text = format!(
        "miek.nl {{\n sign {source} miek.nl {{\n key file {key}\n directory {}\n }}\n}}",
        directory.display()
    );
    let blocks = parse("Corefile", &text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    configured[0]
        .config
        .lifecycle
        .run(Phase::Startup)
        .await
        .unwrap();
    let path = directory.join("db.miek.nl.signed");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let zone = pharos_plugins::zone::Zone::load(apex, &path).unwrap();
    for kind in [
        Type::DNSKEY,
        Type::CDS,
        Type::CDNSKEY,
        Type::NSEC,
        Type::RRSIG,
    ] {
        assert!(
            zone.records().iter().any(|record| record.rtype == kind),
            "missing {kind}"
        );
    }
    configured[0]
        .config
        .lifecycle
        .run(Phase::Shutdown)
        .await
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn sign_lifecycle_can_stop_and_restart() {
    use pharos_server::Phase;
    let directory =
        std::env::temp_dir().join(format!("pharos-sign-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/coredns-miek.zone"
    );
    let text = format!(
        "miek.nl {{\n sign {source} {{\n key file {key}\n directory {}\n }}\n}}",
        directory.display()
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let lifecycle = &configured[0].config.lifecycle;
    lifecycle.run(Phase::Startup).await.unwrap();
    lifecycle.run(Phase::Restart).await.unwrap();
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    let path = directory.join("db.miek.nl.signed");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn coredns_multi_origin_reuses_the_last_key_owner() {
    use pharos_proto::{Type, zone::ZoneParser};
    use pharos_server::Phase;
    let directory =
        std::env::temp_dir().join(format!("pharos-sign-origins-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sign/db.miek.nl_ns"
    );
    let text = format!(
        ". {{\n sign {source} miek.nl example.org {{\n key file {key}\n directory {}\n }}\n}}",
        directory.display()
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let lifecycle = &configured[0].config.lifecycle;
    lifecycle.run(Phase::Startup).await.unwrap();
    let path = directory.join("db.miek.nl.signed");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    let records: Vec<_> = ZoneParser::new(
        std::io::BufReader::new(std::fs::File::open(path).unwrap()),
        "miek.nl.".parse().unwrap(),
        "signed",
    )
    .map(Result::unwrap)
    .collect();
    let owner = records
        .iter()
        .find(|rr| rr.rtype == Type::DNSKEY)
        .unwrap()
        .owner
        .to_string();
    assert_eq!(owner, "example.org.");
    std::fs::remove_dir_all(directory).unwrap();
}
