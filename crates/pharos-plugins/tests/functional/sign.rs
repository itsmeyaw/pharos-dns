use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_sign_setup_accepts_key_and_directory() {
    let key = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dnssec/Kmiek.nl.+013+59725");
    let text = format!("miek.nl {{\n sign db.miek.nl miek.nl {{\n key file {key}\n directory .\n }}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    assert!(configure::<Chain>(&blocks, directives()).is_ok());
}

#[tokio::test]
async fn startup_writes_a_signed_zone_that_file_can_load() {
    use pharos_proto::{Name, Type};
    use pharos_server::Phase;

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../target/sign-functional-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let key = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dnssec/Kmiek.nl.+013+59725");
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/file/coredns-miek.zone");
    let text = format!("miek.nl {{\n sign {source} miek.nl {{\n key file {key}\n directory {}\n }}\n}}", directory.display());
    let blocks = parse("Corefile", &text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    configured[0].config.lifecycle.run(Phase::Startup).await.unwrap();
    let path = directory.join("db.miek.nl.signed");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !path.exists() { tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
    }).await.unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let zone = pharos_plugins::zone::Zone::load(apex, &path).unwrap();
    for kind in [Type::DNSKEY, Type::CDS, Type::CDNSKEY, Type::NSEC, Type::RRSIG] {
        assert!(zone.records().iter().any(|record| record.rtype == kind), "missing {kind}");
    }
    configured[0].config.lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
