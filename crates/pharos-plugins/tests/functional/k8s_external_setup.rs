#![cfg(feature = "plugin-k8s-external")]

use pharos_corefile::{Cursor, configure, parse};
use pharos_plugins::{
    Chain, directives,
    k8s_external::setup::{Config, parse as parse_setup},
};

fn config(text: &str) -> Result<Config, pharos_corefile::Error> {
    let blocks = parse("Corefile", &format!(".:53 {{\n{text}\n}}"))?;
    let tokens = &blocks[0].directives["k8s_external"];
    parse_setup(&mut Cursor::new("Corefile", tokens), &["."])
}

#[test]
fn coredns_setup_defaults_and_options() {
    let defaults = config("k8s_external").unwrap();
    assert_eq!(defaults.zones, ["."]);
    assert_eq!(defaults.apex, "dns");
    assert_eq!(defaults.ttl, 5);
    assert!(!defaults.headless);

    let custom = config("k8s_external example.org {\n apex testdns\n ttl 30\n headless\n fallthrough ip6.arpa in-addr.arpa\n}").unwrap();
    assert_eq!(custom.zones, ["example.org."]);
    assert_eq!(custom.apex, "testdns");
    assert_eq!(custom.ttl, 30);
    assert!(custom.headless);
    assert_eq!(custom.fallthrough.domains, ["ip6.arpa.", "in-addr.arpa."]);
    let repeated = config(
        "k8s_external first.example {\n ttl 20\n}\nk8s_external second.example {\n headless\n}",
    )
    .unwrap();
    assert_eq!(repeated.zones, ["second.example."]);
    assert_eq!(repeated.ttl, 20);
    assert!(repeated.headless);
}

#[test]
fn coredns_setup_rejects_bad_options() {
    for option in ["ttl", "ttl -1", "ttl 3601", "ttl nope", "apex", "unknown"] {
        assert!(
            config(&format!("k8s_external example.org {{\n {option}\n}}")).is_err(),
            "{option}"
        );
    }
    assert!(
        config("k8s_external example.org {\n ttl 0 extra\n apex dns extra\n headless extra\n}")
            .is_ok()
    );
}

#[tokio::test]
async fn startup_requires_kubernetes_in_same_server_block() {
    for (text, valid) in [
        (".:53 {\n k8s_external example.org\n}", false),
        (
            ".:53 {\n k8s_external example.org\n kubernetes cluster.local {\n  endpoint http://127.0.0.1:1\n  startup_timeout 0s\n }\n}",
            true,
        ),
        (
            ".:53 {\n k8s_external example.org\n}\nother:53 {\n kubernetes cluster.local\n}",
            false,
        ),
    ] {
        let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
        let (_, lifecycle) = pharos_plugins::servers(blocks).unwrap();
        if valid {
            lifecycle.run(pharos_server::Phase::Startup).await.unwrap();
            lifecycle.run(pharos_server::Phase::Shutdown).await.unwrap();
        } else {
            let error = lifecycle
                .run(pharos_server::Phase::Startup)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "plugin/k8s_external: kubernetes plugin not loaded",
                "{text}"
            );
        }
    }
}
