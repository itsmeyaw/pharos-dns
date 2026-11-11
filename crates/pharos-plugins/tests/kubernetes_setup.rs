#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]
#![recursion_limit = "512"]

use pharos_corefile::{Cursor, configure, parse};
use pharos_plugins::{
    Chain, directives,
    kubernetes::setup::{Config, parse as parse_setup},
};

fn config(text: &str) -> Result<Config, pharos_corefile::Error> {
    let blocks = parse("Corefile", &format!(".:53 {{\n{text}\n}}"))?;
    let tokens = &blocks[0].directives["kubernetes"];
    parse_setup(&mut Cursor::new("Corefile", tokens), &["."])
}

#[test]
fn defaults_and_ttl_match_coredns() {
    let k = config("kubernetes cluster.local").unwrap();
    assert_eq!(k.zones, ["cluster.local."]);
    assert_eq!(k.ttl, 5);
    assert_eq!(k.pod_mode, "disabled");
    assert!(k.endpoints);
    assert_eq!(k.startup_timeout, std::time::Duration::from_secs(5));
    for (ttl, expected) in [
        ("0", Some(0)),
        ("-0", Some(0)),
        ("56", Some(56)),
        ("3600", Some(3600)),
        ("-1", None),
        ("3601", None),
    ] {
        let result = config(&format!("kubernetes cluster.local {{\n ttl {ttl}\n}}"));
        assert_eq!(result.ok().map(|k| k.ttl), expected, "{ttl}");
    }
}

#[test]
fn setup_registers_backend_and_validates_options() {
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    assert!(
        configure::<Chain>(&blocks, directives()).unwrap()[0]
            .config
            .kubernetes
            .is_some()
    );
    let blocks = parse(
        "Corefile",
        ".:53 {\n kubernetes cluster.local {\n  pods invalid\n }\n}",
    )
    .unwrap();
    assert!(
        configure::<Chain>(&blocks, directives())
            .unwrap_err()
            .message
            .contains("wrong value for pods")
    );
    let blocks = parse(
        "Corefile",
        ".:53 {\n kubernetes first.local\n kubernetes second.local\n}",
    )
    .unwrap();
    assert!(
        configure::<Chain>(&blocks, directives())
            .unwrap_err()
            .message
            .contains("only be used once")
    );
}

#[test]
fn coredns_setup_variants_and_defaults() {
    assert_eq!(config("kubernetes").unwrap().zones, ["."]);
    let k = config("kubernetes 10.in-addr.arpa cluster.local {\n pods insecure\n kubeconfig file\n ignore\n ttl 1 extra\n startup_timeout 1s extra\n}").unwrap();
    assert_eq!(k.primary_zone_index, 1);
    assert_eq!(k.pod_mode, "insecure");
    assert_eq!(k.kubeconfig, Some(("file".into(), None)));
    assert!(!k.ignore_empty_service);
    assert_eq!(k.ttl, 1);
    assert!(config("kubernetes cluster.local {\n pods disabled\n}").is_ok());
    assert!(config("kubernetes cluster.local {\n labels\n}").is_err());
    assert!(config("kubernetes cluster.local {\n namespace_labels\n}").is_err());
    assert!(config("kubernetes first.local\n kubernetes second.local").is_err());
}

#[test]
fn parses_coredns_options() {
    let k = config("kubernetes cluster.local in-addr.arpa ip6.arpa {\n endpoint https://one https://two\n tls cert key ca\n kubeconfig file ctx\n namespaces demo test demo\n labels environment in (production, staging, qa),application=nginx\n pods verified\n endpoint_pod_names\n fallthrough in-addr.arpa ip6.arpa\n ttl 56\n ignore empty_service extra\n startup_timeout 1s\n apiserver_qps 50\n apiserver_burst 100\n apiserver_max_inflight 25\n zonal\n}").unwrap();
    assert_eq!(k.primary_zone_index, 0);
    assert_eq!(k.namespaces.len(), 2);
    assert_eq!(k.endpoints_list, ["https://one", "https://two"]);
    assert_eq!(k.tls, Some(["cert".into(), "key".into(), "ca".into()]));
    assert_eq!(k.kubeconfig, Some(("file".into(), Some("ctx".into()))));
    assert_eq!(
        k.label_selector.as_deref(),
        Some("application=nginx,environment in (production,qa,staging)")
    );
    assert_eq!(k.pod_mode, "verified");
    assert!(k.endpoint_pod_names && k.ignore_empty_service && k.zonal);
    assert_eq!(k.fallthrough.domains, ["in-addr.arpa.", "ip6.arpa."]);
    assert_eq!(k.startup_timeout, std::time::Duration::from_secs(1));
    assert_eq!(
        (k.api_qps, k.api_burst, k.api_max_inflight),
        (50.0, 100, 25)
    );
    let client = k.client_config();
    assert_eq!(client.endpoint.as_deref(), Some("https://one"));
    assert_eq!(client.kubeconfig, Some(("file".into(), Some("ctx".into()))));
    let tls = client.tls.unwrap();
    assert_eq!(
        (tls.cert, tls.key, tls.ca),
        ("cert".into(), "key".into(), "ca".into())
    );
    assert_eq!(
        (client.api_qps, client.api_burst, client.api_max_inflight),
        (50.0, 100, 25)
    );
    let watch = k.watch_config();
    assert_eq!(watch.namespaces.len(), 2);
    assert_eq!(watch.label_selector, k.label_selector);
    assert!(watch.pods_verified && watch.endpoints && watch.zonal);
}

#[test]
fn validates_coredns_options() {
    for option in [
        "endpoint",
        "namespaces",
        "tls a b",
        "pods",
        "pods bad",
        "pods insecure extra",
        "endpoint_pod_names extra",
        "noendpoints extra",
        "zonal extra",
        "kubeconfig",
        "kubeconfig a b c",
        "startup_timeout",
        "startup_timeout nonsense",
        "apiserver_qps -1",
        "apiserver_qps nope",
        "apiserver_burst -1",
        "apiserver_max_inflight -1",
        "apiserver_burst 9223372036854775808",
        "ignore bad",
        "unknown",
    ] {
        assert!(
            config(&format!("kubernetes cluster.local {{\n {option}\n}}")).is_err(),
            "{option}"
        );
    }
    for text in [
        "kubernetes 10.in-addr.arpa a.ip6.arpa",
        "kubernetes cluster.local {\n namespaces a\n namespace_labels app=demo\n}",
        "kubernetes cluster.local {\n noendpoints\n zonal\n}",
    ] {
        assert!(config(text).is_err(), "{text}");
    }
    let k = config(
        "kubernetes cluster.local {\n noendpoints\n fallthrough\n namespace_labels app=demo\n}",
    )
    .unwrap();
    assert!(!k.endpoints);
    assert!(!k.watch_config().endpoints);
    assert_eq!(
        k.watch_config().namespace_label_selector,
        k.namespace_label_selector
    );
    assert_eq!(k.namespace_label_selector.as_deref(), Some("app=demo"));
    assert_eq!(k.fallthrough.domains, ["."]);
}

#[test]
fn validates_label_selector_grammar() {
    for selector in [
        "app=nginx",
        "example.com/app in (foo, bar),!disabled",
        "a=,b==value,c notin (x,y)",
        "foo",
        "foo in ()",
        "app in (a,,b)",
    ] {
        assert!(
            config(&format!(
                "kubernetes cluster.local {{\n labels {selector}\n}}"
            ))
            .is_ok(),
            "{selector}"
        );
    }
    for selector in [
        "environment in (production, qa",
        "bad key=value",
        "app > 1",
        "a!=value",
        "!a=value",
        "!a in (b)",
        "UPPER.example/app=x",
        "bad/=x",
        "app=x,",
    ] {
        assert!(
            config(&format!(
                "kubernetes cluster.local {{\n labels {selector}\n}}"
            ))
            .is_err(),
            "{selector}"
        );
    }
    let k = config("kubernetes cluster.local {\n labels z=first,a in (z,a,z),z=last\n}").unwrap();
    assert_eq!(k.label_selector.as_deref(), Some("a in (a,z),z=last"));
    let long_prefix = format!("{}/app=ok", "a".repeat(64));
    assert!(
        config(&format!(
            "kubernetes cluster.local {{\n labels {long_prefix}\n}}"
        ))
        .is_ok()
    );
}

#[test]
fn multicluster_setup_matches_coredns() {
    let invalid =
        config("kubernetes cluster.local {\n multicluster clusterset.local\n}").unwrap_err();
    assert!(invalid.message.contains("not authoritative"), "{invalid}");
    let invalid_extra = config(
        "kubernetes cluster.local clusterset.local {\n multicluster clusterset.local test.local\n}",
    )
    .unwrap_err();
    assert!(
        invalid_extra.message.contains("not authoritative"),
        "{invalid_extra}"
    );
    let configured =
        config("kubernetes cluster.local clusterset.local {\n multicluster clusterset.local\n}")
            .unwrap();
    assert_eq!(configured.multicluster_zones, ["clusterset.local."]);
    assert!(configured.watch_config().multicluster);
    let empty = config("kubernetes cluster.local {\n multicluster\n}").unwrap();
    assert!(empty.multicluster_zones.is_empty());
    assert!(!empty.watch_config().multicluster);
    for zones in ["bad..zone", "bad..zone cluster.local"] {
        let parsed = config(&format!(
            "kubernetes cluster.local {{\n multicluster {zones}\n}}"
        ))
        .unwrap();
        assert!(
            !parsed.watch_config().multicluster || parsed.multicluster_zones == ["cluster.local."]
        );
    }
    let invalid =
        config("kubernetes cluster.local {\n multicluster cluster.local\n zonal\n noendpoints\n}")
            .unwrap_err();
    assert!(invalid.message.contains("zonal requires"), "{invalid}");
}

#[test]
fn qps_follows_go_float32_syntax_range_and_rounding() {
    for (input, expected) in [
        ("0x1p4", 16.0f32.to_bits()),
        ("0X1.8P2", 6.0f32.to_bits()),
        ("0x_1p2", 4.0f32.to_bits()),
        ("1_2.5", 12.5f32.to_bits()),
        ("0x1p1_0", 1024.0f32.to_bits()),
        ("0x1.000001p0", 1.0f32.to_bits()),
        ("0x1.000003p0", 0x3f800002),
        ("0x1p-150", 0),
        ("0x1.000001p-150", 1),
        ("0x1p-149", 1),
        ("0x1.fffffep127", f32::MAX.to_bits()),
        ("0x0p999999999", 0),
        ("3.4028235e38", f32::MAX.to_bits()),
        ("1e-9999", 0),
        ("-1e-9999", (-0.0f32).to_bits()),
    ] {
        let parsed = config(&format!(
            "kubernetes cluster.local {{\n apiserver_qps {input}\n}}"
        ))
        .unwrap_or_else(|error| panic!("{input}: {error}"));
        assert_eq!(parsed.api_qps.to_bits(), expected, "{input}");
    }
    for input in ["NaN", "nan", "NAN"] {
        assert!(
            config(&format!(
                "kubernetes cluster.local {{\n apiserver_qps {input}\n}}"
            ))
            .unwrap()
            .api_qps
            .is_nan(),
            "{input}"
        );
    }
    for input in ["+Inf", "Infinity", "infinity"] {
        assert_eq!(
            config(&format!(
                "kubernetes cluster.local {{\n apiserver_qps {input}\n}}"
            ))
            .unwrap()
            .api_qps,
            f32::INFINITY,
            "{input}"
        );
    }
    for input in [
        "--1",
        "++1",
        "--0",
        "+-0",
        "-+0",
        "1e39",
        "-1e39",
        "3.4028236e38",
        "0x1.ffffffp127",
        "0x1p999999999",
        "-Inf",
        "+NaN",
        "1__2",
        "1e_3",
        "0x1",
        "0x.p0",
        "0x1_p2",
        "0x1p_2",
    ] {
        assert!(
            config(&format!(
                "kubernetes cluster.local {{\n apiserver_qps {input}\n}}"
            ))
            .is_err(),
            "{input}"
        );
    }
}

#[test]
fn startup_timeout_accepts_zero_and_clamps_negative_values() {
    for input in ["0", "0s", "-0", "-0s", "-5s", "-1h30m"] {
        let result = config(&format!(
            "kubernetes cluster.local {{\n startup_timeout {input}\n}}"
        ))
        .unwrap_or_else(|error| panic!("{input}: {error}"));
        assert_eq!(result.startup_timeout, std::time::Duration::ZERO, "{input}");
    }
}
