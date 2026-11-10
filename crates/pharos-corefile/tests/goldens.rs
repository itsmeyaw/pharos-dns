use pharos_corefile::parse;
use std::fs;

#[test]
fn parses_upstream_default_corefiles() {
    let fixtures = [
        ("kubeadm", include_str!("fixtures/kubeadm.Corefile"), 10),
        (
            "kubernetes-addon",
            include_str!("fixtures/kubernetes-addon.Corefile"),
            10,
        ),
        ("helm", include_str!("fixtures/coredns-helm.Corefile"), 10),
    ];
    for (name, source, count) in fixtures {
        let blocks = parse(name, source).unwrap();
        assert_eq!(blocks.len(), 1, "{name}");
        assert_eq!(blocks[0].keys(), [".:53"], "{name}");
        assert_eq!(blocks[0].directives.len(), count, "{name}");
        assert_eq!(blocks[0].directives["kubernetes"][1].text, "cluster.local");
        assert_eq!(blocks[0].directives["forward"][2].text, "/etc/resolv.conf");
    }
}

#[test]
fn k3s_loads_custom_overrides_and_server_blocks() {
    let dir = std::env::temp_dir().join(format!("pharos-k3s-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("custom.override"), "log\n").unwrap();
    fs::write(dir.join("custom.server"), "custom.local {\n errors\n}\n").unwrap();
    let source = include_str!("fixtures/k3s.Corefile")
        .replace("/etc/coredns/custom", &dir.to_string_lossy());
    let blocks = parse("k3s", &source).unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].keys(), [".:53"]);
    assert!(blocks[0].directives.contains_key("hosts"));
    assert!(blocks[0].directives.contains_key("log"));
    assert_eq!(blocks[1].keys(), ["custom.local"]);
    fs::remove_dir_all(dir).unwrap();
}
