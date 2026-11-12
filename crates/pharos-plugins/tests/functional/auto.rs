use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_auto_setup_cases() {
    for (body, valid) in [
        ("directory /tmp", true),
        ("directory /tmp (.*) {1}\n reload 0", true),
        ("directory /tmp\n upstream 8.8.8.8", true),
        ("directory /tmp (.*)", false),
        ("directory /tmp (.*) {1} extra", false),
        ("directory /tmp abc {1}", false),
        ("directory /tmp\n fallthrough", false),
        ("directory /tmp\n reload -1s", false),
    ] {
        let text = format!("example.org:53 {{\n auto {{\n {body}\n }}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert_eq!(configure::<Chain>(&blocks, directives()).is_ok(), valid, "{body}");
    }
}
