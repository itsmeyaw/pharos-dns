#![forbid(unsafe_code)]
#![cfg(feature = "plugin-root")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn configure_root(
    directives_text: &str,
) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, pharos_corefile::Error> {
    let text = format!(".:53 {{\n{directives_text}\n}}");
    configure(&parse("Corefile", &text)?, directives())
}

#[test]
fn accepts_coredns_root_paths_and_rejects_invalid_setup() {
    for text in ["root /tmp", "root /unlikely-pharos-root-missing"] {
        assert!(configure_root(text).is_ok(), "rejected {text}");
    }
    for text in ["root", "root {\n /tmp\n}", "root bad\0path"] {
        assert!(configure_root(text).is_err(), "accepted {text:?}");
    }
}

#[test]
fn repeated_root_uses_last_path() {
    let blocks = configure_root("root /tmp/first\n root /tmp/last").unwrap();
    assert_eq!(
        blocks[0].config.root.as_deref(),
        Some(std::path::Path::new("/tmp/last"))
    );
}

#[cfg(all(feature = "plugin-hosts", feature = "plugin-loadbalance"))]
#[test]
fn root_resolves_relative_paths_per_server_block() {
    let blocks =
        configure_root("hosts entries\n loadbalance weighted weights\n root /tmp/pharos-root")
            .unwrap();
    assert_eq!(
        blocks[0].config.hosts.as_ref().unwrap().path,
        std::path::Path::new("/tmp/pharos-root/entries")
    );
    assert_eq!(
        blocks[0]
            .config
            .loadbalance
            .as_ref()
            .unwrap()
            .weight_file
            .as_deref(),
        Some(std::path::Path::new("/tmp/pharos-root/weights"))
    );
}

#[cfg(all(feature = "plugin-hosts", feature = "plugin-loadbalance"))]
#[test]
fn absolute_paths_and_default_hosts_are_not_rebased() {
    let blocks = configure_root(
        "root /tmp/pharos-root\n hosts /etc/hosts\n loadbalance weighted /tmp/weights",
    )
    .unwrap();
    assert_eq!(
        blocks[0].config.hosts.as_ref().unwrap().path,
        std::path::Path::new("/etc/hosts")
    );
    assert_eq!(
        blocks[0]
            .config
            .loadbalance
            .as_ref()
            .unwrap()
            .weight_file
            .as_deref(),
        Some(std::path::Path::new("/tmp/weights"))
    );
    let blocks = configure_root("root /tmp/pharos-root\n hosts").unwrap();
    assert_eq!(
        blocks[0].config.hosts.as_ref().unwrap().path,
        std::path::Path::new("/etc/hosts")
    );
}

#[cfg(feature = "plugin-hosts")]
#[test]
fn roots_do_not_leak_between_server_blocks() {
    let text = "one.example:53 {\n root /tmp/one\n hosts entries\n}\ntwo.example:53 {\n root /tmp/two\n hosts entries\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    assert_eq!(
        blocks[0].config.hosts.as_ref().unwrap().path,
        std::path::Path::new("/tmp/one/entries")
    );
    assert_eq!(
        blocks[1].config.hosts.as_ref().unwrap().path,
        std::path::Path::new("/tmp/two/entries")
    );
}

#[cfg(all(feature = "plugin-hosts", feature = "plugin-loadbalance"))]
#[test]
fn root_joins_clean_paths_like_coredns() {
    let blocks =
        configure_root("root a/../base\n hosts ../entries\n loadbalance weighted ./weights")
            .unwrap();
    assert_eq!(
        blocks[0].config.hosts.as_ref().unwrap().path,
        std::path::Path::new("entries")
    );
    assert_eq!(
        blocks[0]
            .config
            .loadbalance
            .as_ref()
            .unwrap()
            .weight_file
            .as_deref(),
        Some(std::path::Path::new("base/weights"))
    );
}
