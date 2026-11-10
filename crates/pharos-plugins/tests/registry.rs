use pharos_corefile::{configure, parse};
use pharos_plugins::{Plugin, directives, plugins_listing};

#[test]
fn whoami_feature_controls_registration() {
    let blocks = parse("Corefile", ".:53 {\n whoami\n}").unwrap();
    let result = configure::<Vec<Plugin>>(&blocks, directives());
    if cfg!(feature = "plugin-whoami") {
        assert_eq!(result.unwrap()[0].config.len(), 1);
        assert!(plugins_listing().lines().any(|name| name == "whoami"));
    } else {
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Unknown directive 'whoami'")
        );
        assert!(!plugins_listing().lines().any(|name| name == "whoami"));
    }
}

#[cfg(feature = "plugin-whoami")]
#[test]
fn whoami_rejects_arguments() {
    let blocks = parse("Corefile", ". {\n whoami extra\n}").unwrap();
    assert!(configure::<Vec<Plugin>>(&blocks, directives()).is_err());
}
