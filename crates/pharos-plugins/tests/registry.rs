use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, plugins_listing};

#[test]
fn whoami_feature_controls_registration() {
    let blocks = parse("Corefile", ".:53 {\n whoami\n}").unwrap();
    let result = configure::<Chain>(&blocks, directives());
    if cfg!(feature = "plugin-whoami") {
        assert!(result.is_ok());
        #[cfg(feature = "plugin-whoami")]
        assert!(result.unwrap()[0].config.whoami.is_some());
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
    assert!(configure::<Chain>(&blocks, directives()).is_err());
}
