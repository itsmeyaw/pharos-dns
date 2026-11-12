#![cfg(feature = "plugin-secondary")]

#[test]
fn secondary_feature_exposes_shared_zone() {
    let _: Option<pharos_plugins::zone::ZoneHolder> = None;
}
