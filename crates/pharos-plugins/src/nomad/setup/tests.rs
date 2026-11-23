use super::*;
use pharos_corefile::lex;

fn parse_text(text: &str) -> Result<Settings, Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens))
}

// CoreDNS v1.15.0 plugin/nomad/setup_test.go TestSetupNomad.
#[test]
fn valid_config_default_ttl() {
    let settings = parse_text(
        "nomad service.nomad {\n    address http://127.0.0.1:4646\n    token test-token\n}",
    )
    .unwrap();
    assert_eq!(settings.filter, "");
    assert_eq!(settings.ttl, 30);
    assert_eq!(settings.token.as_deref(), Some("test-token"));
    assert_eq!(settings.addresses, ["http://127.0.0.1:4646"]);
}

#[test]
fn valid_config_custom_filter_and_ttl() {
    let settings = parse_text(
        "nomad service.nomad {\n    address http://127.0.0.1:4646\n\tfilter \"Tags not contains candidate\"\n    token test-token\n    ttl 60\n}",
    )
    .unwrap();
    assert_eq!(settings.filter, "Tags not contains candidate");
    assert_eq!(settings.ttl, 60);
}

#[test]
fn invalid_ttl_is_rejected() {
    for (ttl, expected) in [
        ("-1", "ttl must be in range [0, 3600]: -1"),
        ("3601", "ttl must be in range [0, 3600]: 3601"),
        ("ten", "error parsing ttl"),
        ("1.5", "error parsing ttl"),
        ("99999999999999999999", "error parsing ttl"),
    ] {
        let error = parse_text(&format!("nomad service.nomad {{\n    ttl {ttl}\n}}"))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{ttl}: {error}");
    }
}

#[test]
fn ttl_bounds_are_accepted() {
    for (ttl, expected) in [("0", 0), ("3600", 3600), ("+7", 7), ("-0", 0)] {
        let settings = parse_text(&format!("nomad service.nomad {{\n    ttl {ttl}\n}}")).unwrap();
        assert_eq!(settings.ttl, expected, "{ttl}");
    }
}

#[test]
fn unknown_property_is_rejected() {
    let error = parse_text(
        "nomad service.nomad {\n    address http://127.0.0.1:4646\n    invalid_property\n}",
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("unknown property 'invalid_property'"),
        "{error}"
    );
}

// CoreDNS v1.15.0 plugin/nomad/setup.go parse: v1.15.0 has no `fallthrough` property.
#[test]
fn fallthrough_is_an_unknown_property() {
    let error = parse_text("nomad service.nomad {\n    fallthrough\n}")
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown property 'fallthrough'"), "{error}");
}

#[test]
fn multiple_addresses_accumulate_across_properties() {
    let settings = parse_text(
        "nomad service.nomad {\n    address http://127.0.0.1:4646 http://127.0.0.2:4646\n    address unix:///run/nomad.sock\n}",
    )
    .unwrap();
    assert_eq!(
        settings.addresses,
        [
            "http://127.0.0.1:4646",
            "http://127.0.0.2:4646",
            "unix:///run/nomad.sock"
        ]
    );
}

#[test]
fn zone_defaults_and_only_first_argument_counts() {
    assert_eq!(parse_text("nomad").unwrap().zone, "service.nomad");
    assert_eq!(
        parse_text("nomad example.nomad").unwrap().zone,
        "example.nomad"
    );
    assert_eq!(
        parse_text("nomad one.nomad two.nomad").unwrap().zone,
        "one.nomad"
    );
}

// CoreDNS v1.15.0 plugin/nomad/setup.go parse: `strings.ToLower(c.Val())`.
#[test]
fn property_names_are_case_insensitive() {
    let settings = parse_text(
        "nomad {\n    ADDRESS http://127.0.0.1:4646\n    Filter x\n    TOKEN t\n    Ttl 5\n}",
    )
    .unwrap();
    assert_eq!(settings.addresses, ["http://127.0.0.1:4646"]);
    assert_eq!(settings.filter, "x");
    assert_eq!(settings.token.as_deref(), Some("t"));
    assert_eq!(settings.ttl, 5);
}

#[test]
fn argument_counts_are_enforced() {
    for (block, expected) in [
        ("address", "at least one address is required"),
        ("filter", "exactly one filter is required"),
        ("filter a b", "exactly one filter is required"),
        ("token", "exactly one token is required"),
        ("token a b", "exactly one token is required"),
        ("ttl", "exactly one ttl value is required"),
        ("ttl 1 2", "exactly one ttl value is required"),
    ] {
        let error = parse_text(&format!("nomad {{\n    {block}\n}}"))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{block}: {error}");
    }
}

#[test]
fn later_scalar_properties_overwrite_earlier_ones() {
    let settings = parse_text(
        "nomad {\n    filter a\n    filter b\n    token x\n    token y\n    ttl 1\n    ttl 2\n}",
    )
    .unwrap();
    assert_eq!(settings.filter, "b");
    assert_eq!(settings.token.as_deref(), Some("y"));
    assert_eq!(settings.ttl, 2);
}
