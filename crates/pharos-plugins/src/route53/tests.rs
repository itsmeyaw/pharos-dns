use super::{Config, Secret, setup::parse};
use pharos_corefile::{Cursor, Error, lex};
use std::{path::PathBuf, time::Duration};

fn parse_text(text: &str) -> Result<Vec<Config>, Error> {
    parse_text_with(text, false)
}

fn parse_text_with(text: &str, load_config: bool) -> Result<Vec<Config>, Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), load_config)
}

fn one(text: &str) -> Config {
    let mut stanzas = parse_text(text).unwrap_or_else(|error| panic!("{text}: {error}"));
    assert_eq!(stanzas.len(), 1, "{text}");
    stanzas.remove(0)
}

fn error_of(text: &str) -> String {
    parse_text(text).unwrap_err().to_string()
}

// CoreDNS v1.15.0 plugin/route53/setup_test.go TestSetupRoute53.
#[test]
fn setup_accepts_and_rejects_what_coredns_does() {
    for (body, expected_error) in [
        ("route53", false),
        ("route53 :", true),
        ("route53 example.org:12345678", false),
        (
            "route53 example.org:12345678 {\n    aws_access_key\n}",
            true,
        ),
        ("route53 example.org:12345678 { }", false),
        ("route53 example.org:12345678 { }", false),
        ("route53 example.org:12345678 { wat\n}", true),
        (
            "route53 example.org:12345678 {\n    aws_access_key ACCESS_KEY_ID SEKRIT_ACCESS_KEY\n}",
            false,
        ),
        ("route53 example.org:12345678 {\n    fallthrough\n}", false),
        ("route53 example.org:12345678 {\n\t\tcredentials\n\t}", true),
        (
            "route53 example.org:12345678 {\n\t\tcredentials default\n\t}",
            false,
        ),
        (
            "route53 example.org:12345678 {\n\t\tcredentials default credentials\n\t}",
            false,
        ),
        (
            "route53 example.org:12345678 {\n\t\tcredentials default credentials extra-arg\n\t}",
            true,
        ),
        (
            "route53 example.org:12345678 example.org:12345678 {\n\t}",
            true,
        ),
        ("route53 example.org:12345678 {\n\trefresh 90\n}", false),
        ("route53 example.org:12345678 {\n\trefresh 5m\n}", false),
        ("route53 example.org:12345678 {\n\trefresh\n}", true),
        ("route53 example.org:12345678 {\n\trefresh foo\n}", true),
        ("route53 example.org:12345678 {\n\trefresh -1m\n}", true),
        ("route53 example.org {\n\t}", true),
        ("route53 example.org:12345678 {\n    aws_endpoint\n}", true),
        (
            "route53 example.org:12345678 {\n    aws_endpoint https://localhost\n}",
            false,
        ),
    ] {
        let result = parse_text(body);
        assert_eq!(result.is_err(), expected_error, "{body}: {result:?}");
    }
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: the Corefile line order of ZONE:HOSTED_ZONE_ID decides the zone and ID order.
#[test]
fn zones_group_hosted_zone_ids_in_first_seen_order() {
    let config = one("route53 org.:2 gov.:Z1 org.:1 gov.:Z2 a.b:c:d");
    assert_eq!(
        config.zones,
        [
            ("org.".to_owned(), vec!["2".to_owned(), "1".to_owned()]),
            ("gov.".to_owned(), vec!["Z1".to_owned(), "Z2".to_owned()]),
            ("a.b".to_owned(), vec!["c:d".to_owned()]),
        ]
    );
    assert!(one("route53").zones.is_empty());
}

#[test]
fn invalid_and_conflicting_zones_are_reported() {
    for text in [
        "route53 :",
        "route53 :id",
        "route53 example.org:",
        "route53 example.org",
    ] {
        assert!(error_of(text).contains("invalid zone"), "{text}");
    }
    let error = error_of("route53 example.org:1 example.org:1");
    assert!(
        error.contains(r#"conflict zone "example.org:1""#),
        "{error}"
    );
    // The same ZONE with another hosted zone ID is not a conflict.
    assert_eq!(one("route53 example.org:1 example.org:2").zones.len(), 1);
}

#[test]
fn defaults_match_coredns() {
    let config = one("route53 example.org:1");
    assert_eq!(config.refresh, Duration::from_secs(60));
    assert_eq!(config.access_key, None);
    assert_eq!(config.endpoint, None);
    assert_eq!(config.profile, None);
    assert_eq!(config.shared_config_files, None);
    assert!(config.fallthrough.domains.is_empty());
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: a plain integer is seconds, anything else is time.ParseDuration.
#[test]
fn refresh_takes_seconds_or_a_duration() {
    for (value, expected) in [
        ("90", Duration::from_secs(90)),
        ("+90", Duration::from_secs(90)),
        ("5m", Duration::from_secs(300)),
        ("1h30m", Duration::from_secs(5400)),
        ("1.5s", Duration::from_millis(1500)),
        ("250ms", Duration::from_millis(250)),
    ] {
        let text = format!("route53 example.org:1 {{\n  refresh {value}\n}}");
        assert_eq!(one(&text).refresh, expected, "{value}");
    }
    for value in ["0", "-5", "-1m", "0s", "foo", "1x"] {
        let text = format!("route53 example.org:1 {{\n  refresh {value}\n}}");
        assert!(parse_text(&text).is_err(), "{value}");
    }
    let error = error_of("route53 example.org:1 {\n  refresh -1m\n}");
    assert!(
        error.contains("refresh interval must be greater than 0"),
        "{error}"
    );
}

#[test]
fn properties_fill_the_config() {
    let config = one(
        "route53 example.org:1 {\n  aws_access_key AK SK\n  aws_endpoint http://127.0.0.1:9\n  credentials work\n  fallthrough example.org\n  upstream 1.1.1.1 8.8.8.8\n  refresh 5m\n}",
    );
    assert_eq!(
        config.access_key,
        Some(("AK".to_owned(), Secret("SK".to_owned())))
    );
    assert_eq!(config.endpoint.as_deref(), Some("http://127.0.0.1:9"));
    assert_eq!(config.profile.as_deref(), Some("work"));
    assert_eq!(config.shared_config_files, None);
    assert_eq!(config.fallthrough.domains, ["example.org."]);
    assert_eq!(config.refresh, Duration::from_secs(300));
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: `fallthrough` without ZONEs falls through for every name.
#[test]
fn bare_fallthrough_covers_the_root() {
    let config = one("route53 example.org:1 {\n  fallthrough\n}");
    assert_eq!(config.fallthrough.domains, ["."]);
}

#[test]
fn the_secret_stays_out_of_debug_output() {
    let config = one("route53 example.org:1 {\n  aws_access_key AK SEKRIT\n}");
    assert!(!format!("{config:?}").contains("SEKRIT"));
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: only `aws_access_key ID SECRET` with at least two arguments is valid.
#[test]
fn access_key_needs_two_arguments() {
    let error = error_of("route53 example.org:1 {\n  aws_access_key AK\n}");
    assert!(error.contains("invalid access key: '[AK]'"), "{error}");
    assert!(parse_text("route53 example.org:1 {\n  aws_access_key AK SK extra\n}").is_ok());
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: `credentials PROFILE FILE` names the shared config file, and AWS_SDK_LOAD_CONFIG adds ~/.aws/config.
#[test]
fn credentials_file_and_load_config() {
    let text = "route53 example.org:1 {\n  credentials work creds.ini\n}";
    let config = parse_text_with(text, false).unwrap().remove(0);
    assert_eq!(config.profile.as_deref(), Some("work"));
    assert_eq!(
        config.shared_config_files,
        Some(vec![PathBuf::from("creds.ini")])
    );
    let config = parse_text_with(text, true).unwrap().remove(0);
    let files = config.shared_config_files.unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0], PathBuf::from("creds.ini"));
    assert!(files[1].ends_with(".aws/config"), "{files:?}");
}

#[test]
fn a_profile_alone_keeps_the_sdk_default_files() {
    let config = parse_text_with("route53 example.org:1 {\n  credentials work\n}", true)
        .unwrap()
        .remove(0);
    assert_eq!(config.shared_config_files, None);
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: `for c.Next()` makes each `route53` line its own stanza.
#[test]
fn every_route53_line_is_a_stanza() {
    let stanzas = parse_text("route53 a.:1 {\n  refresh 5\n}\nroute53 b.:2").unwrap();
    assert_eq!(stanzas.len(), 2);
    assert_eq!(stanzas[0].zones, [("a.".to_owned(), vec!["1".to_owned()])]);
    assert_eq!(stanzas[0].refresh, Duration::from_secs(5));
    assert_eq!(stanzas[1].zones, [("b.".to_owned(), vec!["2".to_owned()])]);
    assert_eq!(stanzas[1].refresh, Duration::from_secs(60));
}
