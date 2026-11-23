use std::time::Duration;

use pharos_corefile::lex;

use super::*;

fn parse_text(text: &str) -> Result<CloudDns, Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens))
}

fn instance(clouddns: &CloudDns, index: usize) -> &Instance {
    &clouddns.shared.instances[index]
}

fn credentials(dir: &tempfile::TempDir, name: &str, body: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    path.display().to_string()
}

// CoreDNS v1.15.0 plugin/clouddns/setup_test.go TestSetupCloudDNS: every row, in order.
#[test]
fn setup_accepts_and_rejects_what_coredns_does() {
    let dir = tempfile::tempdir().unwrap();
    let valid = credentials(&dir, "valid_creds.json", r#"{"type": "service_account"}"#);
    let invalid_type = credentials(&dir, "invalid_type_creds.json", r#"{"type": "bad_type"}"#);
    let empty = credentials(&dir, "empty_creds.json", "{}");
    let invalid_json = credentials(&dir, "invalid_json_creds.json", "{");
    let zone = "example.org.:example-project:zone-name";
    let block = |body: &str| format!("clouddns {zone} {{\n{body}\n}}");
    let cases: Vec<(String, bool)> = vec![
        ("clouddns".to_owned(), false),
        ("clouddns :".to_owned(), true),
        ("clouddns ::".to_owned(), true),
        (format!("clouddns {zone}"), false),
        (format!("clouddns {zone} {{ }}"), false),
        (
            "clouddns example.org.:example-project: { }".to_owned(),
            true,
        ),
        (block("wat"), true),
        (block("fallthrough"), false),
        (block("credentials"), true),
        (block("refresh 3m"), false),
        (block("refresh 30"), false),
        (block("refresh"), true),
        (block("refresh abc"), true),
        (block("refresh 0"), true),
        (block("refresh -5m"), true),
        (block("endpoint https://dns.googleapis.com"), false),
        (block("endpoint"), true),
        (format!("clouddns {zone} {zone} {{\n}}"), true),
        ("clouddns example.org {\n}".to_owned(), true),
        (block(&format!("credentials {valid}")), false),
        (block(&format!("credentials {invalid_type}")), true),
        (block(&format!("credentials {empty}")), true),
        (block(&format!("credentials {invalid_json}")), true),
    ];
    for (body, expect_error) in cases {
        let result = parse_text(&body);
        assert_eq!(result.is_err(), expect_error, "{body}: {:?}", result.err());
    }
}

#[test]
fn credential_errors_name_the_file_and_the_problem() {
    let dir = tempfile::tempdir().unwrap();
    for (body, expected) in [
        (
            r#"{"type": "bad_type"}"#,
            "unknown credential type: bad_type",
        ),
        ("{}", "missing `type` field in credential"),
    ] {
        let path = credentials(&dir, "creds.json", body);
        let text = format!("clouddns a.:p:z {{\ncredentials {path}\n}}");
        let error = parse_text(&text).unwrap_err().to_string();
        assert!(error.contains(&path) && error.contains(expected), "{error}");
    }
    let missing = dir.path().join("absent.json");
    let text = format!("clouddns a.:p:z {{\ncredentials {}\n}}", missing.display());
    assert!(
        parse_text(&text)
            .unwrap_err()
            .to_string()
            .contains("invalid credentials file")
    );
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: every one of the four credential types is accepted.
#[test]
fn every_credential_type_coredns_names_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    for kind in [
        "service_account",
        "authorized_user",
        "impersonated_service_account",
        "external_account",
    ] {
        let path = credentials(&dir, "creds.json", &format!(r#"{{"type": "{kind}"}}"#));
        parse_text(&format!("clouddns a.:p:z {{\ncredentials {path}\n}}")).unwrap();
    }
}

#[test]
fn defaults_follow_coredns() {
    let clouddns = parse_text("clouddns example.org.:p:z").unwrap();
    let line = instance(&clouddns, 0);
    assert_eq!(line.refresh, Duration::from_secs(60));
    assert_eq!(line.endpoint, "https://dns.googleapis.com");
    assert!(line.credentials.is_none() && line.fallthrough.is_empty());
}

#[test]
fn a_bare_directive_serves_no_zone() {
    let clouddns = parse_text("clouddns").unwrap();
    assert!(instance(&clouddns, 0).names.is_empty());
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: an integer is seconds, anything else a Go duration.
#[test]
fn refresh_is_seconds_or_a_duration() {
    for (text, expected) in [
        ("30", Duration::from_secs(30)),
        ("+30", Duration::from_secs(30)),
        ("3m", Duration::from_secs(180)),
        ("1h30m", Duration::from_secs(5400)),
        ("50ms", Duration::from_millis(50)),
        ("1.5s", Duration::from_millis(1500)),
    ] {
        let clouddns = parse_text(&format!("clouddns a.:p:z {{\nrefresh {text}\n}}")).unwrap();
        assert_eq!(instance(&clouddns, 0).refresh, expected, "{text}");
    }
    for text in ["0", "-1", "-5m", "0s", "abc", "5x", "1e3"] {
        assert!(
            parse_text(&format!("clouddns a.:p:z {{\nrefresh {text}\n}}")).is_err(),
            "{text}"
        );
    }
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: several hosted zones may share one DNS name, in configuration order.
#[test]
fn hosted_zones_group_by_dns_name_in_order() {
    let clouddns =
        parse_text("clouddns org:p1:first com.:p2:other org.:p1:second ORG.:p3:third:with:colons")
            .unwrap();
    let names = &instance(&clouddns, 0).names;
    let shown: Vec<_> = names
        .iter()
        .map(|name| {
            let hosted: Vec<_> = name
                .hosted
                .iter()
                .map(|hosted| format!("{}:{}", hosted.project, hosted.zone))
                .collect();
            (name.apex.to_string(), hosted)
        })
        .collect();
    assert_eq!(
        shown,
        [
            (
                "org.".to_owned(),
                vec![
                    "p1:first".to_owned(),
                    "p1:second".to_owned(),
                    "p3:third:with:colons".to_owned()
                ]
            ),
            ("com.".to_owned(), vec!["p2:other".to_owned()]),
        ]
    );
}

#[test]
fn zone_arguments_need_three_non_empty_parts() {
    for arg in ["a.:p", "a.::z", ":p:z", "a.:p:", "a.", ""] {
        let error = parse_text(&format!("clouddns a.:p:z {arg}")).err();
        // The empty argument is just no argument.
        assert_eq!(error.is_some(), !arg.is_empty(), "{arg:?}");
        if let Some(error) = error {
            assert!(error.to_string().contains("invalid zone"), "{arg}: {error}");
        }
    }
    let error = parse_text("clouddns a.:p:z a.:p:z").unwrap_err();
    assert!(error.to_string().contains("conflict zone"), "{error}");
    // Different hosted zones of one name are not a conflict.
    parse_text("clouddns a.:p:z a.:p:y a.:q:z").unwrap();
}

// CoreDNS v1.15.0 plugin/pkg/fall: no argument means every zone; the last `fallthrough` line wins.
#[test]
fn fallthrough_defaults_to_every_zone() {
    let all = parse_text("clouddns a.:p:z {\nfallthrough\n}").unwrap();
    assert_eq!(
        instance(&all, 0).fallthrough,
        [".".parse::<Name>().unwrap()]
    );
    let some = parse_text("clouddns a.:p:z {\nfallthrough example.gov in-addr.arpa.\n}").unwrap();
    assert_eq!(
        instance(&some, 0).fallthrough,
        [
            "example.gov.".parse::<Name>().unwrap(),
            "in-addr.arpa.".parse().unwrap()
        ]
    );
    let last = parse_text("clouddns a.:p:z {\nfallthrough a.\nfallthrough b.\n}").unwrap();
    assert_eq!(
        instance(&last, 0).fallthrough,
        ["b.".parse::<Name>().unwrap()]
    );
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: `upstream` and its arguments are accepted and ignored.
#[test]
fn upstream_is_accepted_and_ignored() {
    parse_text("clouddns a.:p:z {\nupstream\nupstream 10.0.0.1 10.0.0.2\n}").unwrap();
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: `for c.Next()` makes every line its own handler.
#[test]
fn every_line_is_its_own_instance() {
    let clouddns = parse_text(
        "clouddns a.:p:z {\nrefresh 5s\n}\nclouddns b.:p:y {\nendpoint http://127.0.0.1:1\nfallthrough\n}",
    )
    .unwrap();
    assert_eq!(clouddns.shared.instances.len(), 2);
    assert_eq!(instance(&clouddns, 0).refresh, Duration::from_secs(5));
    assert_eq!(instance(&clouddns, 1).refresh, Duration::from_secs(60));
    assert_eq!(instance(&clouddns, 1).endpoint, "http://127.0.0.1:1");
    assert!(instance(&clouddns, 0).fallthrough.is_empty());
    assert_eq!(instance(&clouddns, 1).fallthrough.len(), 1);
}
