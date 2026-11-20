use super::parse;
use pharos_corefile::{Cursor, lex};
use pharos_proto::{Name, Type};

fn config(text: &str, domains: &[&str]) -> Result<super::Config, pharos_corefile::Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), domains, None)
}

#[test]
fn parses_coredns_permissions_and_limits() {
    let parsed = config("dynupdate {\nfile seed.zone\ndatabase updates.db\nallow key.example.org. * A TXT\nallow key.example.org. @ ANY\nmax_records 50\nmax_bytes 6000\nmax_update_records 10\n}", &["example.org"]).unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "host.example.org.".parse().unwrap();
    assert!(parsed.allows(&key, &owner, Type::TXT));
    assert!(!parsed.allows(&key, &owner, Type::AAAA));
    assert!(parsed.allows(&key, &parsed.origin, Type::ANY));
    assert_eq!(parsed.seed, std::path::Path::new("seed.zone"));
    assert_eq!(
        parsed.database.as_deref(),
        Some(std::path::Path::new("updates.db"))
    );
    assert_eq!(
        (
            parsed.max_records,
            parsed.max_bytes,
            parsed.max_update_records
        ),
        (50, 6000, 10)
    );
}

#[test]
fn accepts_relative_allow_names_like_coredns() {
    let parsed = config(
        "dynupdate {\nfile seed.zone\nallow key.example.org host.example.org A\n}",
        &["example.org"],
    )
    .unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "host.example.org.".parse().unwrap();
    assert!(parsed.allows(&key, &owner, Type::A));
}

#[test]
fn allows_explicit_wks_permission_but_rejects_obsolete_spf() {
    let parsed = config(
        "dynupdate {\nfile seed.zone\nallow key.example.org. * TYPE11\n}",
        &["example.org"],
    )
    .unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "host.example.org.".parse().unwrap();
    assert!(parsed.allows(&key, &owner, Type(11)));
    assert!(
        config(
            "dynupdate {\nfile seed.zone\nallow key.example.org. * SPF\n}",
            &["example.org"]
        )
        .is_err()
    );
}

#[test]
fn allows_opaque_rfc3597_policy_types() {
    let parsed = config(
        "dynupdate {\nfile seed.zone\nallow key.example.org. * TYPE65280\n}",
        &["example.org"],
    )
    .unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "host.example.org.".parse().unwrap();
    assert!(parsed.allows(&key, &owner, Type(65280)));
}

#[test]
fn rejects_coredns_unsafe_setup_cases() {
    for body in [
        "allow key.example.org. * A",
        "file seed.zone",
        "file seed.zone\nallow key.example.org. * ATMA",
        "file seed.zone\nallow key.example.org. * UNSPEC",
        "file seed.zone\nallow key.example.org. * * TXT",
        "file seed.zone\nallow * * TXT",
        "file seed.zone\nallow key.example.org. outside.test. TXT",
        "file seed.zone\nallow key.example.org. * A\nmax_records 0",
        "file seed.zone\nallow key.example.org. * A\nfile seed2.zone",
    ] {
        assert!(
            config(&format!("dynupdate {{\n{body}\n}}"), &["example.org"]).is_err(),
            "{body}"
        );
    }
    assert!(
        config(
            "dynupdate {\nfile seed.zone\nallow key.example.org. * A\n}",
            &["example.org", "other.example"]
        )
        .is_err()
    );
    assert!(config("dynupdate example.org. {\nfile seed.zone\nallow key.example.org. host.example.org. ANY\n}", &["example.org", "other.example"]).is_ok());
}

#[test]
fn coredns_invalid_limit_and_duplicate_options() {
    for property in ["max_records", "max_bytes", "max_update_records"] {
        for value in ["0", "-1", "invalid", "999999999999999999999999", "1 2", ""] {
            let text = format!(
                "dynupdate example.org. {{\nfile seed\nallow key.example.org. * A\n{property} {value}\n}}"
            );
            assert!(
                config(&text, &["example.org"]).is_err(),
                "{property} {value}"
            );
        }
        let text = format!(
            "dynupdate example.org. {{\nfile seed\nallow key.example.org. * A\n{property} 1\n{property} 2\n}}"
        );
        assert!(config(&text, &["example.org"]).is_err());
    }
}
