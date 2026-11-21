use pharos_corefile::{Cursor, lex};
use pharos_proto::Name;

use super::{Azure, Environment, config::DEFAULT_REFRESH, setup};

fn config(text: &str) -> super::Config {
    let tokens = lex("Corefile", text);
    setup::parse(&mut Cursor::new("Corefile", &tokens))
        .unwrap_or_else(|error| panic!("{text}: {error}"))
}

fn azure(text: &str) -> Azure {
    Azure::new(config(text)).unwrap()
}

// CoreDNS v1.15.0 plugin/azure/setup_test.go TestSetup: the accessMap keys are RESOURCE_GROUP+ZONE.
fn access_map(config: &super::Config) -> std::collections::BTreeMap<String, &'static str> {
    config
        .zones
        .iter()
        .map(|spec| {
            (
                format!("{}{}", spec.resource_group, spec.zone),
                if spec.private { "private" } else { "public" },
            )
        })
        .collect()
}

fn parse_text(text: &str) -> Result<super::Config, pharos_corefile::Error> {
    let tokens = lex("Corefile", text);
    setup::parse(&mut Cursor::new("Corefile", &tokens))
}

// CoreDNS v1.15.0 plugin/azure/setup_test.go TestSetup.
#[test]
fn setup_accepts_and_rejects_what_coredns_does() {
    type Access = &'static [(&'static str, &'static str)];
    let cases: [(&str, bool, Option<Access>); 27] = [
        ("azure", false, None),
        ("azure :", true, None),
        ("azure resource_set:zone", false, None),
        ("azure resource_set:zone {\n    tenant\n}", true, None),
        ("azure resource_set:zone {\n    tenant abc\n}", false, None),
        ("azure resource_set:zone {\n    client\n}", true, None),
        ("azure resource_set:zone {\n    client abc\n}", false, None),
        ("azure resource_set:zone {\n    subscription\n}", true, None),
        (
            "azure resource_set:zone {\n    subscription abc\n}",
            false,
            None,
        ),
        ("azure resource_set:zone {\n    foo\n}", true, None),
        ("azure resource_set:zone {\n    refresh 3m\n}", false, None),
        ("azure resource_set:zone {\n    refresh 30\n}", false, None),
        ("azure resource_set:zone {\n    refresh\n}", true, None),
        ("azure resource_set:zone {\n    refresh abc\n}", true, None),
        ("azure resource_set:zone {\n    refresh 0\n}", true, None),
        ("azure resource_set:zone {\n    refresh -5m\n}", true, None),
        (
            "azure resource_set:zone {\n    tenant tenant_id\n    client client_id\n    secret client_secret\n    subscription subscription_id\n    access public\n}",
            false,
            None,
        ),
        ("azure resource_set:zone {\n    fallthrough\n}", false, None),
        (
            "azure resource_set:zone {\n\t\tenvironment AZUREPUBLICCLOUD\n\t}",
            false,
            None,
        ),
        (
            "azure resource_set:zone resource_set:zone {\n\t\t\tfallthrough\n\t\t}",
            true,
            None,
        ),
        (
            "azure resource_set:zone,zone2 {\n\t\t\taccess private\n\t\t}",
            false,
            None,
        ),
        (
            "azure resource-set:zone {\n\t\t\taccess public\n\t\t}",
            false,
            None,
        ),
        (
            "azure resource-set:zone {\n\t\t\taccess foo\n\t\t}",
            true,
            None,
        ),
        (
            "azure rg:zone1 rg:zone2 {\n\t\t\taccess private\n\t\t}",
            false,
            Some(&[("rgzone1", "private"), ("rgzone2", "private")]),
        ),
        (
            "azure rg:zone1 {\n\t\t\taccess private\n\t\t}\n\t\tazure rg:zone2 {\n\t\t}",
            false,
            Some(&[("rgzone1", "private"), ("rgzone2", "public")]),
        ),
        (
            "azure rg:zone1 rg:zone2 {\n\t\t}",
            false,
            Some(&[("rgzone1", "public"), ("rgzone2", "public")]),
        ),
        // Ported expectation: an empty resource group or zone is invalid.
        ("azure :zone", true, None),
    ];
    for (body, expect_error, expected_access) in cases {
        let result = parse_text(body);
        assert_eq!(result.is_err(), expect_error, "{body}: {result:?}");
        if let (Ok(config), Some(expected)) = (result, expected_access) {
            let expected = expected
                .iter()
                .map(|&(key, access)| (key.to_owned(), access))
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(access_map(&config), expected, "{body}");
        }
    }
}

#[test]
fn setup_reads_credentials_environment_refresh_and_fallthrough() {
    let config = config(
        "azure rg:example.org rg2:other.example {\n tenant t\n client c\n secret s\n subscription sub\n environment azureusgovernmentcloud\n refresh 90\n fallthrough example.org other.example\n access private\n}",
    );
    assert_eq!(
        (
            config.tenant.as_str(),
            config.client.as_str(),
            config.secret.expose(),
            config.subscription.as_str()
        ),
        ("t", "c", "s", "sub")
    );
    assert_eq!(config.environment, Environment::UsGovernmentCloud);
    assert_eq!(config.refresh, std::time::Duration::from_secs(90));
    assert_eq!(
        config.fallthrough.domains,
        ["example.org.", "other.example."]
    );
    assert_eq!(
        config
            .zones
            .iter()
            .map(|spec| (
                spec.resource_group.as_str(),
                spec.zone.as_str(),
                spec.private
            ))
            .collect::<Vec<_>>(),
        [("rg", "example.org", true), ("rg2", "other.example", true)]
    );
}

#[test]
fn setup_defaults_and_a_bare_directive() {
    let config = config("azure");
    assert!(config.zones.is_empty());
    assert_eq!(config.refresh, DEFAULT_REFRESH);
    assert_eq!(config.environment, Environment::PublicCloud);
    assert!(config.fallthrough.domains.is_empty());
}

#[test]
fn refresh_takes_integers_as_seconds_and_go_durations() {
    for (value, seconds) in [
        ("30", 30.0),
        ("3m", 180.0),
        ("1h30m", 5400.0),
        ("500ms", 0.5),
    ] {
        let config = config(&format!("azure a:b {{\n refresh {value}\n}}"));
        assert_eq!(config.refresh.as_secs_f64(), seconds, "{value}");
    }
}

#[test]
fn environment_selects_the_cloud_endpoints() {
    for (name, resource_manager, active_directory) in [
        (
            "AZUREPUBLICCLOUD",
            "https://management.azure.com/",
            "https://login.microsoftonline.com/",
        ),
        (
            "AZURECHINACLOUD",
            "https://management.chinacloudapi.cn/",
            "https://login.chinacloudapi.cn/",
        ),
        (
            "AZUREGERMANCLOUD",
            "https://management.microsoftazure.de/",
            "https://login.microsoftonline.de/",
        ),
        (
            "AZUREUSGOVERNMENTCLOUD",
            "https://management.usgovcloudapi.net/",
            "https://login.microsoftonline.us/",
        ),
    ] {
        let config = config(&format!("azure a:b {{\n environment {name}\n}}"));
        assert_eq!(
            config.environment.resource_manager_endpoint(),
            resource_manager,
            "{name}"
        );
        assert_eq!(
            config.environment.active_directory_endpoint(),
            active_directory,
            "{name}"
        );
    }
    assert!(parse_text("azure a:b {\n environment AZURESTACKCLOUD\n}").is_err());
    assert!(parse_text("azure a:b {\n environment nowhere\n}").is_err());
}

#[test]
fn access_applies_only_to_the_zones_of_its_own_line() {
    let config = config("azure rg:a.example {\n access private\n}\nazure rg:b.example");
    assert_eq!(
        access_map(&config).into_iter().collect::<Vec<_>>(),
        [
            ("rga.example".to_owned(), "private"),
            ("rgb.example".to_owned(), "public")
        ]
    );
}

#[test]
fn debug_output_never_contains_the_secret() {
    let text = "azure rg:example.org {\n tenant t\n client c\n secret hunter2-distinctive\n}";
    let config = config(text);
    let azure = Azure::new(config.clone()).unwrap();
    for debug in [
        format!("{config:?}"),
        format!("{config:#?}"),
        format!("{azure:?}"),
        format!("{azure:#?}"),
        format!("{:?}", config.secret),
    ] {
        assert!(!debug.contains("hunter2-distinctive"), "{debug}");
    }
    let error = parse_text("azure rg:example.org {\n secret hunter2-distinctive\n bogus\n}")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("hunter2-distinctive"), "{error}");
}

#[test]
fn zones_are_configured_unloaded_with_sorted_unique_names() {
    let azure = azure("azure rg:b.example rg2:b.example rg:a.example");
    assert_eq!(
        azure
            .zone_names()
            .iter()
            .map(Name::to_string)
            .collect::<Vec<_>>(),
        ["a.example.", "b.example."]
    );
    assert_eq!(azure.hosted_zones().len(), 3);
    assert!(
        azure
            .hosted_zones()
            .iter()
            .all(|hosted| hosted.current.load().is_none())
    );
}
