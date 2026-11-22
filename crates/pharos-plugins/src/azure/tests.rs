use std::sync::atomic::{AtomicUsize, Ordering};

use pharos_corefile::{Cursor, configure, lex, parse as parse_corefile};
use pharos_proto::{Class, Message, MessageBuilder, Name, Rcode, Section, Type, zone::ZoneParser};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol, Transport};

use super::{Azure, Environment, config::DEFAULT_REFRESH, setup};
use crate::{Chain, zone::Zone};

pub(super) fn config(text: &str) -> super::Config {
    let tokens = lex("Corefile", text);
    setup::parse(&mut Cursor::new("Corefile", &tokens))
        .unwrap_or_else(|error| panic!("{text}: {error}"))
}

fn azure(text: &str) -> Azure {
    Azure::new(config(text)).unwrap()
}

fn root() -> Name {
    ".".parse().unwrap()
}

fn zone(apex: &str, text: &str) -> Zone {
    let apex: Name = apex.parse().unwrap();
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "azure-test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    Zone::from_records(apex, records).unwrap()
}

// The apex NS set is required by Zone::from_records; every test Zone carries one.
fn simple_zone(apex: &str, extra: &str) -> Zone {
    zone(
        apex,
        &format!(
            "{apex} 300 IN SOA ns.{apex} hostmaster.{apex} 1 3600 300 86400 60\n{apex} 300 IN NS ns.{apex}\n{extra}"
        ),
    )
}

/// CoreDNS v1.15.0 plugin/azure/azure_test.go testHandler: only `example.gov.` has an answer.
struct TestNext<'a>(&'a AtomicUsize);

impl Next for TestNext<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        let question = cx.query.questions().next().unwrap();
        if !question
            .name
            .to_string()
            .eq_ignore_ascii_case("example.gov.")
        {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        }
        let mut builder = MessageBuilder::new(cx.response, 1232, cx.query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::A,
                Class::IN,
                300,
                &[2, 4, 6, 8],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

pub(super) struct Reply {
    pub(super) outcome: Outcome,
    response: Vec<u8>,
    pub(super) next_calls: usize,
}

impl Reply {
    pub(super) fn message(&self) -> Message<'_> {
        Message::parse(&self.response).unwrap()
    }

    /// The Answer section in miekg/dns RR.String form.
    pub(super) fn answers(&self) -> Vec<String> {
        self.message().answers().map(|rr| render(&rr)).collect()
    }

    fn authorities(&self) -> Vec<String> {
        self.message().authorities().map(|rr| render(&rr)).collect()
    }
}

fn render(rr: &pharos_proto::Record<'_>) -> String {
    format!(
        "{}\t{}\tIN\t{}\t{}",
        rr.name,
        rr.ttl,
        rr.rtype,
        rr.data().unwrap()
    )
}

fn query(qname: &str, qtype: Type) -> Vec<u8> {
    let name = Name::parse(qname, &root()).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 7, 0x0100).unwrap();
    builder
        .question(name.as_name_ref(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    wire
}

pub(super) async fn ask(azure: &Azure, qname: &str, qtype: Type) -> Reply {
    let wire = query(qname, qtype);
    let calls = AtomicUsize::new(0);
    let domain = root();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = azure.serve(&mut cx, TestNext(&calls)).await;
    drop(cx);
    Reply {
        outcome,
        response,
        next_calls: calls.load(Ordering::SeqCst),
    }
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

/// CoreDNS v1.15.0 plugin/azure/azure_test.go TestAzure.
///
/// The Go zone puts its SOA and NS at `org.` while the zone is `example.org.`; Pharos needs both at
/// the apex, so they move to `example.org.` and the SOA expectation changes owner with them.
#[tokio::test]
async fn serves_what_coredns_azure_serves() {
    let azure = azure("azure rg:example.org");
    azure.hosted_zones()[0].publish(zone(
        "example.org.",
        "example.org.  300 IN  A   1.2.3.4
example.org.  300 IN  AAAA   2001:db8:85a3::8a2e:370:7334
www.example.org.  300 IN  A   1.2.3.4
www.example.org.  300 IN  A   1.2.3.4
example.org.\t172800\tIN\tNS\tns3-06.azure-dns.org.
example.org.\t300\tIN\tSOA\tns1-06.azure-dns.com. azuredns-hostmaster.microsoft.com. 1 3600 300 2419200 300
cname.example.org. 300 IN CNAME example.org.
mail.example.org. 300 IN MX 10 mailserver.example.com.
ptr.example.org. 300 IN PTR www.ptr-example.com.
example.org. 300 IN SRV 1 10 5269 srv-1.example.com.
example.org. 300 IN SRV 1 10 5269 srv-2.example.com.
txt.example.org. 300 IN TXT \"TXT for example.org\"
",
    ));
    let cases: [(&str, Type, &[&str]); 11] = [
        (
            "example.org.",
            Type::A,
            &["example.org.\t300\tIN\tA\t1.2.3.4"],
        ),
        (
            "example.org",
            Type::AAAA,
            &["example.org.\t300\tIN\tAAAA\t2001:db8:85a3::8a2e:370:7334"],
        ),
        (
            "example.org",
            Type::SOA,
            &[
                "example.org.\t300\tIN\tSOA\tns1-06.azure-dns.com. azuredns-hostmaster.microsoft.com. 1 3600 300 2419200 300",
            ],
        ),
        ("badexample.com", Type::A, &[]),
        (
            "example.gov",
            Type::A,
            &["example.gov.\t300\tIN\tA\t2.4.6.8"],
        ),
        (
            "example.org",
            Type::SRV,
            &[
                "example.org.\t300\tIN\tSRV\t1 10 5269 srv-1.example.com.",
                "example.org.\t300\tIN\tSRV\t1 10 5269 srv-2.example.com.",
            ],
        ),
        (
            "cname.example.org.",
            Type::CNAME,
            &["cname.example.org.\t300\tIN\tCNAME\texample.org."],
        ),
        (
            "cname.example.org.",
            Type::A,
            &[
                "cname.example.org.\t300\tIN\tCNAME\texample.org.",
                "example.org.\t300\tIN\tA\t1.2.3.4",
            ],
        ),
        (
            "mail.example.org.",
            Type::MX,
            &["mail.example.org.\t300\tIN\tMX\t10 mailserver.example.com."],
        ),
        (
            "ptr.example.org.",
            Type::PTR,
            &["ptr.example.org.\t300\tIN\tPTR\twww.ptr-example.com."],
        ),
        (
            "txt.example.org.",
            Type::TXT,
            &["txt.example.org.\t300\tIN\tTXT\t\"TXT for example.org\""],
        ),
    ];
    for (qname, qtype, expected) in cases {
        let reply = ask(&azure, qname, qtype).await;
        let outside = qname.starts_with("badexample") || qname.starts_with("example.gov");
        // Outside every configured zone the Query goes to the next Plugin, once.
        assert_eq!(reply.next_calls, usize::from(outside), "{qname} {qtype}");
        match qname {
            "badexample.com" => assert_eq!(reply.outcome, Outcome::Unanswered(Rcode::SERVFAIL)),
            _ => {
                assert_eq!(reply.outcome, Outcome::Response, "{qname} {qtype}");
                assert_eq!(reply.message().rcode(), Rcode::NOERROR, "{qname} {qtype}");
                assert_eq!(reply.answers(), expected, "{qname} {qtype}");
            }
        }
    }
}

#[tokio::test]
async fn answers_authoritatively_and_names_missing_records() {
    let azure = azure("azure rg:example.org");
    azure.hosted_zones()[0].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.1\n"));
    let reply = ask(&azure, "www.example.org", Type::A).await;
    assert!(reply.message().aa());
    let nodata = ask(&azure, "www.example.org", Type::AAAA).await;
    assert_eq!(
        (nodata.message().rcode(), nodata.answers().len()),
        (Rcode::NOERROR, 0)
    );
    assert_eq!(nodata.authorities().len(), 1);
    let nxdomain = ask(&azure, "nope.example.org", Type::A).await;
    assert_eq!(nxdomain.message().rcode(), Rcode::NXDOMAIN);
    assert_eq!(nxdomain.next_calls, 0);
}

#[tokio::test]
async fn longest_matching_zone_name_serves() {
    let azure = azure("azure rg:example.org rg:sample.example.org");
    azure.hosted_zones()[0].publish(simple_zone(
        "example.org.",
        "host.sample 60 IN A 192.0.2.1\n",
    ));
    azure.hosted_zones()[1].publish(simple_zone(
        "sample.example.org.",
        "host 60 IN A 192.0.2.2\n",
    ));
    let reply = ask(&azure, "host.sample.example.org", Type::A).await;
    assert_eq!(
        reply.answers(),
        ["host.sample.example.org.\t60\tIN\tA\t192.0.2.2"]
    );
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestUnloadedZoneFallthrough.
#[tokio::test]
async fn unloaded_zone_gets_servfail_unless_fallthrough_names_it() {
    let azure = azure(
        "azure rg:healthy.example rg:missing.example {\n access private\n fallthrough missing.example\n}",
    );
    let reply = ask(&azure, "www.healthy.example", Type::A).await;
    assert_eq!(
        (reply.outcome, reply.next_calls),
        (Outcome::Unanswered(Rcode::SERVFAIL), 0)
    );
    let reply = ask(&azure, "www.missing.example", Type::A).await;
    assert_eq!(reply.next_calls, 1);
    let reply = ask(&azure, "www.unrelated.example", Type::A).await;
    assert_eq!(reply.next_calls, 1);

    azure.hosted_zones()[0].publish(simple_zone("healthy.example.", "www 60 IN A 192.0.2.10\n"));
    let reply = ask(&azure, "www.healthy.example", Type::A).await;
    assert_eq!(
        reply.answers(),
        ["www.healthy.example.\t60\tIN\tA\t192.0.2.10"]
    );
    let reply = ask(&azure, "www.missing.example", Type::A).await;
    assert_eq!(reply.next_calls, 1);
}

#[tokio::test]
async fn fallthrough_applies_to_names_a_loaded_zone_lacks() {
    let azure = azure("azure rg:example.org {\n fallthrough\n}");
    azure.hosted_zones()[0].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.1\n"));
    let reply = ask(&azure, "nope.example.org", Type::A).await;
    assert_eq!(reply.next_calls, 1);
    let nodata = ask(&azure, "www.example.org", Type::AAAA).await;
    assert_eq!(
        (nodata.next_calls, nodata.message().rcode()),
        (0, Rcode::NOERROR)
    );
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestSameZoneInMultipleResourceGroups.
#[tokio::test]
async fn an_unloaded_copy_of_a_zone_does_not_mask_a_loaded_one() {
    let azure = azure("azure missing-rg:healthy.example rg:healthy.example {\n access private\n}");
    azure.hosted_zones()[1].publish(simple_zone("healthy.example.", "www 60 IN A 192.0.2.10\n"));
    let reply = ask(&azure, "www.healthy.example", Type::A).await;
    assert_eq!(
        reply.answers(),
        ["www.healthy.example.\t60\tIN\tA\t192.0.2.10"]
    );
}

#[tokio::test]
async fn the_first_loaded_copy_holding_the_name_answers() {
    let azure = azure("azure one:example.org two:example.org");
    azure.hosted_zones()[0].publish(simple_zone(
        "example.org.",
        "a 60 IN A 192.0.2.1\nboth 60 IN A 192.0.2.2\n",
    ));
    azure.hosted_zones()[1].publish(simple_zone(
        "example.org.",
        "b 60 IN A 192.0.2.3\nboth 60 IN A 192.0.2.4\n",
    ));
    assert_eq!(
        ask(&azure, "a.example.org", Type::A).await.answers(),
        ["a.example.org.\t60\tIN\tA\t192.0.2.1"]
    );
    assert_eq!(
        ask(&azure, "b.example.org", Type::A).await.answers(),
        ["b.example.org.\t60\tIN\tA\t192.0.2.3"]
    );
    assert_eq!(
        ask(&azure, "both.example.org", Type::A).await.answers(),
        ["both.example.org.\t60\tIN\tA\t192.0.2.2"]
    );
    assert_eq!(
        ask(&azure, "none.example.org", Type::A)
            .await
            .message()
            .rcode(),
        Rcode::NXDOMAIN
    );
}

// A refresh may swap a copy between the existence check and the answer; the Zone that was checked is the one served.
#[test]
fn select_returns_the_zone_it_checked() {
    let azure = azure("azure one:example.org two:example.org");
    azure.hosted_zones()[0].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.1\n"));
    azure.hosted_zones()[1].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.2\n"));
    let apex: Name = "example.org.".parse().unwrap();
    let name = Name::parse("www.example.org", &root()).unwrap();
    let picked = azure.select(&apex, name.as_wire()).unwrap();
    azure.hosted_zones()[0].publish(simple_zone("example.org.", ""));
    assert!(picked.exists(name.as_wire()));
}

#[tokio::test]
async fn a_new_snapshot_replaces_the_old_one_atomically() {
    let azure = azure("azure rg:example.org");
    azure.hosted_zones()[0].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.1\n"));
    azure.hosted_zones()[0].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.2\n"));
    let reply = ask(&azure, "www.example.org", Type::A).await;
    assert_eq!(reply.answers(), ["www.example.org.\t60\tIN\tA\t192.0.2.2"]);
}

async fn serve_chain(chain: &Chain, qname: &str) -> (Outcome, Vec<u8>) {
    let wire = query(qname, Type::A);
    let domain = root();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = chain.serve(&mut cx).await;
    drop(cx);
    (outcome, response)
}

pub(super) fn configured(
    text: &str,
) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, pharos_corefile::Error> {
    let blocks = parse_corefile("Corefile", text)?;
    configure::<Chain>(&blocks, crate::directives())
}

#[tokio::test]
async fn the_corefile_installs_the_plugin_in_the_chain() {
    let blocks = configured(
        "example.org:53 {\n azure rg:example.org {\n  tenant t\n  secret hunter2-distinctive\n  access private\n }\n azure rg2:example.org\n}",
    )
    .unwrap();
    let azure = blocks[0].config.azure.as_ref().unwrap();
    // CoreDNS v1.15.0 plugin/azure/setup.go parse: every `azure` line of one Server Block joins one handler.
    assert_eq!(azure.hosted_zones().len(), 2);
    assert_eq!(azure.config().tenant, "t");
    assert!(azure.hosted_zones()[0].spec.private && !azure.hosted_zones()[1].spec.private);

    let (outcome, _) = serve_chain(&blocks[0].config, "www.example.org").await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
    azure.hosted_zones()[0].publish(simple_zone("example.org.", "www 60 IN A 192.0.2.1\n"));
    let (outcome, response) = serve_chain(&blocks[0].config, "www.example.org").await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().answers().count(), 1);
}

#[test]
fn the_corefile_rejects_what_parse_rejects() {
    for text in [
        "example.org:53 {\n azure rg\n}",
        "example.org:53 {\n azure rg:example.org {\n  refresh 0\n }\n}",
        "example.org:53 {\n azure rg:example.org {\n  environment nowhere\n }\n}",
    ] {
        assert!(configured(text).is_err(), "{text}");
    }
}
