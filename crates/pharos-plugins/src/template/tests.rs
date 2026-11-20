use super::*;
fn configure(
    text: &str,
) -> Result<Vec<pharos_corefile::BlockContext<crate::Chain>>, pharos_corefile::Error> {
    let blocks = pharos_corefile::parse("Corefile", text)?;
    pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives())
}
#[test]
fn setup_checks_rcodes() {
    for (rcode, valid) in [
        ("NOTIMP", true),
        ("NOTIMPL", true),
        ("BADSIG", true),
        ("BADVERS", false),
    ] {
        assert_eq!(
            configure(&format!(". {{\n template IN A {{\n rcode {rcode}\n }}\n}}")).is_ok(),
            valid
        );
    }
}
#[test]
fn zone_matching_respects_escaped_dots() {
    assert!(!in_zone(r"foo\.example.", "example."));
    assert!(in_zone(r"foo\\.example.", "example."));
}
#[test]
fn workspace_recovers_after_panics_with_taken_slots() {
    let pattern = format!("^{}(?P<host>x)[.]$", "()".repeat(128));
    let variables = (0..40)
        .map(|i| {
            if i == 0 {
                "var v0 group('host')\n".to_owned()
            } else {
                format!("var v{i} v{}\n", i - 1)
            }
        })
        .collect::<String>();
    let text = format!(
        ". {{\n template IN A {{\n match {pattern}\n {variables} answer \"{{{{ .Name }}}} 60 IN TXT \\\"{{{{ index .Match 129 }}}}:{{{{ .Group.129 }}}}:{{{{ .Var.v39 }}}}\\\"\"\n }}\n}}"
    );
    let config = configure(&text).unwrap();
    let template = config[0].config.template.as_ref().unwrap();
    let pool = template.rules[0].workspace.as_ref().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let context = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    for stage in 0..5 {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.with(|workspace| {
                let _matches = (stage <= 2).then(|| std::mem::take(&mut workspace.matches));
                let _groups = (1..=3)
                    .contains(&stage)
                    .then(|| std::mem::take(&mut workspace.groups));
                let _variables =
                    (stage == 2 || stage == 4).then(|| std::mem::take(&mut workspace.variables));
                panic!("simulated query panic");
            });
        }));
        assert!(panic.is_err());
        let MatchResult::Hit(hit) = template.select(&context) else {
            panic!("query did not recover")
        };
        assert_eq!(hit.records[0].1.rdata, b"\x05x:x:x");
        pool.with(|workspace| {
            assert_eq!(workspace.variables.len(), 40);
            assert_eq!(workspace.matches.len(), 130);
            assert_eq!(workspace.groups.len(), 260);
        });
    }
}
#[test]
fn many_function_variables_fit_a_small_worker_stack() {
    let variables = (0..400)
        .map(|i| {
            if i == 0 {
                "var v0 name\n".to_owned()
            } else {
                format!("var v{i} v{}\n", i - 1)
            }
        })
        .collect::<String>();
    let text = format!(
        ".:53 {{\n template IN A {{\n {variables} answer \"{{{{ .Name }}}} 60 IN TXT \\\"{{{{ call .Var.v399 }}}}\\\"\"\n }}\n}}"
    );
    let configured = configure(&text).unwrap();
    let template = configured[0].config.template.as_ref().unwrap();
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn_scoped(scope, || {
                let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
                let root: Name = ".".parse().unwrap();
                let mut response = Vec::with_capacity(512);
                let mut slots = [];
                let context = Context {
                    query: Message::parse(wire).unwrap(),
                    client: "127.0.0.1:1234".parse().unwrap(),
                    local: "127.0.0.1:53".parse().unwrap(),
                    transport: pharos_server::Transport::Dns,
                    protocol: Protocol::Udp,
                    domain: &root,
                    metadata: pharos_server::Metadata::new(&mut slots),
                    response: &mut response,
                    max_response_size: 512,
                };
                let MatchResult::Hit(hit) = template.select(&context) else {
                    panic!("template did not match")
                };
                assert_eq!(hit.records[0].1.rdata, b"\x02x.");
            })
            .unwrap()
            .join()
            .unwrap();
    });
}
#[test]
fn workspace_is_stable_and_distinct_on_each_worker() {
    let configured = configure(". {\n template IN A\n}").unwrap();
    let workspace = configured[0].config.template.as_ref().unwrap().rules[0]
        .workspace
        .as_ref()
        .unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            workspace.with(|state| {
                let address = std::ptr::from_ref(state) as usize;
                barrier.wait();
                address
            })
        });
        let two = scope.spawn(|| {
            workspace.with(|state| {
                let address = std::ptr::from_ref(state) as usize;
                barrier.wait();
                address
            })
        });
        assert_ne!(one.join().unwrap(), two.join().unwrap());
    });
    let first = workspace.with(|state| std::ptr::from_ref(state) as usize);
    let second = workspace.with(|state| std::ptr::from_ref(state) as usize);
    assert_eq!(first, second);
}
#[test]
fn readme_rule_workspace_payload_sizes() {
    fn payload(workspace: &RuleWorkspace) -> usize {
        use std::mem::size_of;
        size_of::<RuleWorkspace>()
            + workspace.scratch.capacity()
            + workspace.render_scratch.capacity()
            + workspace.matchers.capacity() * size_of::<MatcherState>()
            + workspace.variables.capacity() * size_of::<(&str, Value<'_>)>()
            + workspace.matches.capacity() * size_of::<&str>()
            + workspace.groups.capacity() * size_of::<(&str, &str)>()
            + workspace
                .matchers
                .iter()
                .map(|state| {
                    state.cache.memory_usage() + std::mem::size_of_val(state.captures.slots())
                })
                .sum::<usize>()
    }
    for ((name, options), expected) in [
            ("nxdomain", "rcode NXDOMAIN"),
            (
                "address",
                "match (^|[.])ip-(?P<a>[0-9]*)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$",
            ),
            (
                "reverse",
                "match ^(?P<d>[0-9]*)[.](?P<c>[0-9]*)[.](?P<b>[0-9]*)[.](?P<a>[0-9]*)[.]in-addr[.]arpa[.]$",
            ),
            (
                "hex",
                "match ^ip0a(?P<b>[a-f0-9]{2})(?P<c>[a-f0-9]{2})(?P<d>[a-f0-9]{2})[.]example[.]$",
            ),
            (
                "lan",
                "match ^(?P<ip>[0-9]{1,3}(-[0-9]{1,3}){3})[.](?P<id>[a-z2-7]{26})[.]example[.]com[.]$\nvar ip replace(group('ip'), '-', '.')",
            ),
            (
                "patterns",
                "match ^ip-(?P<a>10)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]dc[.]example[.]$\nmatch ^(?P<a>[0-9]*)[.](?P<b>[0-9]*)[.](?P<c>[0-9]*)[.](?P<d>[0-9]*)[.]ext[.]example[.]$",
            ),
            (
                "authority/mx",
                "match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$",
            ),
            ("cname", r#"match "^foogle\.com\.$""#),
            ("search", r#"match "example\.com\.(dc1\.example\.com\.)$""#),
        ]
        .into_iter()
        .zip([
            132_270, 140_974, 138_798, 136_302, 143_278, 145_982, 136_878, 132_366, 134_606,
        ]) {
            let configured =
                configure(&format!(". {{\n template IN A {{\n {options}\n }}\n}}")).unwrap();
            let rule = &configured[0].config.template.as_ref().unwrap().rules[0];
            let bytes = rule
                .workspace
                .as_ref()
                .unwrap()
                .with(|workspace| payload(workspace));
            eprintln!("{name}: {bytes} bytes");
            assert!(bytes < 1_048_576);
            // README: measured on 64-bit macOS; other platforms only get the 1 MiB bound.
            if cfg!(all(target_os = "macos", target_pointer_width = "64")) {
                assert!(
                    bytes.abs_diff(expected) * 50 <= expected,
                    "{name}: {bytes} bytes, README says {expected}"
                );
            }
        }
}
#[test]
fn wildcard_metric_bindings_handle_concurrent_first_use() {
    let registry = pharos_server::metrics::Registry::default();
    let metrics = RuleMetrics {
        address: "127.0.0.1:53".parse().unwrap(),
        zone: ".".into(),
        server: "dns://127.0.0.1:53".into(),
        registry: registry.clone(),
        bindings: arc_swap::ArcSwap::from_pointee(Vec::new()),
        binding_lock: Mutex::new(()),
    };
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for i in 0..8 {
            let metrics = &metrics;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                let qtype = if i % 2 == 0 { "A" } else { "AAAA" };
                for _ in 0..20 {
                    metrics.binding("", "IN", qtype, &[]).matched.matched();
                }
            });
        }
    });
    let mut output = String::new();
    registry.encode(&mut output);
    let lines: Vec<_> = output
        .lines()
        .filter(|line| line.starts_with("pharos_template_matches_total{"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|line| line.ends_with(" 80")), "{output}");
    metrics.binding("internal", "IN", "A", &[]);
    let _guard = metrics.binding_lock.lock().unwrap();
    assert_eq!(metrics.binding("", "IN", "A", &[]).class, "IN");
    assert_eq!(metrics.binding("internal", "IN", "A", &[]).view, "internal");
}
#[tokio::test]
async fn wildcard_metrics_use_actual_question_labels() {
    let mut config = configure(". {\n template ANY ANY {\n rcode NXDOMAIN\n }\n}").unwrap();
    let registry = pharos_server::metrics::Registry::default();
    let local = "127.0.0.1:53".parse().unwrap();
    config[0].config.template.as_mut().unwrap().set_metrics(
        &registry,
        &[pharos_server::ListenerKey {
            transport: pharos_server::Transport::Dns,
            address: local,
        }],
        &[],
    );
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x10\0\x03";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "192.0.2.1:1234".parse().unwrap(),
        local,
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(config[0].config.serve(&mut cx).await, Outcome::Response);
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    let line = metrics
        .lines()
        .find(|line| line.starts_with("pharos_template_matches_total{"))
        .unwrap();
    assert!(
        line.contains("class=\"CH\"") && line.contains("type=\"TXT\""),
        "{line}"
    );
}
#[tokio::test]
async fn record_errors_are_observable_but_expression_errors_are_unanswered() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    for (option, expected) in [
        (
            "answer \"invalid record\"",
            Outcome::Error(Error::Build(pharos_proto::BuildError::InvalidRdata)),
        ),
        (
            "answer \"{{ .Missing }}\"",
            Outcome::Error(Error::Build(pharos_proto::BuildError::InvalidRdata)),
        ),
        (
            "expr incidr('notanip', '10.0.0.0/8')",
            Outcome::Unanswered(Rcode::SERVFAIL),
        ),
    ] {
        let config = configure(&format!(". {{\n template IN A {{\n {option}\n }}\n}}")).unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "192.0.2.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: pharos_server::Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: pharos_server::Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(config[0].config.serve(&mut cx).await, expected);
    }
}
#[tokio::test]
async fn extended_rcode_requires_opt_and_encodes_high_bits() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    for (option, expected) in [("", Outcome::Drop), ("ederror 21", Outcome::Response)] {
        let config = configure(&format!(
            ". {{\n template IN A {{\n rcode BADKEY\n {option}\n }}\n}}"
        ))
        .unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "192.0.2.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: pharos_server::Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: pharos_server::Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(config[0].config.serve(&mut cx).await, expected);
        if expected == Outcome::Response {
            assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::BADKEY);
        }
    }
}
