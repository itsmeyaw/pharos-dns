#[test]
fn response_code_counters_keep_common_codes_inline() {
    use std::sync::atomic::Ordering;
    let counters = super::ResponseCounters::default();
    assert_eq!(super::DENSE_RESPONSE_CODES, 24);
    assert!(std::mem::size_of::<super::ResponseCounters>() <= 224);
    counters.increment(0);
    counters.increment(23);
    assert!(counters.extended.get().is_none());
    counters.increment(24);
    counters.increment(4095);
    let extended = counters.extended.get().unwrap();
    assert_eq!(extended[0].load(Ordering::Relaxed), 1);
    assert_eq!(extended[4095 - 24].load(Ordering::Relaxed), 1);
    assert_eq!(
        counters
            .iter()
            .map(|(_, counter)| counter.load(Ordering::Relaxed))
            .sum::<u64>(),
        4
    );
}

#[test]
fn response_metrics_keep_tsig_badsig_out_of_dns_rcode_labels() {
    use pharos_proto::Message;

    let mut wire = vec![0, 1, 0x80, 9, 0, 0, 0, 0, 0, 0, 0, 1];
    wire.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 17]);
    wire.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0]);
    let response = Message::parse(&wire).unwrap();

    // RFC 6895 §2.3: DNS RCODE 16 is BADVERS; TSIG Error 16 is BADSIG.
    assert_eq!(super::rcode(response.rcode().0), "NOTAUTH");
    assert_eq!(super::rcode(16), "BADVERS");
}

#[test]
fn concurrent_first_extended_rcode_records_every_response() {
    use std::sync::{Arc, Barrier, atomic::Ordering};
    let counters = Arc::new(super::ResponseCounters::default());
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let counters = Arc::clone(&counters);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..100 {
                    counters.increment(42);
                }
            });
        }
    });
    assert_eq!(
        counters.extended.get().unwrap()[42 - 24].load(Ordering::Relaxed),
        800
    );
}

#[test]
fn dynamic_zone_labels_include_block_domain_and_root_fallback() {
    use pharos_proto::{Name, NameRef};
    let registry = super::Registry::new("test", "test", "test");
    let names = super::DynamicZones::default();
    names.set_static_names(vec!["another.org.".parse().unwrap()]);
    let domain: Name = "example.org.".parse().unwrap();
    let binding = names.bind(&registry, "dns://:53", "", &domain, &["auto"]);
    names.publish(vec![
        "org.".parse().unwrap(),
        "Sub.Example.ORG.".parse().unwrap(),
    ]);
    for name in [
        "www.example.org.",
        "WWW.SUB.EXAMPLE.ORG.",
        "www.another.org.",
        "other.test.",
    ] {
        let name: Name = name.parse().unwrap();
        binding.snapshot().record(
            Some(NameRef::parse(name.as_wire(), 0).unwrap()),
            Some("auto"),
            1,
            false,
            false,
            false,
            32,
            64,
            0,
            0.01,
        );
    }
    let mut text = String::new();
    registry.encode(&mut text);
    for zone in ["example.org.", "Sub.Example.ORG.", "another.org.", "."] {
        let expected = format!(
            "pharos_dns_requests_total{{family=\"1\",proto=\"udp\",server=\"dns://:53\",type=\"A\",view=\"\",zone=\"{zone}\"}} 1"
        );
        assert!(text.contains(&expected), "{text}");
    }
    assert!(!text.contains("zone=\"org.\"} 1"));
    let old_snapshot = binding.snapshot();
    names.publish(vec![
        "org.".parse().unwrap(),
        "sub.example.org.".parse().unwrap(),
    ]);
    let name: Name = "www.sub.example.org.".parse().unwrap();
    old_snapshot.record(
        Some(NameRef::parse(name.as_wire(), 0).unwrap()),
        Some("auto"),
        1,
        false,
        false,
        false,
        32,
        64,
        0,
        0.01,
    );
    binding.snapshot().record(
        Some(NameRef::parse(name.as_wire(), 0).unwrap()),
        Some("auto"),
        1,
        false,
        false,
        false,
        32,
        64,
        0,
        0.01,
    );
    text.clear();
    registry.encode(&mut text);
    assert!(
        text.contains("type=\"A\",view=\"\",zone=\"sub.example.org.\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("type=\"A\",view=\"\",zone=\"Sub.Example.ORG.\"} 2"),
        "{text}"
    );
}

#[test]
fn dynamic_zone_bindings_discard_stale_reloads() {
    let registry = super::Registry::new("test", "test", "test");
    let names = super::DynamicZones::default();
    let domain = ".".parse().unwrap();
    for _ in 0..10 {
        let binding = names.bind(&registry, "dns://:53", "", &domain, &[]);
        drop(binding);
    }
    let binding = names.bind(&registry, "dns://:53", "", &domain, &[]);
    assert_eq!(names.state.lock().unwrap().bindings.len(), 1);
    drop(binding);
}

#[test]
fn template_metrics_export_only_used_series_with_coredns_labels_and_help() {
    let registry = super::Registry::new("test", "test", "test");
    let metrics = registry.template("dns://:53", "example.", "", "IN", "A");
    let same = registry.template("dns://:53", "example.", "", "IN", "A");
    let other = registry.template("dns://:53", "other.", "", "IN", "AAAA");
    let failure = metrics.failure("answer", "{{\"x\"}}\n\\");
    let unused = other.failure("authority", "unused");
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(!out.contains("pharos_template_"));

    metrics.matched();
    same.matched();
    other.matched();
    failure.render_failure();
    failure.rr_failure();
    let _ = unused;
    out.clear();
    registry.encode(&mut out);
    for expected in [
        "# HELP pharos_template_matches_total Counter of template regex matches.",
        "# TYPE pharos_template_matches_total counter",
        "# HELP pharos_template_template_failures_total Counter of go template failures.",
        "# TYPE pharos_template_template_failures_total counter",
        "# HELP pharos_template_rr_failures_total Counter of mis-templated RRs.",
        "# TYPE pharos_template_rr_failures_total counter",
        "pharos_template_matches_total{class=\"IN\",server=\"dns://:53\",type=\"A\",view=\"\",zone=\"example.\"} 2",
        "pharos_template_matches_total{class=\"IN\",server=\"dns://:53\",type=\"AAAA\",view=\"\",zone=\"other.\"} 1",
        "pharos_template_template_failures_total{class=\"IN\",section=\"answer\",server=\"dns://:53\",template=\"{{\\\"x\\\"}}\\n\\\\\",type=\"A\",view=\"\",zone=\"example.\"} 1",
        "pharos_template_rr_failures_total{class=\"IN\",section=\"answer\",server=\"dns://:53\",template=\"{{\\\"x\\\"}}\\n\\\\\",type=\"A\",view=\"\",zone=\"example.\"} 1",
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected}\n{out}"
        );
    }
    assert!(!out.contains("section=\"authority\""));
}

#[test]
fn template_failure_series_are_shared_and_independent() {
    let registry = super::Registry::new("test", "test", "test");
    let first = registry.template("s", ".", "", "IN", "A");
    let second = registry.template("s", ".", "", "IN", "A");
    let first_failure = first.failure("answer", "record");
    let shared_failure = second.failure("answer", "record");
    let other_failure = second.failure("additional", "record");

    std::thread::scope(|scope| {
        for _ in 0..4 {
            let failure = first_failure.clone();
            scope.spawn(move || {
                for _ in 0..100 {
                    failure.render_failure();
                }
            });
        }
    });
    shared_failure.render_failure();
    other_failure.rr_failure();
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.contains("pharos_template_template_failures_total{class=\"IN\",section=\"answer\",server=\"s\",template=\"record\",type=\"A\",view=\"\",zone=\".\"} 401\n"));
    assert!(out.contains("pharos_template_rr_failures_total{class=\"IN\",section=\"additional\",server=\"s\",template=\"record\",type=\"A\",view=\"\",zone=\".\"} 1\n"));
    assert!(!out.contains("pharos_template_matches_total"));
    assert!(!out.contains("pharos_template_rr_failures_total{class=\"IN\",section=\"answer\""));
}

#[test]
fn kubernetes_metrics_export_coredns_labels_and_buckets() {
    let registry = super::Registry::new("test", "test", "test");
    let metrics = registry.kubernetes();
    let request = metrics.request("GET", "api:6443");
    request.observe(0.02, "200");
    request.rate_limiter(0.003);
    metrics.programming_duration("cluster_ip", 0.002);
    let mut out = String::new();
    registry.encode(&mut out);
    for line in [
        "pharos_kubernetes_rest_client_request_duration_seconds_count{host=\"api:6443\",verb=\"GET\"} 1",
        "pharos_kubernetes_rest_client_rate_limiter_duration_seconds_count{host=\"api:6443\",verb=\"GET\"} 1",
        "pharos_kubernetes_rest_client_requests_total{code=\"200\",host=\"api:6443\",method=\"GET\"} 1",
        "pharos_kubernetes_dns_programming_duration_seconds_bucket{service_kind=\"cluster_ip\",le=\"0.002\"} 1",
    ] {
        assert!(
            out.lines().any(|actual| actual == line),
            "missing {line}\n{out}"
        );
    }
}
#[test]
fn proxy_series_share_labels_and_escape_values() {
    let registry = super::Registry::new("test", "test", "test");
    let upstream = registry.proxy("forward\"\n", "192.0.2.1:53");
    let same = registry.proxy("forward\"\n", "192.0.2.1:53");
    let other = registry.proxy("forward\"\n", "192.0.2.2:53");
    upstream.request_duration("SERVFAIL").observe(9.0);
    same.request_duration("SERVFAIL").observe(0.0005);
    other.request_duration("NOERROR").observe(0.0);
    upstream.connection_cache("tcp").hit();
    same.connection_cache("tcp").hit();
    other.connection_cache("udp").miss();
    same.healthcheck_failure();

    let mut out = String::new();
    registry.encode(&mut out);
    for expected in [
        "pharos_proxy_request_duration_seconds_bucket{proxy_name=\"forward\\\"\\n\",rcode=\"SERVFAIL\",to=\"192.0.2.1:53\",le=\"0.00025\"} 0",
        "pharos_proxy_request_duration_seconds_bucket{proxy_name=\"forward\\\"\\n\",rcode=\"SERVFAIL\",to=\"192.0.2.1:53\",le=\"8.192\"} 1",
        "pharos_proxy_request_duration_seconds_bucket{proxy_name=\"forward\\\"\\n\",rcode=\"SERVFAIL\",to=\"192.0.2.1:53\",le=\"+Inf\"} 2",
        "pharos_proxy_request_duration_seconds_count{proxy_name=\"forward\\\"\\n\",rcode=\"NOERROR\",to=\"192.0.2.2:53\"} 1",
        "pharos_proxy_conn_cache_hits_total{proto=\"tcp\",proxy_name=\"forward\\\"\\n\",to=\"192.0.2.1:53\"} 2",
        "pharos_proxy_conn_cache_misses_total{proto=\"udp\",proxy_name=\"forward\\\"\\n\",to=\"192.0.2.2:53\"} 1",
        "pharos_proxy_healthcheck_failures_total{proxy_name=\"forward\\\"\\n\",to=\"192.0.2.1:53\"} 1",
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected}\n{out}"
        );
    }
}

#[test]
fn unused_proxy_handles_do_not_emit_series() {
    let registry = super::Registry::new("test", "test", "test");
    let proxy = registry.proxy("forward", "192.0.2.1:53");
    let _ = proxy.request_duration("NOERROR");
    let _ = proxy.connection_cache("udp");
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(!out.contains("pharos_proxy_"));
}

#[test]
fn forward_counters_are_shared_and_exported() {
    let registry = super::Registry::new("test", "test", "test");
    let counters = registry.forward();
    let same = registry.forward();
    counters.healthcheck_broken();
    same.concurrent_reject();
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.contains("pharos_forward_healthcheck_broken_total 1\n"));
    assert!(out.contains("pharos_forward_max_concurrent_rejects_total 1\n"));
}

#[test]
fn proxy_metrics_export_upstream_series() {
    let registry = super::Registry::new("test", "test", "test");
    let upstream = registry.proxy("forward", "dns://192.0.2.1:53");
    let duration = upstream.request_duration("NOERROR");
    let cache = upstream.connection_cache("udp");
    duration.observe(0.00025);
    duration.observe(0.001);
    cache.hit();
    cache.hit();
    cache.miss();
    upstream.healthcheck_failure();
    let mut out = String::new();
    registry.encode(&mut out);

    for expected in [
        "# HELP pharos_proxy_request_duration_seconds Histogram of the time each request took.",
        "# TYPE pharos_proxy_request_duration_seconds histogram",
        "# HELP pharos_proxy_healthcheck_failures_total Counter of the number of failed healthchecks.",
        "# TYPE pharos_proxy_healthcheck_failures_total counter",
        "# HELP pharos_proxy_conn_cache_hits_total Counter of connection cache hits per upstream and protocol.",
        "# TYPE pharos_proxy_conn_cache_hits_total counter",
        "# HELP pharos_proxy_conn_cache_misses_total Counter of connection cache misses per upstream and protocol.",
        "# TYPE pharos_proxy_conn_cache_misses_total counter",
        "pharos_proxy_request_duration_seconds_bucket{proxy_name=\"forward\",rcode=\"NOERROR\",to=\"dns://192.0.2.1:53\",le=\"0.00025\"} 1",
        "pharos_proxy_request_duration_seconds_bucket{proxy_name=\"forward\",rcode=\"NOERROR\",to=\"dns://192.0.2.1:53\",le=\"0.001\"} 2",
        "pharos_proxy_request_duration_seconds_bucket{proxy_name=\"forward\",rcode=\"NOERROR\",to=\"dns://192.0.2.1:53\",le=\"+Inf\"} 2",
        "pharos_proxy_request_duration_seconds_sum{proxy_name=\"forward\",rcode=\"NOERROR\",to=\"dns://192.0.2.1:53\"} 0.00125",
        "pharos_proxy_request_duration_seconds_count{proxy_name=\"forward\",rcode=\"NOERROR\",to=\"dns://192.0.2.1:53\"} 2",
        "pharos_proxy_healthcheck_failures_total{proxy_name=\"forward\",to=\"dns://192.0.2.1:53\"} 1",
        "pharos_proxy_conn_cache_hits_total{proto=\"udp\",proxy_name=\"forward\",to=\"dns://192.0.2.1:53\"} 2",
        "pharos_proxy_conn_cache_misses_total{proto=\"udp\",proxy_name=\"forward\",to=\"dns://192.0.2.1:53\"} 1",
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected}\n{out}"
        );
    }
}

#[test]
fn go_float_formatting() {
    for (value, expected) in [
        (0.0001, "0.0001"),
        (0.00001, "1e-05"),
        (999999., "999999"),
        (1_000_000., "1e+06"),
        (-0.0, "-0"),
        (f64::INFINITY, "+Inf"),
        (f64::NEG_INFINITY, "-Inf"),
        (f64::NAN, "NaN"),
    ] {
        assert_eq!(super::float(value), expected);
    }
}
