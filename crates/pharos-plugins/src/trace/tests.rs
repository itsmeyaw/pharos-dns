use super::*;
use pharos_corefile::lex;
use std::time::Duration;

fn parse_text(text: &str, hosts: &[&str], port: &str) -> Result<Config, Error> {
    let tokens = lex("Corefile", text);
    let hosts: Vec<String> = hosts.iter().map(|host| (*host).to_owned()).collect();
    parse(&mut Cursor::new("Corefile", &tokens), &hosts, port)
}

// CoreDNS v1.15.0 plugin/trace/setup_test.go TestTraceParse.
#[test]
fn parse_accepts_and_rejects_what_coredns_does() {
    struct Case(
        &'static str,
        bool,
        &'static str,
        u64,
        &'static str,
        bool,
        i64,
        i64,
        u64,
    );
    const SPANS: &str = "http://localhost:9411/api/v2/spans";
    let ms = |seconds: u64| seconds * 1000;
    let cases = [
        // oks
        Case("trace", false, SPANS, 1, "coredns", false, 0, 0, 0),
        Case(
            "trace localhost:1234",
            false,
            "http://localhost:1234/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin-http.monitoring:9411",
            false,
            "http://zipkin-http.monitoring:9411/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin http-collector:9411",
            false,
            "http://http-collector:9411/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin myhttpscollector:9411",
            false,
            "http://myhttpscollector:9411/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin https://zipkin-http.monitoring:9411/custom/spans",
            false,
            "https://zipkin-http.monitoring:9411/custom/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace HTTP://collector:9411/api/v2/spans",
            false,
            "HTTP://collector:9411/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin HTTPS://collector:9411/api/v2/spans",
            false,
            "HTTPS://collector:9411/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin HtTpS://collector:9411/Custom/Spans?Tenant=Blue",
            false,
            "HtTpS://collector:9411/Custom/Spans?Tenant=Blue",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin httpS://collector:9411/Custom/Spans?Tenant=Blue",
            false,
            "httpS://collector:9411/Custom/Spans?Tenant=Blue",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace http://localhost:1234/somewhere/else",
            false,
            "http://localhost:1234/somewhere/else",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace zipkin localhost:1234",
            false,
            "http://localhost:1234/api/v2/spans",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace datadog localhost",
            false,
            "localhost",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace datadog http://localhost:8127",
            false,
            "http://localhost:8127",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace datadog localhost {\n datadog_analytics_rate 0.1\n}",
            false,
            "localhost",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n every 100\n}",
            false,
            SPANS,
            100,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n every 100\n service foobar\nclient_server\n}",
            false,
            SPANS,
            100,
            "foobar",
            true,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n every 2\n client_server true\n}",
            false,
            SPANS,
            2,
            "coredns",
            true,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n client_server false\n}",
            false,
            SPANS,
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_backlog_size 100\n zipkin_max_batch_size 200\n zipkin_max_batch_interval 10s\n}",
            false,
            SPANS,
            1,
            "coredns",
            false,
            100,
            200,
            ms(10),
        ),
        // fails
        Case(
            "trace footype localhost:4321",
            true,
            "",
            1,
            "",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n every 2\n client_server junk\n}",
            true,
            "",
            1,
            "",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace datadog localhost {\n datadog_analytics_rate 2\n}",
            true,
            "",
            1,
            "",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_backlog_size wrong\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_batch_size wrong\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_batch_interval wrong\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_backlog_size\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_batch_size\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n zipkin_max_batch_interval\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
        Case(
            "trace {\n evrey 100\n}",
            true,
            "",
            1,
            "coredns",
            false,
            0,
            0,
            0,
        ),
    ];
    for Case(
        input,
        should_err,
        endpoint,
        every,
        service,
        client_server,
        backlog,
        batch,
        interval_ms,
    ) in cases
    {
        let parsed = parse_text(input, &[""], "53");
        if should_err {
            assert!(parsed.is_err(), "{input}: expected an error");
            continue;
        }
        let config = parsed.unwrap_or_else(|error| panic!("{input}: {error}"));
        assert_eq!(config.service_endpoint, "", "{input}");
        assert_eq!(config.endpoint, endpoint, "{input}");
        assert_eq!(config.every, every, "{input}");
        assert_eq!(config.service_name, service, "{input}");
        assert_eq!(config.client_server, client_server, "{input}");
        assert_eq!(config.zipkin_max_backlog_size, backlog, "{input}");
        assert_eq!(config.zipkin_max_batch_size, batch, "{input}");
        assert_eq!(
            config.zipkin_max_batch_interval,
            Duration::from_millis(interval_ms),
            "{input}"
        );
    }
}

// CoreDNS v1.15.0 plugin/trace/setup_test.go TestParseServiceEndpoint.
#[test]
fn service_endpoint_joins_first_listen_host_and_port() {
    for (name, hosts, port, expected) in [
        ("IPv4 address", &["127.0.0.1"][..], "8053", "127.0.0.1:8053"),
        (
            "IPv6 address",
            &["3d47:98c0:b113::3"],
            "8853",
            "[3d47:98c0:b113::3]:8853",
        ),
        ("Hostname", &["localhost"], "8053", "localhost:8053"),
        (
            "Multiple addresses",
            &["3d47:98c0:b113::3", "127.0.0.1"],
            "8853",
            "[3d47:98c0:b113::3]:8853",
        ),
    ] {
        let config = parse_text("trace", hosts, port).unwrap();
        assert_eq!(config.service_endpoint, expected, "{name}");
    }
}

// CoreDNS v1.15.0 plugin/trace/setup.go traceParse: the endpoint type is case-insensitive and picks the default endpoint.
#[test]
fn endpoint_type_is_lowercased_and_defaults_by_type() {
    let config = parse_text("trace DataDog", &[], "53").unwrap();
    assert_eq!(config.endpoint_type, EndpointType::Zipkin);
    assert_eq!(config.endpoint, "http://DataDog/api/v2/spans");
    let config = parse_text("trace DATADOG localhost:8126", &[], "53").unwrap();
    assert_eq!(config.endpoint_type, EndpointType::Datadog);
    let config = parse_text("trace Zipkin", &[], "53").unwrap();
    assert_eq!(config.endpoint_type, EndpointType::Zipkin);
    // One argument is always an endpoint, never a type.
    let config = parse_text("trace datadog", &[], "53").unwrap();
    assert_eq!(config.endpoint, "http://datadog/api/v2/spans");
}

#[test]
fn too_many_arguments_and_bad_numbers_are_errors() {
    for input in [
        "trace zipkin localhost:9411 extra",
        // Go strconv.ParseUint rejects a sign and a negative number.
        "trace {\n every +5\n}",
        "trace {\n every -1\n}",
        "trace {\n every 1 2\n}",
        "trace {\n service\n}",
        "trace {\n client_server true false\n}",
        "trace datadog {\n datadog_analytics_rate -0.5\n}",
        "trace datadog {\n datadog_analytics_rate nope\n}",
    ] {
        assert!(parse_text(input, &[], "53").is_err(), "{input}");
    }
    let config = parse_text("trace {\n every 0\n}", &[], "53").unwrap();
    assert_eq!(config.every, 0);
    let config = parse_text("trace datadog {\n datadog_analytics_rate\n}", &[], "53").unwrap();
    assert_eq!(config.datadog_analytics_rate, 0.0);
}

// CoreDNS v1.15.0 plugin/trace/setup.go traceParse: a later `trace` line overrides the endpoint and keeps earlier options.
#[test]
fn later_line_overrides_endpoint_and_keeps_options() {
    let config = parse_text("trace a:1 {\n every 7\n}\ntrace b:2", &[], "53").unwrap();
    assert_eq!(config.endpoint, "http://b:2/api/v2/spans");
    assert_eq!(config.every, 7);
}
