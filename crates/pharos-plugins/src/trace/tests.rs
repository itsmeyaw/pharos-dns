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

mod serve {
    use std::{collections::VecDeque, sync::Arc};

    use pharos_proto::{Message, Name, Rcode};
    use pharos_server::{
        Context, Error as ServerError, Metadata, Next, Outcome, Plugin, Protocol, Transport,
        metrics::TraceMetrics,
    };

    use super::{super::*, parse_text};
    use crate::trace::{export::Tracer, queue::Queue, span::SpanRecord, zipkin};

    // example.org. IN A, then the same Message as a Response with `rcode`.
    const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";

    fn response(rcode: u8) -> Vec<u8> {
        let mut wire = QUERY.to_vec();
        wire[2] |= 0x80;
        wire[3] = (wire[3] & 0xf0) | rcode;
        wire
    }

    struct Answer(Outcome, Vec<u8>);
    impl Next for Answer {
        async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
            cx.response.extend_from_slice(&self.1);
            self.0
        }
    }

    fn plugin(text: &str) -> (Trace, Arc<Queue>, TraceMetrics) {
        let trace = Trace::new(parse_text(text, &[], "53").unwrap());
        let metrics = TraceMetrics::default();
        let queue = Arc::new(Queue::new(1000, 100, metrics.clone()));
        trace
            .shared
            .tracer
            .store(Some(Arc::new(Tracer::detached(Arc::clone(&queue)))));
        (trace, queue, metrics)
    }

    async fn run(
        trace: &Trace,
        outcome: Outcome,
        wire: Vec<u8>,
        metadata: bool,
    ) -> (Outcome, String) {
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 4];
        let mut cx = Context {
            query: Message::parse(QUERY).unwrap(),
            client: "192.0.2.7:5353".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        cx.metadata.set_enabled(metadata);
        let outcome = trace.serve(&mut cx, Answer(outcome, wire)).await;
        let id = cx
            .metadata
            .get(TRACE_ID_METADATA)
            .unwrap_or_default()
            .to_owned();
        (outcome, id)
    }

    fn drain(queue: &Queue) -> VecDeque<SpanRecord> {
        let mut spans = queue.spare();
        queue.swap(&mut spans);
        spans
    }

    fn json(spans: &VecDeque<SpanRecord>) -> String {
        let mut out = String::new();
        zipkin::encode(spans, None, &mut out);
        out
    }

    // CoreDNS v1.15.0 plugin/trace/trace_test.go TestTrace: name, type, proto, remote and rcode tags, plus `error` when the Plugin failed.
    #[tokio::test]
    async fn span_carries_query_tags_and_rcode() {
        for (label, outcome, wire, rcode, error) in [
            (
                "NXDOMAIN",
                Outcome::Response,
                response(3),
                Some(Rcode::NXDOMAIN),
                false,
            ),
            (
                "NOERROR",
                Outcome::Response,
                response(0),
                Some(Rcode::NOERROR),
                false,
            ),
            // No response written: the status the Plugin returned is the RCODE.
            (
                "unanswered",
                Outcome::Unanswered(Rcode::SERVFAIL),
                Vec::new(),
                Some(Rcode::SERVFAIL),
                false,
            ),
            (
                "error",
                Outcome::Error(ServerError::Internal),
                Vec::new(),
                Some(Rcode::SERVFAIL),
                true,
            ),
            ("drop", Outcome::Drop, Vec::new(), None, false),
        ] {
            let (trace, queue, _) = plugin("trace");
            let (got, _) = run(&trace, outcome.clone(), wire, false).await;
            assert_eq!(got, outcome, "{label}");
            let spans = drain(&queue);
            assert_eq!(spans.len(), 1, "{label}");
            let span = &spans[0];
            assert_eq!(span.rcode, rcode, "{label}");
            assert_eq!(span.error.is_some(), error, "{label}");
            let text = json(&spans);
            assert!(text.contains(r#""name":"servedns""#), "{label}: {text}");
            assert!(text.contains(r#""kind":"SERVER""#), "{label}: {text}");
            assert!(
                text.contains(r#""coredns.io/name":"example.org.""#),
                "{label}: {text}"
            );
            assert!(text.contains(r#""coredns.io/type":"A""#), "{label}: {text}");
            assert!(
                text.contains(r#""coredns.io/proto":"tcp""#),
                "{label}: {text}"
            );
            assert!(
                text.contains(r#""coredns.io/remote":"192.0.2.7""#),
                "{label}: {text}"
            );
            match rcode {
                Some(rcode) => assert!(
                    text.contains(&format!(r#""coredns.io/rcode":"{rcode}""#)),
                    "{label}: {text}"
                ),
                None => assert!(!text.contains("coredns.io/rcode"), "{label}: {text}"),
            }
            assert_eq!(text.contains(r#""error":"true""#), error, "{label}: {text}");
            assert_eq!(
                text.contains(r#""value":"event:error""#),
                error,
                "{label}: {text}"
            );
        }
    }

    // CoreDNS v1.15.0 plugin/trace/trace.go ServeDNS: `count % every == 0` traces, so the first traced Query is the Nth.
    #[tokio::test]
    async fn every_n_traces_the_nth_query() {
        let (trace, queue, _) = plugin("trace {\n every 3\n}");
        for index in 1..=7 {
            run(&trace, Outcome::Response, response(0), false).await;
            let expected = index / 3;
            assert_eq!(queue.len(), expected, "after Query {index}");
        }
        let (trace, queue, _) = plugin("trace {\n every 0\n}");
        for _ in 0..5 {
            run(&trace, Outcome::Response, response(0), false).await;
        }
        assert_eq!(queue.len(), 0);
        assert_eq!(trace.shared.count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn no_tracer_means_no_span() {
        let trace = Trace::new(parse_text("trace", &[], "53").unwrap());
        let (outcome, _) = run(&trace, Outcome::Response, response(0), false).await;
        assert_eq!(outcome, Outcome::Response);
    }

    // CoreDNS v1.15.0 plugin/trace/trace.go: `trace/traceid` is published for the metadata Plugin only.
    #[tokio::test]
    async fn trace_id_metadata_follows_the_metadata_plugin() {
        let (trace, queue, _) = plugin("trace");
        let (_, id) = run(&trace, Outcome::Response, response(0), true).await;
        let spans = drain(&queue);
        assert_eq!(id.len(), 16);
        assert_eq!(id, format!("{:016x}", spans[0].id));
        let (_, id) = run(&trace, Outcome::Response, response(0), false).await;
        assert_eq!(id, "");
    }

    // dd-trace-go v2.10.1 TraceID() and rand.go: the Datadog trace ID is 32 hex digits and span IDs are positive 63-bit integers.
    #[tokio::test]
    async fn datadog_trace_id_metadata_is_the_128_bit_id() {
        let (trace, queue, _) = plugin("trace datadog localhost:8126");
        for _ in 0..50 {
            let (_, id) = run(&trace, Outcome::Response, response(0), true).await;
            let spans = drain(&queue);
            assert_eq!(id.len(), 32);
            assert_eq!(&id[16..], format!("{:016x}", spans[0].id));
            assert_eq!(
                &id[..16],
                format!("{:08x}00000000", spans[0].start_micros / 1_000_000)
            );
            assert!(spans[0].id != 0 && spans[0].id <= i64::MAX as u64);
        }
    }

    #[test]
    fn full_queue_disposes_the_oldest_span_and_counts_it() {
        let metrics = TraceMetrics::default();
        let queue = Queue::new(3, 100, metrics.clone());
        let record = |id| {
            let domain: Name = ".".parse().unwrap();
            let mut response = Vec::new();
            let mut slots = [];
            let cx = Context {
                query: Message::parse(QUERY).unwrap(),
                client: "192.0.2.7:5353".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: Transport::Dns,
                protocol: Protocol::Udp,
                domain: &domain,
                metadata: Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            SpanRecord::capture(id, 0, Duration::ZERO, &cx, &Outcome::Drop)
        };
        for id in 1..=5 {
            queue.push(record(id));
        }
        assert_eq!(metrics.dropped_queue_full_total(), 2);
        let ids: Vec<u64> = drain(&queue).iter().map(|span| span.id).collect();
        assert_eq!(ids, [3, 4, 5]);
        queue.close();
        queue.push(record(6));
        assert_eq!(queue.len(), 0);
    }

    // Zipkin v2 API spec and zipkin-go model/span.go MarshalJSON: the exact body of one server span.
    #[tokio::test]
    async fn zipkin_json_is_exact() {
        let (trace, queue, _) = plugin("trace");
        run(
            &trace,
            Outcome::Error(ServerError::Internal),
            Vec::new(),
            false,
        )
        .await;
        let mut spans = drain(&queue);
        spans[0].id = 0xab;
        spans[0].start_micros = 1_000;
        spans[0].duration_nanos = 400;
        let mut out = String::new();
        let endpoint =
            zipkin::local_endpoint("CoreDNS", Some("127.0.0.1".parse().unwrap()), None, 53);
        zipkin::encode(&spans, endpoint.as_deref(), &mut out);
        assert_eq!(
            out,
            concat!(
                r#"[{"traceId":"00000000000000ab","id":"00000000000000ab","name":"servedns","kind":"SERVER","timestamp":1000,"duration":1,"#,
                r#""localEndpoint":{"serviceName":"coredns","ipv4":"127.0.0.1","port":53},"#,
                r#""annotations":[{"timestamp":1001,"value":"event:error"},{"timestamp":1001,"value":"error:internal plugin error"}],"#,
                r#""tags":{"coredns.io/name":"example.org.","coredns.io/type":"A","coredns.io/proto":"tcp","coredns.io/remote":"192.0.2.7","coredns.io/rcode":"SERVFAIL","error":"true"}}]"#
            )
        );
    }

    #[test]
    fn local_endpoint_omits_empty_fields_and_escapes() {
        assert_eq!(zipkin::local_endpoint("", None, None, 0), None);
        assert_eq!(
            zipkin::local_endpoint("a\"b", None, Some("::1".parse().unwrap()), 0).unwrap(),
            r#"{"serviceName":"a\"b","ipv6":"::1"}"#
        );
    }
}
