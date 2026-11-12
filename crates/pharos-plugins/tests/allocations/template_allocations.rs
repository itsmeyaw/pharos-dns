#![cfg(feature = "plugin-template")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Name};
use pharos_server::{Action, Context, Handler, Metadata, Outcome, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

fn measure(corefile: &str) -> (Poll<Outcome>, stats_alloc::Stats) {
    let blocks = parse("Corefile", corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(wire).unwrap(),
        client: "192.0.2.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let future = configured[0].config.serve(&mut context);
    let mut future = std::pin::pin!(future);
    let outcome = future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()));
    (outcome, region.change())
}

#[test]
#[cfg(feature = "plugin-whoami")]
fn unmatched_and_fallthrough_queries_do_not_allocate() {
    if crate::run_isolated("template::cases::unmatched_and_fallthrough_queries_do_not_allocate") {
        return;
    }
    for directive in [
        "template IN A other {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n}",
        "template IN AAAA example {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n}",
        "template IN A example {\n match ^nomatch$\n fallthrough\n}",
        "template IN A example {\n expr false\n fallthrough\n}",
        "template IN A example {\n match ^(?P<host>[a-z]+)[.]example[.]$\n var host group('host')\n expr host == 'no'\n fallthrough\n}",
    ] {
        let corefile = format!(". {{\n {directive}\n whoami\n}}");
        let (outcome, stats) = measure(&corefile);
        assert_eq!(outcome, Poll::Ready(Outcome::Response), "{directive}");
        assert_eq!(
            (stats.allocations, stats.reallocations),
            (0, 0),
            "{directive}"
        );
    }
}

#[test]
fn matched_zone_record_allocations_are_bounded() {
    if crate::run_isolated("template::cases::matched_zone_record_allocations_are_bounded") {
        return;
    }
    let corefile =
        ". {\n template IN A example {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n }\n}";
    let (outcome, stats) = measure(corefile);
    assert_eq!(outcome, Poll::Ready(Outcome::Response));
    assert!(stats.allocations + stats.reallocations <= 100, "{stats:?}");
    assert!(stats.bytes_allocated <= 262_144, "{stats:?}");
}

#[test]
fn matched_query_with_metrics_allocations_are_bounded() {
    if crate::run_isolated("template::cases::matched_query_with_metrics_allocations_are_bounded") {
        return;
    }
    let corefile =
        ".:53 {\n template IN A example {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n }\n}";
    let blocks = parse("Corefile", corefile).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(65535);
    let peer = "192.0.2.1:1234".parse().unwrap();
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let future = server.handle(wire, peer, Protocol::Udp, &mut response);
    let mut future = std::pin::pin!(future);
    let outcome = future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()));
    let stats = region.change();
    assert_eq!(outcome, Poll::Ready(Action::Respond));
    assert!(stats.allocations + stats.reallocations <= 100, "{stats:?}");
    assert!(stats.bytes_allocated <= 262_144, "{stats:?}");
}

#[test]
#[cfg(feature = "plugin-whoami")]
fn warmed_rule_workspace_on_worker_does_not_allocate() {
    if crate::run_isolated("template::cases::warmed_rule_workspace_on_worker_does_not_allocate") {
        return;
    }
    let vars = (0..40)
        .map(|i| {
            if i == 0 {
                "var v0 group('host')\n".to_owned()
            } else {
                format!("var v{i} v{}\n", i - 1)
            }
        })
        .collect::<String>();
    let pattern = format!("^{}(?P<host>[a-z]+)[.]example[.]$", "()".repeat(128));
    let corefile = format!(
        ". {{\n template IN A example {{\n match {pattern}\n {vars} expr v39 matches '^no$'\n fallthrough\n }}\n whoami\n}}"
    );
    let configured =
        configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
                let domain: Name = ".".parse().unwrap();
                let mut response = Vec::with_capacity(512);
                let mut slots = [];
                let mut context = Context {
                    query: Message::parse(wire).unwrap(),
                    client: "192.0.2.1:1234".parse().unwrap(),
                    local: "127.0.0.1:53".parse().unwrap(),
                    transport: Transport::Dns,
                    protocol: Protocol::Udp,
                    domain: &domain,
                    metadata: Metadata::new(&mut slots),
                    response: &mut response,
                    max_response_size: 512,
                };
                let mut task_context = TaskContext::from_waker(Waker::noop());
                {
                    let mut future = std::pin::pin!(configured[0].config.serve(&mut context));
                    assert_eq!(
                        future.as_mut().poll(&mut task_context),
                        Poll::Ready(Outcome::Response)
                    );
                }
                context.response.clear();
                let region = Region::new(&INSTRUMENTED_SYSTEM);
                let mut future = std::pin::pin!(configured[0].config.serve(&mut context));
                let outcome = future.as_mut().poll(&mut task_context);
                let stats = region.change();
                assert_eq!(outcome, Poll::Ready(Outcome::Response));
                assert_eq!(
                    (stats.allocations, stats.reallocations),
                    (0, 0),
                    "{stats:?}"
                );
            })
            .join()
            .unwrap();
    });
}

#[test]
#[cfg(feature = "plugin-whoami")]
fn warmed_concurrent_large_rule_queries_do_not_allocate() {
    if crate::run_isolated("template::cases::warmed_concurrent_large_rule_queries_do_not_allocate")
    {
        return;
    }
    let variables = (0..40)
        .map(|i| {
            if i == 0 {
                "var v0 group('host')\n".to_owned()
            } else {
                format!("var v{i} v{}\n", i - 1)
            }
        })
        .collect::<String>();
    let pattern = format!("^{}(?P<host>[a-z]+)[.]example[.]$", "()".repeat(128));
    let corefile = format!(
        ". {{\n template IN A example {{\n match {pattern}\n {variables} expr v39 matches '^no$'\n fallthrough\n }}\n whoami\n}}"
    );
    let configured =
        configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let barrier = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let barrier = &barrier;
            let chain = &configured[0].config;
            scope.spawn(move || {
                let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
                let domain: Name = ".".parse().unwrap();
                let mut response = Vec::with_capacity(512);
                let mut slots = [];
                let mut context = Context {
                    query: Message::parse(wire).unwrap(),
                    client: "192.0.2.1:1234".parse().unwrap(),
                    local: "127.0.0.1:53".parse().unwrap(),
                    transport: Transport::Dns,
                    protocol: Protocol::Udp,
                    domain: &domain,
                    metadata: Metadata::new(&mut slots),
                    response: &mut response,
                    max_response_size: 512,
                };
                let mut task_context = TaskContext::from_waker(Waker::noop());
                {
                    let mut future = std::pin::pin!(chain.serve(&mut context));
                    assert_eq!(
                        future.as_mut().poll(&mut task_context),
                        Poll::Ready(Outcome::Response)
                    );
                }
                barrier.wait();
                barrier.wait();
                for _ in 0..10 {
                    context.response.clear();
                    let mut future = std::pin::pin!(chain.serve(&mut context));
                    assert_eq!(
                        future.as_mut().poll(&mut task_context),
                        Poll::Ready(Outcome::Response)
                    );
                }
                barrier.wait();
                barrier.wait();
            });
        }
        barrier.wait();
        let region = Region::new(&INSTRUMENTED_SYSTEM);
        barrier.wait();
        barrier.wait();
        let stats = region.change();
        barrier.wait();
        assert_eq!(
            (stats.allocations, stats.reallocations),
            (0, 0),
            "{stats:?}"
        );
    });
}

#[test]
fn warmed_wildcard_metric_queries_do_not_allocate() {
    if crate::run_isolated("template::cases::warmed_wildcard_metric_queries_do_not_allocate") {
        return;
    }
    let corefile = ".:53 {\n template ANY ANY {\n rcode SERVFAIL\n }\n}";
    let blocks = parse("Corefile", corefile).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(65535);
    let peer = "192.0.2.1:1234".parse().unwrap();
    let mut task_context = TaskContext::from_waker(Waker::noop());
    {
        let mut future = std::pin::pin!(server.handle(wire, peer, Protocol::Udp, &mut response));
        assert_eq!(
            future.as_mut().poll(&mut task_context),
            Poll::Ready(Action::Respond)
        );
    }
    response.clear();
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let mut future = std::pin::pin!(server.handle(wire, peer, Protocol::Udp, &mut response));
    let outcome = future.as_mut().poll(&mut task_context);
    let stats = region.change();
    assert_eq!(outcome, Poll::Ready(Action::Respond));
    assert_eq!(
        (stats.allocations, stats.reallocations),
        (0, 0),
        "{stats:?}"
    );
}
