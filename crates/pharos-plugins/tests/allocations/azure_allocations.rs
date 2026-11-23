use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, zone::Zone};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type, zone::ZoneParser};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::INSTRUMENTED_SYSTEM;

#[tokio::test]
async fn azure_queries_do_not_allocate() {
    if crate::run_isolated("azure_allocations::azure_queries_do_not_allocate") {
        return;
    }
    let blocks = parse("Corefile", "example.org:53 {\n azure rg:example.org\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    // The background sync is not started: the Zone is published as a sync would.
    let apex: Name = "example.org.".parse().unwrap();
    let text = "example.org. 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n\
        example.org. 60 IN NS ns.example.org.\n\
        www.example.org. 60 IN A 192.0.2.1\n\
        alias.example.org. 60 IN CNAME www.example.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "azure")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let azure = chain.azure.as_ref().unwrap();
    azure.hosted_zones()[0].publish(Zone::from_records(apex.clone(), records).unwrap());

    let queries: Vec<_> = [
        ("www.example.org.", Type::A),
        ("alias.example.org.", Type::A),
        ("www.example.org.", Type::AAAA),
        ("absent.example.org.", Type::A),
    ]
    .iter()
    .map(|(name, qtype)| {
        let name: Name = name.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                *qtype,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        query
    })
    .collect();
    let mut response = Vec::with_capacity(512);
    // One round warms; the next hundred must not allocate. The queries avoid the shared Zone Self Lookup paths, which allocate until #86.
    serve_all(chain, &queries, &apex, &mut response, 1).await;
    let before = INSTRUMENTED_SYSTEM.stats();
    serve_all(chain, &queries, &apex, &mut response, 100).await;
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

async fn serve_all(
    chain: &Chain,
    queries: &[Vec<u8>],
    domain: &Name,
    response: &mut Vec<u8>,
    rounds: usize,
) {
    for _ in 0..rounds {
        for query in queries {
            response.clear();
            let mut slots = [None; 8];
            let mut cx = Context {
                query: Message::parse(query).unwrap(),
                client: "127.0.0.1:1234".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: Transport::Dns,
                protocol: Protocol::Udp,
                domain,
                metadata: Metadata::new(&mut slots),
                response,
                max_response_size: 512,
            };
            assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
        }
    }
}
