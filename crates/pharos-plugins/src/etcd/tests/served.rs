//! The Plugin in a running Server, where names outside its zones are looked up through the Server.

use pharos_corefile::{configure, parse};
use pharos_proto::{Class, Message, MessageBuilder, Name, Rcode, Type};
use pharos_server::ListenerRegistry;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::EtcdStub;
use crate::etcd::msg;

async fn request(address: std::net::SocketAddr, qname: &str, qtype: Type) -> Vec<u8> {
    let name: Name = qname.parse().unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 0x1234, 0x0100).unwrap();
    builder
        .question(name.as_name_ref(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    // RFC 7766 §8: a DNS message over TCP has a two-byte length prefix.
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(&query).await.unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut response = vec![0; usize::from(len)];
    stream.read_exact(&mut response).await.unwrap();
    response
}

fn texts(message: &Message<'_>, additional: bool) -> Vec<String> {
    let records: Vec<_> = if additional {
        message.additionals().collect()
    } else {
        message.answers().collect()
    };
    records
        .iter()
        .map(|r| format!("{} {} {} {}", r.name, r.ttl, r.rtype, r.data().unwrap()))
        .collect()
}

// CoreDNS v1.15.0 plugin/backend_lookup.go A, SRV: a target outside the zone is looked up through the Server.
#[tokio::test]
async fn a_target_outside_the_zones_is_looked_up_through_the_server() {
    let stub = EtcdStub::start().await;
    for (key, value) in [
        ("x.skydns.test.", json!({"host": "b.other"})),
        ("srv.skydns.test.", json!({"host": "b.other", "port": 80})),
    ] {
        stub.put(
            &msg::path_with_wildcard(key, "skydns").0,
            &value.to_string(),
        );
    }
    let text = format!(
        "skydns.test.:0 {{\n etcd skydns.test {{\n endpoint {}\n }}\n}}\nother.:0 {{\n hosts /nonexistent other. {{\n 192.0.2.42 b.other.\n }}\n}}",
        stub.endpoint(false)
    );
    let parsed = parse("Corefile", &text).unwrap();
    let blocks = configure::<crate::Chain>(&parsed, crate::directives()).unwrap();
    let (servers, _) = crate::servers(blocks).unwrap();
    let key = *servers.keys().next().unwrap();
    let mut registry = ListenerRegistry::default();
    registry.apply(servers).await.unwrap();
    let address = std::net::SocketAddr::from((
        [127, 0, 0, 1],
        registry.get(&key).unwrap().local_addr().port(),
    ));

    let wire = request(address, "x.skydns.test.", Type::A).await;
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(
        texts(&message, false),
        [
            "x.skydns.test. 300 CNAME b.other.",
            "b.other. 3600 A 192.0.2.42"
        ]
    );

    let wire = request(address, "srv.skydns.test.", Type::SRV).await;
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(
        texts(&message, false),
        ["srv.skydns.test. 300 SRV 10 100 80 b.other."]
    );
    assert_eq!(texts(&message, true), ["b.other. 3600 A 192.0.2.42"]);
    registry.shutdown().await.unwrap();
}
