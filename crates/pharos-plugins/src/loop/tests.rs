use super::*;
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Metadata, Protocol, Transport};
use std::sync::atomic::Ordering;

struct Pass;
impl Next for Pass {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
    }
}

async fn query(plugin: &Loop, name: &str, kind: Type) -> Outcome {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::new();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    plugin.serve(&mut cx, Pass).await
}

// Derived from CoreDNS v1.15.0 plugin/loop/loop_test.go.
#[tokio::test]
async fn counts_only_enabled_matching_hinfo_queries() {
    let plugin = Loop::new("example.org.");
    let name = plugin.state.qname.to_string();
    for (query_name, kind) in [
        ("outside.example.", Type::HINFO),
        (name.as_str(), Type::A),
        ("other.example.org.", Type::HINFO),
    ] {
        assert_eq!(
            query(&plugin, query_name, kind).await,
            Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
        );
    }
    assert_eq!(plugin.state.seen.load(Ordering::Relaxed), 0);
    for count in 1..=2 {
        assert_eq!(
            query(&plugin, &name, Type::HINFO).await,
            Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
        );
        assert_eq!(plugin.state.seen.load(Ordering::Relaxed), count);
    }
    plugin.state.disabled.store(true, Ordering::Relaxed);
    assert_eq!(
        query(&plugin, &name, Type::HINFO).await,
        Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
    );
    assert_eq!(plugin.state.seen.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn startup_probe_stops_on_restart_and_disables_after_success() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let plugin = Loop::new(".");
    let mut lifecycle = Lifecycle::default();
    plugin.register(&mut lifecycle, socket.local_addr().unwrap());
    lifecycle.run(Phase::Started).await.unwrap();
    let mut wire = [0; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let query = Message::parse(&wire[..len]).unwrap();
    assert_eq!(query.questions().next().unwrap().qtype, Type::HINFO);
    assert_eq!(
        query.questions().next().unwrap().name.to_string(),
        plugin.state.qname
    );
    lifecycle.run(Phase::Restart).await.unwrap();
    assert!(plugin.state.disabled.load(Ordering::Acquire));
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    let (len, peer) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    wire[2] |= 0x80;
    socket.send_to(&wire[..len], peer).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !plugin.state.disabled.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(plugin.state.disabled.load(Ordering::Acquire));
    assert!(plugin.state.complete.load(Ordering::Acquire));
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn failed_reload_does_not_repeat_a_successful_probe() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let plugin = Loop::new(".");
    let mut lifecycle = Lifecycle::default();
    plugin.register(&mut lifecycle, socket.local_addr().unwrap());
    lifecycle.run(Phase::Started).await.unwrap();
    let mut wire = [0; 512];
    let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
    wire[2] |= 0x80;
    socket.send_to(&wire[..len], peer).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !plugin.state.complete.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    lifecycle.run(Phase::Restart).await.unwrap();
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut wire))
            .await
            .is_err()
    );
    assert!(plugin.state.disabled.load(Ordering::Acquire));
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn startup_probe_rejects_mismatched_question_fields() {
    for mismatch in 0..3 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut wire = [0; 512];
            let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
            let query = Message::parse(&wire[..len]).unwrap();
            let question = query.questions().next().unwrap();
            let qtype_offset = 12 + question.name.wire_len();
            match mismatch {
                0 => wire[13] = if wire[13] == b'0' { b'1' } else { b'0' },
                1 => wire[qtype_offset..qtype_offset + 2].copy_from_slice(&1_u16.to_be_bytes()),
                _ => wire[qtype_offset + 2..qtype_offset + 4].copy_from_slice(&3_u16.to_be_bytes()),
            }
            wire[2] |= 0x80;
            socket.send_to(&wire[..len], peer).await.unwrap();
        });
        let plugin = Loop::new(".");
        let mut response = [0; 512];

        assert!(plugin.state.exchange(address, &mut response).await.is_err());
        task.await.unwrap();
    }
}
