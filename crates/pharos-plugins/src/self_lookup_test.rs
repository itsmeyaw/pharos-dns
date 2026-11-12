use pharos_corefile::{configure, parse};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, ListenerRegistry, Outcome};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

#[derive(Debug)]
pub struct TestPlugin {
    calls: Arc<AtomicUsize>,
    ttl: u32,
    pause: Option<(Arc<Notify>, Arc<Notify>)>,
    result: Arc<AtomicUsize>,
    done: Arc<Notify>,
}

impl TestPlugin {
    pub async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 1
            && let Some((started, resume)) = &self.pause
        {
            started.notify_one();
            resume.notified().await;
        }
        let target: Name = "b.other.".parse().unwrap();
        let captured = match cx.self_lookup(&target, Type::A).await {
            Ok(wire) => wire,
            Err(error) => return Outcome::Error(error),
        };
        let response = Message::parse(&captured).unwrap();
        self.result.store(
            response
                .answers()
                .last()
                .map_or(0, |rr| usize::from(rr.rdata[3])),
            Ordering::SeqCst,
        );
        self.done.notify_one();
        if response.rcode() != Rcode::NOERROR {
            return Outcome::Error(pharos_server::Error::InvalidQuery);
        }
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let target = NameRef::parse(target.as_wire(), 0).unwrap();
        builder
            .record_with(
                Section::Answer,
                question.name,
                Type::CNAME,
                Class::IN,
                self.ttl,
                |writer| writer.write_name(target),
            )
            .unwrap();
        for answer in response.answers() {
            let data = answer.data().unwrap();
            builder
                .record_with(
                    Section::Answer,
                    answer.name,
                    answer.rtype,
                    answer.class,
                    answer.ttl,
                    |writer| data.write(writer),
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

async fn request(address: std::net::SocketAddr) -> Vec<u8> {
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\x07example\0\0\x01\0\x01";
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(query).await.unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut response = vec![0; usize::from(len)];
    stream.read_exact(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn stale_refresh_self_lookup_caches_chased_cname() {
    let text = "example.:0 {\n cache {\n success 1024 1 0\n serve_stale 10s verify\n }\n whoami\n}\nother.:0 {\n hosts /nonexistent other. {\n 192.0.2.42 b.other.\n }\n}";
    let parsed = parse("Corefile", text).unwrap();
    let mut blocks = configure::<crate::Chain>(&parsed, crate::directives()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    blocks[0].config.self_lookup_test = Some(TestPlugin {
        calls: calls.clone(),
        ttl: 1,
        pause: None,
        result: Arc::new(AtomicUsize::new(0)),
        done: Arc::new(Notify::new()),
    });
    let (servers, _) = crate::servers(blocks).unwrap();
    let key = *servers.keys().next().unwrap();
    let mut registry = ListenerRegistry::default();
    registry.apply(servers).await.unwrap();
    let address = std::net::SocketAddr::from((
        [127, 0, 0, 1],
        registry.get(&key).unwrap().local_addr().port(),
    ));
    let first = request(address).await;
    let message = Message::parse(&first).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answer_count(), 2);
    assert_eq!(message.answers().last().unwrap().rdata, [192, 0, 2, 42]);
    let refreshed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let response = request(address).await;
            if calls.load(Ordering::SeqCst) == 2 {
                break response;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cached answer did not expire");
    let message = Message::parse(&refreshed).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answer_count(), 2);
    assert_eq!(
        message.answers().next().unwrap().ttl,
        1,
        "must return fresh, not stale"
    );
    assert_eq!(message.answers().last().unwrap().rdata, [192, 0, 2, 42]);
    let cached = request(address).await;
    let message = Message::parse(&cached).unwrap();
    assert_eq!(message.answer_count(), 2);
    assert_eq!(message.answers().last().unwrap().rdata, [192, 0, 2, 42]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn detached_prefetch_keeps_its_listener_state_during_reload() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let result = Arc::new(AtomicUsize::new(0));
    let make_servers = |address: u8, plugin: TestPlugin| {
        // CoreDNS cache prefetch: the 50% threshold prevents polling from refreshing before TTL 1.
        let text = format!(
            "example.:0 {{\n cache {{\n success 1024 2 0\n prefetch 1 1m 50%\n }}\n whoami\n}}\nother.:0 {{\n hosts /nonexistent other. {{\n 192.0.2.{address} b.other.\n }}\n}}"
        );
        let parsed = parse("Corefile", &text).unwrap();
        let mut blocks = configure::<crate::Chain>(&parsed, crate::directives()).unwrap();
        blocks[0].config.self_lookup_test = Some(plugin);
        crate::servers(blocks).unwrap().0
    };
    let old = make_servers(
        42,
        TestPlugin {
            calls: calls.clone(),
            ttl: 2,
            pause: Some((started.clone(), resume.clone())),
            result: result.clone(),
            done: done.clone(),
        },
    );
    let key = *old.keys().next().unwrap();
    let mut registry = ListenerRegistry::default();
    registry.apply(old).await.unwrap();
    let address = std::net::SocketAddr::from((
        [127, 0, 0, 1],
        registry.get(&key).unwrap().local_addr().port(),
    ));
    assert_eq!(
        Message::parse(&request(address).await)
            .unwrap()
            .answers()
            .last()
            .unwrap()
            .rdata,
        [192, 0, 2, 42]
    );
    done.notified().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let response = request(address).await;
            let message = Message::parse(&response).unwrap();
            assert_eq!(message.answers().last().unwrap().rdata, [192, 0, 2, 42]);
            if message.answers().next().unwrap().ttl == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cached answer did not age");
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    let new = make_servers(
        99,
        TestPlugin {
            calls: Arc::new(AtomicUsize::new(0)),
            ttl: 2,
            pause: None,
            result: Arc::new(AtomicUsize::new(0)),
            done: Arc::new(Notify::new()),
        },
    );
    let retired = registry.apply(new).await.unwrap();
    let old_state = Arc::downgrade(&retired[0]);
    drop(retired);
    assert!(
        old_state.upgrade().is_some(),
        "detached refresh must retain the old Listener state"
    );
    resume.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), done.notified())
        .await
        .unwrap();
    assert_eq!(result.load(Ordering::SeqCst), 42);
    assert_eq!(
        Message::parse(&request(address).await)
            .unwrap()
            .answers()
            .last()
            .unwrap()
            .rdata,
        [192, 0, 2, 99]
    );
    registry.shutdown().await.unwrap();
}
