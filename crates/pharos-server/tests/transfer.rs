#![forbid(unsafe_code)]

use pharos_proto::{Message, Rcode, Type};
use pharos_server::{
    Chain, Context, Listener, ListenerKey, Next, Outcome, Plugin, Router, Server, Stream, Transport,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Duration, timeout},
};

struct Transfer;

struct SignedTransfer;

impl Chain for SignedTransfer {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let key = std::sync::Arc::new(pharos_proto::TsigKey::new(
            "key.".parse().unwrap(),
            pharos_proto::TsigAlgorithm::Sha256,
            b"secret",
        ));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = match key.verify(cx.query.as_wire(), now, None, 0) {
            Ok(record) => record,
            Err(_) => return Outcome::Unanswered(Rcode::REFUSED),
        };
        cx.metadata
            .set_tsig_signing(pharos_server::TsigSigning::Signed {
                key,
                time: now,
                fudge: record.fudge,
                reserved: 128,
            });
        Chain::serve(&Transfer, cx).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn signed_axfr_stream_authenticates_every_message() {
    let listener_key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        listener_key,
        ".".parse().unwrap(),
        Some(SignedTransfer),
        vec![],
    );
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        Server::new(router, listener_key),
    )
    .await
    .unwrap();
    let key = pharos_proto::TsigKey::new(
        "key.".parse().unwrap(),
        pharos_proto::TsigAlgorithm::Sha256,
        b"secret",
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut query = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 252, 0, 1];
    key.sign(&mut query, now, 300, None).unwrap();
    let mac = pharos_proto::TsigRecord::parse(&query).unwrap().mac;
    let mut verifier = pharos_proto::TsigStream::new(&key, mac);
    let mut socket = TcpStream::connect(listener.local_addr()).await.unwrap();
    socket
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    socket.write_all(&query).await.unwrap();
    for expected in [Type::SOA, Type::A, Type::SOA] {
        let length = timeout(Duration::from_secs(3), socket.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut wire = vec![0; usize::from(length)];
        socket.read_exact(&mut wire).await.unwrap();
        assert!(verifier.verify(&wire, now, 0).unwrap().is_some());
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rtype,
            expected
        );
    }
    verifier.finish().unwrap();
    drop(socket);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn signed_axfr_client_authenticates_stream() {
    let listener_key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        listener_key,
        ".".parse().unwrap(),
        Some(SignedTransfer),
        vec![],
    );
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        Server::new(router, listener_key),
    )
    .await
    .unwrap();
    let key = pharos_proto::TsigKey::new(
        "key.".parse().unwrap(),
        pharos_proto::TsigAlgorithm::Sha256,
        b"secret",
    );
    let mut types = Vec::new();
    pharos_server::transfer::axfr_signed(
        listener.local_addr(),
        &"a.".parse().unwrap(),
        1,
        Duration::from_secs(3),
        &key,
        |message| {
            types.extend(message.answers().map(|r| r.rtype));
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(types, [Type::SOA, Type::A, Type::SOA]);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn signed_axfr_client_rejects_unsigned_last_and_tampering() {
    for tamper in [false, true] {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = socket.accept().await.unwrap();
            let len = connection.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(len)];
            connection.read_exact(&mut query).await.unwrap();
            let key = pharos_proto::TsigKey::new(
                "key.".parse().unwrap(),
                pharos_proto::TsigAlgorithm::Sha256,
                b"secret",
            );
            let mac = pharos_proto::TsigRecord::parse(&query).unwrap().mac;
            let mut signer = pharos_proto::TsigStream::new(&key, mac);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            for index in 0..2 {
                let mut response = vec![0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
                response.extend_from_slice(&[
                    1, b'a', 0, 0, 6, 0, 1, 0, 0, 0, 60, 0, 22, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0,
                    0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
                ]);
                if index == 0 || tamper {
                    signer.sign(&mut response, now, 300).unwrap();
                }
                if index == 1 && tamper {
                    response[3] ^= 1;
                }
                connection
                    .write_all(&(response.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                connection.write_all(&response).await.unwrap();
            }
        });
        let key = pharos_proto::TsigKey::new(
            "key.".parse().unwrap(),
            pharos_proto::TsigAlgorithm::Sha256,
            b"secret",
        );
        let mut count = 0;
        let error = pharos_server::transfer::axfr_signed(
            address,
            &"a.".parse().unwrap(),
            1,
            Duration::from_secs(3),
            &key,
            |_| {
                count += 1;
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(count, 1);
        server.await.unwrap();
    }
}

struct BadClosingSoa;

struct PanickingTransfer;
impl Chain for PanickingTransfer {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Stream(Stream::new(|_| panic!("broken producer")))
    }
    fn is_empty(&self) -> bool {
        false
    }
}

impl Chain for BadClosingSoa {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let Outcome::Stream(mut source) = Chain::serve(&Transfer, cx).await else {
            unreachable!()
        };
        let mut count = 0;
        Outcome::Stream(Stream::new(move |wire| {
            let has_message = source.next(wire)?;
            if count == 2 && has_message {
                let serial_last_byte = wire.len() - 17;
                wire[serial_last_byte] = 2;
            }
            count += 1;
            Ok(has_message)
        }))
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct End;
impl Next for End {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

impl Plugin for Transfer {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, _: N) -> Outcome {
        let id = cx.query.id().to_be_bytes();
        let qtype = cx.query.questions().next().unwrap().qtype.0.to_be_bytes();
        let mut count = 0;
        Outcome::Stream(Stream::new(move |wire| {
            if count == 3 {
                return Ok(false);
            }
            wire.extend_from_slice(&[
                id[0],
                id[1],
                0x84,
                0,
                0,
                u8::from(count == 0),
                0,
                1,
                0,
                0,
                0,
                0,
            ]);
            if count == 0 {
                // RFC 5936 §2.2: the first AXFR Response repeats the Question.
                wire.extend_from_slice(&[1, b'a', 0, qtype[0], qtype[1], 0, 1]);
            }
            if count == 1 {
                wire.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            } else {
                wire.extend_from_slice(&[
                    1, b'a', 0, 0, 6, 0, 1, 0, 0, 0, 60, 0, 22, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0,
                    0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
                ]);
            }
            count += 1;
            Ok(true)
        }))
    }
}

impl Chain for Transfer {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        Plugin::serve(self, cx, End).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn udp_axfr_is_refused_and_ixfr_returns_only_current_soa() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Transfer), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (qtype, rcode) in [(252, Rcode::REFUSED), (251, Rcode::NOERROR)] {
        let query = [
            0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, qtype, 0, 1,
        ];
        socket.send_to(&query, listener.local_addr()).await.unwrap();
        let mut wire = [0; 512];
        let (len, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        let message = Message::parse(&wire[..len]).unwrap();
        assert_eq!(message.rcode(), rcode);
        if qtype == 251 {
            assert_eq!(message.answer_count(), 1);
            assert_eq!(message.answers().next().unwrap().rtype, Type::SOA);
        }
    }
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_ixfr_turns_producer_panic_into_servfail() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(PanickingTransfer), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 251, 0, 1];
    socket.send_to(&query, listener.local_addr()).await.unwrap();
    let mut wire = [0; 512];
    let (len, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::parse(&wire[..len]).unwrap().rcode(),
        Rcode::SERVFAIL
    );
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn axfr_client_reads_stream_and_checks_closing_soa() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Transfer), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    let mut types = Vec::new();
    pharos_server::transfer::axfr(
        listener.local_addr(),
        &"a.".parse().unwrap(),
        1,
        Duration::from_secs(3),
        |message| {
            types.extend(message.answers().map(|record| record.rtype));
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(types, [Type::SOA, Type::A, Type::SOA]);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn axfr_client_rejects_a_different_closing_soa() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(BadClosingSoa), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    let error = pharos_server::transfer::axfr(
        listener.local_addr(),
        &"a.".parse().unwrap(),
        1,
        Duration::from_secs(3),
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn axfr_client_times_out_when_primary_does_not_reply() {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut connection, _) = socket.accept().await.unwrap();
        let length = connection.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        connection.read_exact(&mut query).await.unwrap();
        std::future::pending::<()>().await;
    });
    let error = pharos_server::transfer::axfr(
        address,
        &"a.".parse().unwrap(),
        1,
        Duration::from_millis(100),
        |_| Ok(()),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn notify_sender_retries_refused_responses() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut wire = [0; 512];
        for attempt in 0..2 {
            let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
            let message = Message::parse(&wire[..len]).unwrap();
            assert_eq!(message.opcode(), pharos_proto::Opcode::NOTIFY);
            assert_eq!(message.questions().next().unwrap().qtype, Type::SOA);
            wire[2] |= 0x80;
            wire[3] = if attempt == 0 { 5 } else { 0 };
            socket.send_to(&wire[..len], peer).await.unwrap();
        }
    });
    pharos_server::transfer::notify(address, &"a.".parse().unwrap(), 42, Duration::from_secs(1))
        .await
        .unwrap();
    responder.await.unwrap();
}

#[tokio::test]
async fn plugin_stream_reaches_tcp_listener_as_multiple_messages() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Transfer), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    let mut socket = TcpStream::connect(listener.local_addr()).await.unwrap();
    let query = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 252, 0, 1];
    socket
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    socket.write_all(&query).await.unwrap();
    for expected in [Type::SOA, Type::A, Type::SOA] {
        let length = timeout(Duration::from_secs(3), socket.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut wire = vec![0; usize::from(length)];
        socket.read_exact(&mut wire).await.unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.id(), 1);
        assert_eq!(message.answers().next().unwrap().rtype, expected);
    }
    drop(socket);
    listener.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_axfr_and_ixfr_interoperate_with_plugin_stream() {
    if std::process::Command::new("dig")
        .arg("-v")
        .output()
        .is_err()
    {
        return;
    }
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Transfer), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    for qtype in ["AXFR", "IXFR=0"] {
        let output = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &listener.local_addr().port().to_string(),
                "a.",
                qtype,
                "+tcp",
                "+time=2",
                "+tries=1",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("XFR size:") || text.contains("Transfer completed"),
            "{text}"
        );
        assert_eq!(text.matches("\tSOA\t").count(), 2, "{text}");
    }
    listener.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_signed_axfr_and_ixfr_interoperate_with_plugin_stream() {
    if std::process::Command::new("dig")
        .arg("-v")
        .output()
        .is_err()
    {
        return;
    }
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(SignedTransfer), vec![]);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    for qtype in ["AXFR", "IXFR=0"] {
        let output = std::process::Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &listener.local_addr().port().to_string(),
                "-y",
                "hmac-sha256:key.:c2VjcmV0",
                "a.",
                qtype,
                "+tcp",
                "+time=2",
                "+tries=1",
            ])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{text}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            text.contains("XFR size:") || text.contains("Transfer completed"),
            "{text}"
        );
        assert_eq!(text.matches("\tSOA\t").count(), 2, "{text}");
    }
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn axfr_client_interoperates_with_coredns_file_and_transfer() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let binary = root.join("coredns/v1.15.0/coredns");
    if !binary.exists() {
        return;
    }
    let dir = root.join(format!("transfer-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let zone = dir.join("db.a");
    let mut contents = String::from(
        "$ORIGIN a.\n$TTL 60\n@ IN SOA ns.a. hostmaster.a. 1 3600 600 604800 60\n@ IN NS ns.a.\nns IN A 127.0.0.1\nwww IN A 192.0.2.1\n",
    );
    for index in 0..4000 {
        contents.push_str(&format!("host{index} IN A 192.0.2.1\n"));
    }
    std::fs::write(&zone, contents).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dir.join("Corefile");
    std::fs::write(
        &config,
        format!(
            "a.:{port} {{\n bind 127.0.0.1\n tsig {{\n  secret key. c2VjcmV0\n }}\n file {} a.\n transfer {{\n  to *\n }}\n}}\n",
            zone.display()
        ),
    )
    .unwrap();
    struct Child(std::process::Child, std::path::PathBuf);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _child = Child(
        std::process::Command::new(binary)
            .args(["-conf", config.to_str().unwrap()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    timeout(Duration::from_secs(5), async {
        while TcpStream::connect(address).await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut types = Vec::new();
    pharos_server::transfer::axfr(
        address,
        &"a.".parse().unwrap(),
        1,
        Duration::from_secs(3),
        |message| {
            types.extend(message.answers().map(|record| record.rtype));
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(types.first(), Some(&Type::SOA));
    assert_eq!(types.last(), Some(&Type::SOA));
    assert!(types.contains(&Type::A));
    let key = pharos_proto::TsigKey::new(
        "key.".parse().unwrap(),
        pharos_proto::TsigAlgorithm::Sha256,
        b"secret",
    );
    let mut messages = 0;
    let mut signed_types = Vec::new();
    pharos_server::transfer::axfr_signed(
        address,
        &"a.".parse().unwrap(),
        2,
        Duration::from_secs(3),
        &key,
        |message| {
            messages += 1;
            signed_types.extend(message.answers().map(|record| record.rtype));
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(messages > 1, "signed CoreDNS transfer must span Messages");
    assert_eq!(signed_types.first(), Some(&Type::SOA));
    assert_eq!(signed_types.last(), Some(&Type::SOA));
    assert!(signed_types.contains(&Type::A));
}

#[tokio::test]
async fn coredns_secondary_receives_plugin_axfr_stream() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let binary = root.join("coredns/v1.15.0/coredns");
    if !binary.exists() {
        return;
    }
    struct UnsignedProbe(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Chain for UnsignedProbe {
        async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
            if cx
                .query
                .questions()
                .next()
                .is_some_and(|q| q.qtype == Type::AXFR)
            {
                assert!(cx.query.additionals().all(|r| r.rtype != Type::TSIG));
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Chain::serve(&Transfer, cx).await
        }
        fn is_empty(&self) -> bool {
            false
        }
    }
    let saw_unsigned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(UnsignedProbe(saw_unsigned.clone())),
        vec![],
    );
    let primary = Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
        .await
        .unwrap();
    let dir = root.join(format!("transfer-secondary-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = dir.join("Corefile");
    std::fs::write(
        &config,
        format!(
            "a.:{port} {{\n bind 127.0.0.1\n tsig {{\n  secret key. c2VjcmV0\n }}\n secondary {{\n  transfer from {}\n }}\n}}\n",
            primary.local_addr()
        ),
    )
    .unwrap();
    struct Child(std::process::Child, std::path::PathBuf);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _child = Child(
        std::process::Command::new(binary)
            .args(["-conf", config.to_str().unwrap()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let address = format!("127.0.0.1:{port}");
    timeout(Duration::from_secs(5), async {
        let mut wire = [0; 512];
        loop {
            socket.send_to(&query, &address).await.unwrap();
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(100), socket.recv_from(&mut wire)).await
                && let Ok(message) = Message::parse(&wire[..len])
                && message
                    .answers()
                    .any(|record| record.rtype == Type::A && record.rdata == [127, 0, 0, 1])
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(saw_unsigned.load(std::sync::atomic::Ordering::SeqCst));
    primary.shutdown().await.unwrap();
}
