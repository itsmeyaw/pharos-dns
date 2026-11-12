#![forbid(unsafe_code)]

use pharos_proto::{Message, Rcode, Type};
use pharos_server::{
    Chain, Context, Listener, ListenerKey, Outcome, Router, Server, Stream, Transport,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Duration, timeout},
};

struct Transfer;

impl Chain for Transfer {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let id = cx.query.id().to_be_bytes();
        let mut count = 0;
        Outcome::Stream(Stream::new(move |wire| {
            if count == 3 {
                return Ok(false);
            }
            wire.extend_from_slice(&[id[0], id[1], 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
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
