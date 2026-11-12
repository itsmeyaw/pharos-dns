#![forbid(unsafe_code)]

use pharos_proto::{Message, Type};
use pharos_server::{
    Chain, Context, Listener, ListenerKey, Outcome, Router, Server, Stream, Transport,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
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
