use pharos_plugins::proxy::{Options, Proxy, Transport};
use tokio::net::UdpSocket;

const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

#[tokio::test]
async fn exchanges_a_query_with_a_udp_upstream() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let proxy = Proxy::new(address);
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    assert_eq!(result.len, QUERY.len());
    assert_eq!(&response[..2], &QUERY[..2]);
    assert_ne!(response[2] & 0x80, 0);
    task.await.unwrap();
}

#[tokio::test]
async fn exchanges_a_query_with_a_tcp_upstream() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut wire = [0; 512];
        stream.read_exact(&mut wire[..len]).await.unwrap();
        wire[2] |= 0x80;
        stream.write_u16(len as u16).await.unwrap();
        stream.write_all(&wire[..len]).await.unwrap();
    });
    let proxy = Proxy::new(address);
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
        .await
        .unwrap();
    assert_eq!(result.transport, Transport::Tcp);
    assert_eq!(&response[..2], &QUERY[..2]);
    task.await.unwrap();
}
