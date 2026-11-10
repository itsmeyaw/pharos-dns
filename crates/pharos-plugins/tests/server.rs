#![forbid(unsafe_code)]
#![cfg(feature = "plugin-whoami")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Listener, Phase};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Duration, timeout},
};

fn query(name: &str) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(name.as_wire());
    wire.extend_from_slice(&[0, 1, 0, 1]);
    wire
}

#[tokio::test]
async fn lifecycle_runs_once_for_a_block_with_multiple_listeners() {
    let blocks = parse("Corefile", ".:1053 dns://.:1054 {\n whoami\n}").unwrap();
    let mut configs = configure::<Chain>(&blocks, directives()).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let hook_count = Arc::clone(&count);
    configs[0]
        .config
        .lifecycle
        .register_sync(Phase::Startup, move || {
            hook_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
    let (listeners, lifecycle) = servers(configs).unwrap();
    assert_eq!(listeners.len(), 2);
    lifecycle.run(Phase::Startup).await.unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn grouped_lifecycle_preserves_block_order() {
    let blocks = parse(
        "Corefile",
        "example.org:1053 {\n whoami\n}\nother.org:1054 {\n whoami\n}",
    )
    .unwrap();
    let mut configs = configure::<Chain>(&blocks, directives()).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    for (index, config) in configs.iter_mut().enumerate() {
        let events = Arc::clone(&events);
        config
            .config
            .lifecycle
            .register_sync(Phase::Startup, move || {
                events.lock().unwrap().push(index);
                Ok(())
            });
    }
    let (_, lifecycle) = servers(configs).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    assert_eq!(*events.lock().unwrap(), [0, 1]);
}

#[tokio::test]
async fn corefile_routes_real_udp_and_tcp_queries() {
    let blocks = parse(
        "Corefile",
        "example.org:0 {\n whoami\n}\nother.org:0 {\n whoami\n}",
    )
    .unwrap();
    let mut configs = configure::<Chain>(&blocks, directives()).unwrap();
    let hooks = Arc::new(AtomicUsize::new(0));
    for config in &mut configs {
        for phase in [Phase::Startup, Phase::Shutdown] {
            let hooks = Arc::clone(&hooks);
            config.config.lifecycle.register_sync(phase, move || {
                hooks.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
        }
    }
    let (mut servers, lifecycle) = servers(configs).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    assert_eq!(servers.len(), 1);
    let (key, server) = servers.drain().next().unwrap();
    let listener = Listener::bind(key.address, server).await.unwrap();
    assert_eq!(hooks.load(Ordering::Relaxed), 2);
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr().port()));
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(address).await.unwrap();
    let mut tcp = TcpStream::connect(address).await.unwrap();
    for (name, rcode) in [
        ("www.example.org.", Rcode::NOERROR),
        ("other.org.", Rcode::NOERROR),
        ("missing.org.", Rcode::REFUSED),
    ] {
        let wire = query(name);
        udp.send(&wire).await.unwrap();
        let mut buffer = [0; 2048];
        let size = timeout(Duration::from_secs(2), udp.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = Message::parse(&buffer[..size]).unwrap();
        assert_eq!(response.rcode(), rcode);
        assert_eq!(response.questions().next().unwrap().name.to_string(), name);
        tcp.write_u16(wire.len() as u16).await.unwrap();
        tcp.write_all(&wire).await.unwrap();
        let size = timeout(Duration::from_secs(2), tcp.read_u16())
            .await
            .unwrap()
            .unwrap();
        tcp.read_exact(&mut buffer[..usize::from(size)])
            .await
            .unwrap();
        let response = Message::parse(&buffer[..usize::from(size)]).unwrap();
        assert_eq!(response.rcode(), rcode);
        assert_eq!(response.questions().next().unwrap().name.to_string(), name);
    }
    drop(tcp);
    listener.shutdown().await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(hooks.load(Ordering::Relaxed), 4);
}
