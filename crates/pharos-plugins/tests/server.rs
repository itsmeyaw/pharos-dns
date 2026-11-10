#![forbid(unsafe_code)]
#![cfg(feature = "plugin-whoami")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Handler, Listener, Phase, Protocol};
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
async fn listeners_share_metrics_and_attribute_whoami_responses() {
    let blocks = parse("Corefile", ".:1053 dns://.:1054 {\n whoami\n}").unwrap();
    let configs = configure::<Chain>(&blocks, directives()).unwrap();
    let (servers, _) = servers(configs).unwrap();
    for server in servers.values() {
        server
            .handle(
                &query("a."),
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut Vec::with_capacity(512),
            )
            .await;
    }
    let mut text = String::new();
    servers.values().next().unwrap().metrics().encode(&mut text);
    for port in [1053, 1054] {
        assert!(text.contains(&format!("pharos_plugin_enabled{{name=\"whoami\",server=\"dns://:{port}\",view=\"\",zone=\".\"}} 1")), "{text}");
        assert!(text.contains(&format!("pharos_dns_responses_total{{plugin=\"whoami\",rcode=\"NOERROR\",server=\"dns://:{port}\",view=\"\",zone=\".\"}} 1")), "{text}");
    }
}

#[tokio::test]
async fn plugin_error_log_names_plugin() {
    if std::env::var_os("PHAROS_TEST_PLUGIN_ERROR").is_some() {
        let blocks = parse("Corefile", ".:1053 {\n whoami\n}").unwrap();
        let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
        servers
            .values()
            .next()
            .unwrap()
            .handle(
                &query("a."),
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut Vec::new(),
            )
            .await;
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "plugin_error_log_names_plugin", "--nocapture"])
        .env("PHAROS_TEST_PLUGIN_ERROR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(" ERROR whoami: Plugin error: Response buffer too small\n"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn custom_error_logger_is_preserved_for_named_plugin() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    fn log(_: pharos_server::Error) {
        COUNT.fetch_add(1, Ordering::Relaxed);
    }
    let blocks = parse("Corefile", ".:1053 {\n whoami\n}").unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values_mut().next().unwrap();
    server.logger = log;
    server
        .handle(
            &query("a."),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut Vec::new(),
        )
        .await;
    assert_eq!(COUNT.load(Ordering::Relaxed), 1);
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
