#![forbid(unsafe_code)]
#![cfg(feature = "plugin-hosts")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::Message;
use pharos_server::{Action, Handler, Phase, Protocol};
use std::time::Duration;

#[test]
fn updates_changed_file_and_zero_disables_reload() {
    crate::on_plugin_stack(changed_file_and_zero_reload);
}

async fn changed_file_and_zero_reload() {
    for (interval, expected) in [("10ms", [192, 0, 2, 22]), ("0", [192, 0, 2, 1])] {
        let path =
            std::env::temp_dir().join(format!("pharos-hosts-{}-{interval}", std::process::id()));
        std::fs::write(&path, "192.0.2.1 example.org\n").unwrap();
        let text = format!(
            ".:0 {{\n hosts {} {{\n reload {interval}\n }}\n}}",
            path.display()
        );
        let blocks = parse("Corefile", &text).unwrap();
        let (mut servers, lifecycle) =
            servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
        lifecycle.run(Phase::Startup).await.unwrap();
        let (_, server) = servers.drain().next().unwrap();
        let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";
        let mut response = Vec::with_capacity(65535);
        let client = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(
            server
                .handle(query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            [192, 0, 2, 1]
        );
        std::fs::write(&path, "192.0.2.22 example.org\n").unwrap();
        if interval == "0" {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                assert_eq!(
                    server
                        .handle(query, client, Protocol::Udp, &mut response)
                        .await,
                    Action::Respond
                );
                if Message::parse(&response)
                    .unwrap()
                    .answers()
                    .next()
                    .unwrap()
                    .rdata
                    == expected
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("hosts file did not reload");
        lifecycle.run(Phase::Shutdown).await.unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn reports_hosts_entries_and_reload_timestamp() {
    let path = std::env::temp_dir().join(format!("pharos-hosts-metrics-{}", std::process::id()));
    std::fs::write(&path, "192.0.2.1 one.example.org alias.example.org\n").unwrap();
    let text = format!(".:0 {{\n hosts {} {{\n reload 0\n }}\n}}", path.display());
    let blocks = parse("Corefile", &text).unwrap();
    let registry = pharos_server::metrics::Registry::default();
    let (_, lifecycle) = pharos_plugins::servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains(&format!(
            "pharos_hosts_entries{{hostsfile=\"{}\"}} 4",
            path.display()
        )),
        "{output}"
    );
    assert!(
        output.contains("pharos_hosts_reload_timestamp_seconds "),
        "{output}"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn restart_stops_watcher_and_failed_restart_resumes_it() {
    let path = std::env::temp_dir().join(format!("pharos-hosts-restart-{}", std::process::id()));
    std::fs::write(&path, "192.0.2.1 example.org\n").unwrap();
    let text = format!(
        ".:0 {{\n hosts {} {{\n reload 10ms\n }}\n}}",
        path.display()
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, lifecycle) =
        servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    lifecycle.run(Phase::Restart).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(65535);
    let client = "127.0.0.1:1234".parse().unwrap();
    std::fs::write(&path, "192.0.2.22 example.org\n").unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        server
            .handle(query, client, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    assert_eq!(
        server
            .handle(query, client, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 22]
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_file(path).unwrap();
}
