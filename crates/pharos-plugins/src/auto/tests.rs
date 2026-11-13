use super::*;

#[test]
fn coredns_walk_rejects_wrong_soa_then_loads_corrected_zone() {
    let root = std::env::temp_dir().join(format!("pharos-auto-soa-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("db.example.org");
    std::fs::write(&path, "example.net. 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"^db\.(.*)$").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    auto.shared.scan();
    assert!(auto.shared.zones.load().origins.is_empty());
    std::fs::write(&path, "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    auto.shared.scan();
    assert!(
        auto.shared
            .zones
            .load()
            .origins
            .contains_key("example.org.")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn watcher_started_after_shutdown_exits() {
    let root = std::env::temp_dir().join(format!("pharos-auto-stopped-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.example.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n",
    )
    .unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::from_secs(60),
    );
    auto.shared.scan();
    auto.shared.shutdown.send_replace(true);
    auto.shared.start_watchers(Duration::from_secs(60));
    let entry = Arc::clone(auto.shared.zones.load().origins.values().next().unwrap());
    let task = entry.task.lock().unwrap().take().unwrap();
    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .unwrap()
        .unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn coredns_walk_adds_removes_and_reload_checks_serial() {
    let root = std::env::temp_dir().join(format!("pharos-auto-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("nested")).unwrap();
    let text = "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\nwww 60 IN A 192.0.2.1\n";
    let path = root.join("nested/db.example.org");
    std::fs::write(&path, text).unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::from_secs(1),
    );
    auto.shared.scan();
    assert_eq!(auto.shared.zones.load().origins.len(), 1);
    let entry = Arc::clone(auto.shared.zones.load().origins.values().next().unwrap());
    assert_eq!(entry.current.load().as_ref().unwrap().serial(), Some(1));
    std::fs::write(&path, text.replace("192.0.2.1", "192.0.2.2")).unwrap();
    assert!(!entry.reload());
    std::fs::write(&path, text.replace(" 1 2 3", " 2 2 3")).unwrap();
    assert!(entry.reload());
    assert_eq!(entry.current.load().as_ref().unwrap().serial(), Some(2));
    std::fs::write(&path, "bad zone").unwrap();
    assert!(!entry.reload());
    assert_eq!(entry.current.load().as_ref().unwrap().serial(), Some(2));
    std::fs::remove_file(path).unwrap();
    auto.shared.scan();
    assert!(auto.shared.zones.load().origins.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn coredns_walk_keeps_first_path_and_follows_root_symlink() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("pharos-auto-symlink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let zones = root.join("zones");
    std::fs::create_dir_all(&zones).unwrap();
    let first = zones.join("example.org.zone");
    let second = zones.join("example.org.zone.bak");
    std::fs::write(&first, "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    std::fs::write(&second, "@ 60 IN SOA ns. hostmaster. 2 2 3 4 5\n").unwrap();
    symlink(&zones, root.join("link")).unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.join("link"),
        regex::Regex::new(r"(.*)\.zone").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    auto.shared.scan();
    let entry = Arc::clone(auto.shared.zones.load().origins.values().next().unwrap());
    assert_eq!(entry.current.load().as_ref().unwrap().serial(), Some(1));
    assert_eq!(
        *entry.path.lock().unwrap(),
        std::fs::canonicalize(&first).unwrap()
    );
    std::fs::remove_file(first).unwrap();
    auto.shared.scan();
    assert_eq!(
        *entry.path.lock().unwrap(),
        std::fs::canonicalize(&second).unwrap()
    );
    assert!(entry.reload());
    assert_eq!(entry.current.load().as_ref().unwrap().serial(), Some(2));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "plugin-transfer")]
#[test]
fn coredns_transfer_matches_zone_case_exactly() {
    use crate::transfer::{TransferRequest, Transferer};
    use pharos_proto::{Class, NameRef, Type};
    use pharos_server::Protocol;
    let root = std::env::temp_dir().join(format!("pharos-auto-transfer-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.example.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n",
    )
    .unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    auto.shared.scan();
    for (name, found) in [
        ("example.org.", true),
        ("EXAMPLE.ORG.", false),
        ("other.org.", false),
    ] {
        let name: Name = name.parse().unwrap();
        let request = TransferRequest {
            zone: NameRef::parse(name.as_wire(), 0).unwrap(),
            qtype: Type::AXFR,
            qclass: Class::IN,
            serial: 0,
            id: 1,
            flags: 0,
            protocol: Protocol::Tcp,
        };
        assert_eq!(auto.transfer(request).unwrap().is_some(), found);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn coredns_watcher_adds_reloads_and_removes_zones() {
    let root = std::env::temp_dir().join(format!("pharos-auto-watcher-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::from_millis(20),
    );
    let mut lifecycle = pharos_server::Lifecycle::default();
    auto.register_hooks(&mut lifecycle);
    lifecycle.run(pharos_server::Phase::Startup).await.unwrap();
    let path = root.join("db.example.org");
    std::fs::write(&path, "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while auto.shared.zones.load().origins.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    std::fs::write(&path, "@ 60 IN SOA ns. hostmaster. 2 2 3 4 5\n").unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while auto
            .shared
            .zones
            .load()
            .origins
            .values()
            .next()
            .unwrap()
            .current
            .load()
            .as_ref()
            .and_then(|zone| zone.serial())
            != Some(2)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    std::fs::remove_file(&path).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !auto.shared.zones.load().origins.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    lifecycle.run(pharos_server::Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn coredns_most_specific_zone_and_template_captures() {
    let root = std::env::temp_dir().join(format!("pharos-auto-mapping-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for file in [
        "www.db.example.org",
        "www.db.child.example.org",
        "www.db.UPPER.org",
    ] {
        std::fs::write(root.join(file), "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    }
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"www\.db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    auto.shared.scan();
    for (query, expected) in [
        ("www.example.org.", Some("example.org.")),
        ("www.child.example.org.", Some("child.example.org.")),
        ("www.upper.org.", Some("UPPER.org.")),
        ("www.other.org.", None),
    ] {
        let name: Name = query.parse().unwrap();
        assert_eq!(
            auto.shared
                .find(name.as_wire())
                .as_ref()
                .map(|entry| entry.origin.as_str()),
            expected
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "plugin-transfer")]
#[tokio::test]
async fn changed_serial_sends_notify_without_directory_scan() {
    let root =
        std::env::temp_dir().join(format!("pharos-auto-change-notify-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("db.example.org");
    std::fs::write(&path, "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let text = format!(
        "example.org:53 {{\n transfer {{\n to {}\n }}\n}}",
        socket.local_addr().unwrap()
    );
    let blocks = pharos_corefile::parse("Corefile", &text).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::from_millis(20),
    );
    auto.shared
        .notifier
        .bind(configured[0].config.transfer.as_ref());
    auto.shared.scan();
    auto.shared.start_watchers(Duration::from_millis(20));
    std::fs::write(&path, "@ 60 IN SOA ns. hostmaster. 2 2 3 4 5\n").unwrap();
    let mut wire = [0; 512];
    let (len, peer) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pharos_proto::Message::parse(&wire[..len]).unwrap().opcode(),
        pharos_proto::Opcode::NOTIFY
    );
    wire[2] |= 0x80;
    socket.send_to(&wire[..len], peer).await.unwrap();
    for entry in auto.shared.zones.load().origins.values() {
        if let Some(task) = entry.task.lock().unwrap().take() {
            task.abort();
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
