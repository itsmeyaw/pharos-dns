use super::*;

#[test]
fn coredns_duplicate_warning_names_the_first_file_on_each_scan() {
    if std::env::var_os("PHAROS_AUTO_DUPLICATE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auto::tests::coredns_duplicate_warning_names_the_first_file_on_each_scan",
                "--nocapture",
            ])
            .env("PHAROS_AUTO_DUPLICATE_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let warnings: Vec<_> = stdout
            .lines()
            .filter(|line| {
                line.contains(
                    "WARN auto: Multiple zone files match origin \"example.org.\": using ",
                )
            })
            .collect();
        assert_eq!(warnings.len(), 2, "{stdout}");
        for warning in warnings {
            assert!(
                warning.contains("example.org.zone\" instead of \""),
                "{warning}"
            );
            assert!(
                warning.ends_with("example.org.zone.bak-20260528\""),
                "{warning}"
            );
        }
        return;
    }
    let root = std::env::temp_dir().join(format!("pharos-auto-duplicate-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let first = root.join("example.org.zone");
    let second = root.join("example.org.zone.bak-20260528");
    std::fs::write(&first, "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n").unwrap();
    std::fs::write(&second, "@ 60 IN SOA ns. hostmaster. 2 2 3 4 5\n").unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"(.*)\.zone").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    for _ in 0..2 {
        auto.shared.scan();
        let entry = Arc::clone(
            auto.shared
                .zones
                .load()
                .origins
                .get("example.org.")
                .unwrap(),
        );
        assert_eq!(
            *entry.path.lock().unwrap(),
            std::fs::canonicalize(&first).unwrap()
        );
        assert_eq!(entry.current.load().as_ref().unwrap().serial(), Some(1));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn coredns_walk_missing_directory_leaves_no_zones() {
    let root = std::env::temp_dir().join(format!("pharos-auto-missing-{}", std::process::id()));
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root,
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    auto.shared.scan();
    assert!(auto.shared.zones.load().origins.is_empty());
}

#[tokio::test]
async fn coredns_symlink_repoint_is_served_after_scan() {
    use pharos_proto::{Class, Message, MessageBuilder, NameRef, Type};
    use pharos_server::{Metadata, Protocol, Transport};
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("pharos-auto-repoint-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let old = root.join("old");
    let new = root.join("new");
    std::fs::write(
        &old,
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\nwww 60 IN A 192.0.2.1\n",
    )
    .unwrap();
    std::fs::write(
        &new,
        "@ 60 IN SOA ns. hostmaster. 2 2 3 4 5\nwww 60 IN A 192.0.2.2\n",
    )
    .unwrap();
    let link = root.join("db.example.org");
    symlink(&old, &link).unwrap();
    let auto = Auto::new(
        vec![".".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"^db\.(.*)$").unwrap(),
        "${1}".into(),
        Duration::from_secs(60),
    );
    auto.shared.scan();
    let name: Name = "www.example.org.".parse().unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        auto.serve_with(&mut cx, TestNext, false).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
    std::fs::remove_file(&link).unwrap();
    symlink(&new, &link).unwrap();
    auto.shared.scan();
    assert_eq!(
        auto.serve_with(&mut cx, TestNext, false).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
    let broken = root.join("broken");
    std::fs::write(&broken, "invalid zone").unwrap();
    std::fs::remove_file(&link).unwrap();
    symlink(&broken, &link).unwrap();
    auto.shared.scan();
    assert_eq!(
        auto.serve_with(&mut cx, TestNext, false).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
    std::fs::write(
        &broken,
        "@ 60 IN SOA ns. hostmaster. 3 2 3 4 5\nwww 60 IN A 192.0.2.3\n",
    )
    .unwrap();
    auto.shared.scan();
    assert_eq!(
        auto.serve_with(&mut cx, TestNext, false).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 3]
    );
    std::fs::remove_dir_all(root).unwrap();
}

struct TestNext;
impl Next for TestNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::NOTIMP)
    }
}

#[tokio::test]
async fn restart_during_scan_stops_old_watcher_before_restarting() {
    let root = std::env::temp_dir().join(format!("pharos-auto-race-{}", std::process::id()));
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
        Duration::from_millis(10),
    );
    let mut lifecycle = pharos_server::Lifecycle::default();
    auto.register_hooks(&mut lifecycle);
    lifecycle.run(pharos_server::Phase::Startup).await.unwrap();
    let entry = Arc::clone(
        auto.shared
            .zones
            .load()
            .origins
            .get("example.org.")
            .unwrap(),
    );
    let old = entry.task.lock().unwrap().as_ref().unwrap().abort_handle();
    let path_guard = entry.path.lock().unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while auto.shared.scan_gate.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let stopped = lifecycle.clone();
    let restart = tokio::spawn(async move { stopped.run(pharos_server::Phase::Restart).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !*auto.shared.shutdown.borrow() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!restart.is_finished());
    drop(path_guard);
    tokio::time::timeout(Duration::from_secs(3), restart)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(old.is_finished());
    lifecycle
        .run(pharos_server::Phase::RestartFailed)
        .await
        .unwrap();
    assert_eq!(auto.shared.tasks.lock().unwrap().len(), 1);
    let replacement = entry.task.lock().unwrap().as_ref().unwrap().abort_handle();
    assert!(!replacement.is_finished());
    lifecycle.run(pharos_server::Phase::Shutdown).await.unwrap();
    assert!(replacement.is_finished());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn coredns_unloaded_zone_refuses_or_passes_to_next() {
    use pharos_proto::{Class, Message, MessageBuilder, NameRef, Type};
    use pharos_server::{Metadata, Protocol, Transport};
    let root = std::env::temp_dir().join(format!("pharos-auto-unloaded-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("db.example.org"), "invalid zone").unwrap();
    let auto = Auto::new(
        vec!["example.org.".parse().unwrap()],
        root.clone(),
        regex::Regex::new(r"db\.(.*)").unwrap(),
        "${1}".into(),
        Duration::ZERO,
    );
    auto.shared.scan();
    let name: Name = "test.example.org.".parse().unwrap();
    let domain: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    // A nil or missing map entry behind a known Zone name cannot arise in the atomic snapshot.
    assert_eq!(
        auto.serve_with(&mut cx, TestNext, false).await,
        Outcome::Unanswered(Rcode::REFUSED)
    );
    assert_eq!(
        auto.serve_with(&mut cx, TestNext, true).await,
        Outcome::Unanswered(Rcode::NOTIMP)
    );
    std::fs::remove_dir_all(root).unwrap();
}

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
    assert!(!entry.reload());
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
