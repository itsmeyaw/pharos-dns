use super::*;
use pharos_proto::{Message, MessageBuilder, NameRef, Section, Type, zone::ZoneRecord};
use std::{fmt::Write, io, net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn primary_matches(address: &str, client: SocketAddr) -> bool {
    let host = if let Some(value) = address.strip_prefix('[') {
        match value.split_once(']') {
            Some((host, _)) => host,
            None => return false,
        }
    } else {
        match address.rsplit_once(':') {
            Some((host, _)) => host,
            None => return false,
        }
    };
    let (host, scope) = host
        .split_once('%')
        .map_or((host, None), |(host, scope)| (host, Some(scope)));
    struct Text {
        bytes: [u8; 64],
        len: usize,
    }
    impl std::fmt::Write for Text {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
            self.bytes
                .get_mut(self.len..end)
                .ok_or(std::fmt::Error)?
                .copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut rendered = Text {
        bytes: [0; 64],
        len: 0,
    };
    if write!(rendered, "{}", client.ip()).is_err()
        || rendered.bytes[..rendered.len] != *host.as_bytes()
    {
        return false;
    }
    match (client, scope) {
        (SocketAddr::V4(_), None) => true,
        (SocketAddr::V6(client), None) => client.scope_id() == 0,
        (SocketAddr::V6(client), Some(scope)) => {
            // RFC 4007 §11: a scoped IPv6 address identifies an interface zone.
            // shortcut: numeric and named scopes compare equal; use text when remote scope names are available.
            let scope_id = scope.parse().ok().or_else(|| {
                (scope.len() < nix::libc::IF_NAMESIZE)
                    .then(|| nix::net::if_::if_nametoindex(scope).ok())
                    .flatten()
            });
            scope_id == Some(client.scope_id())
        }
        (SocketAddr::V4(_), Some(_)) => false,
    }
}

fn random_id() -> u16 {
    let mut bytes = [0; 2];
    let _ = getrandom::getrandom(&mut bytes);
    u16::from_ne_bytes(bytes)
}

pub(super) async fn transfer(shared: &Arc<Shared>, zone: &SecondaryZone) -> io::Result<()> {
    let mut error = io::Error::other("no Primary Server");
    for primary in &zone.config.from {
        let addresses = match tokio::net::lookup_host(primary).await {
            Ok(addresses) => addresses,
            Err(err) => {
                error = err;
                continue;
            }
        };
        for address in addresses {
            let mut records = Vec::new();
            let result = pharos_server::transfer::axfr_coredns(
                address,
                &zone.config.apex,
                random_id(),
                Duration::from_secs(5),
                |message| {
                    for record in message.answers() {
                        let data = record.data().map_err(io::Error::other)?;
                        // RFC 5936 §2.2: transferred names are expanded before storing a Zone snapshot.
                        let mut wire = Vec::with_capacity(512);
                        let mut builder = MessageBuilder::new(&mut wire, 65535, 0, 0)
                            .map_err(io::Error::other)?;
                        let written = builder
                            .record_with(
                                Section::Answer,
                                record.name,
                                record.rtype,
                                record.class,
                                record.ttl,
                                |writer| {
                                    writer.disable_compression();
                                    data.write(writer)
                                },
                            )
                            .map_err(io::Error::other)?;
                        if !written {
                            return Err(io::Error::other("record exceeds Message limit"));
                        }
                        let _ = builder.finish();
                        let parsed = Message::parse(&wire).map_err(io::Error::other)?;
                        let expanded = parsed
                            .answers()
                            .next()
                            .ok_or_else(|| io::Error::other("missing record"))?;
                        records.push(ZoneRecord {
                            owner: record.name.to_name(),
                            rtype: record.rtype,
                            class: record.class,
                            ttl: record.ttl,
                            rdata: expanded.rdata.to_vec(),
                        });
                    }
                    Ok(())
                },
            )
            .await;
            match result {
                Ok(()) => {
                    let next = match crate::zone::Zone::from_records(
                        zone.config.apex.clone(),
                        records.clone(),
                    ) {
                        Ok(next) => next,
                        Err(err) => {
                            error = io::Error::other(err);
                            continue;
                        }
                    };
                    let catalog = if zone.config.catalog.is_some() {
                        Some(
                            super::catalog::parse(&zone.config.apex, &records)
                                .map_err(io::Error::other)?,
                        )
                    } else {
                        None
                    };
                    zone.current.store(Some(Arc::new(next)));
                    zone.expired.store(false, Ordering::Relaxed);
                    if let Some(catalog) = catalog {
                        super::catalog::apply(shared, zone, catalog);
                    }
                    #[cfg(feature = "plugin-transfer")]
                    if let Some(notifier) = shared.notifier.get() {
                        // RFC 1996 §3.1: notify downstream Secondary Servers after a transfer.
                        if let Err(err) = notifier.notify(&zone.config.apex).await {
                            pharos_server::logging::log(
                                "WARN",
                                "secondary",
                                &format!("NOTIFY {}: {err}", zone.config.apex),
                            );
                        }
                    }
                    return Ok(());
                }
                Err(err) => error = err,
            }
        }
    }
    Err(error)
}

pub(super) async fn should_transfer(zone: &SecondaryZone) -> io::Result<bool> {
    let mut error = None;
    for primary in &zone.config.from {
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut socket = tokio::net::TcpStream::connect(primary).await?;
            let mut query = Vec::with_capacity(512);
            let id = random_id();
            let mut builder =
                MessageBuilder::new(&mut query, 512, id, 0).map_err(io::Error::other)?;
            builder
                .question(
                    NameRef::parse(zone.config.apex.as_wire(), 0).map_err(io::Error::other)?,
                    Type::SOA,
                    Class::IN,
                )
                .map_err(io::Error::other)?;
            let _ = builder.finish();
            socket.write_u16(query.len() as u16).await?;
            socket.write_all(&query).await?;
            let len = socket.read_u16().await?;
            let mut response = vec![0; usize::from(len)];
            socket.read_exact(&mut response).await?;
            let message = Message::parse(&response).map_err(io::Error::other)?;
            // RFC 1035 §4.1.1: a Response ID matches the original Query.
            if message.id() != id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SOA Response ID mismatch",
                ));
            }
            if message.rcode() != Rcode::NOERROR {
                return Ok(None);
            }
            for answer in message.answers() {
                if let Ok(pharos_proto::Rdata::Soa { serial, .. }) = answer.data() {
                    return Ok(Some(serial));
                }
            }
            Ok::<_, io::Error>(None)
        })
        .await;
        match result {
            Ok(Ok(Some(serial))) => {
                let current = zone.current.load();
                return Ok(current
                    .as_ref()
                    .and_then(|zone| zone.serial())
                    .is_none_or(|local| serial_less(local, serial)));
            }
            Ok(Ok(None)) => error = None,
            Ok(Err(err)) => error = Some(err),
            Err(err) => error = Some(io::Error::new(io::ErrorKind::TimedOut, err)),
        }
    }
    error.map_or(Ok(false), Err)
}

// RFC 1982 §3.2: compare serial numbers modulo 2^32.
pub(super) fn serial_less(a: u32, b: u32) -> bool {
    if a < b {
        b - a <= i32::MAX as u32
    } else {
        a - b > i32::MAX as u32
    }
}

// RFC 1035 §3.3.13: SOA supplies refresh, retry and expire intervals.
pub(super) fn timers(zone: &SecondaryZone) -> (Duration, Duration, Duration) {
    let current = zone.current.load();
    let soa = current
        .as_ref()
        .and_then(|zone| zone.records().iter().find(|rr| rr.rtype == Type::SOA));
    let value = |offset: usize| {
        soa.and_then(|rr| {
            rr.rdata
                .get(rr.rdata.len().checked_sub(20)? + offset..)?
                .get(..4)
        })
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(1)
        .max(1)
    };
    (
        Duration::from_secs(u64::from(value(4))),
        Duration::from_secs(u64::from(value(8))),
        Duration::from_secs(u64::from(value(12))),
    )
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn run(shared: Arc<Shared>, zone: Arc<SecondaryZone>) {
    let notify_shared = Arc::clone(&shared);
    let notify_zone = Arc::clone(&zone);
    let _notify_task = AbortOnDrop(tokio::spawn(async move {
        let mut checks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = notify_zone.notify.notified() => {
                    while notify_zone.notify_pending.try_update(Ordering::Relaxed, Ordering::Relaxed, |pending| pending.checked_sub(1)).is_ok() {
                        let shared = Arc::clone(&notify_shared);
                        let zone = Arc::clone(&notify_zone);
                        // RFC 1996 §3: process each NOTIFY outside the Query path.
                        checks.spawn(async move {
                            match should_transfer(&zone).await {
                                Ok(true) => if let Err(error) = transfer(&shared, &zone).await {
                                    pharos_server::logging::log("WARN", "secondary", &format!("NOTIFY transfer {}: {error}", zone.config.apex));
                                },
                                Ok(false) => {},
                                Err(error) => pharos_server::logging::log("WARN", "secondary", &format!("NOTIFY check {}: {error}", zone.config.apex)),
                            }
                        });
                    }
                }
                _ = checks.join_next(), if !checks.is_empty() => {}
            }
        }
    }));
    let mut delay = Duration::from_millis(250);
    while let Err(error) = transfer(&shared, &zone).await {
        pharos_server::logging::log(
            "WARN",
            "secondary",
            &format!(
                "Transfer {} failed; retrying in {delay:?}: {error}",
                zone.config.apex
            ),
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(10));
    }
    'restart: loop {
        let (refresh, retry, expire) = timers(&zone);
        let mut refresh = tokio::time::interval_at(tokio::time::Instant::now() + refresh, refresh);
        let mut retry = tokio::time::interval_at(tokio::time::Instant::now() + retry, retry);
        let mut expire = tokio::time::interval_at(tokio::time::Instant::now() + expire, expire);
        let mut retry_active = false;
        loop {
            let jitter = tokio::select! {
                _ = refresh.tick() => 5000,
                _ = retry.tick(), if retry_active => 2000,
                _ = expire.tick() => {
                    if retry_active { zone.expired.store(true, Ordering::Relaxed); }
                    continue;
                }
            };
            if jitter > 0 {
                tokio::time::sleep(Duration::from_millis(u64::from(random_id() % jitter))).await;
            }
            match should_transfer(&zone).await {
                Ok(true) => {
                    if let Err(error) = transfer(&shared, &zone).await {
                        pharos_server::logging::log(
                            "WARN",
                            "secondary",
                            &format!("Transfer {}: {error}", zone.config.apex),
                        );
                        retry_active = true;
                        continue;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    pharos_server::logging::log(
                        "WARN",
                        "secondary",
                        &format!("SOA check {}: {error}", zone.config.apex),
                    );
                    retry_active = true;
                    continue;
                }
            }
            continue 'restart;
        }
    }
}
