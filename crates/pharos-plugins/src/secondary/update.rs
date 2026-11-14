use super::*;
use pharos_proto::{Message, MessageBuilder, NameRef, Section, Type, zone::ZoneRecord};
use std::{fmt::Write, io, net::SocketAddr, time::Duration};
use tokio::io::AsyncReadExt;

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
            // RFC 4007 §11.2: an interface-name zone matches only the peer's own interface.
            // RFC 4007 §11: a scoped IPv6 address identifies an interface zone.
            // CoreDNS compares the zone text Go renders: the interface name.
            client.scope_id() != 0
                && nix::net::if_::if_indextoname(client.scope_id())
                    .is_ok_and(|name| name.as_bytes() == scope.as_bytes())
        }
        (SocketAddr::V4(_), Some(_)) => false,
    }
}

// RFC 1996 §3.11: Keep the notifying primary IP and use its configured service port.
pub(super) fn primary_address(address: &str, client: SocketAddr) -> Option<SocketAddr> {
    if !primary_matches(address, client) {
        return None;
    }
    let port = if let Some(value) = address.strip_prefix('[') {
        value.split_once(']')?.1.strip_prefix(':')?.parse().ok()?
    } else {
        address.rsplit_once(':')?.1.parse().ok()?
    };
    let mut primary = client;
    primary.set_port(port);
    Some(primary)
}

// RFC 1035 §4.1.1: DNS query IDs are 16-bit identifiers assigned by the query generator.
fn random_id() -> u16 {
    let mut bytes = [0; 2];
    let _ = getrandom::getrandom(&mut bytes);
    u16::from_ne_bytes(bytes)
}

#[cfg(not(test))]
fn random_delay(bound: u16) -> u16 {
    random_id() % bound
}

#[cfg(test)]
fn random_delay(_: u16) -> u16 {
    0
}

// RFC 1034 §2.4: name servers periodically refresh zones from master copies.
pub(super) async fn transfer(shared: &Arc<Shared>, zone: &SecondaryZone) -> io::Result<()> {
    transfer_inner(shared, zone, None).await
}

pub(super) async fn transfer_from(
    shared: &Arc<Shared>,
    zone: &SecondaryZone,
    primary: SocketAddr,
) -> io::Result<()> {
    transfer_inner(shared, zone, Some(primary)).await
}

async fn transfer_inner(
    shared: &Arc<Shared>,
    zone: &SecondaryZone,
    primary: Option<SocketAddr>,
) -> io::Result<()> {
    let mut error = io::Error::other("no Primary Server");
    let mut addresses = Vec::new();
    if let Some(primary) = primary {
        addresses.push(primary);
    } else {
        for primary in &zone.config.from {
            match tokio::net::lookup_host(primary).await {
                Ok(found) => addresses.extend(found),
                Err(err) => error = err,
            }
        }
    }
    for address in addresses {
        let mut records = Vec::new();
        let result = pharos_server::transfer::axfr(
            address,
            &zone.config.apex,
            random_id(),
            Duration::from_secs(5),
            |message| {
                // RFC 5936 §2.2: Ignore duplicate resource records in an AXFR stream.
                for record in message.answers() {
                    let data = record.data().map_err(io::Error::other)?;
                    // RFC 5936 §3.4: re-encode RDATA without compressed names.
                    let mut wire = Vec::with_capacity(512);
                    let mut builder =
                        MessageBuilder::new(&mut wire, 65535, 0, 0).map_err(io::Error::other)?;
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
                    let expanded = ZoneRecord {
                        owner: record.name.to_name(),
                        rtype: record.rtype,
                        class: record.class,
                        ttl: record.ttl,
                        rdata: expanded.rdata.to_vec(),
                    };
                    records.push(expanded);
                }
                Ok(())
            },
        )
        .await;
        match result {
            Ok(()) => {
                // RFC 5936 §2.2: Sort and remove duplicate RRs without a second full-size index.
                records.sort_unstable_by(|a, b| {
                    a.owner
                        .cmp(&b.owner)
                        .then(a.rtype.cmp(&b.rtype))
                        .then(a.class.cmp(&b.class))
                        .then(a.ttl.cmp(&b.ttl))
                        .then(a.rdata.cmp(&b.rdata))
                });
                records.dedup();
                // RFC 5936 §6: publish a validated Zone snapshot atomically after transfer.
                let next = match crate::zone::Zone::from_records(
                    zone.config.apex.clone(),
                    records.clone(),
                ) {
                    Ok(next) => next,
                    Err(err) => {
                        if zone.config.catalog.is_some() {
                            super::catalog::invalidate(shared, zone);
                        }
                        error = io::Error::other(err);
                        continue;
                    }
                };
                // RFC 9432 §5.1: Apply catalog changes after each valid transfer.
                let catalog = if zone.config.catalog.is_some() {
                    match super::catalog::parse(&zone.config.apex, &records) {
                        Ok(catalog) => Some(catalog),
                        Err(parse_error) => {
                            super::catalog::invalidate(shared, zone);
                            error = io::Error::other(parse_error);
                            continue;
                        }
                    }
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
                    // RFC 1996 §4.2: Forward NOTIFY only after the Zone transfer succeeds.
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
    Err(error)
}

// RFC 1034 §4.3.5: poll the primary SOA serial to detect Zone changes.
pub(super) async fn should_transfer(zone: &SecondaryZone) -> io::Result<bool> {
    let mut error = None;
    for primary in &zone.config.from {
        match tokio::net::lookup_host(primary).await {
            Ok(addresses) => {
                for address in addresses {
                    match should_transfer_at(zone, address).await {
                        Ok(changed) => return Ok(changed),
                        Err(err) => error = Some(err),
                    }
                }
            }
            Err(err) => error = Some(err),
        }
    }
    error.map_or(Ok(false), Err)
}

pub(super) async fn should_transfer_from(
    zone: &SecondaryZone,
    primary: SocketAddr,
) -> io::Result<bool> {
    should_transfer_at(zone, primary).await
}

async fn should_transfer_at(zone: &SecondaryZone, primary: SocketAddr) -> io::Result<bool> {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut socket = tokio::net::TcpStream::connect(primary).await?;
        let mut query = Vec::with_capacity(512);
        let id = random_id();
        let mut builder = MessageBuilder::new(&mut query, 512, id, 0).map_err(io::Error::other)?;
        builder
            // RFC 1035 §4.1.2: The Question section carries QNAME, QTYPE, and QCLASS.
            .question(
                NameRef::parse(zone.config.apex.as_wire(), 0).map_err(io::Error::other)?,
                Type::SOA,
                Class::IN,
            )
            .map_err(io::Error::other)?;
        let _ = builder.finish();
        // RFC 1035 §4.2.2: TCP DNS messages use a two-octet length prefix.
        pharos_server::write_tcp_frame(&mut socket, &query).await?;
        let len = socket.read_u16().await?;
        let mut response = vec![0; usize::from(len)];
        socket.read_exact(&mut response).await?;
        let message = Message::parse(&response).map_err(io::Error::other)?;
        // RFC 1035 §4.1.1: A Response carries the Query ID and opcode.
        // RFC 5452 §4.2: Match every Question field before using the SOA answer.
        if message.id() != id
            || message.flags() & 0xf800 != 0x8000
            || message.question_count() != 1
            || message.questions().next().is_none_or(|question| {
                question.name != zone.config.apex
                    || question.qtype != Type::SOA
                    || question.qclass != Class::IN
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOA Response does not match Query",
            ));
        }
        if message.rcode() != Rcode::NOERROR {
            // RFC 1034 §4.3.5: A failed SOA check must enter the RETRY state.
            return Err(io::Error::other("SOA check returned non-NOERROR"));
        }
        for answer in message.answers() {
            if answer.name == zone.config.apex
                && answer.class == Class::IN
                && let Ok(pharos_proto::Rdata::Soa { serial, .. }) = answer.data()
            {
                let current = zone.current.load();
                return Ok(current
                    .as_ref()
                    .and_then(|zone| zone.serial())
                    .is_none_or(|local| serial_less(local, serial)));
            }
        }
        Err(io::Error::other("SOA Response has no apex SOA"))
    })
    .await;
    result.map_err(|err| io::Error::new(io::ErrorKind::TimedOut, err))?
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
        // RFC 1034 §4.3.5: shortcut: 1s floor avoids hot polling; upgrade after a bounded zero-timer policy exists.
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

// RFC 5936 §1.2: maintain zone coherence through periodic AXFR and NOTIFY-triggered transfers.
pub(super) async fn run(shared: Arc<Shared>, zone: Arc<SecondaryZone>) {
    let notify_shared = Arc::clone(&shared);
    let notify_zone = Arc::clone(&zone);
    let _notify_task = AbortOnDrop(tokio::spawn(async move {
        loop {
            notify_zone.notify.notified().await;
            let Some(source) = notify_zone.notify_source.lock().unwrap().take() else {
                continue;
            };
            // RFC 1996 §4.4: Defer duplicate NOTIFY work until current check completes.
            // RFC 1996 §3.11: Query and transfer from the master that sent NOTIFY.
            match should_transfer_from(&notify_zone, source).await {
                Ok(true) => {
                    if let Err(error) = transfer_from(&notify_shared, &notify_zone, source).await {
                        pharos_server::logging::log(
                            "WARN",
                            "secondary",
                            &format!("NOTIFY transfer {}: {error}", notify_zone.config.apex),
                        );
                    }
                }
                Ok(false) => {}
                Err(error) => pharos_server::logging::log(
                    "WARN",
                    "secondary",
                    &format!("NOTIFY check {}: {error}", notify_zone.config.apex),
                ),
            }
        }
    }));
    let mut delay = Duration::from_millis(250);
    // RFC 9432 §5.1: Retry transfers so catalog processing resumes after success.
    while let Err(error) = transfer(&shared, &zone).await {
        // RFC 9432 §5.1: Log transfer failures with errors to identify broken catalogs.
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
        // RFC 1034 §4.3.5: EXPIRE is measured from the last successful SOA check.
        let expire_at = tokio::time::Instant::now() + expire;
        let mut retry_active = false;
        loop {
            let jitter = tokio::select! {
                _ = refresh.tick(), if !retry_active => 5000,
                _ = retry.tick(), if retry_active => 2000,
                _ = tokio::time::sleep_until(expire_at), if retry_active && !zone.expired.load(Ordering::Relaxed) => {
                    zone.expired.store(true, Ordering::Relaxed);
                    super::catalog::invalidate(&shared, &zone);
                    continue;
                }
            };
            if jitter > 0 {
                tokio::time::sleep(Duration::from_millis(u64::from(random_delay(jitter)))).await;
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
                // RFC 1034 §4.3.5: A successful unchanged SOA check renews this secondary copy.
                Ok(false) => zone.expired.store(false, Ordering::Relaxed),
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
