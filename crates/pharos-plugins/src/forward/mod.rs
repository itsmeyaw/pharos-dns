//! Forward Queries to configured Upstreams.

#[cfg(feature = "plugin-dnstap")]
mod dnstap;
mod resolve;
pub(crate) mod setup;

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use pharos_proto::{Message, Name, NameRef, Rcode, TsigRecord, Type};
use pharos_server::{
    Context, Next, Outcome, Plugin, Protocol,
    metrics::ForwardMetrics,
    tls::{ClientOptions, ServerName},
};
use tokio::time::{Instant, timeout_at};

use crate::proxy::{self, Options, Proxy};
use setup::Policy;

struct Upstream {
    proxy: Option<Proxy>,
    address: String,
}

struct Stanza {
    from: Name,
    ignored: Vec<Name>,
    proxies: Vec<Upstream>,
    has_valid_upstream: bool,
    options: Options,
    policy: Policy,
    robin: AtomicUsize,
    concurrent: AtomicUsize,
    max_concurrent: usize,
    max_connect_attempts: Option<u32>,
    failfast: bool,
    failover: Vec<Rcode>,
    next: Vec<Rcode>,
    next_on_nodata: bool,
    allow_special: bool,
}

#[derive(Clone, Copy)]
enum QueryMode {
    Unsigned,
    UnsignedEcs,
    Signed,
}

fn should_preserve_tsig_response(query_signed: bool, response: &[u8]) -> bool {
    // RFC 8945 §5.5: Preserve a parseable TSIG response only for a signed forwarded Query.
    query_signed && TsigRecord::parse(response).is_ok()
}

/// Multiple forward Directives form one contiguous Plugin Chain segment.
#[derive(Default)]
pub struct Forward {
    stanzas: Vec<Stanza>,
    metrics: Option<ForwardMetrics>,
    buffers: BufferPool,
    // The Server Block's dnstap taps; empty unless a `dnstap` Directive is configured.
    #[cfg(feature = "plugin-dnstap")]
    taps: Vec<crate::dnstap::Tap>,
}

// shortcut: retain four idle scratch buffers; raise only if measured burst allocations justify memory.
const MAX_IDLE_SCRATCH: usize = 4;

#[derive(Default)]
struct BufferPool(Mutex<Vec<Scratch>>);

struct Scratch {
    bytes: Vec<u8>,
    order: Vec<usize>,
    query: Vec<u8>,
    fallback: Vec<u8>,
    upstream_attempts: Vec<u8>,
}

impl Scratch {
    fn new() -> Self {
        Self {
            bytes: vec![0; 65535],
            order: Vec::new(),
            query: Vec::new(),
            fallback: Vec::new(),
            upstream_attempts: Vec::new(),
        }
    }
}

struct Buffer<'a> {
    pool: &'a BufferPool,
    scratch: Option<Scratch>,
}

struct BufferParts<'a> {
    order: &'a mut Vec<usize>,
    bytes: &'a mut [u8],
    query: &'a mut Vec<u8>,
    fallback: &'a mut Vec<u8>,
    upstream_attempts: &'a mut Vec<u8>,
}

impl BufferPool {
    fn get(&self) -> Buffer<'_> {
        let scratch = { self.0.lock().unwrap().pop() };
        let scratch = scratch.unwrap_or_else(Scratch::new);
        Buffer {
            pool: self,
            scratch: Some(scratch),
        }
    }
}

impl Buffer<'_> {
    fn parts(&mut self) -> BufferParts<'_> {
        let scratch = self.scratch.as_mut().expect("buffer returned only on drop");
        BufferParts {
            order: &mut scratch.order,
            bytes: &mut scratch.bytes,
            query: &mut scratch.query,
            fallback: &mut scratch.fallback,
            upstream_attempts: &mut scratch.upstream_attempts,
        }
    }
}

impl Drop for Buffer<'_> {
    fn drop(&mut self) {
        let scratch = self.scratch.take().expect("buffer exists");
        let mut pool = self.pool.0.lock().unwrap();
        if pool.len() < MAX_IDLE_SCRATCH {
            pool.push(scratch);
        }
    }
}

impl std::fmt::Debug for Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forward")
            .field("stanzas", &self.stanzas.len())
            .finish()
    }
}

fn random(max: usize) -> usize {
    let mut bytes = [0_u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        return 0;
    }
    (u64::from_ne_bytes(bytes) % max as u64) as usize
}

// RFC 9520 §3.1: Send at most three Queries per server address and transport.
const MAX_ATTEMPTS: u8 = 3;

fn max_attempts(configured: Option<u32>) -> u8 {
    configured.map_or(2, |attempts| {
        attempts.clamp(1, u32::from(MAX_ATTEMPTS)) as u8
    })
}

// RFC 9520 §3.1 and RFC 7871 §7.1.3: Reserve final query slot for required ECS fallback.
fn primary_attempt_limit(configured: Option<u32>, reserve_ecs_retry: bool) -> u8 {
    let limit = max_attempts(configured);
    if reserve_ecs_retry {
        limit.min(2)
    } else {
        limit
    }
}

struct InFlight<'a>(&'a AtomicUsize);
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Forward {
    pub(crate) fn parse(
        cursor: &mut pharos_corefile::Cursor<'_>,
        root: Option<&std::path::Path>,
    ) -> Result<Self, pharos_corefile::Error> {
        let mut result = Self::default();
        while cursor.has_next() {
            let config = setup::parse(cursor, root)?;
            let parse_name = |name: &str| {
                name.parse::<Name>()
                    .map_err(|_| cursor.error(format!("invalid Domain {name}")))
            };
            let from = parse_name(&config.from)?;
            let from_special = NameRef::parse(from.as_wire(), 0)
                .ok()
                .and_then(crate::special_use);
            // RFC 6761 §6.4: `.invalid` names are guaranteed negative and cannot be forwarded.
            if from_special == Some(crate::SpecialUse::Invalid) {
                return Err(cursor.error("cannot forward .invalid"));
            }
            // RFC 6761 §§6.1–6.2: explicit special-use forwarding Zones are opt-in by configuration.
            let configured_special_zone = from.as_wire() != [0]
                && from_special.is_some_and(crate::SpecialUse::permits_upstream);
            let ignored = config
                .except
                .iter()
                .map(|name| parse_name(name))
                .collect::<Result<Vec<_>, _>>()?;
            let domain = parse_name(&config.health_domain)?;
            let mut proxies = Vec::new();
            // RFC 1034 §5.3.1: Stub forwarding delegates resolution to configured servers.
            let mut tls_config = config.tls_client.clone();
            for target in config.upstreams {
                let https = matches!(target, setup::Target::Https { .. });
                let quic = matches!(target, setup::Target::Tls { quic: true, .. });
                let (address, tls) = match target {
                    setup::Target::Address(address) => (address, None),
                    setup::Target::Tls {
                        address,
                        server_name,
                        ..
                    }
                    | setup::Target::Https {
                        address,
                        server_name,
                    } => {
                        let client = match &tls_config {
                            Some(client) => client.clone(),
                            None => {
                                // CoreDNS v1.15.0 plugin/pkg/tls/tls.go: without `tls` arguments the system roots verify the server.
                                let client =
                                    pharos_server::tls::client_config(&ClientOptions::default())
                                        .map_err(|error| cursor.error(error.to_string()))?;
                                tls_config = Some(client.clone());
                                client
                            }
                        };
                        // RFC 6125 §6.4.1: verify the name the Corefile gives, else the Upstream's IP address.
                        let name = server_name
                            .or_else(|| config.tls_servername.clone())
                            .unwrap_or_else(|| address.ip().to_string());
                        let server_name = ServerName::try_from(name.clone())
                            .map_err(|_| cursor.error(format!("invalid TLS server name {name}")))?;
                        (
                            address,
                            Some((
                                proxy::Tls {
                                    config: client,
                                    server_name,
                                },
                                quic,
                            )),
                        )
                    }
                    setup::Target::Invalid(address) => {
                        proxies.push(Upstream {
                            proxy: None,
                            address,
                        });
                        continue;
                    }
                };
                let mut proxy = Proxy::new(address);
                match tls {
                    // RFC 9250 §4.1.1: a `quic://` Upstream speaks DoQ.
                    Some((tls, true)) => proxy.set_quic(tls),
                    Some((tls, false)) if https => {
                        // RFC 8484 §4.1: `doh_method` picks GET or POST for Queries.
                        let method = if config.doh_method == "GET" {
                            hyper::Method::GET
                        } else {
                            hyper::Method::POST
                        };
                        proxy.set_https(proxy::Https::new(address, tls, method));
                    }
                    Some((tls, false)) => proxy.set_tls(tls),
                    None => {}
                }
                proxy.set_expire(config.expire);
                proxy.set_max_age(config.max_age);
                proxy.set_max_idle_conns(config.max_idle_conns);
                proxy.set_read_timeout(config.read_timeout);
                proxy.set_source_address(config.source_address);
                let mut health = proxy::HealthConfig::new(address, config.max_fails);
                health.domain = domain.clone();
                health.recursive = config.health_recursion_desired;
                health.force_tcp = config.force_tcp;
                health.interval = config.health_interval;
                health.source_address = config.source_address;
                proxy.set_health_config(health);
                proxies.push(Upstream {
                    proxy: Some(proxy),
                    address: address.to_string(),
                });
            }
            result.stanzas.push(Stanza {
                from,
                ignored,
                has_valid_upstream: proxies.iter().any(|upstream| upstream.proxy.is_some()),
                proxies,
                options: Options {
                    force_tcp: config.force_tcp,
                    prefer_udp: config.prefer_udp,
                    ..Options::default()
                },
                policy: config.policy,
                robin: AtomicUsize::new(0),
                concurrent: AtomicUsize::new(0),
                max_concurrent: config.max_concurrent,
                max_connect_attempts: config.max_connect_attempts,
                failfast: config.failfast_all_unhealthy_upstreams,
                failover: config.failover.into_iter().map(Rcode).collect(),
                next: config.next.into_iter().map(Rcode).collect(),
                next_on_nodata: config.next_on_nodata,
                allow_special: config.allow_special || configured_special_zone,
            });
        }
        Ok(result)
    }

    pub(crate) fn set_metrics(&mut self, registry: &pharos_server::metrics::Registry) {
        self.metrics = Some(registry.forward());
        for stanza in &mut self.stanzas {
            for upstream in &mut stanza.proxies {
                if let Some(proxy) = &mut upstream.proxy {
                    proxy.set_metrics(registry, "forward");
                }
            }
        }
    }

    // CoreDNS v1.15.0 plugin/forward/setup.go: a `dnstap` Directive in the same Server Block hands its taps to `forward`.
    #[cfg(feature = "plugin-dnstap")]
    pub(crate) fn set_taps(&mut self, taps: &[crate::dnstap::Tap]) {
        self.taps = taps.to_vec();
    }

    pub(crate) fn stop(&self) {
        for stanza in &self.stanzas {
            for upstream in &stanza.proxies {
                if let Some(proxy) = &upstream.proxy {
                    proxy.stop();
                }
            }
        }
    }

    pub(crate) fn allows_special(&self, name: NameRef<'_>) -> bool {
        // RFC 6761 §§6.1–6.2: permit special-name forwarding only inside opted-in, non-excluded stanzas.
        self.stanzas.iter().any(|stanza| {
            stanza.allow_special
                && crate::name_within(name, &stanza.from)
                && (name == NameRef::parse(stanza.from.as_wire(), 0).expect("configured Domain")
                    || !stanza
                        .ignored
                        .iter()
                        .any(|ignored| crate::name_within(name, ignored)))
        })
    }
}

// RFC 6761 §§6.1–6.2: opt in via allow_special or a non-root special-use Forward Zone.
impl Plugin for Forward {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let root = [0];
        let name = cx.query.questions().next().map_or_else(
            || NameRef::parse(&root, 0).expect("root"),
            |question| question.name,
        );
        let special = cx
            .query
            .questions()
            .next()
            .and_then(|question| crate::special_use(question.name));
        if let Some(special) = special
            && (!special.permits_upstream() || !self.allows_special(name))
        {
            // RFC 6761 §§6.1, 6.2 and 6.4: defer reserved names to the Chain's terminal answer.
            return next.run(cx).await;
        }
        // RFC 6761 §6.5: Forward example names like other DNS names.
        for (index, stanza) in self.stanzas.iter().enumerate() {
            if !crate::name_within(name, &stanza.from)
                || (name != stanza.from
                    && stanza
                        .ignored
                        .iter()
                        .any(|ignored| crate::name_within(name, ignored)))
            {
                continue;
            }
            let _guard = if stanza.max_concurrent > 0 {
                let old = stanza.concurrent.fetch_add(1, Ordering::Relaxed);
                let guard = InFlight(&stanza.concurrent);
                if old >= stanza.max_concurrent {
                    if let Some(metrics) = &self.metrics {
                        metrics.concurrent_reject();
                    }
                    // RFC 1035 §4.1.1: Return REFUSED when local policy rejects a query.
                    return Outcome::Unanswered(Rcode::REFUSED);
                }
                Some(guard)
            } else {
                None
            };

            let count = stanza.proxies.len();
            if !stanza.has_valid_upstream {
                // RFC 1034 §5.2.3: An unusable resolver set is a temporary resolution failure.
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
            let mut buffer = self.buffers.get();
            let BufferParts {
                order,
                bytes: wire,
                query: query_buffer,
                fallback: fallback_buffer,
                upstream_attempts,
            } = buffer.parts();
            // RFC 1034 §4.3.1: Forward RD unchanged so recursion occurs only on request.
            let original_query = cx.query.as_wire();
            let query_wire = if cx.query.wire_changed() {
                if cx.query.flags() != u16::from_be_bytes([original_query[2], original_query[3]])
                    && !cx.query.can_change_flags_in_wire()
                {
                    // RFC 1035 §4.1.1: Return FORMERR when the query cannot be interpreted.
                    return Outcome::Unanswered(Rcode::FORMERR);
                }
                if cx.query.copy_wire_checked(query_buffer).is_err() {
                    return Outcome::Unanswered(Rcode::FORMERR);
                }
                query_buffer.as_slice()
            } else {
                original_query
            };
            // RFC 8945 §5.5: Preserve upstream TSIG only for a TSIG-bearing client Query.
            let query_signed = cx.query.additionals().any(|rr| rr.rtype == Type::TSIG);
            let query_has_ecs = if query_signed {
                false
            } else if cx.query.wire_changed() {
                proxy::has_unsigned_ecs(query_wire)
            } else {
                proxy::has_unsigned_ecs_message(&cx.query)
            };
            let query_mode = if query_signed {
                QueryMode::Signed
            } else if query_has_ecs {
                QueryMode::UnsignedEcs
            } else {
                QueryMode::Unsigned
            };
            order.clear();
            order.extend(0..count);
            match stanza.policy {
                Policy::Random => {
                    for i in (1..count).rev() {
                        order.swap(i, random(i + 1));
                    }
                }
                Policy::RoundRobin => {
                    let first = (stanza.robin.fetch_add(1, Ordering::Relaxed) + 1) % count;
                    order[0] = first;
                    let mut j = 1;
                    for i in 0..count {
                        if i != first {
                            order[j] = i;
                            j += 1;
                        }
                    }
                }
                Policy::Sequential => {}
            }
            // CoreDNS v1.15.0 plugin/forward/forward.go ServeDNS: the time of the first Query to an Upstream is the dnstap query time.
            #[cfg(feature = "plugin-dnstap")]
            let tapped_at = (!self.taps.is_empty()).then(std::time::SystemTime::now);
            // RFC 1035 §4.2.1: Retry lost UDP queries after timeout, trying other servers first.
            let deadline = Instant::now() + Duration::from_secs(5);
            let attempt_limit = primary_attempt_limit(
                stanza.max_connect_attempts,
                matches!(query_mode, QueryMode::UnsignedEcs),
            );
            // CoreDNS v1.15.0 plugin/forward/forward.go ServeDNS: with retries left, a stalled TLS handshake gets half the window.
            let started = Instant::now();
            let options = Options {
                tls_connect_deadline: Some(if attempt_limit == 1 {
                    deadline
                } else {
                    started + (deadline - started) / 2
                }),
                ..stanza.options
            };
            upstream_attempts.clear();
            upstream_attempts.resize(count, 0);
            let mut i = 0;
            let mut fails = 0;
            let mut failovers = 0;
            let mut try_next = false;
            // RFC 7766 §5: Forward DNS queries using the selected UDP or TCP transport.
            let protocol = if cx.protocol == Protocol::Tcp {
                proxy::Transport::Tcp
            } else {
                proxy::Transport::Udp
            };
            'upstream_loop: while Instant::now() < deadline
                && order
                    .iter()
                    .any(|&upstream| upstream_attempts[upstream] < attempt_limit)
            {
                if i == count {
                    i = 0;
                    fails = 0;
                }
                let mut upstream_index = order[i];
                let mut upstream = &stanza.proxies[upstream_index];
                i += 1;
                if upstream.proxy.as_ref().is_some_and(Proxy::down) {
                    fails += 1;
                    if fails < count {
                        continue;
                    }
                    if let Some(metrics) = &self.metrics {
                        metrics.healthcheck_broken();
                    }
                    if stanza.failfast {
                        break;
                    }
                    upstream_index = random(count);
                    upstream = &stanza.proxies[upstream_index];
                }
                if upstream_attempts[upstream_index] >= attempt_limit {
                    continue;
                }
                if cx.metadata.enabled() {
                    cx.metadata
                        .insert_inline("forward/upstream", &upstream.address);
                }
                let Some(proxy) = &upstream.proxy else {
                    upstream_attempts[upstream_index] = attempt_limit;
                    if fails >= count {
                        break;
                    }
                    // RFC 1034 §5.3.3: Continue resolution when this server target cannot be used.
                    continue;
                };
                let result = loop {
                    if upstream_attempts[upstream_index] >= attempt_limit {
                        continue 'upstream_loop;
                    }
                    upstream_attempts[upstream_index] += 1;
                    let result = timeout_at(
                        deadline,
                        proxy.exchange(query_wire, wire, protocol, options),
                    )
                    .await;
                    // RFC 7766 §6.2.4: Retry unanswered queries after a connection closes.
                    if matches!(result, Ok(Err(proxy::Error::CachedClosed))) {
                        continue;
                    }
                    break result;
                };
                #[cfg(feature = "plugin-dnstap")]
                if let Some(start) = tapped_at {
                    let exchange = result.as_ref().ok().and_then(|result| result.as_ref().ok());
                    dnstap::exchanged(
                        &self.taps,
                        cx,
                        start,
                        proxy.address(),
                        exchange,
                        (query_wire, wire),
                        (options, protocol),
                    );
                }
                let mut exchange = match result {
                    Ok(Ok(exchange)) => exchange,
                    Ok(Err(proxy::Error::Mismatch(_len))) => {
                        #[cfg(feature = "plugin-debug")]
                        if pharos_server::logging::debug_enabled()
                            && let Some(question) = cx.query.questions().next()
                        {
                            crate::debug::log_message(
                                &format!(
                                    "Wrong reply for id: {}, {} {}",
                                    u16::from_be_bytes([wire[0], wire[1]]),
                                    question.name,
                                    question.qtype.0
                                ),
                                &wire[.._len],
                            );
                        }
                        // RFC 1035 §4.1.1: An upstream mismatch is not a client FORMERR.
                        if fails >= count {
                            break;
                        }
                        continue;
                    }
                    Ok(Err(proxy::Error::InvalidRequest)) => {
                        return Outcome::Unanswered(Rcode::FORMERR);
                    }
                    Ok(Err(proxy::Error::UnsupportedRequest)) => {
                        return Outcome::Unanswered(Rcode::NOTIMP);
                    }
                    _ => {
                        if fails >= count {
                            break;
                        }
                        continue;
                    }
                };
                let (mut rcode, mut answer_count, mut preserve_tsig_response) = {
                    let response =
                        Message::parse(&wire[..exchange.len]).expect("proxy validated Response");
                    (
                        response.rcode(),
                        response.answer_count(),
                        should_preserve_tsig_response(
                            matches!(query_mode, QueryMode::Signed),
                            &wire[..exchange.len],
                        ),
                    )
                };
                // RFC 7871 §7.1.3: Keep the original REFUSED candidate when fallback fails.
                let mut use_refused_fallback = false;
                if matches!(query_mode, QueryMode::UnsignedEcs)
                    && rcode == Rcode::REFUSED
                    && let Some(fallback_len) =
                        proxy::without_ecs(query_wire, fallback_buffer, protocol)
                            .ok()
                            .flatten()
                    && upstream_attempts[upstream_index] < MAX_ATTEMPTS
                {
                    // RFC 7871 §7.1.3: Retry REFUSED without the ECS address.
                    let refused_len = exchange.len;
                    cx.response.clear();
                    cx.response.extend_from_slice(&wire[..refused_len]);
                    upstream_attempts[upstream_index] += 1;
                    let retry = timeout_at(
                        deadline,
                        proxy.exchange(&fallback_buffer[..fallback_len], wire, protocol, options),
                    )
                    .await;
                    match retry {
                        Ok(Ok(retried)) => {
                            cx.response.clear();
                            exchange = retried;
                            let response = Message::parse(&wire[..exchange.len])
                                .expect("proxy validated ECS-free Response");
                            rcode = response.rcode();
                            answer_count = response.answer_count();
                            preserve_tsig_response = should_preserve_tsig_response(
                                matches!(query_mode, QueryMode::Signed),
                                &wire[..exchange.len],
                            );
                        }
                        _ => use_refused_fallback = true,
                    }
                }
                if stanza.failover.contains(&rcode) {
                    failovers += 1;
                    if failovers < count {
                        if use_refused_fallback {
                            cx.response.clear();
                        }
                        continue;
                    }
                }
                if index + 1 < self.stanzas.len()
                    && (stanza.next.contains(&rcode)
                        || (stanza.next_on_nodata && rcode == Rcode::NOERROR && answer_count == 0))
                {
                    if use_refused_fallback {
                        cx.response.clear();
                    }
                    try_next = true;
                    break;
                }
                if use_refused_fallback {
                    // RFC 8945 §§4.3, 5.3.1: Rewriting the Response invalidates its TSIG MAC.
                    if !preserve_tsig_response {
                        // RFC 4035 §4.6: Ignore AD from an upstream without a secure channel.
                        cx.response[3] &= !0x20;
                    }
                    // RFC 8945 §5.5: Listener clears AD if it re-signs this forwarded Response.
                    cx.metadata.mark_forwarded_response();
                    return Outcome::Response;
                }
                let answer = &wire[..exchange.len];
                // RFC 7871 §7.3: Preserve valid ECS response scope, including scope longer than source.
                cx.response.clear();
                // RFC 5625 §4.3: return Responses without filtering RRs by TYPE or CLASS.
                cx.response.extend_from_slice(answer);
                // RFC 8945 §§4.3, 5.3.1: Rewriting the Response invalidates its TSIG MAC.
                if !preserve_tsig_response {
                    // RFC 4035 §4.6: Ignore AD from an upstream without a secure channel.
                    cx.response[3] &= !0x20;
                }
                // RFC 8945 §5.5: Listener clears AD if it re-signs this forwarded Response.
                cx.metadata.mark_forwarded_response();
                return Outcome::Response;
            }
            // RFC 1034 §5.2.3: Temporary resolution failures return SERVFAIL.
            if !try_next {
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
        }
        next.run(cx).await
    }
}

#[cfg(test)]
mod tests;
