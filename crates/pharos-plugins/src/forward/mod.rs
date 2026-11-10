//! Forward Queries to configured Upstreams.

mod resolve;
mod setup;

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use pharos_proto::{Message, Name, NameRef, Rcode};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol, metrics::ForwardMetrics};
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
}

/// Multiple forward Directives form one contiguous Plugin Chain segment.
#[derive(Default)]
pub struct Forward {
    stanzas: Vec<Stanza>,
    metrics: Option<ForwardMetrics>,
    buffers: BufferPool,
}

#[derive(Default)]
// shortcut: the pool retains peak concurrency, cap it if idle memory becomes costly.
struct BufferPool(Mutex<Vec<Scratch>>);

struct Scratch {
    bytes: Vec<u8>,
    order: Vec<usize>,
}

struct Buffer<'a> {
    pool: &'a BufferPool,
    scratch: Option<Scratch>,
}

impl BufferPool {
    fn get(&self) -> Buffer<'_> {
        let scratch = self.0.lock().unwrap().pop().unwrap_or_else(|| Scratch {
            bytes: vec![0; 65535],
            order: Vec::new(),
        });
        Buffer {
            pool: self,
            scratch: Some(scratch),
        }
    }
}

impl Buffer<'_> {
    fn parts(&mut self) -> (&mut Vec<usize>, &mut [u8]) {
        let scratch = self.scratch.as_mut().expect("buffer returned only on drop");
        (&mut scratch.order, &mut scratch.bytes)
    }
}

impl Drop for Buffer<'_> {
    fn drop(&mut self) {
        self.pool
            .0
            .lock()
            .unwrap()
            .push(self.scratch.take().expect("buffer exists"));
    }
}

impl std::fmt::Debug for Forward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forward")
            .field("stanzas", &self.stanzas.len())
            .finish()
    }
}

fn contains(name: NameRef<'_>, domain: &Name) -> bool {
    let domain = NameRef::parse(domain.as_wire(), 0).expect("valid configured Domain");
    let count = name.labels().count();
    let suffix = domain.labels().count();
    count >= suffix
        && name
            .labels()
            .skip(count - suffix)
            .zip(domain.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn random(max: usize) -> usize {
    let mut bytes = [0_u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        return 0;
    }
    (u64::from_ne_bytes(bytes) % max as u64) as usize
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
    ) -> Result<Self, pharos_corefile::Error> {
        let mut result = Self::default();
        while cursor.has_next() {
            let config = setup::parse(cursor)?;
            let parse_name = |name: &str| {
                name.parse::<Name>()
                    .map_err(|_| cursor.error(format!("invalid Domain {name}")))
            };
            let from = parse_name(&config.from)?;
            let ignored = config
                .except
                .iter()
                .map(|name| parse_name(name))
                .collect::<Result<Vec<_>, _>>()?;
            let domain = parse_name(&config.health_domain)?;
            let mut proxies = Vec::new();
            for target in config.upstreams {
                let address = match target {
                    setup::Target::Address(address) => address,
                    setup::Target::Invalid(address) => {
                        proxies.push(Upstream {
                            proxy: None,
                            address,
                        });
                        continue;
                    }
                };
                let mut proxy = Proxy::new(address);
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
                proxies,
                options: Options {
                    force_tcp: config.force_tcp,
                    prefer_udp: config.prefer_udp,
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

    pub(crate) fn stop(&self) {
        for stanza in &self.stanzas {
            for upstream in &stanza.proxies {
                if let Some(proxy) = &upstream.proxy {
                    proxy.stop();
                }
            }
        }
    }
}

impl Plugin for Forward {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let root = [0];
        let name = cx.query.questions().next().map_or_else(
            || NameRef::parse(&root, 0).expect("root"),
            |question| question.name,
        );
        for (index, stanza) in self.stanzas.iter().enumerate() {
            if !contains(name, &stanza.from)
                || (name != stanza.from
                    && stanza.ignored.iter().any(|ignored| contains(name, ignored)))
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
                    return Outcome::Unanswered(Rcode::REFUSED);
                }
                Some(guard)
            } else {
                None
            };

            let count = stanza.proxies.len();
            let mut buffer = self.buffers.get();
            let (order, wire) = buffer.parts();
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
            let deadline = Instant::now() + Duration::from_secs(5);
            let max_attempts = stanza
                .max_connect_attempts
                .map_or((count * 2) as u64, u64::from);
            let mut attempts = 0_u64;
            let mut i = 0;
            let mut fails = 0;
            let mut failovers = 0;
            let mut try_next = false;
            let protocol = if cx.protocol == Protocol::Tcp {
                proxy::Transport::Tcp
            } else {
                proxy::Transport::Udp
            };
            while Instant::now() < deadline && (max_attempts == 0 || attempts < max_attempts) {
                if i == count {
                    i = 0;
                    fails = 0;
                }
                let mut upstream = &stanza.proxies[order[i]];
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
                    upstream = &stanza.proxies[random(count)];
                }
                cx.metadata
                    .insert_inline("forward/upstream", &upstream.address);
                let Some(proxy) = &upstream.proxy else {
                    attempts += 1;
                    if fails >= count {
                        break;
                    }
                    continue;
                };
                let result = loop {
                    let result = timeout_at(
                        deadline,
                        proxy.exchange(cx.query.as_wire(), wire, protocol, stanza.options),
                    )
                    .await;
                    if matches!(result, Ok(Err(proxy::Error::CachedClosed))) {
                        continue;
                    }
                    break result;
                };
                let exchange = match result {
                    Ok(Ok(exchange)) => exchange,
                    Ok(Err(proxy::Error::Mismatch | proxy::Error::InvalidRequest)) => {
                        return Outcome::Unanswered(Rcode::FORMERR);
                    }
                    Ok(Err(proxy::Error::UnsupportedRequest)) => {
                        return Outcome::Unanswered(Rcode::NOTIMP);
                    }
                    _ => {
                        attempts += 1;
                        if fails >= count {
                            break;
                        }
                        continue;
                    }
                };
                let answer = &wire[..exchange.len];
                let response = Message::parse(answer).expect("proxy validated Response");
                if stanza.failover.contains(&response.rcode()) {
                    failovers += 1;
                    if failovers < count {
                        continue;
                    }
                }
                if index + 1 < self.stanzas.len()
                    && (stanza.next.contains(&response.rcode())
                        || (stanza.next_on_nodata
                            && response.rcode() == Rcode::NOERROR
                            && response.answer_count() == 0))
                {
                    try_next = true;
                    break;
                }
                cx.response.clear();
                cx.response.extend_from_slice(answer);
                return Outcome::Response;
            }
            if !try_next {
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
        }
        next.run(cx).await
    }
}

#[cfg(test)]
mod tests {
    use super::BufferPool;

    #[test]
    fn returned_buffers_keep_their_contents_and_are_reused() {
        let pool = BufferPool::default();
        {
            let mut buffer = pool.get();
            buffer.parts().1[65534] = 123;
        }
        let mut buffer = pool.get();
        assert_eq!(buffer.parts().1[65534], 123);
    }
}
