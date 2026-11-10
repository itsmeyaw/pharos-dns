//! Cache configuration and DNS Response storage.

mod setup;
mod store;

use std::{
    fmt::Write,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Instant, SystemTime},
};

use pharos_proto::{
    Message, MessageBuilder, MessageMut, Name, NameRef, Opcode, Rcode, Rdata, ResponseType, Type,
};
use pharos_server::{Context, Next, Outcome, Plugin};

/// Configuration for the cache Plugin.
pub struct Cache {
    config: setup::Config,
    success: store::Store,
    denial: store::Store,
    metrics: Vec<(SocketAddr, pharos_server::metrics::CacheMetrics)>,
    chain: OnceLock<Weak<crate::Chain>>,
    writes: Mutex<()>,
}

struct RefreshGuard {
    chain: Arc<crate::Chain>,
    key: u64,
    stored: Instant,
    denial: bool,
    recheck: std::time::Duration,
    success: bool,
}

struct LocalRefreshGuard<'a> {
    store: &'a store::Store,
    key: u64,
    stored: Instant,
    recheck: std::time::Duration,
    success: bool,
}

struct QueryGuard<'a, 'b> {
    context: &'a mut Context<'b>,
    query: Message<'b>,
}

impl Drop for QueryGuard<'_, '_> {
    fn drop(&mut self) {
        self.context.query = self.query;
    }
}

impl Drop for LocalRefreshGuard<'_> {
    fn drop(&mut self) {
        self.store
            .finish_refresh(self.key, self.stored, self.recheck, self.success);
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if let Some(cache) = &self.chain.cache {
            let store = if self.denial {
                &cache.denial
            } else {
                &cache.success
            };
            store.finish_refresh(self.key, self.stored, self.recheck, self.success);
        }
    }
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Cache {
    pub(crate) fn parse(
        cursor: &mut pharos_corefile::Cursor<'_>,
        zones: &[String],
    ) -> Result<Self, pharos_corefile::Error> {
        let zones: Vec<&str> = zones.iter().map(String::as_str).collect();
        let config = setup::parse(cursor, &zones)?;
        Ok(Self {
            success: store::Store::new(config.success_capacity),
            denial: store::Store::new(config.denial_capacity),
            metrics: Vec::new(),
            chain: OnceLock::new(),
            writes: Mutex::new(()),
            config,
        })
    }

    pub(crate) fn bind(&self, chain: &Arc<crate::Chain>) {
        let _ = self.chain.set(Arc::downgrade(chain));
    }

    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
    ) {
        let zones = self
            .config
            .zones
            .iter()
            .map(Name::canonical)
            .collect::<Vec<_>>()
            .join(",");
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            self.metrics
                .push((address, registry.cache(&server, &zones, "")));
        }
    }
}

impl Plugin for Cache {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        if query.opcode() != Opcode::QUERY
            || query.additionals().any(|record| record.rtype == Type::TSIG)
            || question.name.wire_len()
                != question
                    .name
                    .labels()
                    .map(|label| label.len() + 1)
                    .sum::<usize>()
                    + 1
            || !self
                .config
                .zones
                .iter()
                .any(|zone| contains(question.name, zone))
        {
            return next.run(cx).await;
        }
        let metrics = self
            .metrics
            .iter()
            .find_map(|(address, metrics)| (*address == cx.local).then_some(metrics));
        if let Some(metrics) = metrics {
            metrics.request();
        }
        let key = key(&query);
        let can_grow = cx.protocol == pharos_server::Protocol::Tcp;
        let positive_first = self.config.prefer_positive && !self.config.stale.is_zero();
        let positive = positive_first
            .then(|| {
                self.success
                    .serve(key, &query, cx.response, &self.config, true, can_grow)
            })
            .flatten();
        let hit = if let Some(hit) = positive {
            Some((false, hit))
        } else if let Some(denial) =
            self.denial
                .serve(key, &query, cx.response, &self.config, false, can_grow)
        {
            if cx.response[3] & 15 == 2 {
                if let Some(positive) =
                    self.success
                        .serve(key, &query, cx.response, &self.config, false, can_grow)
                {
                    if let Some(stored) = denial.refresh {
                        self.denial
                            .finish_refresh(key, stored, std::time::Duration::ZERO, true);
                    }
                    Some((false, positive))
                } else {
                    Some((true, denial))
                }
            } else {
                Some((true, denial))
            }
        } else {
            self.success
                .serve(key, &query, cx.response, &self.config, false, can_grow)
                .map(|hit| (false, hit))
        };
        if let Some((denial, hit)) = hit {
            if let Some(metrics) = metrics {
                metrics.hit(denial);
            }
            if let Some(stored) = hit.refresh {
                let store = if denial { &self.denial } else { &self.success };
                if let Some(chain) = self.chain.get().and_then(Weak::upgrade) {
                    if (!hit.stale || !self.config.verify)
                        && let Some(metrics) = metrics
                    {
                        metrics.prefetch();
                    }
                    let task = self.spawn_refresh(chain, cx, key, denial, hit);
                    if hit.stale && self.config.verify {
                        let result = if self.config.verify_timeout.is_zero() {
                            task.await.ok()
                        } else {
                            tokio::time::timeout(self.config.verify_timeout, task)
                                .await
                                .ok()
                                .and_then(Result::ok)
                        };
                        if let Some(Some(mut response)) = result {
                            if !query.ad() && !query.opt().is_some_and(|opt| opt.dnssec_ok()) {
                                response[3] &= !0x20;
                            }
                            *cx.response = response;
                            return Outcome::Response;
                        }
                    }
                } else if hit.stale && self.config.verify {
                    let mut guard = LocalRefreshGuard {
                        store,
                        key,
                        stored,
                        recheck: self.config.stale_recheck,
                        success: false,
                    };
                    let stale = cx.response.clone();
                    let outcome = {
                        cx.query = query.with_ad();
                        let guard = QueryGuard {
                            context: &mut *cx,
                            query,
                        };
                        next.run(&mut *guard.context).await
                    };
                    let valid =
                        outcome == Outcome::Response && self.accept_refresh(&query, cx.response);
                    if valid
                        || (self.config.prefer_positive
                            && outcome == Outcome::Response
                            && Self::matches_refresh(&query, cx.response))
                    {
                        self.process_response(cx, outcome, Some((denial, hit.generation)));
                    }
                    if !valid {
                        cx.response.clear();
                        cx.response.extend_from_slice(&stale);
                    }
                    guard.success = valid;
                    if valid {
                        return Outcome::Response;
                    }
                } else {
                    store.finish_refresh(key, stored, self.config.stale_recheck, false);
                }
            }
            if hit.stale
                && let Some(metrics) = metrics
            {
                metrics.served_stale();
            }
            return Outcome::Response;
        }
        if let Some(metrics) = metrics {
            metrics.miss();
        }
        let outcome = {
            cx.query = query.with_ad();
            let guard = QueryGuard {
                context: &mut *cx,
                query,
            };
            next.run(&mut *guard.context).await
        };
        self.process_response(cx, outcome, None)
    }
}

impl Cache {
    fn matches_refresh(query: &Message<'_>, wire: &[u8]) -> bool {
        let Ok(response) = Message::parse(wire) else {
            return false;
        };
        let (Some(expected), Some(actual)) =
            (query.questions().next(), response.questions().next())
        else {
            return false;
        };
        if response.tc()
            || !response.qr()
            || response.question_count() != 1
            || response
                .additionals()
                .any(|record| record.rtype == Type::TSIG)
            || expected.name != actual.name
            || expected.qtype != actual.qtype
            || expected.qclass != actual.qclass
        {
            return false;
        }
        true
    }

    fn accept_refresh(&self, query: &Message<'_>, wire: &[u8]) -> bool {
        if !Self::matches_refresh(query, wire) {
            return false;
        }
        let Ok(response) = Message::parse(wire) else {
            return false;
        };
        if !matches!(response.rcode(), Rcode::NOERROR | Rcode::NXDOMAIN) {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64);
        let kind = pharos_proto::typify_response(Some(&response), now);
        if !matches!(
            kind,
            ResponseType::Positive
                | ResponseType::Referral
                | ResponseType::NoData
                | ResponseType::NxDomain
        ) {
            return false;
        }
        !self.config.prefer_positive
            || (response.rcode() == Rcode::NOERROR && answers_question(&response))
    }

    fn spawn_refresh(
        &self,
        chain: Arc<crate::Chain>,
        cx: &Context<'_>,
        key: u64,
        denial: bool,
        hit: store::Hit,
    ) -> tokio::task::JoinHandle<Option<Vec<u8>>> {
        let stored = hit.refresh.expect("refresh requested");
        let generation = hit.generation;
        let stale = hit.stale;
        let mut wire = cx.query.as_wire().to_vec();
        wire[3] |= 0x20;
        let domain = cx.domain.clone();
        let synthetic = !stale || !self.config.verify;
        let client = if synthetic {
            ([0, 0, 0, 0], 0).into()
        } else {
            cx.client
        };
        let local = cx.local;
        let transport = cx.transport;
        let protocol = if synthetic {
            pharos_server::Protocol::Tcp
        } else {
            cx.protocol
        };
        let max_response_size = if synthetic {
            65535
        } else {
            cx.max_response_size
        };
        let guard = RefreshGuard {
            chain,
            key,
            stored,
            denial,
            recheck: if stale {
                self.config.stale_recheck
            } else {
                std::time::Duration::ZERO
            },
            success: false,
        };
        tokio::spawn(async move {
            let mut guard = guard;
            let Some(cache) = &guard.chain.cache else {
                return None;
            };
            let Ok(query) = Message::parse(&wire) else {
                return None;
            };
            let mut response = Vec::with_capacity(65535);
            let mut slots = [None; 16];
            let mut context = Context {
                query,
                client,
                local,
                transport,
                protocol,
                domain: &domain,
                metadata: pharos_server::Metadata::new(&mut slots),
                response: &mut response,
                max_response_size,
            };
            let outcome = guard.chain.cache_refresh_next(&mut context).await;
            let valid = outcome == Outcome::Response
                && cache.accept_refresh(&context.query, context.response);
            if valid
                || (!stale && outcome == Outcome::Response)
                || (stale
                    && cache.config.prefer_positive
                    && outcome == Outcome::Response
                    && Self::matches_refresh(&context.query, context.response))
            {
                cache.process_response(&mut context, outcome, Some((denial, generation)));
                if valid
                    && denial
                    && Message::parse(context.response).is_ok_and(|message| {
                        message.rcode() == Rcode::NOERROR
                            && message.answer_count() > 0
                            && answers_question(&message)
                    })
                {
                    let _write = cache.writes.lock().unwrap();
                    if cache.denial.remove_if_stored(key, stored)
                        && let Some(metrics) = cache
                            .metrics
                            .iter()
                            .find_map(|(address, metrics)| (*address == local).then_some(metrics))
                    {
                        metrics.entries(true, cache.denial.len());
                    }
                }
            }
            guard.success = valid;
            valid.then_some(response)
        })
    }

    fn insert_response(
        &self,
        key: u64,
        response: &Message<'_>,
        ttl: u32,
        denial: bool,
        expected: Option<(bool, Instant)>,
    ) -> Option<bool> {
        let _write = self.writes.lock().unwrap();
        if let Some((old_denial, stored)) = expected {
            let old = if old_denial {
                &self.denial
            } else {
                &self.success
            };
            if !old.is_current(key, stored) {
                return None;
            }
        }
        if denial {
            self.denial.insert(key, response, ttl, false)
        } else {
            self.success
                .insert(key, response, ttl, self.config.prefer_positive)
        }
    }

    fn process_response(
        &self,
        cx: &mut Context<'_>,
        outcome: Outcome,
        expected: Option<(bool, Instant)>,
    ) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return outcome;
        };
        let key = key(&query);
        let metrics = self
            .metrics
            .iter()
            .find_map(|(address, metrics)| (*address == cx.local).then_some(metrics));
        if outcome != Outcome::Response {
            if matches!(
                outcome,
                Outcome::Unanswered(Rcode::SERVFAIL) | Outcome::Error(_)
            ) && !self.config.fail_ttl.is_zero()
                && !self
                    .config
                    .disable_denial
                    .iter()
                    .any(|zone| contains(question.name, zone))
            {
                let ttl = self.config.fail_ttl.as_secs() as u32;
                if ttl > 0
                    && let Ok(mut builder) = MessageBuilder::new(
                        cx.response,
                        65535,
                        query.id(),
                        0x8002 | (query.flags() & 0x0110),
                    )
                    && matches!(
                        builder.question(question.name, question.qtype, question.qclass),
                        Ok(true)
                    )
                {
                    let _ = builder.finish();
                    if let Ok(response) = Message::parse(cx.response)
                        && let Some(evicted) =
                            self.insert_response(key, &response, ttl, true, expected)
                        && let Some(metrics) = metrics
                    {
                        if evicted {
                            metrics.evict(true);
                        }
                        metrics.entries(false, self.success.len());
                        metrics.entries(true, self.denial.len());
                    }
                }
            }
            return outcome;
        }
        let Ok(response) = Message::parse(cx.response) else {
            return outcome;
        };
        if response
            .additionals()
            .any(|record| record.rtype == Type::TSIG)
        {
            return outcome;
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64);
        let mut response_type = pharos_proto::typify_response(Some(&response), now);
        let has_soa = response.authorities().any(|rr| rr.rtype == Type::SOA);
        let incomplete = response_type == ResponseType::Positive
            && response.answer_count() > 0
            && !answers_question(&response);
        if incomplete && has_soa {
            response_type = ResponseType::NoData;
        }
        let denial = matches!(
            response_type,
            ResponseType::NxDomain | ResponseType::NoData | ResponseType::ServerError
        );
        let (minimum, maximum) = if denial {
            (self.config.denial_min_ttl, self.config.denial_max_ttl)
        } else {
            (self.config.success_min_ttl, self.config.success_max_ttl)
        };
        let minimum = minimum.as_secs().min(u64::from(u32::MAX)) as u32;
        let maximum = maximum.as_secs().min(u64::from(u32::MAX)) as u32;
        let mut ttl = maximum;
        let mut found = false;
        for record in response
            .answers()
            .chain(response.authorities())
            .chain(response.additionals())
        {
            if record.rtype == Type::OPT {
                continue;
            }
            found = true;
            ttl = ttl.min(record.ttl);
            if denial && let Ok(Rdata::Soa { minimum, .. }) = record.data() {
                ttl = ttl.min(minimum);
            }
        }
        if !found || response_type == ResponseType::Referral {
            ttl = 5;
        }
        ttl = ttl.max(minimum).min(maximum);
        if response_type == ResponseType::ServerError {
            ttl = self.config.fail_ttl.as_secs() as u32;
        }
        let matches = response.questions().next().is_some_and(|q| {
            q.name == question.name && q.qtype == question.qtype && q.qclass == question.qclass
        });
        let eligible = !response.tc()
            && ttl > 0
            && (!incomplete || has_soa)
            && (matches!(
                response_type,
                ResponseType::Positive
                    | ResponseType::Referral
                    | ResponseType::NoData
                    | ResponseType::ServerError
            ) || (response_type == ResponseType::NxDomain && has_soa));
        if eligible
            && !matches
            && let Some(metrics) = metrics
        {
            metrics.drop_response();
        }
        let cacheable = eligible && matches;
        let disabled = if denial {
            &self.config.disable_denial
        } else {
            &self.config.disable_success
        };
        let cacheable = cacheable && !disabled.iter().any(|zone| contains(question.name, zone));
        if let Ok(mut mutable) = MessageMut::parse(cx.response) {
            mutable.rewrite_ttls(|_| ttl);
        }
        if cacheable && let Ok(response) = Message::parse(cx.response) {
            let inserted = self.insert_response(key, &response, ttl, denial, expected);
            if let Some(evicted) = inserted
                && let Some(metrics) = metrics
            {
                if evicted {
                    metrics.evict(denial);
                }
                metrics.entries(false, self.success.len());
                metrics.entries(true, self.denial.len());
            }
        }
        if !query.ad() && !query.opt().is_some_and(|opt| opt.dnssec_ok()) {
            cx.response[3] &= !0x20;
        }
        strip_trailing_opt(cx.response);
        outcome
    }
}

fn strip_trailing_opt(wire: &mut Vec<u8>) {
    let Ok(message) = Message::parse(wire) else {
        return;
    };
    if message.rcode().0 > 15 {
        return;
    }
    let Some(opt) = message
        .additionals()
        .last()
        .filter(|record| record.rtype == Type::OPT)
    else {
        return;
    };
    let start = opt.ttl_offset - 4 - opt.name.wire_len();
    let count = message.additional_count() - 1;
    wire.truncate(start);
    wire[10..12].copy_from_slice(&count.to_be_bytes());
}

fn answers_question(message: &Message<'_>) -> bool {
    let Some(question) = message.questions().next() else {
        return false;
    };
    let matches_class =
        |class| question.qclass == pharos_proto::Class::ANY || question.qclass == class;
    if question.qtype == Type::ANY {
        return message
            .answers()
            .any(|rr| rr.name == question.name && matches_class(rr.class));
    }
    let mut name = question.name.to_name();
    let mut visited = Vec::new();
    loop {
        if visited.contains(&name) {
            return false;
        }
        visited.push(name.clone());
        let mut target: Option<Name> = None;
        for rr in message.answers() {
            if rr.rtype != Type::CNAME || rr.name != name || !matches_class(rr.class) {
                continue;
            }
            let Ok(Rdata::Cname(alias)) = rr.data() else {
                return false;
            };
            if target.as_ref().is_some_and(|existing| alias != *existing) {
                return false;
            }
            target = Some(alias.to_name());
        }
        if question.qtype == Type::CNAME {
            return target.is_some();
        }
        match target {
            Some(alias) => name = alias,
            None => {
                return message.answers().any(|rr| {
                    rr.rtype == question.qtype && rr.name == name && matches_class(rr.class)
                });
            }
        }
    }
}

fn contains(name: NameRef<'_>, domain: &Name) -> bool {
    let domain = NameRef::parse(domain.as_wire(), 0).expect("configured Domain");
    let count = name.labels().count();
    let suffix = domain.labels().count();
    count >= suffix
        && name
            .labels()
            .skip(count - suffix)
            .zip(domain.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

struct KeyHash(u64);
impl KeyHash {
    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
}
impl std::fmt::Write for KeyHash {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        for byte in value.bytes() {
            self.bytes(&[byte.to_ascii_lowercase()]);
        }
        Ok(())
    }
}

fn key(query: &Message<'_>) -> u64 {
    let question = query.questions().next().expect("Query has a Question");
    let mut hash = KeyHash(0xcbf29ce484222325);
    hash.bytes(&[if query.opt().is_some_and(|opt| opt.dnssec_ok()) {
        b'1'
    } else {
        b'0'
    }]);
    hash.bytes(&[if query.cd() { b'1' } else { b'0' }]);
    hash.bytes(&question.qtype.0.to_be_bytes());
    hash.bytes(&question.qclass.0.to_be_bytes());
    write!(hash, "{}", question.name).expect("hash writer never fails");
    hash.0
}
