//! Cache configuration and DNS Response storage.

pub(crate) mod setup;
mod store;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Instant, SystemTime},
};

use pharos_proto::{
    EdnsOption, Message, MessageBuilder, MessageMut, Name, NameRef, Opcode, Opt, Rcode, Rdata,
    ResponseType, Type,
};
use pharos_server::{Context, Next, Outcome, Plugin};

/// Configuration for the cache Plugin.
pub struct Cache {
    config: setup::Config,
    success: store::Store,
    denial: store::Store,
    metrics: Vec<(SocketAddr, pharos_server::metrics::CacheMetrics)>,
    chain: OnceLock<Weak<crate::Chain>>,
    #[cfg(feature = "plugin-dynupdate")]
    bypass: OnceLock<Name>,
    writes: Mutex<()>,
}

const MAX_CACHED_TTL: u32 = 604_800;

#[derive(Clone, Copy)]
struct CacheKeys {
    exact: u64,
    nxdomain: u64,
    dnssec_ok: bool,
    allow_nxdomain: bool,
}

#[derive(Clone, Copy)]
struct Expected {
    denial: bool,
    key: u64,
    stored: Instant,
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

struct QueryGuard<'a, 'b, 'c> {
    context: &'a mut Context<'b, 'c>,
    query: Message<'b>,
}

impl Drop for QueryGuard<'_, '_, '_> {
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
            #[cfg(feature = "plugin-dynupdate")]
            bypass: OnceLock::new(),
            writes: Mutex::new(()),
            config,
        })
    }

    pub(crate) fn bind(&self, chain: &Arc<crate::Chain>) {
        let _ = self.chain.set(Arc::downgrade(chain));
        // CoreDNS plugin/cache/setup.go:27-32 and plugin/dynupdate/dynupdate.go:88-91 bypass mutable Zones.
        #[cfg(feature = "plugin-dynupdate")]
        if let Some(dynamic) = &chain.dynupdate {
            let _ = self.bypass.set(dynamic.origin().clone());
        }
    }

    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
        view: &str,
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
                .push((address, registry.cache(&server, &zones, view)));
        }
    }
}

// RFC 1034 §5.1: a shared resolver cache avoids repeated upstream queries and network delay.
impl Plugin for Cache {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        let opt = query.opt();
        #[cfg(feature = "plugin-dynupdate")]
        let dynamic = self
            .bypass
            .get()
            .is_some_and(|zone| contains(question.name, zone));
        #[cfg(not(feature = "plugin-dynupdate"))]
        let dynamic = false;
        // RFC 8945 §4.1: TSIG records are not cached.
        if query.opcode() != Opcode::QUERY
            || dynamic
            || question.qtype == Type::TKEY // RFC 2930 §3: TKEY transactions are transient.
            || has_client_subnet(opt) // RFC 7871 §7.3: Do not reuse ECS-tailored data across networks.
            // RFC 8945 §4.3.2: TSIG-signed queries bypass cache because the MAC covers the wire.
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
        let keys = cache_keys(&query, opt);
        let can_grow = cx.protocol == pharos_server::Protocol::Tcp;
        let positive_first = self.config.prefer_positive && !self.config.stale.is_zero();
        let positive = positive_first
            .then(|| {
                self.success
                    .serve(keys, &query, cx.response, &self.config, true, can_grow)
            })
            .flatten();
        let hit = if let Some(hit) = positive {
            Some((false, hit))
        } else if let Some(denial) = self.denial.serve(
            CacheKeys {
                allow_nxdomain: true,
                ..keys
            },
            &query,
            cx.response,
            &self.config,
            false,
            can_grow,
        ) {
            if cx.response[3] & 15 == 2 {
                if let Some(positive) =
                    self.success
                        .serve(keys, &query, cx.response, &self.config, false, can_grow)
                {
                    if let Some(stored) = denial.refresh {
                        self.denial.finish_refresh(
                            denial.key,
                            stored,
                            std::time::Duration::ZERO,
                            true,
                        );
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
                .serve(keys, &query, cx.response, &self.config, false, can_grow)
                .map(|hit| (false, hit))
        };
        // RFC 9520 §3.2: Handle a cached resolution failure as a cache hit.
        if let Some((denial, hit)) = hit {
            if let Some(metrics) = metrics {
                metrics.hit(denial);
            }
            // RFC 8767 §4: an expired cache entry triggers a source refresh attempt.
            if let Some(stored) = hit.refresh {
                let store = if denial { &self.denial } else { &self.success };
                if !query.can_set_ad_in_wire() {
                    store.finish_refresh(hit.key, stored, self.config.stale_recheck, false);
                } else if let Some(chain) = self.chain.get().and_then(Weak::upgrade) {
                    if (!hit.stale || !self.config.verify)
                        && let Some(metrics) = metrics
                    {
                        metrics.prefetch();
                    }
                    let task = self.spawn_refresh(chain, cx, keys, denial, hit);
                    if hit.stale && self.config.verify {
                        // RFC 8767 §5: Serve stale after the timer while refresh continues.
                        let result = if self.config.verify_timeout.is_zero() {
                            task.await.ok()
                        } else {
                            tokio::time::timeout(self.config.verify_timeout, task)
                                .await
                                .ok()
                                .and_then(Result::ok)
                        };
                        if let Some(Some(mut response)) = result {
                            // RFC 6840 §5.8: only signal AD when the query requested AD or DO.
                            if !query.ad() && !opt.is_some_and(|opt| opt.dnssec_ok()) {
                                response[3] &= !0x20;
                            }
                            *cx.response = response;
                            return Outcome::Response;
                        }
                    }
                } else if hit.stale && self.config.verify {
                    let mut guard = LocalRefreshGuard {
                        store,
                        key: hit.key,
                        stored,
                        recheck: self.config.stale_recheck,
                        success: false,
                    };
                    let stale = cx.response.clone();
                    let outcome = {
                        // RFC 6840 §5.7: Set AD to request AD response data.
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
                        self.process_response(
                            cx,
                            outcome,
                            keys,
                            Some(Expected {
                                denial,
                                key: hit.key,
                                stored: hit.generation,
                            }),
                        );
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
                    store.finish_refresh(hit.key, stored, self.config.stale_recheck, false);
                }
            }
            if hit.stale
                && let Some(metrics) = metrics
            {
                metrics.served_stale();
            }
            // RFC 9520 §3.2: Return a cached resolution failure after any refresh handling.
            return Outcome::Response;
        }
        if let Some(metrics) = metrics {
            metrics.miss();
        }
        if !query.can_set_ad_in_wire() {
            return next.run(cx).await;
        }
        let outcome = {
            // RFC 6840 §5.7: Set AD to signal interest in the upstream response's AD bit.
            cx.query = query.with_ad();
            let guard = QueryGuard {
                context: &mut *cx,
                query,
            };
            next.run(&mut *guard.context).await
        };
        self.process_response(cx, outcome, keys, None)
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
        // RFC 8767 §4: NOERROR and NXDOMAIN answers can refresh cached data.
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
        cx: &Context<'_, '_>,
        keys: CacheKeys,
        denial: bool,
        hit: store::Hit,
    ) -> tokio::task::JoinHandle<Option<Vec<u8>>> {
        let stored = hit.refresh.expect("refresh requested");
        let generation = hit.generation;
        let stale = hit.stale;
        let mut wire = Vec::with_capacity(cx.query.as_wire().len());
        let safe_query =
            cx.query.can_set_ad_in_wire() && cx.query.copy_wire_checked(&mut wire).is_ok();
        if safe_query {
            wire[3] |= 0x20;
        }
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
        let self_lookup = cx.self_lookup_handle();
        let guard = RefreshGuard {
            chain,
            key: hit.key,
            stored,
            denial,
            recheck: if stale {
                self.config.stale_recheck
            } else {
                std::time::Duration::ZERO
            },
            success: false,
        };
        // RFC 8767 §7: continue refresh attempts after serving stale data.
        tokio::spawn(async move {
            let mut guard = guard;
            if !safe_query {
                return None;
            }
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
                metadata: pharos_server::Metadata::with_self_lookup(
                    &mut slots,
                    self_lookup.as_ref(),
                ),
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
                cache.process_response(
                    &mut context,
                    outcome,
                    keys,
                    Some(Expected {
                        denial,
                        key: hit.key,
                        stored: generation,
                    }),
                );
                if valid
                    && denial
                    && Message::parse(context.response).is_ok_and(|message| {
                        message.rcode() == Rcode::NOERROR
                            && message.answer_count() > 0
                            && answers_question(&message)
                    })
                {
                    let _write = cache.writes.lock().unwrap();
                    if cache.denial.remove_if_stored(hit.key, stored)
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
        expected: Option<Expected>,
    ) -> Option<bool> {
        let _write = self.writes.lock().unwrap();
        if let Some(expected) = expected {
            let old = if expected.denial {
                &self.denial
            } else {
                &self.success
            };
            if !old.is_current(expected.key, expected.stored) {
                return None;
            }
        }
        if denial {
            self.denial
                .insert(key, response, ttl, false, expected.is_some())
        } else {
            self.success.insert(
                key,
                response,
                ttl,
                self.config.prefer_positive,
                expected.is_some(),
            )
        }
    }

    fn process_response(
        &self,
        cx: &mut Context<'_, '_>,
        outcome: Outcome,
        keys: CacheKeys,
        expected: Option<Expected>,
    ) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return outcome;
        };
        let key = keys.exact;
        let metrics = self
            .metrics
            .iter()
            .find_map(|(address, metrics)| (*address == cx.local).then_some(metrics));
        // RFC 9520 §3.2: cache resolution failures so matching queries skip upstream.
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
                let ttl = self
                    .denial
                    .next_failure_ttl(key, self.config.fail_ttl.as_secs() as u32);
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
        // RFC 2930 §3: TKEY transactions are transient and must not be cached.
        if has_client_subnet(response.opt())
            || has_record_type(&response, Type::TSIG)
            || has_record_type(&response, Type::TKEY)
        {
            return outcome;
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64);
        let mut response_type = pharos_proto::typify_response(Some(&response), now);
        let has_soa = response.authorities().any(|rr| rr.rtype == Type::SOA);
        let has_ns = response.authorities().any(|rr| rr.rtype == Type::NS);
        // RFC 2308 §2.1: NXDOMAIN can include CNAME answers before the final name error.
        if response.rcode() == Rcode::NXDOMAIN && has_soa {
            response_type = ResponseType::NxDomain;
        }
        let incomplete = response_type == ResponseType::Positive
            && response.answer_count() > 0
            && !answers_question(&response);
        // RFC 2308 §2.2: NODATA can include CNAMEs and an SOA in the authority section.
        if incomplete && has_soa {
            response_type = ResponseType::NoData;
        }
        // RFC 8020 §2: store NXDOMAIN as a denial for subsequent matching queries.
        let failure = is_resolution_failure(response.rcode());
        let no_data_without_soa = is_soa_less_nodata(&response, has_soa, has_ns);
        let denial = failure
            || matches!(
                response_type,
                ResponseType::NxDomain | ResponseType::NoData | ResponseType::ServerError
            );
        let (minimum, maximum) = if denial {
            // RFC 2308 §3: A configured denial minimum cannot extend the SOA-derived lifetime.
            (std::time::Duration::ZERO, self.config.denial_max_ttl)
        } else {
            (self.config.success_min_ttl, self.config.success_max_ttl)
        };
        let minimum = minimum.as_secs().min(u64::from(u32::MAX)) as u32;
        // RFC 8767 §4: Cached TTLs must not exceed the recommended one-week maximum.
        let maximum = cached_maximum(maximum.as_secs());
        let mut ttl = maximum;
        let mut signature_remaining = u32::MAX;
        let mut found = false;
        // RFC 4035 §4.5: use the shortest RR TTL so the cache entry expires together.
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
            // RFC 2308 §4: bound the negative-response TTL by SOA.MINIMUM.
            if denial && let Ok(Rdata::Soa { minimum, .. }) = record.data() {
                ttl = ttl.min(minimum);
            }
            if let Ok(Rdata::Rrsig { expiration, .. }) = record.data() {
                signature_remaining =
                    signature_remaining.min(signature_ttl(expiration, now as u32));
            }
        }
        if !found
            || !matches!(
                response_type,
                ResponseType::Positive
                    | ResponseType::Referral
                    | ResponseType::NxDomain
                    | ResponseType::NoData
            )
        {
            ttl = 5;
        }
        ttl = bound_ttl(ttl, denial, minimum, maximum);
        // RFC 4033 §8.1: Signature validity bounds cache lifetime after all TTL floors.
        ttl = cap_ttl_at_signature(ttl, signature_remaining);
        if failure {
            // RFC 9520 §3.2: Cache SERVFAIL and REFUSED with the failure backoff.
            ttl = self
                .denial
                .next_failure_ttl(key, self.config.fail_ttl.as_secs() as u32);
        } else if response_type == ResponseType::ServerError {
            ttl = self.config.fail_ttl.as_secs() as u32;
        }
        let matches = response.questions().next().is_some_and(|q| {
            q.name == question.name && q.qtype == question.qtype && q.qclass == question.qclass
        });
        // RFC 1035 §7.4: reject truncated responses that may contain incomplete RRsets.
        let eligible = !response.tc()
            && ttl > 0
            && (!incomplete || has_soa)
            && !no_data_without_soa
            && (matches!(
                response_type,
                ResponseType::Positive
                    | ResponseType::Referral
                    | ResponseType::NoData
                    | ResponseType::ServerError
            ) || (response_type == ResponseType::NxDomain && has_soa)
                || failure);
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
        // RFC 1034 §4.3.3: Explicit wildcard QNAMEs are never admitted to cache.
        let cacheable = cacheable
            && !has_explicit_wildcard(question.name)
            && !disabled.iter().any(|zone| contains(question.name, zone));
        if let Ok(mut mutable) = MessageMut::parse(cx.response) {
            mutable.rewrite_ttls(|_| ttl);
        }
        // RFC 1035 §7.4: retain complete responses for later matching queries.
        if cacheable && let Ok(response) = Message::parse(cx.response) {
            let response_key = if response_type == ResponseType::NxDomain {
                keys.nxdomain
            } else {
                key
            };
            let inserted = self.insert_response(response_key, &response, ttl, denial, expected);
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
        // RFC 6840 §5.8: only signal AD when the query requested AD or DO.
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

fn has_client_subnet(opt: Option<Opt<'_>>) -> bool {
    // RFC 7871 §7.3: Avoid sharing ECS-tailored responses across client networks.
    opt.is_some_and(|opt| {
        opt.options()
            .iter()
            .any(|option| matches!(option, EdnsOption::ClientSubnet(_)))
    })
}

fn has_record_type(message: &Message<'_>, rtype: Type) -> bool {
    message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .any(|record| record.rtype == rtype)
}

fn has_explicit_wildcard(name: NameRef<'_>) -> bool {
    name.labels().any(|label| label == b"*")
}

fn is_soa_less_nodata(message: &Message<'_>, has_soa: bool, has_ns: bool) -> bool {
    // RFC 2308 §5: Do not cache NODATA without an SOA in the authority section.
    message.rcode() == Rcode::NOERROR && message.answer_count() == 0 && !has_soa && !has_ns
}

fn bound_ttl(ttl: u32, denial: bool, minimum: u32, maximum: u32) -> u32 {
    if denial {
        // RFC 2308 §3: Never raise a negative TTL above its SOA-derived lifetime.
        ttl.min(maximum)
    } else {
        // RFC 1035 §3.2.1 deviation (ADR 0002): Retain documented CoreDNS positive-TTL flooring.
        ttl.max(minimum).min(maximum)
    }
}

fn cap_ttl_at_signature(ttl: u32, signature_ttl: u32) -> u32 {
    ttl.min(signature_ttl)
}

fn cached_maximum(maximum: u64) -> u32 {
    // RFC 8767 §4: Cap cached TTLs at the recommended 604800 seconds.
    maximum.min(u64::from(MAX_CACHED_TTL)) as u32
}

fn signature_ttl(expiration: u32, now: u32) -> u32 {
    // RFC 4034 §3.1.5: Compare RRSIG times with 32-bit serial arithmetic.
    u32::try_from(expiration.wrapping_sub(now) as i32).unwrap_or(0)
}

fn is_resolution_failure(rcode: Rcode) -> bool {
    // RFC 9520 §§2.1–2.2: SERVFAIL and REFUSED are resolution failures.
    matches!(rcode, Rcode::SERVFAIL | Rcode::REFUSED)
}

// RFC 8482 §4.2: decide cacheability from the answer records alone, with no HINFO-specific case.
fn answers_question(message: &Message<'_>) -> bool {
    let Some(question) = message.questions().next() else {
        return false;
    };
    let matches_class =
        |class| question.qclass == pharos_proto::Class::ANY || question.qclass == class;
    // RFC 8482 §5: cache ANY replies with an answer RR at QNAME using normal TTLs.
    if question.qtype == Type::ANY {
        return message
            .answers()
            .any(|rr| rr.name == question.name && matches_class(rr.class));
    }
    // RFC 1034 §3.6.2: follow CNAME chains and detect loops.
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
            // RFC 1035 §3.1: DNS labels are compared case-insensitively.
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
// RFC 2308 §5: Hash both query keys in one pass so NXDOMAIN fallback shares the hot-path work.
fn cache_keys(query: &Message<'_>, opt: Option<Opt<'_>>) -> CacheKeys {
    let question = query.questions().next().expect("Query has a Question");
    let mut exact = KeyHash(0xcbf29ce484222325);
    let mut nxdomain = KeyHash(0xcbf29ce484222325);
    exact.bytes(b"Q");
    nxdomain.bytes(b"N");
    let dnssec_ok = opt.is_some_and(|opt| opt.dnssec_ok());
    let dnssec_key = if dnssec_ok { b'1' } else { b'0' };
    let checking_disabled = if query.cd() { b'1' } else { b'0' };
    exact.bytes(&[dnssec_key, checking_disabled]);
    nxdomain.bytes(&[dnssec_key, checking_disabled]);
    exact.bytes(&question.qtype.0.to_be_bytes());
    exact.bytes(&question.qclass.0.to_be_bytes());
    nxdomain.bytes(&question.qclass.0.to_be_bytes());
    for label in question.name.labels() {
        // RFC 1035 §3.1: Hash wire labels case-insensitively without formatting or allocation.
        let length = [label.len() as u8];
        exact.bytes(&length);
        nxdomain.bytes(&length);
        for byte in label {
            let byte = [byte.to_ascii_lowercase()];
            exact.bytes(&byte);
            nxdomain.bytes(&byte);
        }
    }
    exact.bytes(&[0]);
    nxdomain.bytes(&[0]);
    let shard = nxdomain.0 & 0xff;
    CacheKeys {
        exact: (exact.0 & !0xff) | shard,
        nxdomain: (nxdomain.0 & !0xff) | shard,
        dnssec_ok,
        allow_nxdomain: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_proto::{Class, MessageBuilder};

    fn query(qtype: Type) -> Vec<u8> {
        let name = NameRef::parse(b"\x01x\0", 0).unwrap();
        let mut wire = Vec::with_capacity(64);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder.question(name, qtype, Class::IN).unwrap();
        let _ = builder.finish();
        wire
    }

    #[test]
    fn cache_keys_separate_exact_qtype_and_shared_nxdomain_shard() {
        let a_wire = query(Type::A);
        let aaaa_wire = query(Type::AAAA);
        let a = Message::parse(&a_wire).unwrap();
        let aaaa = Message::parse(&aaaa_wire).unwrap();
        let a_keys = cache_keys(&a, a.opt());
        let aaaa_keys = cache_keys(&aaaa, aaaa.opt());
        assert_eq!(a_keys.nxdomain, aaaa_keys.nxdomain);
        assert_ne!(a_keys.exact, aaaa_keys.exact);
        assert_eq!(a_keys.exact & 255, a_keys.nxdomain & 255);
    }

    #[test]
    fn explicit_wildcard_names_are_detected() {
        let wildcard = NameRef::parse(b"\x01*\x07example\x03org\0", 0).unwrap();
        let ordinary = NameRef::parse(b"\x01x\x07example\x03org\0", 0).unwrap();
        assert!(has_explicit_wildcard(wildcard));
        assert!(!has_explicit_wildcard(ordinary));
    }

    #[test]
    fn ecs_query_is_detected_for_conservative_cache_bypass() {
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x01x\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\0\0\0\x0b\0\x08\0\x07\0\x01\x18\0\xc0\0\x02";
        assert!(has_client_subnet(Message::parse(wire).unwrap().opt()));
        assert!(!has_client_subnet(
            Message::parse(&query(Type::A)).unwrap().opt()
        ));
    }

    #[test]
    fn negative_ttl_is_not_raised_to_positive_minimum() {
        assert_eq!(bound_ttl(1, true, 5, 100), 1);
        assert_eq!(bound_ttl(1, false, 5, 100), 5);
    }

    #[test]
    fn expired_signature_caps_the_positive_ttl_floor() {
        let ttl = bound_ttl(0, false, 5, 100);
        assert_eq!(cap_ttl_at_signature(ttl, 0), 0);
        assert_eq!(cap_ttl_at_signature(ttl, 2), 2);
    }

    #[test]
    fn cache_ttl_cap_is_one_week() {
        assert_eq!(cached_maximum(u64::MAX), MAX_CACHED_TTL);
    }

    #[test]
    fn cache_ttl_ends_at_rrsig_expiration() {
        assert_eq!(signature_ttl(1_040, 1_000), 40);
        assert_eq!(signature_ttl(990, 1_000), 0);
        assert_eq!(signature_ttl(10, u32::MAX - 9), 20);
    }

    #[test]
    fn refused_is_a_cacheable_resolution_failure() {
        assert!(is_resolution_failure(Rcode::REFUSED));
        assert!(is_resolution_failure(Rcode::SERVFAIL));
        assert!(!is_resolution_failure(Rcode::FORMERR));
    }

    #[test]
    fn nodata_without_soa_is_not_cacheable() {
        let name = NameRef::parse(b"\x01x\0", 0).unwrap();
        let mut wire = Vec::with_capacity(64);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        let _ = builder.finish();
        let response = Message::parse(&wire).unwrap();
        assert!(is_soa_less_nodata(&response, false, false));
    }
}
