//! Cache configuration and DNS Response storage.

pub(crate) mod setup;
mod store;

use std::{
    cmp::Ordering,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Instant, SystemTime},
};

use pharos_proto::{
    Class, EdnsOption, Message, MessageBuilder, Name, NameRef, Opcode, Opt, Rcode, Rdata,
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
    writes: Box<[Mutex<()>]>,
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
    // RFC 8767 §5: serialize refresh validation with writes in the same shard.
    fn lock_writes(&self, key: u64) -> std::sync::MutexGuard<'_, ()> {
        self.writes[key as usize & 255].lock().unwrap()
    }

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
            writes: (0..256).map(|_| Mutex::new(())).collect(),
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
        let special = crate::special_use(question.name);
        #[cfg(feature = "plugin-forward")]
        let upstream_allowed = special.is_some_and(|special| {
            special.permits_upstream()
                && self
                    .chain
                    .get()
                    .and_then(Weak::upgrade)
                    .and_then(|chain| {
                        chain
                            .forward
                            .as_ref()
                            .map(|forward| forward.allows_special(question.name))
                    })
                    .unwrap_or(false)
        });
        #[cfg(not(feature = "plugin-forward"))]
        let upstream_allowed = false;
        let opt = query.opt();
        #[cfg(feature = "plugin-dynupdate")]
        let dynamic = self
            .bypass
            .get()
            .is_some_and(|zone| crate::name_within(question.name, zone));
        #[cfg(not(feature = "plugin-dynupdate"))]
        let dynamic = false;
        // RFC 8945 §4.1: TSIG records are not cached.
        if query.opcode() != Opcode::QUERY
            || dynamic
            || question.qtype == Type::TKEY // RFC 2930 §3: TKEY transactions are transient.
            || has_client_subnet(opt) // RFC 7871 §7.3: Do not reuse ECS-tailored data across networks.
            // RFC 8945 §4.3.2: TSIG-signed queries bypass cache because the MAC covers the wire.
            || query.additionals().any(|record| record.rtype == Type::TSIG)
            // RFC 6761 §§6.1–6.4: let later owner Plugins handle special names before cache admission.
            || special.is_some() && !upstream_allowed
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
                .any(|zone| crate::name_within(question.name, zone))
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
                    let _write = cache.lock_writes(hit.key);
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

    #[cfg(test)]
    fn insert_response(
        &self,
        key: u64,
        response: &Message<'_>,
        ttl: u32,
        denial: bool,
        expected: Option<Expected>,
    ) -> Option<bool> {
        self.insert_response_counted(key, response, ttl, denial, expected)
            .map(|evictions| evictions > 0)
    }

    fn insert_response_counted(
        &self,
        key: u64,
        response: &Message<'_>,
        ttl: u32,
        denial: bool,
        expected: Option<Expected>,
    ) -> Option<usize> {
        // RFC 2181 §5.4.1: prepare complete response data before synchronizing cache writes.
        let item = store::Item::new(response, ttl)?;
        let _write = self.lock_writes(key);
        if let Some(expected) = expected {
            // RFC 8767 §5: exact and NXDOMAIN keys share a shard for atomic refreshes.
            debug_assert_eq!(key & 255, expected.key & 255);
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
                .insert_prepared(key, item, false, expected.is_some())
        } else {
            self.success
                .insert_prepared(key, item, self.config.prefer_positive, expected.is_some())
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
            ) && !self
                .config
                .disable_denial
                .iter()
                .any(|zone| crate::name_within(question.name, zone))
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
                            self.insert_response_counted(key, &response, ttl, true, expected)
                        && let Some(metrics) = metrics
                    {
                        // CoreDNS cache metrics: count every evicted entry.
                        for _ in 0..evicted {
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
        // RFC 8767 §4: Use its recommended 604800-second cap for cached TTLs.
        let maximum = cached_maximum(maximum.as_secs());
        let mut records = index_response_rrsets(&response);
        let malformed_non_authoritative_rrset =
            !response.aa() && records.iter().any(|record| record.mixed_ttl);
        // RFC 4033 §8.1: Keep cached data within every RRSIG's validity interval.
        let signature_remaining = records
            .iter()
            .filter_map(|record| {
                record
                    .rrsig_expiration
                    .map(|expiration| signature_ttl(expiration, now as u32))
            })
            .min()
            .unwrap_or(u32::MAX);
        // RFC 2308 §§3, 5: Cache negative Authority data no longer than its SOA-derived TTL.
        let negative_ttl =
            if !failure && matches!(response_type, ResponseType::NxDomain | ResponseType::NoData) {
                records
                    .iter()
                    .filter(|record| {
                        record.section == RecordSection::Authority && record.key.rtype == Type::SOA
                    })
                    .filter_map(|record| {
                        record
                            .soa_minimum
                            .map(|minimum| record.minimum_ttl.min(minimum))
                    })
                    .min()
                    .map(|ttl| cap_ttl_at_signature(ttl.min(maximum), signature_remaining))
            } else {
                None
            };
        let mut ttl = maximum;
        // RFC 2181 §5.2: Normalize TTLs to each RRset's minimum, not the whole Response's.
        for record in &mut records {
            let record_ttl = if failure {
                self.config.fail_ttl.as_secs().min(u64::from(u32::MAX)) as u32
            } else {
                cap_ttl_at_signature(
                    normalized_rrset_ttl(
                        record.key.rtype,
                        record.minimum_ttl,
                        record.soa_minimum,
                        denial,
                        minimum,
                        maximum,
                    ),
                    signature_remaining,
                )
            };
            let record_ttl = if record.section == RecordSection::Authority {
                record_ttl.min(negative_ttl.unwrap_or(u32::MAX))
            } else {
                record_ttl
            };
            record.ttl = record_ttl;
            if record.section != RecordSection::Additional {
                ttl = ttl.min(record_ttl);
            }
        }
        if failure {
            // RFC 9520 §3.2: Cache SERVFAIL and REFUSED with the failure backoff.
            ttl = self
                .denial
                .next_failure_ttl(key, self.config.fail_ttl.as_secs() as u32);
        } else if response_type == ResponseType::ServerError {
            ttl = self.config.fail_ttl.as_secs() as u32;
        }
        if failure || response_type == ResponseType::ServerError {
            for record in &mut records {
                record.ttl = ttl;
            }
        }
        let matches = response.questions().next().is_some_and(|q| {
            q.name == question.name && q.qtype == question.qtype && q.qclass == question.qclass
        });
        // RFC 2181 §9: Reject truncated responses that may contain incomplete RRsets.
        let eligible = !response.tc()
            && ttl > 0
            && (!incomplete || has_soa)
            && !no_data_without_soa
            && !malformed_non_authoritative_rrset
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
        // RFC 2181 §5.4 / RFC 5452 §6: Cache only query-relevant, in-domain response data.
        let eligible = eligible
            && matches
            && response_records_relevant(question.name, question.qtype, question.qclass, &response);
        let cacheable = eligible;
        let disabled = if denial {
            &self.config.disable_denial
        } else {
            &self.config.disable_success
        };
        // RFC 1034 §4.3.3: Explicit wildcard QNAMEs are never admitted to cache.
        let cacheable = cacheable
            && !has_explicit_wildcard(question.name)
            && !disabled
                .iter()
                .any(|zone| crate::name_within(question.name, zone));
        let mut ttl_updates = Vec::with_capacity(records.len());
        for record in records {
            ttl_updates.push((record.ttl_offset, record.ttl));
        }
        for (offset, record_ttl) in ttl_updates {
            let offset = offset as usize;
            cx.response[offset..offset + 4].copy_from_slice(&record_ttl.to_be_bytes());
        }
        // RFC 1035 §7.4: retain complete responses for later matching queries.
        if cacheable && let Ok(response) = Message::parse(cx.response) {
            let response_key = if response_type == ResponseType::NxDomain {
                keys.nxdomain
            } else {
                key
            };
            let inserted =
                self.insert_response_counted(response_key, &response, ttl, denial, expected);
            if let Some(evicted) = inserted
                && let Some(metrics) = metrics
            {
                // CoreDNS cache metrics: count every evicted entry.
                for _ in 0..evicted {
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct RrsetKey<'a> {
    name: NameRef<'a>,
    rtype: Type,
    class: Class,
    covered_type: Option<Type>,
}

// RFC 4343 §3 / RFC 1035 §2.3.3: RRset owner names compare case-insensitively.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordSection {
    Answer,
    Authority,
    Additional,
}

struct IndexedRecord<'a> {
    key: RrsetKey<'a>,
    section: RecordSection,
    ttl_offset: u32,
    ttl: u32,
    soa_minimum: Option<u32>,
    rrsig_expiration: Option<u32>,
    minimum_ttl: u32,
    mixed_ttl: bool,
}

impl<'a> IndexedRecord<'a> {
    fn new(record: pharos_proto::Record<'a>, section: RecordSection) -> Self {
        let mut covered_type = None;
        let mut soa_minimum = None;
        let mut rrsig_expiration = None;
        if record.rtype == Type::RRSIG {
            if let Ok(Rdata::Rrsig {
                type_covered,
                expiration,
                ..
            }) = record.data()
            {
                covered_type = Some(type_covered);
                rrsig_expiration = Some(expiration);
            }
        } else if record.rtype == Type::SOA
            && let Ok(Rdata::Soa { minimum, .. }) = record.data()
        {
            soa_minimum = Some(minimum);
        }
        Self {
            key: RrsetKey {
                name: record.name,
                rtype: record.rtype,
                class: record.class,
                // RFC 4034 §3.1.1: RRSIG TTL groups are keyed by Type Covered.
                covered_type,
            },
            section,
            // RFC 1035 §4.2.2: DNS Message lengths fit in the 16-bit offset space.
            ttl_offset: record.ttl_offset as u32,
            ttl: record.ttl,
            soa_minimum,
            rrsig_expiration,
            minimum_ttl: record.ttl,
            mixed_ttl: false,
        }
    }
}

fn compare_name_refs(left: NameRef<'_>, right: NameRef<'_>) -> Ordering {
    let mut left_labels = left.labels();
    let mut right_labels = right.labels();
    loop {
        match (left_labels.next(), right_labels.next()) {
            (Some(left), Some(right)) => {
                let order = left
                    .iter()
                    .map(|byte| byte.to_ascii_lowercase())
                    .cmp(right.iter().map(|byte| byte.to_ascii_lowercase()));
                if order != Ordering::Equal {
                    return order;
                }
            }
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

fn compare_rrset_keys(left: &RrsetKey<'_>, right: &RrsetKey<'_>) -> Ordering {
    compare_name_refs(left.name, right.name)
        .then_with(|| left.class.0.cmp(&right.class.0))
        .then_with(|| left.rtype.0.cmp(&right.rtype.0))
        .then_with(|| {
            left.covered_type
                .map(|rtype| rtype.0)
                .cmp(&right.covered_type.map(|rtype| rtype.0))
        })
}

// RFC 2181 §5.2: Sort RRset keys once, then reuse per-record TTL metadata.
fn index_response_rrsets<'a>(message: &Message<'a>) -> Vec<IndexedRecord<'a>> {
    let capacity = usize::from(message.answer_count())
        + usize::from(message.authority_count())
        + usize::from(message.additional_count());
    let mut records = Vec::with_capacity(capacity);
    records.extend(
        message
            .answers()
            .map(|record| IndexedRecord::new(record, RecordSection::Answer)),
    );
    records.extend(
        message
            .authorities()
            .map(|record| IndexedRecord::new(record, RecordSection::Authority)),
    );
    records.extend(
        message
            .additionals()
            .filter(|record| record.rtype != Type::OPT)
            .map(|record| IndexedRecord::new(record, RecordSection::Additional)),
    );
    records.sort_unstable_by(|left, right| compare_rrset_keys(&left.key, &right.key));

    let mut start = 0;
    while start < records.len() {
        let mut end = start + 1;
        while end < records.len() && records[end].key == records[start].key {
            end += 1;
        }
        let rrset = &records[start..end];
        let minimum_ttl = rrset
            .iter()
            .map(|record| record.ttl)
            .min()
            .unwrap_or_default();
        let mixed_ttl = rrset.iter().any(|record| record.ttl != rrset[0].ttl);
        for record in &mut records[start..end] {
            record.minimum_ttl = minimum_ttl;
            record.mixed_ttl = mixed_ttl;
        }
        start = end;
    }
    records
}

fn normalized_rrset_ttl(
    rtype: Type,
    rrset_minimum: u32,
    soa_minimum: Option<u32>,
    denial: bool,
    minimum: u32,
    maximum: u32,
) -> u32 {
    let ttl = if denial && rtype == Type::SOA {
        soa_minimum.map_or(rrset_minimum, |minimum| rrset_minimum.min(minimum))
    } else {
        rrset_minimum
    };
    bound_ttl(ttl, denial, minimum, maximum)
}

// RFC 5452 §6: Reject response data outside the queried name's bailiwick.
fn response_records_relevant(
    qname: NameRef<'_>,
    qtype: Type,
    qclass: Class,
    response: &Message<'_>,
) -> bool {
    let mut chain = Vec::with_capacity(8);
    chain.push(qname);
    if qtype != Type::CNAME {
        loop {
            let Some(&current) = chain.last() else {
                return false;
            };
            let mut target: Option<NameRef<'_>> = None;
            for record in response
                .answers()
                .filter(|record| record.rtype == Type::CNAME && record.name == current)
            {
                if qclass != Class::ANY && record.class != qclass {
                    continue;
                }
                let Ok(Rdata::Cname(alias)) = record.data() else {
                    return false;
                };
                if target.as_ref().is_some_and(|existing| existing != &alias) {
                    return false;
                }
                target = Some(alias);
            }
            let Some(target) = target else {
                break;
            };
            if chain.contains(&target) {
                return false;
            }
            chain.push(target);
        }
    }
    let mut denial_zones = Vec::with_capacity(4);
    for record in response.authorities() {
        if matches!(record.rtype, Type::SOA | Type::NS)
            && chain.iter().any(|name| contains_ref(*name, record.name))
        {
            denial_zones.push(record.name);
        }
    }
    for record in response.answers() {
        if qclass != Class::ANY && record.class != qclass {
            return false;
        }
        // RFC 6672 §2: A DNAME owner may be an ancestor of the original QNAME.
        let index = chain.iter().position(|name| *name == record.name);
        let dname_ancestor = chain.iter().any(|name| contains_ref(*name, record.name));
        let relevant = match record.rtype {
            Type::DNAME => {
                if qtype == Type::DNAME {
                    record.name == qname
                } else {
                    dname_ancestor
                }
            }
            Type::CNAME => index.is_some_and(|index| {
                index + 1 < chain.len() || (qtype == Type::CNAME && index == 0)
            }),
            Type::RRSIG => match record.data() {
                Ok(Rdata::Rrsig { type_covered, .. }) => {
                    if type_covered == Type::DNAME {
                        dname_ancestor || (qtype == Type::DNAME && record.name == qname)
                    } else {
                        index.is_some_and(|index| {
                            let has_target = index + 1 < chain.len();
                            (type_covered == Type::CNAME
                                && (has_target || (qtype == Type::CNAME && index == 0)))
                                || (qtype == Type::ANY
                                    || (type_covered == qtype
                                        && !has_target
                                        && response.rcode() != Rcode::NXDOMAIN))
                        })
                    }
                }
                _ => false,
            },
            rtype => index.is_some_and(|index| {
                let has_target = index + 1 < chain.len();
                qtype == Type::ANY
                    || (rtype == qtype && !has_target && response.rcode() != Rcode::NXDOMAIN)
            }),
        };
        if !relevant {
            return false;
        }
    }
    for record in response.authorities() {
        if qclass != Class::ANY && record.class != qclass {
            return false;
        }
        let denial_proof = matches!(record.rtype, Type::NSEC | Type::NSEC3)
            || (record.rtype == Type::RRSIG
                && matches!(
                    record.data(),
                    Ok(Rdata::Rrsig {
                        type_covered: Type::NSEC | Type::NSEC3,
                        ..
                    })
                ));
        // RFC 2308 §5: Denial proof owners need only belong to the question's authority zone.
        let in_zone = denial_proof
            && denial_zones
                .iter()
                .any(|zone| contains_ref(record.name, *zone));
        let in_domain = chain.iter().any(|name| contains_ref(*name, record.name)) || in_zone;
        if !in_domain {
            return false;
        }
        let relevant_type = match record.rtype {
            Type::NS | Type::SOA | Type::DS | Type::NSEC | Type::NSEC3 => true,
            Type::RRSIG => matches!(
                record.data(),
                Ok(Rdata::Rrsig {
                    type_covered: Type::NS | Type::SOA | Type::DS | Type::NSEC | Type::NSEC3,
                    ..
                })
            ),
            _ => false,
        };
        if !relevant_type {
            return false;
        }
    }
    true
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
    let mut name = question.name;
    let mut visited = Vec::with_capacity(8);
    loop {
        if visited.contains(&name) {
            return false;
        }
        visited.push(name);
        let mut target: Option<NameRef<'_>> = None;
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
            target = Some(alias);
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

fn contains_ref(name: NameRef<'_>, domain: NameRef<'_>) -> bool {
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
mod tests;
