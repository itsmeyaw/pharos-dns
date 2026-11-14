use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use pharos_dnssec::{
    canonical::{CanonicalRecord, signed_data},
    denial::{BlackLieKind, black_lie},
    digest::key_tag,
    sign::SigningKey,
};
use pharos_proto::{
    Class, Message, MessageBuilder, NameRef, Rdata, Record, ResponseType, Section, Type,
    typify_response,
};
use pharos_server::{Context, Error};

use super::Dnssec;

enum SignMode {
    All(u32),
    Last,
}

#[derive(Debug)]
pub(super) struct CacheEntry {
    wire: Vec<u8>,
    max_size: usize,
    expires: u64,
    inception: u32,
    sets: usize,
}

impl CacheEntry {
    fn valid(&self, now: u64, max_size: usize) -> bool {
        // RFC 4034 §3.1.5: compare signature times using 32-bit serial arithmetic.
        let horizon = (now as u32).wrapping_add(2 * 86400);
        self.max_size == max_size
            && self.expires >= now
            && horizon.wrapping_sub(self.inception) <= i32::MAX as u32
    }
}

// Budget for retained Responses; 65,535-octet Responses fit, larger entries are never cached.
const CACHE_BYTES: usize = 32 << 20;
// Approximate per-entry cost of the key allocation, map slot and `CacheEntry` fields.
const ENTRY_OVERHEAD: usize = 128;

/// Whole-Response signature cache bounded by entry count and bytes; totals are kept
/// incrementally so metric updates never scan the map.
#[derive(Debug, Default)]
pub(super) struct SigCache {
    map: HashMap<Vec<u8>, CacheEntry>,
    sets: usize,
    bytes: usize,
}

impl SigCache {
    fn cost(key: &[u8], entry: &CacheEntry) -> usize {
        key.len() + entry.wire.len() + ENTRY_OVERHEAD
    }

    fn remove(&mut self, key: &[u8]) {
        if let Some(old) = self.map.remove(key) {
            self.sets -= old.sets;
            self.bytes -= Self::cost(key, &old);
        }
    }

    /// Insert `entry`, evicting arbitrary entries until count and bytes fit; returns false if it can never fit.
    fn insert(&mut self, key: &[u8], entry: CacheEntry, capacity: usize) -> bool {
        let cost = Self::cost(key, &entry);
        if cost > CACHE_BYTES || capacity == 0 {
            return false;
        }
        self.remove(key);
        while self.map.len() >= capacity || self.bytes + cost > CACHE_BYTES {
            let Some(victim) = self.map.keys().next().cloned() else {
                break;
            };
            self.remove(&victim);
        }
        self.sets += entry.sets;
        self.bytes += cost;
        self.map.insert(key.to_vec(), entry);
        true
    }
}

/// One RRset of a Response: its lowest TTL and the Sections holding its records.
struct RrSet<'a> {
    name: NameRef<'a>,
    class: Class,
    rtype: Type,
    ttl: u32,
    sections: u8,
}

const SECTIONS: [(u8, Section); 3] = [
    (1, Section::Answer),
    (2, Section::Authority),
    (4, Section::Additional),
];

// One pass over the Message replaces a full rescan per record.
// RFC 2181 §5.2: records in one RRset use the lowest received TTL.
// RFC 4034 §3: a covering RRSIG joins the RRset it covers, sharing its TTL without extending its lifetime.
// shortcut: lookup is linear in the RRset count; hash by owner if Responses carry many RRsets.
fn rrsets<'a>(message: &Message<'a>) -> Result<Vec<RrSet<'a>>, Error> {
    let mut sets: Vec<RrSet<'a>> = Vec::new();
    for (bit, records) in [
        (SECTIONS[0].0, message.answers()),
        (SECTIONS[1].0, message.authorities()),
        (SECTIONS[2].0, message.additionals()),
    ] {
        for rr in records {
            let (rtype, sections) = match rr.data().map_err(|_| Error::InvalidQuery)? {
                Rdata::Rrsig { type_covered, .. } => (type_covered, 0),
                _ => (rr.rtype, bit),
            };
            match find_set(&sets, rr.name, rr.class, rtype) {
                Some(index) => {
                    sets[index].ttl = sets[index].ttl.min(rr.ttl);
                    sets[index].sections |= sections;
                }
                None => sets.push(RrSet {
                    name: rr.name,
                    class: rr.class,
                    rtype,
                    ttl: rr.ttl,
                    sections,
                }),
            }
        }
    }
    Ok(sets)
}

fn find_set(sets: &[RrSet<'_>], name: NameRef<'_>, class: Class, rtype: Type) -> Option<usize> {
    sets.iter()
        .position(|set| set.name == name && set.class == class && set.rtype == rtype)
}

fn same_rrset(left: &Record<'_>, right: &Record<'_>) -> bool {
    // RFC 2181 §5: an RRset shares its owner, class and type.
    left.name == right.name && left.rtype == right.rtype && left.class == right.class
}

impl Dnssec {
    pub(super) fn sign_response(&self, cx: &mut Context<'_, '_>) -> Result<(), Error> {
        let max_size =
            Self::ensure_response_capacity(cx.response, cx.protocol, cx.max_response_size)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let metrics = self
            .metrics
            .iter()
            .find(|(address, _)| *address == cx.local)
            .map(|(_, metrics)| metrics);
        {
            let cache = self.cache.lock().map_err(|_| Error::PluginPanic)?;
            // RFC 4034 §3.1.4: a signature's Original TTL belongs to its covered RRset.
            if let Some(entry) = cache.map.get(cx.response.get(2..).ok_or(Error::InvalidQuery)?)
                && entry.valid(now, cx.max_response_size)
            {
                if let Some(metrics) = metrics {
                    metrics.hit(entry.sets);
                }
                let id = [cx.response[0], cx.response[1]];
                cx.response.clear();
                cx.response.extend_from_slice(&entry.wire);
                cx.response[..2].copy_from_slice(&id);
                return Ok(());
            }
        }
        // shortcut: concurrent misses can sign twice; add bounded single-flight when RRset caching is implemented.
        // shortcut: cache misses allocate for canonical RRsets and signing; remove when signing accepts caller buffers.
        let original = cx.response.clone();
        let message = Message::parse(&original).map_err(|_| Error::InvalidQuery)?;
        let kind = typify_response(Some(&message), now as i64);
        let denial = matches!(kind, ResponseType::NxDomain | ResponseType::NoData);
        if denial
            && (message.authority_count() != 1
                || !message
                    .authorities()
                    .next()
                    .is_some_and(|rr| rr.rtype == Type::SOA))
        {
            return Ok(());
        }
        let referral = kind == ResponseType::Referral && message.authority_count() > 0;
        let make_lie =
            denial || (referral && !message.authorities().any(|rr| rr.rtype == Type::DS));
        let question = message.questions().next().ok_or(Error::InvalidQuery)?;
        let zone = self.zone_for(question.name).ok_or(Error::InvalidQuery)?;
        let special_nsec = denial && question.qtype == Type::NSEC;
        let mut lie_wire = Vec::new();
        if make_lie {
            // shortcut: CoreDNS-style spans are not checked against zone inventory; validate when authoritative names are available.
            let lie = black_lie(
                &question.name.to_name(),
                zone,
                question.qtype,
                if referral {
                    BlackLieKind::Referral
                } else {
                    BlackLieKind::Negative
                },
            )
            .map_err(|_| Error::InvalidQuery)?;
            let ttl = message.authorities().next().ok_or(Error::InvalidQuery)?.ttl;
            let mut lie_builder =
                MessageBuilder::new(&mut lie_wire, 65535, 0, 0).map_err(Error::Build)?;
            let owner = NameRef::parse(lie.owner.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
            lie_builder
                .record_with(
                    Section::Answer,
                    owner,
                    Type::NSEC,
                    Class::IN,
                    ttl,
                    |writer| lie.rdata().write(writer),
                )
                .map_err(Error::Build)?;
            let _ = lie_builder.finish();
        }
        let lie = if make_lie {
            Some(Message::parse(&lie_wire).map_err(|_| Error::InvalidQuery)?)
        } else {
            None
        };
        // RFC 4470 §3: synthetic NSEC proves nonexistence without disclosing Zone contents.
        // RFC 6604 §2.2: Preserve AD from the response without asserting authenticity.
        let flags = if denial {
            message.flags() & !0xf
        } else {
            message.flags()
        };
        let mut builder = MessageBuilder::new(cx.response, max_size, message.id(), flags)
            .map_err(Error::Build)?;
        for question in message.questions() {
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
        }
        // CoreDNS plugin/dnssec: without keys, the final pair is SOA and NSEC.
        if special_nsec && self.keys.is_empty() {
            let rr = message.authorities().next().ok_or(Error::InvalidQuery)?;
            let data = rr.data().map_err(|_| Error::InvalidQuery)?;
            builder
                .record_with(
                    Section::Answer,
                    rr.name,
                    rr.rtype,
                    rr.class,
                    rr.ttl,
                    |writer| data.write(writer),
                )
                .map_err(Error::Build)?;
        }
        let sets = rrsets(&message)?;
        let set_of = |name, class, rtype| find_set(&sets, name, class, rtype).map(|index| &sets[index]);
        let mut signed_sets = 0;
        let mut attempted_sets = 0;
        // RFC 4035 §3.1.4: Referral signatures cover DS, not delegation NS or glue.
        let signs_section = |section, rtype| {
            !special_nsec
                && (!referral || (section == Section::Authority && rtype == Type::DS))
                && (!denial || section == Section::Authority)
        };
        // RFC 4035 §3.1.1: Place each RRSIG in the same section as its covered RRset.
        for (section, records) in [
            (Section::Answer, message.answers()),
            (Section::Authority, message.authorities()),
            (Section::Additional, message.additionals()),
        ] {
            let records: Vec<_> = records.collect();
            for rr in &records {
                if special_nsec && section == Section::Authority {
                    continue;
                }
                let data = rr.data().map_err(|_| Error::InvalidQuery)?;
                let covered = match data {
                    Rdata::Rrsig { type_covered, .. } => type_covered,
                    _ => rr.rtype,
                };
                // RFC 2181 §5.2: use one TTL for each RRset selected for signing.
                let set = set_of(rr.name, rr.class, covered);
                let signed = !self.keys.is_empty()
                    && !matches!(covered, Type::RRSIG | Type::OPT | Type::TSIG)
                    && self.zone_for(rr.name).is_some()
                    && set.is_some_and(|set| {
                        SECTIONS
                            .iter()
                            .any(|&(bit, section)| set.sections & bit != 0 && signs_section(section, covered))
                    });
                // RFC 4035 §2.2: RRSIG TTLs with a common owner may differ across RRsets.
                // RFC 4034 §3: RRSIG TTLs may differ when they cover different RRsets.
                let ttl = match set {
                    Some(set) if signed => set.ttl,
                    _ => rr.ttl,
                };
                builder
                    .record_with(section, rr.name, rr.rtype, rr.class, ttl, |writer| {
                        data.write(writer)
                    })
                    .map_err(Error::Build)?;
            }
            // RFC 4033 §3.1: Sign RRsets to verify DNS data origin and integrity.
            let mut groups: Vec<Vec<Record<'_>>> = Vec::new();
            for rr in &records {
                match groups.iter_mut().find(|group| same_rrset(&group[0], rr)) {
                    Some(group) => group.push(*rr),
                    None => groups.push(vec![*rr]),
                }
            }
            for group in &groups {
                let rr = group[0];
                // RFC 4035 §2.2: an RRSIG RR is never signed; OPT and TSIG are not zone data.
                if !signs_section(section, rr.rtype)
                    || matches!(rr.rtype, Type::RRSIG | Type::OPT | Type::TSIG)
                {
                    continue;
                }
                let Some(zone) = self.zone_for(rr.name) else {
                    continue;
                };
                let ttl = set_of(rr.name, rr.class, rr.rtype).map_or(rr.ttl, |set| set.ttl);
                // RFC 4035 §3.1.1: Include each RRSIG in its covered RRset's section.
                signed_sets += usize::from(self.sign_set(
                    &mut builder,
                    section,
                    group,
                    zone,
                    now,
                    SignMode::All(ttl),
                )?);
                attempted_sets += 1;
            }
            // RFC 9824 §3.1: A QNAME-matching denial NSEC can appear in Authority.
            if let Some(lie) = &lie
                && section
                    == if special_nsec {
                        Section::Answer
                    } else {
                        Section::Authority
                    }
            {
                let rr = lie.answers().next().ok_or(Error::InvalidQuery)?;
                signed_sets += usize::from(self.sign_set(
                    &mut builder,
                    section,
                    &[rr],
                    zone,
                    now,
                    if special_nsec {
                        SignMode::Last
                    } else {
                        SignMode::All(rr.ttl)
                    },
                )?);
                attempted_sets += 1;
                let data = rr.data().map_err(|_| Error::InvalidQuery)?;
                builder
                    .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                        data.write(writer)
                    })
                    .map_err(Error::Build)?;
            }
        }
        let _ = builder.finish();
        if let Some(metrics) = metrics {
            metrics.miss(attempted_sets);
        }
        // CoreDNS plugin/dnssec: cache only RRsets that produced signatures.
        if signed_sets > 0 {
            let mut cache = self.cache.lock().map_err(|_| Error::PluginPanic)?;
            cache.insert(
                &original[2..],
                CacheEntry {
                    wire: cx.response.clone(),
                    max_size: cx.max_response_size,
                    expires: now.saturating_add(6 * 86400),
                    inception: now.saturating_sub(3 * 3600) as u32,
                    sets: signed_sets,
                },
                self.capacity,
            );
            if let Some(metrics) = metrics {
                metrics.entries(cache.sets);
            }
        }
        Ok(())
    }

    fn sign_set(
        &self,
        builder: &mut MessageBuilder<'_>,
        section: Section,
        records: &[Record<'_>],
        zone: &pharos_proto::Name,
        now: u64,
        mode: SignMode,
    ) -> Result<bool, Error> {
        let first = records.first().ok_or(Error::InvalidQuery)?;
        let (ttl, last_only) = match mode {
            SignMode::All(ttl) => (ttl, false),
            SignMode::Last => (first.ttl, true),
        };
        // RFC 4034 §3.1.7: The Signer's Name identifies the zone of the covered RRset.
        let signer = NameRef::parse(zone.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
        // RFC 6781 §3.2.3: SEP flags distinguish KSKs from ZSKs for signing operations.
        // RFC 4034 §2.1.1: the SEP bit (257) marks a KSK; the Zone Key bit alone (256) marks a ZSK.
        let has_ksk = self.keys.iter().any(|k| k.public.flags & 257 == 257);
        let has_zsk = self.keys.iter().any(|k| k.public.flags & 257 == 256);
        let canonical: Vec<_> = records
            .iter()
            .map(|rr| {
                Ok(CanonicalRecord {
                    owner: rr.name,
                    class: rr.class,
                    data: rr.data().map_err(|_| Error::InvalidQuery)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        let keys = self.keys.iter().zip(&self.public).filter(|(key, _)| {
            !(has_ksk
                && has_zsk
                && (key.public.flags & 257
                    != if first.rtype == Type::DNSKEY {
                        257
                    } else {
                        256
                    }))
        });
        // CoreDNS plugin/dnssec: special NSEC replies retain only the last signature.
        let last_key = last_only
            .then(|| keys.clone().next_back().map(|(key, _)| key))
            .flatten();
        let mut signed = false;
        for (key, public) in keys {
            if last_only && !last_key.is_some_and(|last| std::ptr::eq(last, key)) {
                continue;
            }
            // RFC 4034 §3.1.3: a leading wildcard label is not counted in Labels.
            let labels = first.name.labels().count()
                - usize::from(first.name.labels().next() == Some(b"*".as_slice()));
            // RFC 4034 §3.1.8.1: The signature covers the RRSIG prefix and canonical RRset.
            let mut sig = Rdata::Rrsig {
                type_covered: first.rtype,
                algorithm: key.public.algorithm,
                labels: labels as u8,
                // RFC 4034 §3.1.4: Original TTL is the covered RRset's TTL.
                original_ttl: ttl,
                expiration: now.wrapping_add(8 * 86400) as u32,
                inception: now.saturating_sub(3 * 3600) as u32,
                // RFC 4034 §3.1.6: The Key Tag identifies the validating DNSKEY.
                key_tag: key_tag(public).ok_or(Error::InvalidQuery)?,
                signer,
                signature: &[],
            };
            let data = signed_data(&sig, &canonical).map_err(|_| Error::InvalidQuery)?;
            // RFC 3007 §4.3: Sign RRSIGs using online zone private keys.
            let der = key
                .private
                .to_pkcs8_der()
                .map_err(|_| Error::InvalidQuery)?;
            let key = SigningKey::from_pkcs8(key.public.algorithm, &der)
                .map_err(|_| Error::InvalidQuery)?;
            let bytes = key.sign(&data).map_err(|_| Error::InvalidQuery)?;
            if let Rdata::Rrsig {
                ref mut signature, ..
            } = sig
            {
                *signature = &bytes;
            }
            // RFC 4034 §3: the RRSIG RR's TTL matches the covered RRset's TTL.
            builder
                .record_with(
                    section,
                    first.name,
                    Type::RRSIG,
                    first.class,
                    ttl,
                    |writer| sig.write(writer),
                )
                .map_err(Error::Build)?;
            signed = true;
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::CacheEntry;

    #[test]
    fn poisoned_signature_cache_reports_plugin_panic() {
        use pharos_corefile::{configure, parse};
        use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
        use pharos_server::{Context, Error, Metadata, Protocol, Transport};

        let mut chain = configure::<crate::Chain>(
            &parse("Corefile", "miek.nl {\n dnssec\n}").unwrap(),
            crate::directives(),
        )
        .unwrap();
        let dnssec = chain[0].config.dnssec.as_mut().unwrap();
        let _ = std::panic::catch_unwind(|| {
            let _guard = dnssec.cache.lock().unwrap();
            panic!("poison cache");
        });
        let domain: Name = "miek.nl.".parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(dnssec.sign_response(&mut cx), Err(Error::PluginPanic));
    }

    #[test]
    fn signature_cache_separates_original_ttls() {
        use pharos_corefile::{configure, parse};
        use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};
        use pharos_server::{Context, Metadata, Protocol, Transport};

        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
        );
        let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
        let mut chain =
            configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
                .unwrap();
        let dnssec = chain[0].config.dnssec.as_mut().unwrap();
        let domain: Name = "miek.nl.".parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut query = Vec::new();
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let mut first = Vec::new();
        for (ttl, expected_entries) in [(120, 1), (60, 2), (120, 2)] {
            let mut builder = MessageBuilder::new(cx.response, 512, 1, 0x8400).unwrap();
            builder.question(name, Type::A, Class::IN).unwrap();
            builder
                .record(
                    Section::Answer,
                    name,
                    Type::A,
                    Class::IN,
                    ttl,
                    &[127, 0, 0, 1],
                )
                .unwrap();
            let _ = builder.finish();
            dnssec.sign_response(&mut cx).unwrap();
            let message = Message::parse(cx.response).unwrap();
            let sig = message
                .answers()
                .find(|rr| rr.rtype == Type::RRSIG)
                .unwrap();
            assert_eq!(sig.ttl, ttl);
            assert!(
                matches!(sig.data().unwrap(), Rdata::Rrsig { original_ttl, .. } if original_ttl == ttl)
            );
            assert_eq!(dnssec.cache.lock().unwrap().map.len(), expected_entries);
            if first.is_empty() {
                first = cx.response.clone();
            } else if ttl == 120 {
                assert_eq!(*cx.response, first);
            }
        }
    }

    #[test]
    fn empty_response_does_not_evict_a_signed_response() {
        use pharos_corefile::{configure, parse};
        use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
        use pharos_server::{Context, Metadata, Protocol, Transport};

        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
        );
        let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
        let mut chain =
            configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
                .unwrap();
        let dnssec = chain[0].config.dnssec.as_mut().unwrap();
        dnssec.capacity = 1;
        let domain: Name = "miek.nl.".parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut query = Vec::new();
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        for answer in [true, false] {
            let mut builder = MessageBuilder::new(cx.response, 512, 1, 0x8400).unwrap();
            builder.question(name, Type::A, Class::IN).unwrap();
            if answer {
                builder
                    .record(
                        Section::Answer,
                        name,
                        Type::A,
                        Class::IN,
                        60,
                        &[127, 0, 0, 1],
                    )
                    .unwrap();
            }
            let _ = builder.finish();
            dnssec.sign_response(&mut cx).unwrap();
        }
        let cache = dnssec.cache.lock().unwrap();
        assert_eq!(cache.map.len(), 1);
        let cached = Message::parse(&cache.map.values().next().unwrap().wire).unwrap();
        assert!(cached.answers().any(|rr| rr.rtype == Type::RRSIG));
    }

    fn entry(len: usize, sets: usize) -> CacheEntry {
        CacheEntry {
            wire: vec![0; len],
            max_size: 512,
            expires: 0,
            inception: 0,
            sets,
        }
    }

    #[test]
    fn cache_evicts_to_stay_within_byte_budget_for_max_size_responses() {
        use super::{CACHE_BYTES, SigCache};
        let mut cache = SigCache::default();
        for i in 0..(2 * CACHE_BYTES / 65_535) as u32 {
            assert!(cache.insert(&i.to_be_bytes(), entry(65_535, 2), usize::MAX));
            assert!(cache.bytes <= CACHE_BYTES);
        }
        assert_eq!(cache.sets, 2 * cache.map.len());
        assert!(cache.map.len() >= CACHE_BYTES / (65_535 + 256) - 1);
    }

    #[test]
    fn cache_tracks_sets_on_replace_and_rejects_entries_over_budget() {
        use super::{CACHE_BYTES, SigCache};
        let mut cache = SigCache::default();
        assert!(cache.insert(b"a", entry(10, 3), 4));
        assert!(cache.insert(b"a", entry(20, 1), 4));
        assert_eq!((cache.map.len(), cache.sets), (1, 1));
        assert!(!cache.insert(b"b", entry(CACHE_BYTES, 1), 4));
        assert_eq!((cache.map.len(), cache.sets), (1, 1));
        for key in [b"c", b"d", b"e", b"f"] {
            cache.insert(key, entry(1, 1), 4);
        }
        assert_eq!((cache.map.len(), cache.sets), (4, 4));
    }

    #[test]
    fn cache_expires_after_six_days_and_checks_buffer_limit() {
        let entry = CacheEntry {
            wire: Vec::new(),
            max_size: 512,
            expires: 6 * 86400,
            inception: 0,
            sets: 1,
        };
        assert!(entry.valid(6 * 86400 - 1, 512));
        assert!(entry.valid(6 * 86400, 512));
        assert!(!entry.valid(6 * 86400 + 1, 512));
        assert!(!entry.valid(1, 1232));
    }

    // CoreDNS plugin/dnssec/cache_test.go TestCacheNotValidYet: validate at now plus two days.
    #[test]
    fn cache_rejects_signatures_not_valid_at_refresh_horizon() {
        let entry = CacheEntry {
            wire: Vec::new(),
            max_size: 512,
            expires: 15 * 86400,
            inception: 9 * 86400 - 3 * 3600,
            sets: 1,
        };
        assert!(!entry.valid(0, 512));
        assert!(entry.valid(7 * 86400, 512));
    }

    #[test]
    fn cache_inception_comparison_wraps_at_u32_boundary() {
        let signed = u32::MAX as u64 - 86400;
        let entry = CacheEntry {
            wire: Vec::new(),
            max_size: 512,
            expires: signed + 6 * 86400,
            inception: (signed - 3 * 3600) as u32,
            sets: 1,
        };
        assert!(!entry.valid(signed - 9 * 86400, 512));
        assert!(entry.valid(signed, 512));
        assert!(entry.valid(signed + 2 * 86400, 512));
    }
}
