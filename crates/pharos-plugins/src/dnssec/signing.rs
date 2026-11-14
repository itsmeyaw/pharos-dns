use std::time::{SystemTime, UNIX_EPOCH};

use pharos_dnssec::{
    canonical::{CanonicalRecord, signed_data},
    denial::{BlackLieKind, black_lie},
    digest::key_tag,
    sign::SigningKey,
};
use pharos_proto::{
    Message, MessageBuilder, NameRef, Rdata, Record, ResponseType, Section, Type, typify_response,
};
use pharos_server::{Context, Error};

use super::Dnssec;

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

fn same_rrset(left: &Record<'_>, right: &Record<'_>) -> bool {
    // RFC 2181 §5: an RRset shares its owner, class and type.
    left.name == right.name && left.rtype == right.rtype && left.class == right.class
}

fn strict_subdomain(name: NameRef<'_>, parent: NameRef<'_>) -> bool {
    // RFC 6672 §3: A synthesized CNAME owner is below its DNAME owner; compare labels without allocation.
    let name_labels = name.labels().count();
    let parent_labels = parent.labels().count();
    name_labels > parent_labels
        && name
            .labels()
            .skip(name_labels - parent_labels)
            .zip(parent.labels())
            .all(|(name, parent)| name.eq_ignore_ascii_case(parent))
}

fn rrset_ttl(message: &Message<'_>, rr: &Record<'_>, covered: Option<Type>) -> u32 {
    // RFC 2181 §5.2: records in one RRset use the lowest received TTL.
    // RFC 4034 §3: a covering RRSIG shares that TTL without extending its lifetime.
    // shortcut: scans the Message for each RR on a cache miss; index RRsets if miss cost becomes significant.
    let target = covered.unwrap_or(rr.rtype);
    message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .filter(|other| {
            other.name == rr.name
                && other.class == rr.class
                && ((other.rtype == target && target != Type::RRSIG)
                    || (other.rtype == Type::RRSIG
                        && matches!(other.data(), Ok(Rdata::Rrsig { type_covered, .. }) if type_covered == target)))
        })
        .map(|other| other.ttl)
        .min()
        .unwrap_or(rr.ttl)
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
            if let Some(entry) = cache.get(cx.response.get(2..).ok_or(Error::InvalidQuery)?)
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
        let soa = message.authorities().find(|rr| rr.rtype == Type::SOA);
        if denial && soa.is_none() {
            return Ok(());
        }
        let referral = kind == ResponseType::Referral && message.authority_count() > 0;
        let make_lie =
            denial || (referral && !message.authorities().any(|rr| rr.rtype == Type::DS));
        let question = message.questions().next().ok_or(Error::InvalidQuery)?;
        let zone = self.zone_for(question.name).ok_or(Error::InvalidQuery)?;
        let mut lie_wire = Vec::new();
        if make_lie {
            // shortcut: CoreDNS-style spans are not checked against zone inventory; validate when authoritative names are available.
            let lie = black_lie(
                &question.name.to_name(),
                zone,
                question.qtype,
                if referral {
                    BlackLieKind::Referral
                } else if kind == ResponseType::NxDomain {
                    BlackLieKind::NameError
                } else {
                    BlackLieKind::Negative
                },
            )
            .map_err(|_| Error::InvalidQuery)?;
            // RFC 9077 §3.2: Synthetic NSEC TTL is min(SOA TTL, SOA.MINIMUM).
            let ttl = if let Some(soa) = soa {
                match soa.data().map_err(|_| Error::InvalidQuery)? {
                    Rdata::Soa { minimum, .. } => soa.ttl.min(minimum),
                    _ => return Err(Error::InvalidQuery),
                }
            } else {
                message.authorities().next().ok_or(Error::InvalidQuery)?.ttl
            };
            let mut lie_builder =
                MessageBuilder::new(&mut lie_wire, 65535, 0, 0).map_err(Error::Build)?;
            let owner = NameRef::parse(lie.owner.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
            lie_builder
                .record_with(
                    Section::Answer,
                    owner,
                    Type::NSEC,
                    question.qclass,
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
        // RFC 4035 §3.1.3: Keep denial proofs in Authority; preserve the documented RCODE change.
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
        let mut signed_sets = 0;
        let mut attempted_sets = 0;
        let mut required_tc = message.flags() & 0x0200 != 0;
        let mut tc_before_additional = false;
        let mut additional_data_omitted = false;
        let mut additional_signature_omitted = false;
        // RFC 4035 §3.1.4: Referral signatures cover DS, not delegation NS or glue.
        let dname_owner = message
            .answers()
            .find(|rr| rr.rtype == Type::DNAME)
            .map(|rr| rr.name);
        // RFC 6672 §5.3.1: A DNAME-synthesized CNAME is never signed.
        let signs_section = |section, rtype, owner| {
            (!referral || (section == Section::Authority && rtype == Type::DS))
                && (!denial || section == Section::Authority)
                && !(section == Section::Answer
                    && rtype == Type::CNAME
                    && owner == question.name
                    && dname_owner.is_some_and(|dname| strict_subdomain(owner, dname)))
        };
        // RFC 4035 §3.1.1: Keep each Answer/Authority signature beside its covered RRset.
        for (section, records) in [
            (Section::Answer, message.answers()),
            (Section::Authority, message.authorities()),
            (Section::Additional, message.additionals()),
        ] {
            if section == Section::Additional {
                tc_before_additional = required_tc;
            }
            let records: Vec<_> = records.collect();
            // RFC 4035 §3.1.1: Put denial proofs and their signatures in Authority, not Answer.
            if section == Section::Authority
                && let Some(lie) = &lie
            {
                let rr = lie.answers().next().ok_or(Error::InvalidQuery)?;
                let data = rr.data().map_err(|_| Error::InvalidQuery)?;
                let added = builder
                    .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                        data.write(writer)
                    })
                    .map_err(Error::Build)?;
                required_tc |= !added;
                let (signed, omitted) =
                    self.sign_set(&mut builder, section, &[rr], zone, now, rr.ttl)?;
                required_tc |= omitted && section != Section::Additional;
                signed_sets += usize::from(signed);
                additional_signature_omitted |= section == Section::Additional && omitted;
                attempted_sets += 1;
            }
            if section == Section::Additional {
                // RFC 4035 §3.1.1: Write all Additional data before optional signatures.
                for (i, rr) in records.iter().enumerate() {
                    if rr.rtype == Type::RRSIG
                        || records[..i].iter().any(|previous| same_rrset(previous, rr))
                    {
                        continue;
                    }
                    let group: Vec<_> = records
                        .iter()
                        .copied()
                        .filter(|member| same_rrset(member, rr))
                        .collect();
                    let signed = !self.keys.is_empty()
                        && !matches!(rr.rtype, Type::OPT | Type::TSIG)
                        && self.zone_for(rr.name).is_some()
                        && signs_section(section, rr.rtype, rr.name);
                    // RFC 2181 §5.2: Normalize signed RRsets only; preserve TTLs on unsigned records.
                    let normalized_ttl = if signed {
                        Some(rrset_ttl(&message, rr, None))
                    } else {
                        None
                    };
                    for member in &group {
                        let data = member.data().map_err(|_| Error::InvalidQuery)?;
                        let added = builder
                            .record_with(
                                section,
                                member.name,
                                member.rtype,
                                member.class,
                                normalized_ttl.unwrap_or(member.ttl),
                                |writer| data.write(writer),
                            )
                            .map_err(Error::Build)?;
                        if !added {
                            additional_data_omitted = true;
                            break;
                        }
                    }
                    if additional_data_omitted {
                        break;
                    }
                }
                // RFC 4035 §3.1.1: Existing Additional RRSIGs are optional when space runs out.
                if !additional_data_omitted {
                    for rr in records.iter().filter(|rr| rr.rtype == Type::RRSIG) {
                        let data = rr.data().map_err(|_| Error::InvalidQuery)?;
                        let Rdata::Rrsig { type_covered, .. } = data else {
                            continue;
                        };
                        let signed = !self.keys.is_empty()
                            && self.zone_for(rr.name).is_some()
                            && signs_section(section, type_covered, rr.name)
                            && records.iter().any(|other| {
                                other.name == rr.name
                                    && other.class == rr.class
                                    && other.rtype == type_covered
                            });
                        let ttl = if signed {
                            rrset_ttl(&message, rr, Some(type_covered))
                        } else {
                            rr.ttl
                        };
                        let added = builder
                            .record_with(section, rr.name, rr.rtype, rr.class, ttl, |writer| {
                                data.write(writer)
                            })
                            .map_err(Error::Build)?;
                        if !added {
                            additional_signature_omitted = true;
                            break;
                        }
                    }
                }
                if !additional_data_omitted && !additional_signature_omitted {
                    for (i, rr) in records.iter().enumerate() {
                        if matches!(rr.rtype, Type::RRSIG | Type::OPT | Type::TSIG)
                            || records[..i].iter().any(|previous| same_rrset(previous, rr))
                            || !signs_section(section, rr.rtype, rr.name)
                        {
                            continue;
                        }
                        let Some(zone) = self.zone_for(rr.name) else {
                            continue;
                        };
                        let group: Vec<_> = records
                            .iter()
                            .copied()
                            .filter(|member| same_rrset(member, rr))
                            .collect();
                        let (signed, omitted) = self.sign_set(
                            &mut builder,
                            section,
                            &group,
                            zone,
                            now,
                            rrset_ttl(&message, rr, None),
                        )?;
                        signed_sets += usize::from(signed);
                        additional_signature_omitted |= omitted;
                        attempted_sets += 1;
                        if omitted {
                            break;
                        }
                    }
                }
                continue;
            }
            for (i, rr) in records.iter().enumerate() {
                if records[..i].iter().any(|previous| same_rrset(previous, rr)) {
                    continue;
                }
                let group: Vec<_> = records
                    .iter()
                    .copied()
                    .filter(|r| same_rrset(r, rr))
                    .collect();
                let mut rrset_complete = true;
                let normalized_ttl =
                    (rr.rtype != Type::RRSIG).then(|| rrset_ttl(&message, rr, None));
                for member in &group {
                    let data = member.data().map_err(|_| Error::InvalidQuery)?;
                    let covered = match data {
                        Rdata::Rrsig { type_covered, .. } => type_covered,
                        _ => member.rtype,
                    };
                    // RFC 2181 §5.2: use one TTL for each RRset selected for signing.
                    let signed = !self.keys.is_empty()
                        && !matches!(covered, Type::RRSIG | Type::OPT | Type::TSIG)
                        && self.zone_for(member.name).is_some()
                        && signs_section(section, covered, member.name)
                        && (member.rtype != Type::RRSIG
                            || message
                                .answers()
                                .chain(message.authorities())
                                .chain(message.additionals())
                                .any(|other| {
                                    other.name == member.name
                                        && other.class == member.class
                                        && other.rtype == covered
                                }));
                    // RFC 4035 §2.2: RRSIG TTLs with a common owner may differ across RRsets.
                    let ttl = match data {
                        _ if !signed => member.ttl,
                        Rdata::Rrsig { type_covered, .. } => {
                            rrset_ttl(&message, member, Some(type_covered))
                        }
                        _ => normalized_ttl.unwrap_or(member.ttl),
                    };
                    let added = builder
                        .record_with(
                            section,
                            member.name,
                            member.rtype,
                            member.class,
                            ttl,
                            |writer| data.write(writer),
                        )
                        .map_err(Error::Build)?;
                    if section == Section::Additional && !added {
                        if member.rtype == Type::RRSIG {
                            additional_signature_omitted = true;
                        } else {
                            additional_data_omitted = true;
                        }
                    }
                    if section != Section::Additional && !added {
                        required_tc = true;
                    }
                    rrset_complete &= added;
                }
                if section == Section::Additional
                    && (additional_data_omitted || additional_signature_omitted)
                {
                    break;
                }
                // RFC 4035 §2.2: RRSIG, OPT, and TSIG are not signed as zone data.
                if rrset_complete
                    && !matches!(rr.rtype, Type::RRSIG | Type::OPT | Type::TSIG)
                    && signs_section(section, rr.rtype, rr.name)
                    && let Some(zone) = self.zone_for(rr.name)
                {
                    let (signed, omitted) = self.sign_set(
                        &mut builder,
                        section,
                        &group,
                        zone,
                        now,
                        rrset_ttl(&message, rr, None),
                    )?;
                    signed_sets += usize::from(signed);
                    additional_signature_omitted |= section == Section::Additional && omitted;
                    required_tc |= omitted && section != Section::Additional;
                    attempted_sets += 1;
                }
                if section == Section::Additional && additional_signature_omitted {
                    break;
                }
            }
        }
        let clear_additional_tc =
            additional_signature_omitted && !tc_before_additional && !additional_data_omitted;
        let _ = builder.finish();
        if clear_additional_tc {
            // RFC 4035 §3.1.1: Additional RRSIG omission alone does not justify TC.
            cx.response[2] &= !0x02;
        }
        if let Some(metrics) = metrics {
            metrics.miss(attempted_sets);
        }
        // CoreDNS plugin/dnssec: cache only RRsets that produced signatures.
        if signed_sets > 0 {
            let mut cache = self.cache.lock().map_err(|_| Error::PluginPanic)?;
            if cache.len() >= self.capacity
                && !cache.contains_key(&original[2..])
                && let Some(key) = cache.keys().next().cloned()
            {
                cache.remove(&key);
            }
            cache.insert(
                original[2..].to_vec(),
                CacheEntry {
                    wire: cx.response.clone(),
                    max_size: cx.max_response_size,
                    expires: now.saturating_add(6 * 86400),
                    inception: now.saturating_sub(3 * 3600) as u32,
                    sets: signed_sets,
                },
            );
            if let Some(metrics) = metrics {
                metrics.entries(cache.values().map(|entry| entry.sets).sum());
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
        ttl: u32,
    ) -> Result<(bool, bool), Error> {
        let first = records.first().ok_or(Error::InvalidQuery)?;
        // RFC 4034 §3.1.7: The Signer's Name identifies the zone of the covered RRset.
        let signer = NameRef::parse(zone.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
        // RFC 6840 §5.11: each DNSKEY algorithm signs every required RRset.
        let apex = signer;
        let apex_dnskey = first.rtype == Type::DNSKEY && first.name == apex;
        // RFC 6840 §5.11: Track KSK/ZSK roles per algorithm without query-path allocation.
        let mut roles_by_algorithm = [0u8; 16];
        for key in self.keys.iter().filter(|key| key.public.owner == *zone) {
            if let Some(roles) = roles_by_algorithm.get_mut(usize::from(key.public.algorithm)) {
                *roles |= match key.public.flags & 257 {
                    257 => 1,
                    256 => 2,
                    _ => 0,
                };
            }
        }
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
            // RFC 8080 §8: A zone's private key must not sign another zone's data.
            if key.public.owner != *zone {
                return false;
            }
            let roles = roles_by_algorithm
                .get(usize::from(key.public.algorithm))
                .copied()
                .unwrap_or_default();
            // RFC 6781 §3.1: In split-key signing, KSKs sign only the apex DNSKEY RRset.
            roles != 3 || (key.public.flags & 257 == if apex_dnskey { 257 } else { 256 })
        });
        let mut signed = false;
        let mut signature_omitted = false;
        for (key, public) in keys {
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
            let included = builder
                .record_with(
                    section,
                    first.name,
                    Type::RRSIG,
                    first.class,
                    ttl,
                    |writer| sig.write(writer),
                )
                .map_err(Error::Build)?;
            signed |= included;
            signature_omitted |= !included;
        }
        Ok((signed, signature_omitted))
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
            assert_eq!(dnssec.cache.lock().unwrap().len(), expected_entries);
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
        assert_eq!(cache.len(), 1);
        let cached = Message::parse(&cache.values().next().unwrap().wire).unwrap();
        assert!(cached.answers().any(|rr| rr.rtype == Type::RRSIG));
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
