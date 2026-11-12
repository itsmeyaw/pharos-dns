use std::time::{SystemTime, UNIX_EPOCH};

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
use pharos_server::{Context, Error, Protocol};

use super::Dnssec;

#[derive(Debug)]
pub(super) struct CacheEntry {
    wire: Vec<u8>,
    max_size: usize,
    expires: u64,
    sets: usize,
}

impl CacheEntry {
    fn valid(&self, now: u64, max_size: usize) -> bool {
        self.max_size == max_size && self.expires > now
    }
}

impl Dnssec {
    pub(super) fn sign_response(&self, cx: &mut Context<'_, '_>) -> Result<(), Error> {
        let max_size = cx.max_response_size.max(512);
        if cx.response.capacity() < max_size {
            if cx.protocol == Protocol::Tcp {
                cx.response
                    .reserve(max_size.saturating_sub(cx.response.len()));
            } else {
                return Err(Error::ResponseBufferTooSmall);
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let metrics = self
            .metrics
            .iter()
            .find(|(address, _)| *address == cx.local)
            .map(|(_, metrics)| metrics);
        {
            let cache = self.cache.lock().map_err(|_| Error::InvalidQuery)?;
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
        let denial = matches!(kind, ResponseType::NxDomain | ResponseType::NoData)
            && message.authority_count() == 1
            && message
                .authorities()
                .next()
                .is_some_and(|rr| rr.rtype == Type::SOA);
        let referral = kind == ResponseType::Referral && message.authority_count() > 0;
        let make_lie =
            denial || (referral && !message.authorities().any(|rr| rr.rtype == Type::DS));
        let question = message.questions().next().ok_or(Error::InvalidQuery)?;
        let zone = self.zone_for(question.name).ok_or(Error::InvalidQuery)?;
        let special_nsec = denial && question.qtype == Type::NSEC;
        let mut lie_wire = Vec::new();
        if make_lie {
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
        let flags = if denial {
            message.flags() & !0xf
        } else {
            message.flags()
        };
        let mut builder = MessageBuilder::new(
            cx.response,
            cx.max_response_size.max(512),
            message.id(),
            flags,
        )
        .map_err(Error::Build)?;
        for question in message.questions() {
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
        }
        let mut signed_sets = 0;
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
                builder
                    .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                        data.write(writer)
                    })
                    .map_err(Error::Build)?;
            }
            for (i, rr) in records.iter().enumerate() {
                if special_nsec
                    || (referral && (section != Section::Authority || rr.rtype != Type::DS))
                    || (denial && section != Section::Authority)
                {
                    continue;
                }
                if matches!(rr.rtype, Type::RRSIG | Type::OPT | Type::TSIG)
                    || records[..i]
                        .iter()
                        .any(|r| r.name == rr.name && r.rtype == rr.rtype && r.class == rr.class)
                {
                    continue;
                }
                let Some(zone) = self.zone_for(rr.name) else {
                    continue;
                };
                let group: Vec<_> = records
                    .iter()
                    .copied()
                    .filter(|r| r.name == rr.name && r.rtype == rr.rtype && r.class == rr.class)
                    .collect();
                self.sign_set(&mut builder, section, &group, zone, now)?;
                signed_sets += 1;
            }
            if let Some(lie) = &lie
                && section
                    == if special_nsec {
                        Section::Answer
                    } else {
                        Section::Authority
                    }
            {
                let rr = lie.answers().next().ok_or(Error::InvalidQuery)?;
                self.sign_set(&mut builder, section, &[rr], zone, now)?;
                signed_sets += 1;
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
            metrics.miss(signed_sets);
        }
        if self.capacity > 0 {
            let mut cache = self.cache.lock().map_err(|_| Error::InvalidQuery)?;
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
    ) -> Result<(), Error> {
        let first = records.first().ok_or(Error::InvalidQuery)?;
        let signer = NameRef::parse(zone.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
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
        for (key, public) in self.keys.iter().zip(&self.public) {
            if has_ksk
                && has_zsk
                && (key.public.flags & 257
                    != if first.rtype == Type::DNSKEY {
                        257
                    } else {
                        256
                    })
            {
                continue;
            }
            let labels = first.name.labels().count()
                - usize::from(first.name.labels().next() == Some(b"*".as_slice()));
            // RFC 4034 §3.1.8: the signature covers the RRSIG prefix and canonical RRset.
            let mut sig = Rdata::Rrsig {
                type_covered: first.rtype,
                algorithm: key.public.algorithm,
                labels: labels as u8,
                original_ttl: 3600,
                expiration: now.wrapping_add(8 * 86400) as u32,
                inception: now.saturating_sub(3 * 3600) as u32,
                key_tag: key_tag(public).ok_or(Error::InvalidQuery)?,
                signer,
                signature: &[],
            };
            let data = signed_data(&sig, &canonical).map_err(|_| Error::InvalidQuery)?;
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
            builder
                .record_with(
                    section,
                    first.name,
                    Type::RRSIG,
                    first.class,
                    first.ttl,
                    |writer| sig.write(writer),
                )
                .map_err(Error::Build)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CacheEntry;

    #[test]
    fn cache_expires_after_six_days_and_checks_buffer_limit() {
        let entry = CacheEntry {
            wire: Vec::new(),
            max_size: 512,
            expires: 6 * 86400,
            sets: 1,
        };
        assert!(entry.valid(6 * 86400 - 1, 512));
        assert!(!entry.valid(6 * 86400, 512));
        assert!(!entry.valid(1, 1232));
    }
}
