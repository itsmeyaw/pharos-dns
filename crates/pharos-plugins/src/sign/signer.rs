use std::{collections::BTreeMap, path::Path};

use pharos_dnssec::{
    canonical::{CanonicalRecord, canonical_rdata, signed_data},
    denial::{ZoneName, nsec_chain},
    digest::{DigestType, cds_rdata, key_tag},
    keys::KeyPair,
    sign::SigningKey,
};
use pharos_proto::{Class, Name, NameRef, Rdata, Type, zone::ZoneRecord};

use crate::zone::Zone;

pub(super) fn sign(
    apex: &Name,
    path: &Path,
    keys: &[KeyPair],
    now: u32,
    inception_jitter: u32,
    expiration_jitter: u32,
) -> Result<Vec<ZoneRecord>, String> {
    let zone = Zone::load(apex.clone(), path)?;
    let mut records = zone.records().to_vec();
    records.retain(|rr| {
        !matches!(
            rr.rtype,
            Type::DNSKEY | Type::RRSIG | Type::CDS | Type::CDNSKEY
        )
    });

    let soa = records
        .iter_mut()
        .find(|rr| rr.rtype == Type::SOA)
        .ok_or_else(|| "Zone has no SOA".to_string())?;
    let Rdata::Soa { minimum, .. } =
        Rdata::parse(Type::SOA, &soa.rdata).map_err(|e| e.to_string())?
    else {
        return Err("invalid SOA".into());
    };
    let soa_ttl = soa.ttl;
    // RFC 1035 §3.3.13: SOA serial is the first of five trailing 32-bit values.
    let serial_offset = soa.rdata.len().checked_sub(20).ok_or("invalid SOA")?;
    soa.rdata[serial_offset..serial_offset + 4].copy_from_slice(&now.to_be_bytes());

    let mut signers = Vec::with_capacity(keys.len());
    for key in keys {
        // RFC 9905 §2: SHA-1 DNSSEC algorithms must not create signatures.
        if matches!(key.public.algorithm, 5 | 7) {
            return Err("SHA-1 DNSSEC signing algorithm is forbidden".into());
        }
        let mut dnskey = key.public.flags.to_be_bytes().to_vec();
        dnskey.extend_from_slice(&[key.public.protocol, key.public.algorithm]);
        dnskey.extend_from_slice(&key.public.public_key);
        let tag = key_tag(&dnskey).ok_or("invalid DNSKEY")?;
        let cds = cds_rdata(apex, &dnskey, DigestType::Sha256).ok_or("invalid DNSKEY")?;
        // RFC 7344 §§4.1–4.2: CDS and CDNSKEY publish the child key's delegation data.
        for (rtype, rdata) in [
            (Type::DNSKEY, dnskey.clone()),
            (Type::CDNSKEY, dnskey),
            (Type::CDS, cds),
        ] {
            records.push(ZoneRecord {
                owner: apex.clone(),
                ttl: soa_ttl,
                class: Class::IN,
                rtype,
                rdata,
            });
        }
        let der = key.private.to_pkcs8_der().map_err(|e| e.to_string())?;
        signers.push((
            key.public.algorithm,
            tag,
            SigningKey::from_pkcs8(key.public.algorithm, &der).map_err(|e| e.to_string())?,
        ));
    }
    // RFC 4035 §2.3: delegation names are authoritative, but descendants are not.
    let cuts: Vec<_> = records
        .iter()
        .filter(|rr| rr.rtype == Type::NS && rr.owner != *apex && rr.owner.is_subdomain_of(apex))
        .map(|rr| rr.owner.clone())
        .collect();
    let authoritative = |name: &Name| {
        name.is_subdomain_of(apex)
            && !cuts
                .iter()
                .any(|cut| name != cut && name.is_subdomain_of(cut))
    };
    let mut owners = BTreeMap::<Name, Vec<Type>>::new();
    for rr in &records {
        if authoritative(&rr.owner) {
            owners.entry(rr.owner.clone()).or_default().push(rr.rtype);
        }
    }
    let names: Vec<_> = owners
        .into_iter()
        .map(|(name, types)| ZoneName { name, types })
        .collect();
    // RFC 4034 §4.1: NSEC links authoritative names in canonical order and lists their types.
    for nsec in nsec_chain(apex, &names).map_err(|e| e.to_string())? {
        let mut rdata = nsec.next.as_wire().to_vec();
        rdata.extend_from_slice(&nsec.bitmap);
        records.push(ZoneRecord {
            owner: nsec.owner,
            ttl: minimum,
            class: Class::IN,
            rtype: Type::NSEC,
            rdata,
        });
    }

    let mut rrsets = BTreeMap::<(Name, u16, u16), Vec<usize>>::new();
    for (index, rr) in records.iter().enumerate() {
        if authoritative(&rr.owner)
            && rr.rtype != Type::RRSIG
            && (rr.rtype != Type::NS || rr.owner == *apex)
        {
            rrsets
                .entry((rr.owner.clone(), rr.rtype.0, rr.class.0))
                .or_default()
                .push(index);
        }
    }
    let signer = NameRef::parse(apex.as_wire(), 0).map_err(|e| e.to_string())?;
    // RFC 4034 §3.1.5: signature times use unsigned 32-bit serial arithmetic.
    let inception = now.wrapping_sub(3 * 60 * 60).wrapping_sub(inception_jitter);
    let expiration = now
        .wrapping_add(32 * 24 * 60 * 60)
        .wrapping_add(expiration_jitter);
    let mut signatures = Vec::new();
    for ((owner, rtype, _), indices) in rrsets {
        let first = &records[indices[0]];
        let ttl = if owner == *apex && first.rtype == Type::NS {
            soa_ttl
        } else {
            first.ttl
        };
        let owner_ref = NameRef::parse(owner.as_wire(), 0).map_err(|e| e.to_string())?;
        let rrset = indices
            .iter()
            .map(|&index| {
                let rr = &records[index];
                Ok(CanonicalRecord {
                    owner: owner_ref,
                    class: rr.class,
                    data: Rdata::parse(rr.rtype, &rr.rdata).map_err(|e| e.to_string())?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        // RFC 4034 §3.1.3: wildcard RRSIG labels exclude the wildcard label.
        let labels = owner.label_count() - usize::from(owner.as_wire().starts_with(&[1, b'*']));
        for (algorithm, tag, key) in &signers {
            let rrsig = Rdata::Rrsig {
                type_covered: Type(rtype),
                algorithm: *algorithm,
                labels: labels as u8,
                original_ttl: ttl,
                expiration,
                inception,
                key_tag: *tag,
                signer,
                signature: &[],
            };
            // RFC 4034 §3.1.8: sign the RRSIG prefix and the canonical RRset.
            let data = signed_data(&rrsig, &rrset).map_err(|e| e.to_string())?;
            let signature = key.sign(&data).map_err(|e| e.to_string())?;
            let mut rdata = canonical_rdata(&rrsig).map_err(|e| e.to_string())?;
            rdata.extend_from_slice(&signature);
            signatures.push(ZoneRecord {
                owner: owner.clone(),
                ttl,
                class: first.class,
                rtype: Type::RRSIG,
                rdata,
            });
        }
    }
    records.extend(signatures);
    records.sort_by_key(|rr| {
        if rr.owner != *apex {
            return 4;
        }
        match rr.rtype {
            Type::SOA => 0,
            Type::NS => 2,
            Type::RRSIG if rr.rdata.starts_with(&Type::SOA.0.to_be_bytes()) => 1,
            Type::RRSIG if rr.rdata.starts_with(&Type::NS.0.to_be_bytes()) => 3,
            _ => 4,
        }
    });
    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    use pharos_dnssec::{
        canonical::{CanonicalRecord, signed_data},
        keys::KeyPair,
    };
    use pharos_proto::{Name, NameRef, Rdata, Type};

    use super::sign;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn key() -> KeyPair {
        KeyPair::from_files(
            fixture("dnssec/miek-ed25519-ksk.key"),
            fixture("dnssec/miek-ed25519-ksk.private"),
        )
        .unwrap()
    }

    #[test]
    fn signs_authoritative_records_and_preserves_unsigned_glue() {
        let apex: Name = "miek.nl.".parse().unwrap();
        let delegation: Name = "delegated.miek.nl.".parse().unwrap();
        let glue: Name = "a.delegated.miek.nl.".parse().unwrap();
        let key = key();
        let records = sign(
            &apex,
            &fixture("file/coredns-delegation.zone"),
            &[key],
            1_700_000_000,
            0,
            0,
        )
        .unwrap();
        assert_eq!(records[0].rtype, Type::SOA);
        assert_eq!(records[1].rtype, Type::RRSIG);
        assert!(records[1].rdata.starts_with(&Type::SOA.0.to_be_bytes()));
        assert!(
            records
                .iter()
                .any(|r| r.owner == glue && r.rtype == Type::A)
        );
        assert!(
            !records
                .iter()
                .any(|r| r.owner == glue && matches!(r.rtype, Type::RRSIG | Type::NSEC))
        );
        assert!(
            records
                .iter()
                .any(|r| r.owner == delegation && r.rtype == Type::NSEC)
        );
        assert!(!records.iter().any(|r| r.owner == delegation
            && r.rtype == Type::RRSIG
            && r.rdata.starts_with(&Type::NS.0.to_be_bytes())));
        let soa = records.iter().find(|r| r.rtype == Type::SOA).unwrap();
        assert!(matches!(
            Rdata::parse(Type::SOA, &soa.rdata).unwrap(),
            Rdata::Soa {
                serial: 1_700_000_000,
                ..
            }
        ));
        for kind in [Type::DNSKEY, Type::CDNSKEY, Type::CDS] {
            assert!(records.iter().any(|r| r.owner == apex && r.rtype == kind));
        }
        let cds = records.iter().find(|r| r.rtype == Type::CDS).unwrap();
        assert_eq!(cds.rdata[3], 2);
    }

    #[test]
    fn signatures_verify_against_canonical_rrsets() {
        let apex: Name = "miek.nl.".parse().unwrap();
        let key = key();
        let records = sign(
            &apex,
            &fixture("file/coredns-miek.zone"),
            std::slice::from_ref(&key),
            1_700_000_000,
            13,
            29,
        )
        .unwrap();
        for rr in records.iter().filter(|r| r.rtype == Type::RRSIG) {
            let signature = Rdata::parse(Type::RRSIG, &rr.rdata).unwrap();
            let Rdata::Rrsig {
                type_covered,
                signature: bytes,
                inception,
                expiration,
                ..
            } = signature
            else {
                unreachable!()
            };
            assert_eq!(inception, 1_700_000_000 - 3 * 60 * 60 - 13);
            assert_eq!(expiration, 1_700_000_000 + 32 * 24 * 60 * 60 + 29);
            let rrset: Vec<_> = records
                .iter()
                .filter(|r| r.owner == rr.owner && r.rtype == type_covered)
                .map(|r| CanonicalRecord {
                    owner: NameRef::parse(r.owner.as_wire(), 0).unwrap(),
                    class: r.class,
                    data: Rdata::parse(r.rtype, &r.rdata).unwrap(),
                })
                .collect();
            let data = signed_data(&signature, &rrset).unwrap();
            UnparsedPublicKey::new(&ED25519, &key.public.public_key)
                .verify(&data, bytes)
                .unwrap();
        }
        assert!(records.iter().any(|r| r.rtype == Type::RRSIG));
    }

    #[test]
    fn nsec_chain_is_circular_in_canonical_order() {
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(
            &apex,
            &fixture("file/coredns-miek.zone"),
            &[key()],
            1_700_000_000,
            0,
            0,
        )
        .unwrap();
        let mut nsecs: Vec<_> = records.iter().filter(|r| r.rtype == Type::NSEC).collect();
        nsecs.sort_by(|a, b| a.owner.cmp(&b.owner));
        for (i, rr) in nsecs.iter().enumerate() {
            let Rdata::Nsec { next, .. } = Rdata::parse(Type::NSEC, &rr.rdata).unwrap() else {
                unreachable!()
            };
            assert_eq!(next.to_name(), nsecs[(i + 1) % nsecs.len()].owner);
            assert_eq!(rr.ttl, 14_400);
        }
        assert!(!nsecs.is_empty());
    }

    #[test]
    fn replaces_existing_signatures_and_dnskeys() {
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(
            &apex,
            &fixture("file/coredns-miek-signed.zone"),
            &[key()],
            1_700_000_000,
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            records.iter().filter(|r| r.rtype == Type::DNSKEY).count(),
            1
        );
        for rr in records.iter().filter(|r| r.rtype == Type::RRSIG) {
            assert_eq!(rr.rdata[2], 15);
        }
    }

    #[test]
    fn invalid_zone_path_returns_error() {
        let apex: Name = "miek.nl.".parse().unwrap();
        assert!(
            sign(
                &apex,
                &fixture("file/missing.zone"),
                &[key()],
                1_700_000_000,
                0,
                0
            )
            .is_err()
        );
    }
}
