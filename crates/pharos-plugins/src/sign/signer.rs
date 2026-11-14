use std::{collections::BTreeMap, io::BufReader, path::Path};

use pharos_dnssec::{
    canonical::{CanonicalRecord, canonical_rdata, signed_data},
    denial::type_bitmap,
    digest::{DigestType, cds_rdata, key_tag},
    keys::KeyPair,
    sign::SigningKey,
};
use pharos_proto::{
    Class, Name, NameRef, Rdata, Type,
    zone::{ZoneParser, ZoneRecord},
};

use crate::zone::Zone;

#[cfg(test)]
pub(super) fn sign(
    apex: &Name,
    path: &Path,
    keys: &[KeyPair],
    now: u32,
    inception_jitter: u32,
    expiration_jitter: u32,
) -> Result<Vec<ZoneRecord>, String> {
    sign_with_owner(
        apex,
        apex,
        path,
        keys,
        now,
        inception_jitter,
        expiration_jitter,
    )
}

pub(super) fn sign_with_owner(
    apex: &Name,
    key_owner: &Name,
    path: &Path,
    keys: &[KeyPair],
    now: u32,
    inception_jitter: u32,
    expiration_jitter: u32,
) -> Result<Vec<ZoneRecord>, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut parser = ZoneParser::new(BufReader::new(file), apex.clone(), path.to_string_lossy());
    parser.set_include_allowed(true);
    let mut records = parser
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let delete_cds = records
        .iter()
        .find(|rr| rr.rtype == Type::CDS && rr.rdata == [0, 0, 0, 0, 0]);
    let delete_cdnskey = records
        .iter()
        .find(|rr| rr.rtype == Type::CDNSKEY && rr.rdata == [0, 0, 3, 0, 0]);
    // RFC 8078 §4: A delete signal must be the sole record in its CDS/CDNSKEY RRset.
    for (rtype, delete) in [(Type::CDS, delete_cds), (Type::CDNSKEY, delete_cdnskey)] {
        if delete.is_some() && records.iter().filter(|rr| rr.rtype == rtype).count() != 1 {
            return Err("DNSSEC delete signal must be the only RR in its RRset".into());
        }
    }
    // RFC 8078 §4: Preserve the single-record CDS/CDNSKEY delete signal for signing.
    let delete_cds = delete_cds.cloned();
    let delete_cdnskey = delete_cdnskey.cloned();
    // RFC 4035 §2.5: Reject non-DNSSEC data that conflicts with a CNAME owner.
    for cname in records.iter().filter(|rr| rr.rtype == Type::CNAME) {
        if records.iter().any(|rr| {
            rr.owner == cname.owner
                && !matches!(rr.rtype, Type::CNAME | Type::KEY | Type::NSEC | Type::RRSIG)
        }) {
            return Err("CNAME owner contains incompatible RR type".into());
        }
    }
    records.retain(|rr| {
        !matches!(
            rr.rtype,
            Type::DNSKEY | Type::RRSIG | Type::CDS | Type::CDNSKEY
        )
    });
    // CoreDNS sign retains the last SOA; RFC 4034 requires that owner to identify this zone.
    let last_soa = records
        .iter()
        .rposition(|rr| rr.rtype == Type::SOA)
        .ok_or("Zone has no SOA")?;
    let soa_owner = records[last_soa].owner.clone();
    // RFC 4034 §3.1.7: The Signer's Name must identify the zone containing each RRset.
    if soa_owner != *apex {
        // RFC 4034 §3.1.7: Signer Name cannot identify a different SOA-owner zone.
        return Err("SOA owner differs from configured Zone".into());
    }
    if delete_cds.as_ref().is_some_and(|rr| rr.owner != soa_owner)
        || delete_cdnskey
            .as_ref()
            .is_some_and(|rr| rr.owner != soa_owner)
    {
        return Err("DNSSEC delete signal must be at the zone apex".into());
    }
    let mut index = 0;
    records.retain(|rr| {
        let keep = rr.rtype != Type::SOA || index == last_soa;
        index += 1;
        keep
    });
    let zone = Zone::from_records(soa_owner.clone(), records)?;
    let mut records = zone.records().to_vec();
    // RFC 4035 §2.4: DS is data in the parent zone, never at its own apex.
    if records
        .iter()
        .any(|rr| rr.owner == soa_owner && rr.rtype == Type::DS)
    {
        return Err("DS RRset cannot appear at the zone apex".into());
    }

    let soa = records
        .iter_mut()
        .find(|rr| rr.rtype == Type::SOA)
        .ok_or_else(|| "Zone has no SOA".to_string())?;
    let Rdata::Soa {
        minimum,
        serial: previous_serial,
        ..
    } =
        Rdata::parse(Type::SOA, &soa.rdata).map_err(|e| e.to_string())?
    else {
        return Err("invalid SOA".into());
    };
    let soa_ttl = soa.ttl;
    // RFC 1035 §3.3.13: SOA serial is the first of five trailing 32-bit values.
    let serial_offset = soa.rdata.len().checked_sub(20).ok_or("invalid SOA")?;
    // RFC 4033 §8.2: A time-derived SOA serial must advance when it is not newer.
    let serial = if now <= previous_serial {
        previous_serial.wrapping_add(1)
    } else {
        now
    };
    soa.rdata[serial_offset..serial_offset + 4].copy_from_slice(&serial.to_be_bytes());

    let mut signers = Vec::with_capacity(keys.len());
    for key in keys {
        // RFC 9905 §2: SHA-1 DNSSEC algorithms must not create signatures.
        if matches!(key.public.algorithm, 5 | 7) {
            return Err("SHA-1 DNSSEC signing algorithm is forbidden".into());
        }
        let mut dnskey = key.public.flags.to_be_bytes().to_vec();
        dnskey.extend_from_slice(&[key.public.protocol, key.public.algorithm]);
        dnskey.extend_from_slice(&key.public.public_key);
        // RFC 4034 §3.1.6: The RRSIG key tag identifies the DNSKEY used to create the signature.
        let tag = key_tag(&dnskey).ok_or("invalid DNSKEY")?;
        // RFC 9904 §4: Uses SHA-256, required for DNSSEC delegation.
        let cds = cds_rdata(key_owner, &dnskey, DigestType::Sha256).ok_or("invalid DNSKEY")?;
        // RFC 7344 §§4.1–4.2: CDS and CDNSKEY publish the child key's delegation data.
        // RFC 8078 §2.1: publishing CDS and CDNSKEY tells the parent to synchronize the DS RRset.
        for (rtype, rdata) in [
            (Type::DNSKEY, dnskey.clone()),
            (Type::CDNSKEY, dnskey.clone()),
            (Type::CDS, cds),
        ] {
            if (rtype == Type::CDS && delete_cds.is_some())
                || (rtype == Type::CDNSKEY && delete_cdnskey.is_some())
            {
                continue;
            }
            records.push(ZoneRecord {
                owner: key_owner.clone(),
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
    if let Some(record) = delete_cds {
        records.push(record);
    }
    if let Some(record) = delete_cdnskey {
        records.push(record);
    }
    // RFC 4035 §2.3: delegation names are authoritative, but descendants are not.
    let cuts: Vec<_> = records
        .iter()
        .filter(|rr| rr.rtype == Type::NS && rr.owner != *apex)
        .map(|rr| rr.owner.clone())
        .collect();
    // RFC 4035 §2.4: DS TTL SHOULD match the delegating NS RRset TTL.
    let ns_ttls = records
        .iter()
        .filter(|rr| rr.rtype == Type::NS && rr.owner != *apex)
        .fold(BTreeMap::<Name, u32>::new(), |mut ttls, rr| {
            ttls.entry(rr.owner.clone())
                .and_modify(|ttl| *ttl = (*ttl).min(rr.ttl))
                .or_insert(rr.ttl);
            ttls
        });
    for rr in records.iter_mut().filter(|rr| rr.rtype == Type::DS) {
        if let Some(ttl) = ns_ttls.get(&rr.owner) {
            rr.ttl = *ttl;
        }
    }
    // RFC 4034 §4.1.1: NSEC links exclude glue and other non-authoritative names.
    let authoritative = |name: &Name| {
        !cuts
            .iter()
            .any(|cut| name != cut && name.is_subdomain_of(cut))
    };
    let mut owners = BTreeMap::<Name, Vec<Type>>::new();
    for rr in &records {
        // RFC 4035 §2.3: Create NSEC records at authoritative names and delegations.
        if authoritative(&rr.owner)
            && rr.rtype != Type::SOA
            && !(rr.owner == *apex && rr.rtype == Type::NS)
        {
            // RFC 4034 §4.1.3: wildcard labels remain literal NSEC owner names.
            owners.entry(rr.owner.clone()).or_default().push(rr.rtype);
        }
    }
    // RFC 4592 §4.7; RFC 4034 §4: Empty non-terminals are authoritative NSEC owners.
    for rr in &records {
        if !authoritative(&rr.owner) {
            continue;
        }
        let mut parent = rr.owner.parent();
        while let Some(name) = parent {
            if !name.is_subdomain_of(apex) || !authoritative(&name) {
                break;
            }
            owners.entry(name.clone()).or_default();
            parent = name.parent();
        }
    }
    let names: Vec<_> = owners.into_iter().collect();
    // RFC 4034 §4.1: NSEC links authoritative names in canonical order and lists their types.
    for (index, (owner, types)) in names.iter().enumerate() {
        let mut types = types.clone();
        // RFC 4035 §2.3: each NSEC type bitmap includes NSEC and its corresponding RRSIG.
        types.extend([Type::NSEC, Type::RRSIG]);
        if owner == apex {
            types.extend([Type::NS, Type::SOA]);
        } else if cuts.iter().any(|cut| cut == owner) {
            // RFC 4034 §4.1.2: At a delegation, parent-side bitmap data is NS and DS only.
            types.retain(|rtype| matches!(*rtype, Type::NS | Type::DS));
            types.extend([Type::NSEC, Type::RRSIG]);
        }
        let mut rdata = names[(index + 1) % names.len()].0.as_wire().to_vec();
        rdata.extend_from_slice(&type_bitmap(&types).map_err(|e| e.to_string())?);
        records.push(ZoneRecord {
            owner: owner.clone(),
            // RFC 9077 §3.1: NSEC TTL is the lesser of SOA TTL and SOA.MINIMUM.
            ttl: minimum.min(soa_ttl),
            class: Class::IN,
            rtype: Type::NSEC,
            rdata,
        });
    }

    // RFC 4035 §2.4: sign each DS RRset in the parent zone.
    let mut rrsets = BTreeMap::<(Name, u16, u16), Vec<usize>>::new();
    for (index, rr) in records.iter().enumerate() {
        if (rr.rtype == Type::SOA || authoritative(&rr.owner))
            // RFC 4034 §3: Do not sign RRSIG records as zone data.
            && rr.rtype != Type::RRSIG
            // RFC 4035 §2.2: Do not sign NS RRsets at non-apex delegation points.
            && (rr.rtype != Type::NS || rr.owner == *apex)
        {
            rrsets
                .entry((rr.owner.clone(), rr.rtype.0, rr.class.0))
                .or_default()
                .push(index);
        }
    }
    let signer = NameRef::parse(apex.as_wire(), 0).map_err(|e| e.to_string())?;
    // RFC 1982 §3; RFC 4034 §3.1.5: signature times use unsigned 32-bit serial arithmetic.
    let inception = now.wrapping_sub(3 * 60 * 60).wrapping_sub(inception_jitter);
    let expiration = now
        .wrapping_add(32 * 24 * 60 * 60)
        .wrapping_add(expiration_jitter);
    let mut signatures = Vec::new();
    // RFC 4035 §2.2: Sign each authoritative RRset with its matching RRSIG fields and zone key.
    for ((owner, rtype, _), indices) in rrsets {
        // RFC 2181 §5.2: Use the RRset's lowest TTL for both RRSIG TTL and Original TTL.
        let ttl = indices
            .iter()
            .map(|&index| records[index].ttl)
            .min()
            .unwrap_or(records[indices[0]].ttl);
        for index in indices.iter().copied() {
            records[index].ttl = ttl;
        }
        let first = &records[indices[0]];
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
        // RFC 4035 §2.2: an RRset may have multiple associated RRSIG records.
        for (algorithm, tag, key) in &signers {
            // RFC 4034 §3.1.1: Type Covered is the type of the RRset this RRSIG covers.
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
            // RFC 4034 §3.1.8.1: Sign the RRSIG prefix and canonical RRset.
            let data = signed_data(&rrsig, &rrset).map_err(|e| e.to_string())?;
            let signature = key.sign(&data).map_err(|e| e.to_string())?;
            let mut rdata = canonical_rdata(&rrsig).map_err(|e| e.to_string())?;
            rdata.extend_from_slice(&signature);
            signatures.push(ZoneRecord {
                owner: owner.clone(),
                ttl,
                // RFC 4034 §3: each RRSIG uses the class of its covered RRset.
                class: first.class,
                rtype: Type::RRSIG,
                rdata,
            });
        }
    }
    records.extend(signatures);
    records.sort_by_key(|rr| {
        if rr.rtype == Type::SOA {
            return 0;
        }
        if rr.rtype == Type::RRSIG && rr.rdata.starts_with(&Type::SOA.0.to_be_bytes()) {
            return 1;
        }
        if rr.owner != *apex {
            return 4;
        }
        match rr.rtype {
            Type::NS => 2,
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

    // RFC 4033 §8.2: Time-based signing must advance a non-increasing SOA serial.
    #[test]
    fn soa_serial_advances_when_unix_time_is_not_newer() {
        let path = std::env::temp_dir().join(format!("pharos-sign-serial-{}", std::process::id()));
        let apex: Name = "miek.nl.".parse().unwrap();
        for (previous, now) in [(100, 100), (100, 99)] {
            std::fs::write(
                &path,
                format!(
                    "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. ({previous} 4H 1H 7D 4H)\n@ IN NS ns.\n"
                ),
            )
            .unwrap();
            let records = sign(&apex, &path, &[key()], now, 0, 0).unwrap();
            let soa = records.iter().find(|rr| rr.rtype == Type::SOA).unwrap();
            assert!(matches!(
                Rdata::parse(Type::SOA, &soa.rdata).unwrap(),
                Rdata::Soa { serial: 101, .. }
            ));
        }
        std::fs::remove_file(path).unwrap();
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
            assert_eq!(rr.ttl, 1_800);
        }
        assert!(!nsecs.is_empty());
    }

    #[test]
    fn nsec_chain_includes_empty_nonterminal_wildcard_owner() {
        let path = std::env::temp_dir().join(format!("pharos-sign-wildcard-ent-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\nleaf.* IN A 192.0.2.1\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        let wildcard: Name = "*.miek.nl.".parse().unwrap();
        let nsec = records
            .iter()
            .find(|rr| rr.owner == wildcard && rr.rtype == Type::NSEC)
            .unwrap();
        let Rdata::Nsec { bitmap, .. } = Rdata::parse(Type::NSEC, &nsec.rdata).unwrap() else {
            panic!("expected NSEC")
        };
        assert_eq!(bitmap, pharos_dnssec::denial::type_bitmap(&[Type::NSEC, Type::RRSIG]).unwrap());
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

    #[test]
    fn rejects_a_zone_whose_soa_owner_differs_from_origin() {
        let apex: Name = "example.org.".parse().unwrap();
        assert!(
            sign(
                &apex,
                &fixture("file/coredns-miek.zone"),
                &[key()],
                1_700_000_000,
                0,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn coredns_nsec_chain_includes_delegation_but_not_glue() {
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(
            &apex,
            &fixture("sign/db.miek.nl_ns"),
            &[key()],
            1_700_000_000,
            0,
            0,
        )
        .unwrap();
        let child: Name = "child.miek.nl.".parse().unwrap();
        let nsec = records
            .iter()
            .find(|rr| rr.owner == child && rr.rtype == Type::NSEC)
            .unwrap();
        let Rdata::Nsec { next, bitmap } = Rdata::parse(Type::NSEC, &nsec.rdata).unwrap() else {
            panic!("expected NSEC")
        };
        assert_eq!(next.to_name().to_string(), "www.miek.nl.");
        assert_eq!(nsec.ttl, 1800);
        let nsec = pharos_dnssec::denial::Nsec {
            owner: child.clone(),
            next: next.to_name(),
            bitmap: bitmap.to_vec(),
        };
        for kind in [Type::NS, Type::DS, Type::RRSIG, Type::NSEC] {
            assert!(nsec.bitmap_contains(kind));
        }
        assert!(!nsec.bitmap_contains(Type::A));
        assert!(!nsec.bitmap_contains(Type::AAAA));
        assert_eq!(
            records
                .iter()
                .filter(|rr| rr.owner == child && rr.rtype == Type::RRSIG)
                .count(),
            2
        );
        assert!(
            !records
                .iter()
                .any(|rr| rr.owner.to_string() == "ns.child.miek.nl." && rr.rtype == Type::RRSIG)
        );
    }

    #[test]
    fn coredns_signs_apex_only_and_sets_key_ttl() {
        let path = std::env::temp_dir().join(format!("pharos-sign-apex-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 30M\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n IN NS ns.\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        let nsec = records.iter().find(|rr| rr.rtype == Type::NSEC).unwrap();
        assert!(
            matches!(Rdata::parse(Type::NSEC, &nsec.rdata).unwrap(), Rdata::Nsec { next, .. } if next.to_name() == apex)
        );
        assert_eq!(
            records
                .iter()
                .find(|rr| rr.rtype == Type::DNSKEY)
                .unwrap()
                .ttl,
            1800
        );
        assert!(records.iter().any(|rr| rr.rtype == Type::RRSIG
            && rr.rdata.starts_with(&Type::DNSKEY.0.to_be_bytes())
            && rr.ttl == 1800));
    }

    #[test]
    fn apex_ns_signature_and_nsec_use_their_required_ttls() {
        let path = std::env::temp_dir().join(format!("pharos-sign-ttls-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ 3600 IN SOA ns. host. (1 4H 1H 7D 4H)\n@ 900 IN NS ns.\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        let ns_signature = records
            .iter()
            .find(|rr| rr.rtype == Type::RRSIG && rr.rdata.starts_with(&Type::NS.0.to_be_bytes()))
            .unwrap();
        assert_eq!(ns_signature.ttl, 900);
        assert!(
            records
                .iter()
                .filter(|rr| rr.rtype == Type::NSEC)
                .all(|rr| rr.ttl == 3600)
        );
    }

    #[test]
    fn mixed_ttl_rrset_uses_minimum_for_records_and_signature() {
        let path =
            std::env::temp_dir().join(format!("pharos-sign-mixed-ttl-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\nwww 900 IN A 192.0.2.1\nwww 300 IN A 192.0.2.2\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        let owner: Name = "www.miek.nl.".parse().unwrap();
        assert!(
            records
                .iter()
                .filter(|rr| rr.owner == owner && rr.rtype == Type::A)
                .all(|rr| rr.ttl == 300)
        );
        let signature = records
            .iter()
            .find(|rr| rr.owner == owner && rr.rtype == Type::RRSIG)
            .unwrap();
        assert_eq!(signature.ttl, 300);
        assert!(matches!(
            Rdata::parse(Type::RRSIG, &signature.rdata).unwrap(),
            Rdata::Rrsig {
                type_covered: Type::A,
                original_ttl: 300,
                ..
            }
        ));
    }

    #[test]
    fn delegation_ds_ttl_matches_parent_ns_ttl() {
        let path = std::env::temp_dir().join(format!("pharos-sign-ds-ttl-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\ndeleg 600 IN NS ns.deleg.\ndeleg 1800 IN DS 34385 13 2 fc7397c77afbccb6742fcff19c7b1410d0044661e7085fc200ae1ab3d15a5842\nns.deleg 600 IN A 192.0.2.1\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        let child: Name = "deleg.miek.nl.".parse().unwrap();
        let ns_ttl = records
            .iter()
            .find(|rr| rr.owner == child && rr.rtype == Type::NS)
            .unwrap()
            .ttl;
        let ds_ttl = records
            .iter()
            .find(|rr| rr.owner == child && rr.rtype == Type::DS)
            .unwrap()
            .ttl;
        assert_eq!(ds_ttl, ns_ttl);
        assert_eq!(ns_ttl, 600);
    }

    #[test]
    fn rejects_apex_ds_and_cname_mixed_data() {
        let path = std::env::temp_dir().join(format!("pharos-sign-invalid-{}", std::process::id()));
        let apex: Name = "miek.nl.".parse().unwrap();
        for text in [
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\n@ IN DS 34385 13 2 fc7397c77afbccb6742fcff19c7b1410d0044661e7085fc200ae1ab3d15a5842\n",
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\nalias IN CNAME target.\nalias IN A 192.0.2.1\n",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).is_err());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn preserves_and_signs_cds_and_cdnskey_delete_signals() {
        let path = std::env::temp_dir().join(format!("pharos-sign-delete-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\n@ IN CDS 0 0 0 00\n@ IN CDNSKEY 0 3 0 AA==\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            records
                .iter()
                .any(|rr| rr.rtype == Type::CDS && rr.rdata == [0, 0, 0, 0, 0])
        );
        assert!(
            records
                .iter()
                .any(|rr| rr.rtype == Type::CDNSKEY && rr.rdata == [0, 0, 3, 0, 0])
        );
        assert!(
            records
                .iter()
                .any(|rr| rr.rtype == Type::RRSIG
                    && rr.rdata.starts_with(&Type::CDS.0.to_be_bytes()))
        );
        assert!(
            records.iter().any(|rr| rr.rtype == Type::RRSIG
                && rr.rdata.starts_with(&Type::CDNSKEY.0.to_be_bytes()))
        );
    }

    #[test]
    fn coredns_rejects_bad_and_missing_soa() {
        let path = std::env::temp_dir().join(format!("pharos-sign-bad-soa-{}", std::process::id()));
        let apex: Name = "example.org.".parse().unwrap();
        for text in [
            "$TTL 1M\n$ORIGIN example.org.\n@ IN SOA ns. admin. foobarbaz 1200 144 1814400 2h\n",
            "$TTL 1M\n$ORIGIN example.org.\nwww IN A 192.0.2.14\n",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).is_err());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn coredns_without_keys_accepts_apex_only_zone() {
        let path = std::env::temp_dir().join(format!("pharos-sign-no-keys-{}", std::process::id()));
        std::fs::write(
            &path,
            "$TTL 30M\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n IN NS ns.\n",
        )
        .unwrap();
        let apex: Name = "miek.nl.".parse().unwrap();
        let records = sign(&apex, &path, &[], 1_700_000_000, 0, 0).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(records.len(), 2);
        assert!(
            !records
                .iter()
                .any(|rr| matches!(rr.rtype, Type::NSEC | Type::RRSIG))
        );
    }
}
