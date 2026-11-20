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
    } = Rdata::parse(Type::SOA, &soa.rdata).map_err(|e| e.to_string())?
    else {
        return Err("invalid SOA".into());
    };
    let soa_ttl = soa.ttl;
    // RFC 1035 §3.3.13: SOA serial is the first of five trailing 32-bit values.
    let serial_offset = soa.rdata.len().checked_sub(20).ok_or("invalid SOA")?;
    // RFC 1982 §3.2; RFC 4033 §8.2: Half-range and equal serials are not newer.
    let delta = now.wrapping_sub(previous_serial);
    let serial = if delta == 0 || delta >= (1_u32 << 31) {
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
mod tests;
