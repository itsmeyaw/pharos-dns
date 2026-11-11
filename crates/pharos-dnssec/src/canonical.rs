//! Canonical DNSSEC wire encodings and RRSIG signed data.

use std::fmt;

use pharos_proto::{Class, NameRef, Rdata, Type};

/// Invalid or unsupported input to canonical serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalError {
    /// The RDATA is malformed, unsupported, or too long.
    Rdata,
    /// The supplied records do not form the RRset covered by the RRSIG.
    Rrset,
    /// The supplied data is not an RRSIG or has an invalid Labels field.
    Rrsig,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rdata => "invalid or unsupported RDATA",
            Self::Rrset => "invalid RRset",
            Self::Rrsig => "invalid RRSIG",
        })
    }
}

impl std::error::Error for CanonicalError {}

/// A record to be covered by an RRSIG; the RRSIG supplies its original TTL.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalRecord<'a> {
    pub owner: NameRef<'a>,
    pub class: Class,
    pub data: Rdata<'a>,
}

// RFC 4034 §6.2: canonical names are uncompressed and ASCII case-folded.
fn write_name(out: &mut Vec<u8>, name: NameRef<'_>, lowercase: bool) {
    for label in name.labels() {
        out.push(label.len() as u8);
        out.extend(label.iter().map(|byte| {
            if lowercase {
                byte.to_ascii_lowercase()
            } else {
                *byte
            }
        }));
    }
    out.push(0);
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CanonicalError> {
    out.push(u8::try_from(bytes.len()).map_err(|_| CanonicalError::Rdata)?);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Returns uncompressed canonical RDATA, rejecting malformed or unsupported data.
pub fn canonical_rdata(data: &Rdata<'_>) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    // RFC 4034 §6.2: only the listed legacy RDATA name types are case-folded.
    // RFC 6840 §5.1: NSEC next names retain case; RRSIG signer names do not.
    match *data {
        Rdata::A(addr) => out.extend_from_slice(&addr.octets()),
        Rdata::Aaaa(addr) => out.extend_from_slice(&addr.octets()),
        Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Ptr(name) => write_name(&mut out, name, true),
        Rdata::Mx {
            preference,
            exchange,
        } => {
            out.extend_from_slice(&preference.to_be_bytes());
            write_name(&mut out, exchange, true);
        }
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            write_name(&mut out, mname, true);
            write_name(&mut out, rname, true);
            for value in [serial, refresh, retry, expire, minimum] {
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        Rdata::Txt(bytes) => out.extend_from_slice(bytes),
        Rdata::Hinfo { cpu, os } => {
            string(&mut out, cpu)?;
            string(&mut out, os)?;
        }
        Rdata::Caa { flags, tag, value } => {
            out.push(flags);
            string(&mut out, tag)?;
            out.extend_from_slice(value);
        }
        Rdata::Uri {
            priority,
            weight,
            target,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(target);
        }
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for value in [priority, weight, port] {
                out.extend_from_slice(&value.to_be_bytes());
            }
            write_name(&mut out, target, true);
        }
        Rdata::Naptr {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        } => {
            out.extend_from_slice(&order.to_be_bytes());
            out.extend_from_slice(&preference.to_be_bytes());
            for value in [flags, services, regexp] {
                string(&mut out, value)?;
            }
            write_name(&mut out, replacement, true);
        }
        Rdata::Svcb {
            priority,
            target,
            params,
        }
        | Rdata::Https {
            priority,
            target,
            params,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            write_name(&mut out, target, false);
            out.extend_from_slice(params);
        }
        Rdata::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
        | Rdata::Cds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            out.extend_from_slice(&key_tag.to_be_bytes());
            out.extend_from_slice(&[algorithm, digest_type]);
            out.extend_from_slice(digest);
        }
        Rdata::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        }
        | Rdata::Cdnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            out.extend_from_slice(&flags.to_be_bytes());
            out.extend_from_slice(&[protocol, algorithm]);
            out.extend_from_slice(public_key);
        }
        Rdata::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        } => {
            write_rrsig_prefix(
                &mut out,
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
            );
            out.extend_from_slice(signature);
        }
        Rdata::Nsec { next, bitmap } => {
            write_name(&mut out, next, false);
            out.extend_from_slice(bitmap);
        }
        Rdata::Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_owner,
            bitmap,
        } => {
            out.extend_from_slice(&[hash_algorithm, flags]);
            out.extend_from_slice(&iterations.to_be_bytes());
            string(&mut out, salt)?;
            string(&mut out, next_owner)?;
            out.extend_from_slice(bitmap);
        }
        Rdata::Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        } => {
            out.extend_from_slice(&[hash_algorithm, flags]);
            out.extend_from_slice(&iterations.to_be_bytes());
            string(&mut out, salt)?;
        }
        Rdata::Tlsa {
            usage,
            selector,
            matching_type,
            certificate,
        } => {
            out.extend_from_slice(&[usage, selector, matching_type]);
            out.extend_from_slice(certificate);
        }
        Rdata::Sshfp {
            algorithm,
            fingerprint_type,
            fingerprint,
        } => {
            out.extend_from_slice(&[algorithm, fingerprint_type]);
            out.extend_from_slice(fingerprint);
        }
        Rdata::Zonemd {
            serial,
            scheme,
            hash_algorithm,
            digest,
        } => {
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&[scheme, hash_algorithm]);
            out.extend_from_slice(digest);
        }
        Rdata::Tsig {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        } => {
            if time_signed > 0xffff_ffff_ffff {
                return Err(CanonicalError::Rdata);
            }
            write_name(&mut out, algorithm, false);
            out.extend_from_slice(&time_signed.to_be_bytes()[2..]);
            out.extend_from_slice(&fudge.to_be_bytes());
            out.extend_from_slice(
                &u16::try_from(mac.len())
                    .map_err(|_| CanonicalError::Rdata)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(mac);
            out.extend_from_slice(&original_id.to_be_bytes());
            out.extend_from_slice(&error.to_be_bytes());
            out.extend_from_slice(
                &u16::try_from(other.len())
                    .map_err(|_| CanonicalError::Rdata)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(other);
        }
        // shortcut: A6 and legacy name-bearing types need typed proto support before signing.
        Rdata::Unknown(Type(38), _) => return Err(CanonicalError::Rdata),
        Rdata::Unknown(_, bytes) => out.extend_from_slice(bytes),
    }
    if out.len() > usize::from(u16::MAX) {
        return Err(CanonicalError::Rdata);
    }
    let parsed = Rdata::parse(data.rtype(), &out).map_err(|_| CanonicalError::Rdata)?;
    if matches!(data, Rdata::Unknown(..)) && !matches!(parsed, Rdata::Unknown(..)) {
        return Err(CanonicalError::Rdata);
    }
    Ok(out)
}

// RFC 4034 §3.1.8.1: the signature covers this prefix but not the Signature field.
#[expect(
    clippy::too_many_arguments,
    reason = "the fields are the RRSIG wire prefix"
)]
fn write_rrsig_prefix(
    out: &mut Vec<u8>,
    rtype: Type,
    algorithm: u8,
    labels: u8,
    ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: NameRef<'_>,
) {
    out.extend_from_slice(&rtype.0.to_be_bytes());
    out.extend_from_slice(&[algorithm, labels]);
    for value in [ttl, expiration, inception] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&key_tag.to_be_bytes());
    write_name(out, signer, true);
}

fn write_rr(out: &mut Vec<u8>, owner: &[u8], rtype: Type, class: Class, ttl: u32, rdata: &[u8]) {
    // RFC 4034 §3.1.8.1: every signed RR has owner, type, class, original TTL, length, and RDATA.
    out.extend_from_slice(owner);
    out.extend_from_slice(&rtype.0.to_be_bytes());
    out.extend_from_slice(&class.0.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// Returns one canonical RR using the supplied original TTL.
pub fn canonical_rr(
    owner: NameRef<'_>,
    class: Class,
    original_ttl: u32,
    data: &Rdata<'_>,
) -> Result<Vec<u8>, CanonicalError> {
    let rdata = canonical_rdata(data)?;
    let mut name = Vec::new();
    write_name(&mut name, owner, true);
    let mut out = Vec::new();
    write_rr(&mut out, &name, data.rtype(), class, original_ttl, &rdata);
    Ok(out)
}

/// Serializes the RRSIG prefix and canonical RRset for signing or verification.
/// Duplicate canonical records are removed; expanded wildcard owners are restored.
pub fn signed_data(
    signature: &Rdata<'_>,
    records: &[CanonicalRecord<'_>],
) -> Result<Vec<u8>, CanonicalError> {
    let Rdata::Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer,
        ..
    } = *signature
    else {
        return Err(CanonicalError::Rrsig);
    };
    let first = records.first().ok_or(CanonicalError::Rrset)?;
    let count = first.owner.labels().count();
    if usize::from(labels) > count {
        return Err(CanonicalError::Rrsig);
    }
    let mut owner = Vec::new();
    // RFC 4035 §5.3.2: a smaller Labels value reconstructs the wildcard owner.
    if usize::from(labels) < count {
        owner.extend_from_slice(&[1, b'*']);
        for label in first.owner.labels().skip(count - usize::from(labels)) {
            owner.push(label.len() as u8);
            owner.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        owner.push(0);
    } else {
        write_name(&mut owner, first.owner, true);
    }
    let mut rdatas = Vec::with_capacity(records.len());
    for record in records {
        if record.owner != first.owner
            || record.class != first.class
            || record.data.rtype() != type_covered
        {
            return Err(CanonicalError::Rrset);
        }
        rdatas.push(canonical_rdata(&record.data)?);
    }
    // RFC 4034 §6.3: order by canonical RDATA and discard duplicates.
    rdatas.sort_unstable();
    rdatas.dedup();
    let mut out = Vec::new();
    write_rrsig_prefix(
        &mut out,
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer,
    );
    for rdata in &rdatas {
        write_rr(
            &mut out,
            &owner,
            type_covered,
            first.class,
            original_ttl,
            rdata,
        );
    }
    Ok(out)
}
