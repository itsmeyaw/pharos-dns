//! Construction of DNSSEC denial records; callers supply authoritative Zone data.

use std::{collections::BTreeMap, fmt};

use aws_lc_rs::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use pharos_proto::{Name, NameRef, Rdata, Type};

/// One authoritative owner name and the RR types present at that name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneName {
    pub name: Name,
    pub types: Vec<Type>,
}

/// An error constructing denial records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialError {
    OutOfZone,
    MissingApex,
    InvalidType,
    SaltTooLong,
    NameTooLong,
    HashCollision,
}

impl fmt::Display for DenialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutOfZone => "owner name is outside the Zone",
            Self::MissingApex => "Zone Apex is missing",
            Self::InvalidType => "meta-type or QTYPE cannot appear in a type bitmap",
            Self::SaltTooLong => "NSEC3 salt exceeds 255 octets",
            Self::NameTooLong => "generated domain name is too long",
            Self::HashCollision => "NSEC3 hash collision; choose a different salt",
        })
    }
}

impl std::error::Error for DenialError {}

/// Encodes RR types in canonical NSEC/NSEC3 bitmap windows.
pub fn type_bitmap(types: &[Type]) -> Result<Vec<u8>, DenialError> {
    let mut types = types.to_vec();
    // RFC 5155 §3.2.1: meta-types and QTYPEs cannot be asserted in a bitmap.
    if types
        .iter()
        .any(|t| matches!(t.0, 0 | 41 | 129..=255 | 65535))
    {
        return Err(DenialError::InvalidType);
    }
    types.sort_unstable();
    types.dedup();
    let mut out = Vec::new();
    let mut pos = 0;
    // RFC 4034 §4.1.2: windows are ordered and trailing zero octets are omitted.
    while pos < types.len() {
        let window = types[pos].0 >> 8;
        let end = pos + types[pos..].partition_point(|t| t.0 >> 8 == window);
        let len = usize::from((types[end - 1].0 & 255) / 8 + 1);
        out.push(window as u8);
        out.push(len as u8);
        let start = out.len();
        out.resize(start + len, 0);
        for t in &types[pos..end] {
            let bit = usize::from(t.0 & 255);
            out[start + bit / 8] |= 0x80 >> (bit % 8);
        }
        pos = end;
    }
    Ok(out)
}

/// An NSEC record without class or TTL, for use with a Message builder or signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec {
    pub owner: Name,
    pub next: Name,
    pub bitmap: Vec<u8>,
}

impl Nsec {
    /// Borrows the typed RDATA from this record.
    #[must_use]
    pub fn rdata(&self) -> Rdata<'_> {
        Rdata::Nsec {
            next: NameRef::parse(self.next.as_wire(), 0).expect("Name is valid"),
            bitmap: &self.bitmap,
        }
    }

    /// Tests whether a type is asserted in this record's bitmap.
    #[must_use]
    pub fn bitmap_contains(&self, rtype: Type) -> bool {
        let mut remaining = self.bitmap.as_slice();
        while remaining.len() >= 2 {
            let window = remaining[0];
            let len = usize::from(remaining[1]);
            if remaining.len() < len + 2 {
                return false;
            }
            if u16::from(window) == rtype.0 >> 8 {
                let bit = usize::from(rtype.0 & 255);
                return bit / 8 < len && remaining[2 + bit / 8] & (0x80 >> (bit % 8)) != 0;
            }
            remaining = &remaining[2 + len..];
        }
        false
    }
}

fn zone_names(apex: &Name, names: &[ZoneName]) -> Result<BTreeMap<Name, Vec<Type>>, DenialError> {
    let mut owners = BTreeMap::<Name, Vec<Type>>::new();
    for entry in names {
        if !entry.name.is_subdomain_of(apex) {
            return Err(DenialError::OutOfZone);
        }
        owners
            .entry(entry.name.clone())
            .or_default()
            .extend_from_slice(&entry.types);
    }
    Ok(owners)
}

/// Builds a circular NSEC chain from authoritative owner names in canonical order.
///
/// Include the Apex's SOA and NS types and exclude glue and other non-authoritative data.
pub fn nsec_chain(apex: &Name, names: &[ZoneName]) -> Result<Vec<Nsec>, DenialError> {
    let owners = zone_names(apex, names)?;
    // RFC 4035 §2.3: the Zone Apex participates in the NSEC chain.
    if !owners.contains_key(apex) {
        return Err(DenialError::MissingApex);
    }
    let owners = owners.into_iter().collect::<Vec<_>>();
    let mut records = Vec::with_capacity(owners.len());
    // RFC 4034 §4.1.1: the last NSEC points back to the first canonical owner.
    for (i, (owner, types)) in owners.iter().enumerate() {
        let mut types = types.clone();
        types.extend([Type::RRSIG, Type::NSEC]);
        records.push(Nsec {
            owner: owner.clone(),
            next: owners[(i + 1) % owners.len()].0.clone(),
            bitmap: type_bitmap(&types)?,
        });
    }
    Ok(records)
}

/// Whether a black lie is for a negative response or a referral.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlackLieKind {
    Negative,
    Referral,
}

/// Creates the CoreDNS-style synthetic NSEC; sign it and convert NXDOMAIN to NODATA.
///
/// A caller must ensure the synthetic span does not cover existing names.
pub fn black_lie(
    qname: &Name,
    apex: &Name,
    qtype: Type,
    kind: BlackLieKind,
) -> Result<Nsec, DenialError> {
    if !qname.is_subdomain_of(apex) {
        return Err(DenialError::OutOfZone);
    }
    let at_apex = qname == apex;
    let zone_cut = !at_apex && (kind == BlackLieKind::Referral || qtype == Type::DS);
    let mut types = vec![
        Type::A,
        Type::HINFO,
        Type::TXT,
        Type::AAAA,
        Type::LOC,
        Type::SRV,
        Type::CERT,
        Type::SSHFP,
        Type::RRSIG,
        Type::NSEC,
        Type::TLSA,
        Type::HIP,
        Type::OPENPGPKEY,
        Type::SPF,
    ];
    if at_apex {
        types.extend([Type::NS, Type::SOA, Type::MX, Type::DNSKEY]);
    } else if zone_cut {
        types.push(Type::NS);
    }
    if !zone_cut && kind == BlackLieKind::Negative && qtype != Type::NSEC {
        types.retain(|t| *t != qtype);
    }
    // RFC 4470 §3: synthetic NSEC spans must not cover existing names.
    let mut wire = qname.as_wire().to_vec();
    if kind == BlackLieKind::Referral && !at_apex {
        // Append a zero octet to the first label for a minimal Referral span.
        let len = usize::from(wire[0]);
        if len == 63 {
            return Err(DenialError::NameTooLong);
        }
        wire[0] += 1;
        wire.insert(1 + len, 0);
    } else {
        wire.splice(0..0, [1, 0]);
    }
    let next = NameRef::parse(&wire, 0)
        .map_err(|_| DenialError::NameTooLong)?
        .to_name();
    Ok(Nsec {
        owner: qname.clone(),
        next,
        bitmap: type_bitmap(&types)?,
    })
}

/// Computes the binary NSEC3 SHA-1 hash using canonical uncompressed name wire data.
pub fn nsec3_hash(name: &Name, iterations: u16, salt: &[u8]) -> Result<[u8; 20], DenialError> {
    if salt.len() > 255 {
        return Err(DenialError::SaltTooLong);
    }
    // RFC 5155 §5: hash the canonical name and salt, then hash each prior digest with salt.
    let wire = name
        .as_wire()
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(&wire);
    context.update(salt);
    let mut hash: [u8; 20] = context
        .finish()
        .as_ref()
        .try_into()
        .expect("SHA-1 is 20 octets");
    for _ in 0..iterations {
        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(&hash);
        context.update(salt);
        hash.copy_from_slice(context.finish().as_ref());
    }
    Ok(hash)
}

/// Encodes an NSEC3 SHA-1 digest as an unpadded base32hex label.
#[must_use]
pub fn nsec3_hash_label(hash: &[u8; 20]) -> String {
    // RFC 5155 §3.3: hashed owner labels use unpadded base32 extended hex.
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut label = String::with_capacity(32);
    for chunk in hash.as_chunks::<5>().0 {
        let bits = chunk
            .iter()
            .fold(0u64, |n, byte| (n << 8) | u64::from(*byte));
        for shift in (0..8).rev() {
            label.push(char::from(ALPHABET[((bits >> (shift * 5)) & 31) as usize]));
        }
    }
    label
}

/// An NSEC3 record without class or TTL, including its original owner for lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec3 {
    pub original: Name,
    pub owner: Name,
    pub hash: [u8; 20],
    pub next_hash: [u8; 20],
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub bitmap: Vec<u8>,
}

impl Nsec3 {
    /// Borrows the typed RDATA from this record.
    #[must_use]
    pub fn rdata(&self) -> Rdata<'_> {
        Rdata::Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: self.iterations,
            salt: &self.salt,
            next_owner: &self.next_hash,
            bitmap: &self.bitmap,
        }
    }
}

/// Builds a complete non-opt-out NSEC3 chain, including empty non-terminals.
///
/// Include Apex NSEC3PARAM and all RRSIG types that exist at original owners;
/// exclude glue, data below Zone Cuts, and types belonging solely to NSEC3 RRs.
pub fn nsec3_chain(
    apex: &Name,
    names: &[ZoneName],
    iterations: u16,
    salt: &[u8],
) -> Result<Vec<Nsec3>, DenialError> {
    if salt.len() > 255 {
        return Err(DenialError::SaltTooLong);
    }
    let mut owners = zone_names(apex, names)?;
    if !owners.contains_key(apex) {
        return Err(DenialError::MissingApex);
    }
    // RFC 5155 §7.1: every empty non-terminal has an NSEC3 record with an empty bitmap.
    for entry in names {
        let mut parent = entry.name.parent();
        while let Some(name) = parent {
            if !name.is_subdomain_of(apex) {
                break;
            }
            parent = name.parent();
            owners.entry(name).or_default();
        }
    }
    let mut records = Vec::with_capacity(owners.len());
    for (original, mut types) in owners {
        // RFC 5155 §7.1: NSEC3 itself is never asserted in the original owner's bitmap.
        types.retain(|t| *t != Type::NSEC3);
        let hash = nsec3_hash(&original, iterations, salt)?;
        let owner_text = if apex.as_wire() == [0] {
            format!("{}.", nsec3_hash_label(&hash))
        } else {
            format!("{}.{}", nsec3_hash_label(&hash), apex)
        };
        let owner = owner_text.parse().map_err(|_| DenialError::NameTooLong)?;
        records.push(Nsec3 {
            original,
            owner,
            hash,
            next_hash: hash,
            iterations,
            salt: salt.to_vec(),
            bitmap: type_bitmap(&types)?,
        });
    }
    // RFC 5155 §7.1: sort by binary hash, reject collisions, and link circularly.
    records.sort_unstable_by_key(|r| r.hash);
    if records.windows(2).any(|pair| pair[0].hash == pair[1].hash) {
        return Err(DenialError::HashCollision);
    }
    for i in 0..records.len() {
        records[i].next_hash = records[(i + 1) % records.len()].hash;
    }
    Ok(records)
}
