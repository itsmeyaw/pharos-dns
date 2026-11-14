use aws_lc_rs::signature;
use pharos_dnssec::{
    canonical::{CanonicalRecord, signed_data},
    digest::{key_tag, signature_valid_at},
    keys::Dnskey,
};
use pharos_proto::{Message, Rdata, Type};

pub(crate) fn validate_response(
    message: &Message<'_>,
    key: &Dnskey,
    now: u32,
) -> Result<(), String> {
    let mut rdata = key.flags.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[key.protocol, key.algorithm]);
    rdata.extend_from_slice(&key.public_key);
    // RFC 4034 Appendix B: The DNSKEY RDATA key tag selects a matching key.
    let tag = key_tag(&rdata).ok_or("invalid DNSKEY")?;
    let (algorithm, public): (&dyn signature::VerificationAlgorithm, Vec<u8>) = match key.algorithm
    {
        13 => (
            &signature::ECDSA_P256_SHA256_FIXED,
            [&[4][..], &key.public_key].concat(),
        ),
        // RFC 8080 §3: Ed25519 DNSKEY public keys are raw 32-octet verification keys.
        15 => (&signature::ED25519, key.public_key.clone()),
        _ => return Err("unsupported test DNSKEY algorithm".into()),
    };
    let verifier = signature::UnparsedPublicKey::new(algorithm, public);
    let mut checked = 0;
    for records in [
        message.answers().collect::<Vec<_>>(),
        message.authorities().collect(),
    ] {
        for rr in &records {
            let data = rr.data().map_err(|e| e.to_string())?;
            let Rdata::Rrsig {
                type_covered,
                algorithm,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
                ..
            } = data
            else {
                continue;
            };
            // RFC 4035 §5.3.1: Signer, key tag, algorithm, validity, and RRset must agree.
            // RFC 4034 §B: Key tags narrow candidates but do not uniquely identify a DNSKEY.
            if signer != key.owner
                || key_tag != tag
                || algorithm != key.algorithm
                || !signature_valid_at(inception, expiration, now)
            {
                return Err("invalid RRSIG metadata or validity".into());
            }
            let rrset = records
                .iter()
                .filter(|record| {
                    record.name == rr.name
                        && record.class == rr.class
                        && record.rtype == type_covered
                })
                .map(|record| {
                    Ok(CanonicalRecord {
                        owner: record.name,
                        class: record.class,
                        data: record.data().map_err(|e| e.to_string())?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let input = signed_data(&data, &rrset).map_err(|e| e.to_string())?;
            // RFC 8032 §5.1.7: Verify Ed25519 signatures using the key and signed data.
            verifier
                .verify(&input, signature)
                .map_err(|_| "invalid DNSSEC signature")?;
            checked += 1;
        }
        for record in records.iter().filter(|r| r.rtype != Type::RRSIG) {
            let covered = records.iter().any(|sig| sig.name == record.name && sig.class == record.class && matches!(sig.data(), Ok(Rdata::Rrsig { type_covered, .. }) if type_covered == record.rtype));
            if !covered {
                return Err(format!("unsigned RRset: {} {}", record.name, record.rtype));
            }
        }
    }
    if checked == 0 {
        return Err("Response contains no RRSIG".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use pharos_dnssec::{
        canonical::{CanonicalRecord, signed_data},
        digest::key_tag,
        keys::Dnskey,
        sign::SigningKey,
    };
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};

    #[test]
    fn validates_rrsets_and_rejects_corruption_or_missing_signature() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let private = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = private.public_key().as_ref();
        let owner: Name = "example.org.".parse().unwrap();
        let name = NameRef::parse(owner.as_wire(), 0).unwrap();
        let key = Dnskey {
            owner: owner.clone(),
            ttl: None,
            flags: 257,
            protocol: 3,
            algorithm: 15,
            public_key: public.to_vec(),
        };
        let mut key_rdata = vec![1, 1, 3, 15];
        key_rdata.extend_from_slice(public);
        let record = Rdata::A("192.0.2.1".parse().unwrap());
        let mut sig = Rdata::Rrsig {
            type_covered: Type::A,
            algorithm: 15,
            labels: 2,
            original_ttl: 60,
            expiration: 2000,
            inception: 1000,
            key_tag: key_tag(&key_rdata).unwrap(),
            signer: name,
            signature: &[],
        };
        let input = signed_data(
            &sig,
            &[CanonicalRecord {
                owner: name,
                class: Class::IN,
                data: record,
            }],
        )
        .unwrap();
        let signer = SigningKey::from_ed25519(private);
        let signature = signer.sign(&input).unwrap();
        if let Rdata::Rrsig {
            signature: bytes, ..
        } = &mut sig
        {
            *bytes = &signature;
        }
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 65535, 0, 0x8400).unwrap();
        builder
            .record_with(Section::Answer, name, Type::A, Class::IN, 60, |w| {
                record.write(w)
            })
            .unwrap();
        builder
            .record_with(Section::Answer, name, Type::RRSIG, Class::IN, 60, |w| {
                sig.write(w)
            })
            .unwrap();
        let _ = builder.finish();
        assert!(super::validate_response(&Message::parse(&wire).unwrap(), &key, 1500).is_ok());
        assert!(super::validate_response(&Message::parse(&wire).unwrap(), &key, 2500).is_err());
        *wire.last_mut().unwrap() ^= 1;
        assert!(super::validate_response(&Message::parse(&wire).unwrap(), &key, 1500).is_err());
        let mut unsigned = Vec::new();
        let mut builder = MessageBuilder::new(&mut unsigned, 65535, 0, 0x8400).unwrap();
        builder
            .record_with(Section::Answer, name, Type::A, Class::IN, 60, |w| {
                record.write(w)
            })
            .unwrap();
        let _ = builder.finish();
        assert!(super::validate_response(&Message::parse(&unsigned).unwrap(), &key, 1500).is_err());
    }
}
