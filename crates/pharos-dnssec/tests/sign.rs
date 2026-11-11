#![forbid(unsafe_code)]

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::KeySize,
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, UnparsedPublicKey},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pharos_dnssec::{
    canonical::{CanonicalRecord, signed_data},
    digest::key_tag,
    sign::{SignError, SigningKey},
};
use pharos_proto::{Class, Name, NameRef, Rdata, Type};

const MESSAGE: &[u8] = b"canonical RRSIG fields and RRset";

#[test]
fn rsa_signatures_verify_as_pkcs1_v15() {
    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let der = key.as_der().unwrap();
    for (algorithm, verifier) in [
        (8, &signature::RSA_PKCS1_2048_8192_SHA256),
        (10, &signature::RSA_PKCS1_2048_8192_SHA512),
    ] {
        let signer = SigningKey::from_pkcs8(algorithm, der.as_ref()).unwrap();
        let signed = signer.sign(MESSAGE).unwrap();
        let verifier = UnparsedPublicKey::new(verifier, key.public_key().as_ref());
        assert_eq!(signed.len(), 256);
        assert!(verifier.verify(MESSAGE, &signed).is_ok());
        assert!(verifier.verify(b"altered", &signed).is_err());
    }
}

#[test]
fn ecdsa_signatures_are_fixed_width_dns_wire_format() {
    let random = SystemRandom::new();
    for (number, signer, verifier, size) in [
        (
            13,
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &signature::ECDSA_P256_SHA256_FIXED,
            64,
        ),
        (
            14,
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &signature::ECDSA_P384_SHA384_FIXED,
            96,
        ),
    ] {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(signer, &random).unwrap();
        let original = EcdsaKeyPair::from_pkcs8(signer, pkcs8.as_ref()).unwrap();
        let key = SigningKey::from_pkcs8(number, pkcs8.as_ref()).unwrap();
        let signed = key.sign(MESSAGE).unwrap();
        let verifier = UnparsedPublicKey::new(verifier, original.public_key().as_ref());
        assert_eq!(signed.len(), size);
        assert!(verifier.verify(MESSAGE, &signed).is_ok());
        assert!(verifier.verify(b"altered", &signed).is_err());
    }
}

#[test]
fn ed25519_matches_rfc_8032_vector() {
    // RFC 8032 §7.1: first Ed25519 test vector, with a PKCS#8 seed wrapper.
    let pkcs8 = hex(
        "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    let key = SigningKey::from_pkcs8(15, &pkcs8).unwrap();
    let signature = key.sign(b"").unwrap();
    assert_eq!(
        signature,
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
        5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    let original = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    let verifier = UnparsedPublicKey::new(&signature::ED25519, original.public_key().as_ref());
    assert!(verifier.verify(b"", &signature).is_ok());
    assert!(verifier.verify(b"altered", &signature).is_err());
}

#[test]
fn invalid_keys_and_unsupported_algorithms_fail_closed() {
    assert!(matches!(
        SigningKey::from_pkcs8(253, &[]),
        Err(SignError::UnsupportedAlgorithm(253))
    ));
    assert!(matches!(
        SigningKey::from_pkcs8(5, &[]),
        Err(SignError::UnsupportedAlgorithm(5))
    ));
    for algorithm in [8, 10, 13, 14, 15] {
        assert!(matches!(
            SigningKey::from_pkcs8(algorithm, &[]),
            Err(SignError::InvalidKey)
        ));
    }
}

#[test]
fn accepts_parsed_keypairs_and_rejects_wrong_algorithm() {
    let random = SystemRandom::new();
    let rsa = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let public = rsa.public_key().as_ref().to_vec();
    let signer = SigningKey::from_rsa(8, rsa).unwrap();
    let signed = signer.sign(MESSAGE).unwrap();
    UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public)
        .verify(MESSAGE, &signed)
        .unwrap();

    let ecdsa = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    assert!(matches!(
        SigningKey::from_ecdsa(14, ecdsa),
        Err(SignError::InvalidKey)
    ));
    let der = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let ed = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let public = ed.public_key().as_ref().to_vec();
    let signed = SigningKey::from_ed25519(ed).sign(MESSAGE).unwrap();
    UnparsedPublicKey::new(&signature::ED25519, public)
        .verify(MESSAGE, &signed)
        .unwrap();
}

#[test]
fn emit_miekg_dns_verification_vectors() {
    let rsa = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let rsa_der = rsa.as_der().unwrap();
    let public = rsa.public_key();
    let exponent = public.exponent().big_endian_without_leading_zero();
    let modulus = public.modulus().big_endian_without_leading_zero();
    // RFC 3110 §2: the exponent length precedes the exponent and modulus.
    let mut rsa_public = vec![u8::try_from(exponent.len()).unwrap()];
    rsa_public.extend_from_slice(exponent);
    rsa_public.extend_from_slice(modulus);
    for algorithm in [8, 10] {
        let signer = SigningKey::from_pkcs8(algorithm, rsa_der.as_ref()).unwrap();
        emit_vector(algorithm, &rsa_public, &signer);
    }

    for (algorithm, method) in [
        (13, &signature::ECDSA_P256_SHA256_FIXED_SIGNING),
        (14, &signature::ECDSA_P384_SHA384_FIXED_SIGNING),
    ] {
        let key = EcdsaKeyPair::generate(method).unwrap();
        // RFC 6605 §4: DNSKEY holds x || y without the SEC1 0x04 prefix.
        let public = key.public_key().as_ref()[1..].to_vec();
        emit_vector(
            algorithm,
            &public,
            &SigningKey::from_ecdsa(algorithm, key).unwrap(),
        );
    }
    let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let public = key.public_key().as_ref().to_vec();
    emit_vector(15, &public, &SigningKey::from_ed25519(key));
}

fn emit_vector(algorithm: u8, public: &[u8], key: &SigningKey) {
    let mut dnskey = vec![1, 0, 3, algorithm];
    dnskey.extend_from_slice(public);
    let tag = key_tag(&dnskey).unwrap();
    let signer: Name = "Example.Org.".parse().unwrap();
    let owner: Name = "WWW.Example.Org.".parse().unwrap();
    let signer = NameRef::parse(signer.as_wire(), 0).unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    let sig = Rdata::Rrsig {
        type_covered: Type::A,
        algorithm,
        labels: 3,
        original_ttl: 300,
        expiration: 2_000_000_000,
        inception: 1_600_000_000,
        key_tag: tag,
        signer,
        signature: &[],
    };
    let input = signed_data(
        &sig,
        &[CanonicalRecord {
            owner,
            class: Class::IN,
            data: Rdata::A("192.0.2.1".parse().unwrap()),
        }],
    )
    .unwrap();
    let signed = key.sign(&input).unwrap();
    println!(
        "PHAROS_SIGN_VECTOR {algorithm} {tag} {} {}",
        STANDARD.encode(public),
        STANDARD.encode(signed)
    );
}

fn hex(input: &str) -> Vec<u8> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
