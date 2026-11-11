use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rand::SystemRandom,
    rsa::KeySize,
    signature::{self, KeyPair as _},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pharos_dnssec::{
    digest::{DigestType, ds_digest, key_tag},
    keys::{KeyPair, PrivateKey, parse_key_pair, parse_pkcs8},
};

const PUBLIC: &str = include_str!("fixtures/Kmiek.nl.+013+59725.key");
const PRIVATE: &str = include_str!("fixtures/Kmiek.nl.+013+59725.private");

#[test]
fn loads_ldns_keygen_bind_files_and_matches_ds() {
    for (public, private, tag, digest) in [
        (
            include_str!("fixtures/Kpharos-test.example.+008+39227.key"),
            include_str!("fixtures/Kpharos-test.example.+008+39227.private"),
            39227,
            "22d72e21f1d953c88bf6a01165d711b5f665fc5d3358e5e63527c5807c4664fa",
        ),
        (
            include_str!("fixtures/Kpharos-test.example.+015+21336.key"),
            include_str!("fixtures/Kpharos-test.example.+015+21336.private"),
            21336,
            "da8b01e8f004d794fed8b169294ab6eea98d2322b8757c8f61f1c1fbd34157b8",
        ),
    ] {
        let pair = parse_key_pair(public, private).unwrap();
        let mut wire = pair.public.flags.to_be_bytes().to_vec();
        wire.extend_from_slice(&[pair.public.protocol, pair.public.algorithm]);
        wire.extend_from_slice(&pair.public.public_key);
        assert_eq!(key_tag(&wire), Some(tag));
        let actual = ds_digest(&pair.public.owner, &wire, DigestType::Sha256);
        let actual: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, digest);
        assert!(parse_pkcs8(public, &pair.private.to_pkcs8_der().unwrap()).is_ok());
    }
}

#[test]
fn loads_coredns_ecdsa_key_pair_and_signs() {
    let pair = parse_key_pair(PUBLIC, PRIVATE).unwrap();
    assert_eq!(pair.public.owner.to_string(), "miek.nl.");
    assert_eq!(
        (
            pair.public.flags,
            pair.public.protocol,
            pair.public.algorithm
        ),
        (257, 3, 13)
    );
    let PrivateKey::Ecdsa(private) = pair.private else {
        panic!("ECDSA expected")
    };
    let signature = private.sign(&SystemRandom::new(), b"test").unwrap();
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, private.public_key())
        .verify(b"test", signature.as_ref())
        .unwrap();
}

#[test]
fn rejects_mismatched_and_invalid_bind_keys() {
    assert!(parse_key_pair(PUBLIC, &PRIVATE.replace("Algorithm: 13", "Algorithm: 14")).is_err());
    assert!(parse_key_pair(PUBLIC, &PRIVATE.replace("rm7E", "am7E")).is_err());
    assert!(parse_key_pair(PUBLIC, &PRIVATE.replace("v1.3", "v1.4")).is_err());
    assert!(parse_key_pair(PUBLIC, &PRIVATE.replace("PrivateKey:", "Unknown:")).is_err());
    assert!(parse_key_pair(&PUBLIC.replace(" DNSKEY ", " A "), PRIVATE).is_err());
    assert!(parse_key_pair(&PUBLIC.replace(" 257 3 13 ", " 257 2 13 "), PRIVATE).is_err());
    assert!(parse_key_pair(&PUBLIC.replace("257 3 13", "257 3 13 ("), PRIVATE).is_err());
    assert!(parse_key_pair(&PUBLIC.replace("257 3 13", "257 3 13 )"), PRIVATE).is_err());
}

#[test]
fn accepts_wrapped_dnskey_and_private_format_v12() {
    let public = PUBLIC.replace("257 3 13 ", "257 3 13 ( ") + " )\n";
    let pair = parse_key_pair(&public, &PRIVATE.replace("v1.3", "v1.2")).unwrap();
    assert_eq!(pair.public.algorithm, 13);
}

#[test]
fn loads_ed25519_bind_and_pkcs8_and_rejects_wrong_public() {
    let rng = SystemRandom::new();
    let der = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let signing = signature::Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let public = format!(
        "example. 300 IN DNSKEY 256 3 15 {}",
        STANDARD.encode(signing.public_key().as_ref())
    );
    let loaded = parse_pkcs8(&public, der.as_ref()).unwrap();
    assert_eq!(loaded.public.ttl, Some(300));
    let PrivateKey::Ed25519(private) = loaded.private else {
        panic!("Ed25519 expected")
    };
    signature::UnparsedPublicKey::new(&signature::ED25519, signing.public_key())
        .verify(b"test", private.sign(b"test").as_ref())
        .unwrap();

    let other = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    assert!(parse_pkcs8(&public, other.as_ref()).is_err());
    assert!(parse_pkcs8(&public, b"not a key").is_err());
}

#[test]
fn bind_keys_export_pkcs8_for_signing() {
    let pair = parse_key_pair(PUBLIC, PRIVATE).unwrap();
    let pkcs8 = pair.private.to_pkcs8_der().unwrap();
    let parsed = parse_pkcs8(PUBLIC, &pkcs8).unwrap();
    assert_eq!(pair.public.public_key, parsed.public.public_key);
}

#[test]
fn loads_generated_p384_bind_pkcs8_and_pem() {
    let key =
        signature::EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
    let encoded = key.to_pkcs8v1().unwrap();
    let public = format!(
        "example. IN DNSKEY 257 3 14 {}",
        STANDARD.encode(&key.public_key().as_ref()[1..])
    );
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(encoded.as_ref())
    );
    assert!(parse_pkcs8(&public, pem.as_bytes()).is_ok());
    let private = format!(
        "Private-key-format: v1.3\nAlgorithm: 14\nPrivateKey: {}\n",
        STANDARD.encode(ec_scalar(encoded.as_ref()))
    );
    let loaded = parse_key_pair(&public, &private).unwrap();
    assert!(parse_pkcs8(&public, &loaded.private.to_pkcs8_der().unwrap()).is_ok());
}

#[test]
fn loads_generated_ed25519_bind_key() {
    let seed = [17u8; 32];
    let key = signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public = format!(
        "example. IN DNSKEY 256 3 15 {}",
        STANDARD.encode(key.public_key().as_ref())
    );
    let private = format!(
        "Private-key-format: v1.3\nAlgorithm: 15\nPrivateKey: {}\n",
        STANDARD.encode(seed)
    );
    let loaded = parse_key_pair(&public, &private).unwrap();
    assert!(parse_pkcs8(&public, &loaded.private.to_pkcs8_der().unwrap()).is_ok());
    assert!(
        parse_key_pair(
            &public,
            &private.replace(&STANDARD.encode(seed), &STANDARD.encode([17u8; 33]))
        )
        .is_err()
    );
}

#[test]
fn loads_generated_rsa_bind_and_pkcs8() {
    let key = signature::RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let encoded: Pkcs8V1Der = key.as_der().unwrap();
    let mut pkcs8 = sequence(encoded.as_ref());
    let _version = take(&mut pkcs8, 2);
    let _algorithm = take(&mut pkcs8, 0x30);
    let mut rsa = sequence(take(&mut pkcs8, 4));
    let _version = take(&mut rsa, 2);
    let values: Vec<_> = (0..8).map(|_| take(&mut rsa, 2)).collect();
    let modulus = unsigned(values[0]);
    let exponent = unsigned(values[1]);
    let mut dnskey = vec![exponent.len() as u8];
    dnskey.extend_from_slice(exponent);
    dnskey.extend_from_slice(modulus);
    let public = format!("example. IN DNSKEY 256 3 8 {}", STANDARD.encode(dnskey));
    let mut private = "Private-key-format: v1.3\nAlgorithm: 8\n".to_owned();
    for (name, value) in [
        "Modulus",
        "PublicExponent",
        "PrivateExponent",
        "Prime1",
        "Prime2",
        "Exponent1",
        "Exponent2",
        "Coefficient",
    ]
    .iter()
    .zip(values)
    {
        private.push_str(&format!("{name}: {}\n", STANDARD.encode(unsigned(value))));
    }
    let loaded = parse_key_pair(&public, &private).unwrap();
    assert!(parse_pkcs8(&public, encoded.as_ref()).is_ok());
    assert!(parse_pkcs8(&public, &loaded.private.to_pkcs8_der().unwrap()).is_ok());
    for algorithm in [5, 7, 8, 10] {
        let public = public.replace(" 3 8 ", &format!(" 3 {algorithm} "));
        let private = private.replace("Algorithm: 8", &format!("Algorithm: {algorithm}"));
        assert!(parse_key_pair(&public, &private).is_ok());
        assert!(parse_pkcs8(&public, encoded.as_ref()).is_ok());
    }
    let PrivateKey::Rsa(key) = loaded.private else {
        panic!("RSA expected")
    };
    let mut signed = vec![0; key.public_modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        b"test",
        &mut signed,
    )
    .unwrap();
    signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key.public_key())
        .verify(b"test", &signed)
        .unwrap();
}

fn unsigned(value: &[u8]) -> &[u8] {
    if value.first() == Some(&0) {
        &value[1..]
    } else {
        value
    }
}

fn take<'a>(input: &mut &'a [u8], tag: u8) -> &'a [u8] {
    assert_eq!(input[0], tag);
    let first = input[1] as usize;
    let (length, start) = if first < 128 {
        (first, 2)
    } else {
        let count = first & 127;
        (
            input[2..2 + count]
                .iter()
                .fold(0, |v, b| v * 256 + *b as usize),
            2 + count,
        )
    };
    let result = &input[start..start + length];
    *input = &input[start + length..];
    result
}

fn sequence(input: &[u8]) -> &[u8] {
    take(&mut &*input, 0x30)
}

fn ec_scalar(input: &[u8]) -> &[u8] {
    let mut pkcs8 = sequence(input);
    let _version = take(&mut pkcs8, 2);
    let _algorithm = take(&mut pkcs8, 0x30);
    let mut ec = sequence(take(&mut pkcs8, 4));
    let _version = take(&mut ec, 2);
    take(&mut ec, 4)
}

#[test]
fn loads_key_pair_from_paths() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/Kmiek.nl.+013+59725"
    );
    let pair = KeyPair::from_files(format!("{base}.key"), format!("{base}.private")).unwrap();
    assert_eq!(pair.public.algorithm, 13);
    assert!(KeyPair::from_files(format!("{base}.key"), "missing.private").is_err());
}
