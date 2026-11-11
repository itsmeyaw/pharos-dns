use pharos_proto::{Message, Name, TsigAlgorithm, TsigError, TsigKey, TsigRecord, TsigStream};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// miekg/dns TestTsigErrors: a complete independently signed UPDATE Message.
#[test]
fn verifies_miekg_message_and_checks_mac_before_time() {
    let wire = hex(concat!(
        "c60028000001000000010001076578616d706c6503636f6d00000600010161c00c0001000100000e100004c0000201",
        "07746573746b65790000fa00ff00000000003d0b686d61632d7368613235360000005f0f9043012c0020",
        "8cf23e0081d915478a182edcea7ff48ad102948e6c7ef8e887536957d1fa5616c60000000000"
    ));
    let name: Name = "testkey.".parse().unwrap();
    let key = TsigKey::new(
        name,
        TsigAlgorithm::Sha256,
        &hex("3684c2254f8332a156cb068fcb14a28eb0c403f782de72b4c62dc030466e3d59"),
    );
    assert!(key.verify(&wire, 1594855491, None, 0).is_ok());
    assert_eq!(
        key.verify(&wire, 1594855792, None, 0).unwrap_err(),
        TsigError::BadTime
    );
    let mut tampered = wire;
    tampered[3] ^= 1;
    assert_eq!(
        key.verify(&tampered, 1594855792, None, 0).unwrap_err(),
        TsigError::BadSig
    );
}

#[test]
fn signs_miekg_fixture_byte_for_byte() {
    let mut wire = hex(
        "c60028000001000000010000076578616d706c6503636f6d00000600010161c00c0001000100000e100004c0000201",
    );
    let key = TsigKey::new(
        "testkey.".parse().unwrap(),
        TsigAlgorithm::Sha256,
        &hex("3684c2254f8332a156cb068fcb14a28eb0c403f782de72b4c62dc030466e3d59"),
    );
    key.sign(&mut wire, 1594855491, 300, None).unwrap();
    let parsed = key.verify(&wire, 1594855491, None, 0).unwrap();
    assert_eq!(
        parsed.mac,
        hex("8cf23e0081d915478a182edcea7ff48ad102948e6c7ef8e887536957d1fa5616")
    );
}

#[test]
fn stream_chains_every_response_and_requires_signed_endpoints() {
    let key = TsigKey::new(
        "testkey.".parse().unwrap(),
        TsigAlgorithm::Sha256,
        b"test secret",
    );
    let query_mac = [42; 32];
    let mut signer = TsigStream::new(&key, &query_mac);
    let mut first = hex("000180000000000000000000");
    let mut second = hex("000180000000000000000000");
    signer.sign(&mut first, 1000, 300).unwrap();
    signer.sign(&mut second, 1001, 300).unwrap();

    let mut verifier = TsigStream::new(&key, &query_mac);
    assert!(verifier.verify(&first, 1000, 0).unwrap().is_some());
    assert!(verifier.verify(&second, 1001, 0).unwrap().is_some());
    verifier.finish().unwrap();
    let mut wrong = TsigStream::new(&key, &[0; 32]);
    assert_eq!(
        wrong.verify(&first, 1000, 0).unwrap_err(),
        TsigError::BadSig
    );
    let mut incomplete = TsigStream::new(&key, &query_mac);
    incomplete.verify(&first, 1000, 0).unwrap();
    assert!(
        incomplete
            .verify(&hex("000180000000000000000000"), 1000, 0)
            .unwrap()
            .is_none()
    );
    assert_eq!(incomplete.finish(), Err(TsigError::Format));
}

#[test]
fn badtime_is_signed_but_bad_signature_response_is_unsigned() {
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let mut query = hex("000100000000000000000000");
    key.sign(&mut query, 1000, 30, None).unwrap();
    let query_mac = TsigRecord::parse(&query).unwrap().mac.to_vec();
    let mut response = hex("000180000000000000000000");
    assert_eq!(
        key.sign_error_response(&mut response, &query, 1000, 0)
            .unwrap(),
        None
    );
    assert_eq!(response, hex("000180000000000000000000"));
    let wrong_key = TsigKey::new("other.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let mut badkey = response.clone();
    assert_eq!(
        wrong_key
            .sign_error_response(&mut badkey, &query, 1000, 0)
            .unwrap(),
        Some(TsigError::BadKey)
    );
    let badkey_tsig = TsigRecord::parse(&badkey).unwrap();
    assert_eq!(badkey_tsig.error, 17);
    assert!(badkey_tsig.mac.is_empty());
    let mut invalid_query = query.clone();
    let error_offset = invalid_query.len() - 4;
    invalid_query[error_offset + 1] = 16;
    assert_eq!(
        key.verify(&invalid_query, 1000, None, 0).unwrap_err(),
        TsigError::Format
    );
    assert_eq!(
        key.sign_error_response(&mut response, &query, 1100, 0)
            .unwrap(),
        Some(TsigError::BadTime)
    );
    assert_eq!(Message::parse(&response).unwrap().rcode().0, 9);
    let tsig = key.verify(&response, 1000, Some(&query_mac), 0).unwrap();
    assert_eq!(tsig.error, 18);
    assert_eq!(tsig.time_signed, 1000);
    assert_eq!(tsig.other, &1100u64.to_be_bytes()[2..]);

    query[3] ^= 1;
    let mut response = hex("000180000000000000000000");
    assert_eq!(
        key.sign_error_response(&mut response, &query, 1100, 0)
            .unwrap(),
        Some(TsigError::BadSig)
    );
    let tsig = TsigRecord::parse(&response).unwrap();
    assert_eq!(tsig.error, 16);
    assert_eq!(tsig.mac.len(), 0);
    assert_eq!(tsig.time_signed, 0);
}

#[test]
fn miekg_interoperability_for_all_algorithms_and_streams() {
    let secret = hex("3684c2254f8332a156cb068fcb14a28eb0c403f782de72b4c62dc030466e3d59");
    let mut lines = include_str!("corpus/tsig-miekg.txt").lines();
    for algorithm in [
        TsigAlgorithm::Md5,
        TsigAlgorithm::Sha1,
        TsigAlgorithm::Sha224,
        TsigAlgorithm::Sha256,
        TsigAlgorithm::Sha384,
        TsigAlgorithm::Sha512,
    ] {
        let query = hex(lines.next().unwrap().split_whitespace().nth(1).unwrap());
        let response = hex(lines.next().unwrap().split_whitespace().nth(1).unwrap());
        let next = hex(lines.next().unwrap().split_whitespace().nth(1).unwrap());
        let key = TsigKey::new("testkey.".parse().unwrap(), algorithm, &secret);
        let query_mac = key.verify(&query, 1594855491, None, 0).unwrap().mac;
        let mut generated_query = hex("c60028000001000000000000076578616d706c6503636f6d0000060001");
        key.sign(&mut generated_query, 1594855491, 300, None)
            .unwrap();
        assert_eq!(generated_query, query);
        let mut signer = TsigStream::new(&key, query_mac);
        let mut verifier = TsigStream::new(&key, query_mac);
        for expected in [&response, &next] {
            assert!(verifier.verify(expected, 1594855491, 0).unwrap().is_some());
            let mut generated = hex("c60080000000000000000000");
            signer.sign(&mut generated, 1594855491, 300).unwrap();
            assert_eq!(&generated, expected);
        }
        verifier.finish().unwrap();
    }
}

#[test]
fn truncated_mac_respects_format_time_and_local_policy_order() {
    let secret = hex("3684c2254f8332a156cb068fcb14a28eb0c403f782de72b4c62dc030466e3d59");
    let key = TsigKey::new("testkey.".parse().unwrap(), TsigAlgorithm::Sha256, &secret);
    let mut full = hex("c60028000001000000000000076578616d706c6503636f6d0000060001");
    key.sign(&mut full, 1000, 30, None).unwrap();
    let rr = Message::parse(&full).unwrap().additionals().next().unwrap();
    let length_offset = rr.ttl_offset + 4;
    let mac_start = full.len() - 6 - 32;
    let old_rdata_len = u16::from_be_bytes([full[length_offset], full[length_offset + 1]]);
    let truncate = |len: usize| {
        let mut msg = full.clone();
        msg.drain(mac_start + len..mac_start + 32);
        msg[length_offset..length_offset + 2]
            .copy_from_slice(&(old_rdata_len - (32 - len) as u16).to_be_bytes());
        msg[mac_start - 2..mac_start].copy_from_slice(&(len as u16).to_be_bytes());
        msg
    };
    let short = truncate(16);
    let mut signed_short = hex("c60028000001000000000000076578616d706c6503636f6d0000060001");
    key.sign_truncated(&mut signed_short, 1000, 30, None, 16)
        .unwrap();
    assert_eq!(signed_short, short);
    assert!(key.verify(&short, 1000, None, 0).is_ok());
    assert_eq!(
        key.verify(&short, 1000, None, 17).unwrap_err(),
        TsigError::BadTrunc
    );
    assert_eq!(
        key.verify(&short, 1031, None, 17).unwrap_err(),
        TsigError::BadTime
    );
    let mut bad = short.clone();
    bad[mac_start] ^= 1;
    assert_eq!(
        key.verify(&bad, 1031, None, 17).unwrap_err(),
        TsigError::BadSig
    );
    assert_eq!(
        key.verify(&truncate(15), 1000, None, 0).unwrap_err(),
        TsigError::Format
    );
    let mut response = hex("c60080000000000000000000");
    assert_eq!(
        key.sign_error_response(&mut response, &short, 1000, 17)
            .unwrap(),
        Some(TsigError::BadTrunc)
    );
    let record = key
        .verify(&response, 1000, Some(&short[mac_start..mac_start + 16]), 0)
        .unwrap();
    assert_eq!(record.error, 22);
}

#[test]
fn unsigned_intermediate_is_covered_and_limited() {
    let secret = hex("3684c2254f8332a156cb068fcb14a28eb0c403f782de72b4c62dc030466e3d59");
    let key = TsigKey::new("testkey.".parse().unwrap(), TsigAlgorithm::Sha256, &secret);
    let lines: Vec<_> = include_str!("corpus/tsig-miekg.txt").lines().collect();
    let query = hex(lines[9].split_whitespace().nth(1).unwrap());
    let first = hex(lines[10].split_whitespace().nth(1).unwrap());
    // Independently computed with Python hmac over prior MAC, both Messages and timers.
    let last = hex(
        "c6008000000000000000000107746573746b65790000fa00ff00000000003d0b686d61632d7368613235360000005f0f9043012c002008286d64268c92a303a9cca5ce2016eac2d09b4e49b092427c88df2474c9e33ac60000000000",
    );
    let query_mac = TsigRecord::parse(&query).unwrap().mac;
    let unsigned = hex("c60080000000000000000000");
    let mut signer = TsigStream::new(&key, query_mac);
    let mut generated_first = unsigned.clone();
    signer.sign(&mut generated_first, 1594855491, 300).unwrap();
    signer.add_unsigned(&unsigned).unwrap();
    let mut generated_last = unsigned.clone();
    signer.sign(&mut generated_last, 1594855491, 300).unwrap();
    assert_eq!(generated_last, last);
    let mut verifier = TsigStream::new(&key, query_mac);
    verifier.verify(&first, 1594855491, 0).unwrap();
    assert!(verifier.verify(&unsigned, 1594855491, 0).unwrap().is_none());
    verifier.verify(&last, 1594855491, 0).unwrap();
    verifier.finish().unwrap();
    let mut forged_error = last.clone();
    let error_offset = forged_error.len() - 4;
    forged_error[error_offset + 1] = 18;
    let mut verifier = TsigStream::new(&key, query_mac);
    verifier.verify(&first, 1594855491, 0).unwrap();
    verifier.verify(&unsigned, 1594855491, 0).unwrap();
    assert_eq!(
        verifier.verify(&forged_error, 1594855491, 0).unwrap_err(),
        TsigError::Format
    );
    let mut altered = unsigned.clone();
    altered[3] ^= 1;
    let mut verifier = TsigStream::new(&key, query_mac);
    verifier.verify(&first, 1594855491, 0).unwrap();
    verifier.verify(&altered, 1594855491, 0).unwrap();
    assert_eq!(
        verifier.verify(&last, 1594855491, 0).unwrap_err(),
        TsigError::BadSig
    );
    let mut verifier = TsigStream::new(&key, query_mac);
    verifier.verify(&first, 1594855491, 0).unwrap();
    for _ in 0..99 {
        verifier.verify(&unsigned, 1594855491, 0).unwrap();
    }
    assert_eq!(
        verifier.verify(&unsigned, 1594855491, 0).unwrap_err(),
        TsigError::Format
    );
}

#[test]
fn stream_time_does_not_move_backwards() {
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let query_mac = [42; 32];
    let mut signer = TsigStream::new(&key, &query_mac);
    let mut first = hex("000180000000000000000000");
    signer.sign(&mut first, 1000, 300).unwrap();
    let mut next = hex("000180000000000000000000");
    assert_eq!(signer.sign(&mut next, 999, 300), Err(TsigError::BadTime));

    let secret = hex("3684c2254f8332a156cb068fcb14a28eb0c403f782de72b4c62dc030466e3d59");
    let key = TsigKey::new("testkey.".parse().unwrap(), TsigAlgorithm::Sha256, &secret);
    let lines: Vec<_> = include_str!("corpus/tsig-miekg.txt").lines().collect();
    let query = hex(lines[9].split_whitespace().nth(1).unwrap());
    let first = hex(lines[10].split_whitespace().nth(1).unwrap());
    // miekg/dns generated with timers-only and a one-second earlier timestamp.
    let earlier = hex(
        "c6008000000000000000000107746573746b65790000fa00ff00000000003d0b686d61632d7368613235360000005f0f9042012c00206aeb47f475280d4c87016d147056e0d9f51efcb01c7927fbc847130b6b7898bcc60000000000",
    );
    let mut verifier = TsigStream::new(&key, TsigRecord::parse(&query).unwrap().mac);
    verifier.verify(&first, 1594855491, 0).unwrap();
    assert_eq!(
        verifier.verify(&earlier, 1594855491, 0).unwrap_err(),
        TsigError::BadTime
    );
}

#[test]
fn rejects_misplaced_duplicate_and_malformed_tsig() {
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let mut query = hex("000100000000000000000000");
    key.sign(&mut query, 1000, 30, None).unwrap();
    let rr = Message::parse(&query)
        .unwrap()
        .additionals()
        .next()
        .unwrap();
    let start = rr.name.offset();
    let class_offset = rr.ttl_offset - 2;
    let mut duplicate = query.clone();
    duplicate.extend_from_slice(&query[start..]);
    duplicate[10..12].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        key.verify(&duplicate, 1000, None, 0).unwrap_err(),
        TsigError::Format
    );
    let mut wrong_section = query.clone();
    wrong_section[6..8].copy_from_slice(&1u16.to_be_bytes());
    wrong_section[10..12].fill(0);
    assert_eq!(
        key.verify(&wrong_section, 1000, None, 0).unwrap_err(),
        TsigError::Format
    );
    let mut invalid_class = query.clone();
    invalid_class[class_offset + 1] = 1;
    assert_eq!(
        key.verify(&invalid_class, 1000, None, 0).unwrap_err(),
        TsigError::Format
    );
    let mut trailing = query;
    trailing.push(0);
    assert_eq!(
        key.verify(&trailing, 1000, None, 0).unwrap_err(),
        TsigError::Format
    );
}
