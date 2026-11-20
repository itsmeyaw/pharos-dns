use super::*;

const SOURCE_V4: &str = "192.0.2.1:12345";

fn v2(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
    let mut wire = V2_SIGNATURE.to_vec();
    wire.extend([command, family]);
    wire.extend(u16::try_from(block.len()).unwrap().to_be_bytes());
    wire.extend(block);
    wire
}

fn v4_block(source: [u8; 4], port: u16, tlvs: &[u8]) -> Vec<u8> {
    let mut block = source.to_vec();
    block.extend([192, 0, 2, 53]);
    block.extend(port.to_be_bytes());
    block.extend(53u16.to_be_bytes());
    block.extend(tlvs);
    block
}

fn header(input: &[u8]) -> Header<'_> {
    match parse(input) {
        Ok(Parse::Header(header)) => header,
        other => panic!("expected a header, got {other:?}"),
    }
}

#[test]
fn v1_tcp4_yields_the_source_and_consumes_the_line() {
    let wire = b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\nDNS";
    let parsed = header(wire);
    assert_eq!(parsed.source, Some(SOURCE_V4.parse().unwrap()));
    assert_eq!(parsed.command, Command::Proxy);
    assert_eq!(&wire[parsed.length..], b"DNS");
}

#[test]
fn v1_tcp6_yields_the_source() {
    let parsed = header(b"PROXY TCP6 2001:db8::1 2001:db8::53 40000 53\r\n");
    assert_eq!(parsed.source, Some("[2001:db8::1]:40000".parse().unwrap()));
}

#[test]
fn v1_unknown_is_local_and_ignores_the_rest_of_the_line() {
    let parsed = header(b"PROXY UNKNOWN ignored words\r\n");
    assert_eq!((parsed.command, parsed.source), (Command::Local, None));
}

#[test]
fn v1_rejects_malformed_lines() {
    for line in [
        &b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\n"[..],
        b"PROXY TCP4 192.0.2.1 192.0.2.53 12345\r\n",
        b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53 extra\r\n",
        b"PROXY TCP4  192.0.2.1 192.0.2.53 12345 53\r\n",
        b"PROXY TCP4 2001:db8::1 192.0.2.53 12345 53\r\n",
        b"PROXY TCP6 192.0.2.1 2001:db8::53 12345 53\r\n",
        b"PROXY TCP6 fe80::1%eth0 2001:db8::53 12345 53\r\n",
        b"PROXY TCP4 192.0.2.1 192.0.2.53 012345 53\r\n",
        b"PROXY TCP4 192.0.2.1 192.0.2.53 65536 53\r\n",
        b"PROXY TCP4 192.0.2.1 192.0.2.53 +1 53\r\n",
        b"PROXY TCP4 192.0.2.1 192.0.2.53 -1 53\r\n",
        b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 \r\n",
        b"PROXY UDP4 192.0.2.1 192.0.2.53 12345 53\r\n",
        b"PROXY\r\n",
        b"PROXYjunk TCP4 192.0.2.1 192.0.2.53 12345 53\r\n",
    ] {
        assert!(parse(line).is_err(), "{}", String::from_utf8_lossy(line));
    }
}

#[test]
fn v1_line_without_lf_is_incomplete_until_107_octets() {
    let line = format!("PROXY UNKNOWN {}", "x".repeat(92));
    assert_eq!(line.len(), 106);
    assert_eq!(parse(line.as_bytes()), Ok(Parse::Incomplete));
    assert!(parse(format!("{line}x").as_bytes()).is_err());
}

#[test]
fn v1_line_of_exactly_107_octets_is_accepted() {
    let line = format!("PROXY UNKNOWN {}\r\n", "x".repeat(91));
    assert_eq!(line.len(), 107);
    assert_eq!(header(line.as_bytes()).length, 107);
}

#[test]
fn v2_ipv4_yields_the_source_and_the_tlv_vector() {
    let tlvs = [0xEA, 0, 2, 1, 2];
    let wire = v2(0x21, 0x12, &v4_block([192, 0, 2, 1], 12345, &tlvs));
    let parsed = header(&wire);
    assert_eq!(parsed.source, Some(SOURCE_V4.parse().unwrap()));
    assert!(parsed.datagram);
    assert_eq!(parsed.tlvs, tlvs);
    assert_eq!(parsed.length, wire.len());
}

#[test]
fn v2_ipv6_yields_the_source() {
    let mut block = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec();
    block.extend("2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
    block.extend(40000u16.to_be_bytes());
    block.extend(53u16.to_be_bytes());
    let wire = v2(0x21, 0x21, &block);
    let parsed = header(&wire);
    assert_eq!(parsed.source, Some("[2001:db8::1]:40000".parse().unwrap()));
    assert!(!parsed.datagram);
}

#[test]
fn v2_local_keeps_the_peer_and_discards_the_block() {
    let wire = v2(
        0x20,
        0x12,
        &v4_block([192, 0, 2, 1], 12345, &[0xEA, 0, 1, 9]),
    );
    let parsed = header(&wire);
    assert_eq!(
        (parsed.command, parsed.source, parsed.tlvs),
        (Command::Local, None, &[][..])
    );
    assert_eq!(parsed.length, wire.len());
}

#[test]
fn v2_local_with_unspecified_family_skips_its_whole_block() {
    let wire = v2(0x20, 0x00, &[7; 9]);
    assert_eq!(header(&wire).length, wire.len());
}

#[test]
fn v2_local_with_a_short_block_for_its_family_is_skipped() {
    let wire = v2(0x20, 0x11, &[]);
    assert_eq!(header(&wire).length, 16);
}

#[test]
fn v2_local_ignores_family_protocol_and_address_block() {
    for family in [0x13, 0x41, 0x44, 0x7F, 0xFF] {
        for block in [&[][..], &[0xAB; 7], &[0xCD; 300]] {
            let wire = v2(0x20, family, block);
            let parsed = header(&wire);
            assert_eq!(
                (parsed.command, parsed.source, parsed.tlvs),
                (Command::Local, None, &[][..]),
                "{family:02x}"
            );
            assert_eq!(parsed.length, wire.len());
            assert_eq!(parse(&wire[..wire.len() - 1]), Ok(Parse::Incomplete));
        }
    }
}

#[test]
fn v2_rejects_invalid_headers() {
    let block = v4_block([192, 0, 2, 1], 1, &[]);
    let mut oversized = v2(0x21, 0x11, &block);
    oversized[14..16].copy_from_slice(&4097u16.to_be_bytes());
    for wire in [
        v2(0x22, 0x11, &block),
        v2(0x11, 0x11, &block),
        v2(0x21, 0x13, &block),
        v2(0x21, 0x41, &block),
        v2(0x21, 0x00, &[]),
        v2(0x21, 0x11, &block[..11]),
        v2(0x21, 0x31, &[0; 216]),
        oversized,
    ] {
        assert!(parse(&wire).is_err(), "{wire:02x?}");
    }
}

#[test]
fn v2_local_above_the_length_limit_is_rejected() {
    let mut wire = v2(0x20, 0x00, &[]);
    wire[14..16].copy_from_slice(&4097u16.to_be_bytes());
    assert!(parse(&wire).is_err());
}

#[test]
fn every_strict_prefix_of_a_valid_header_is_incomplete() {
    for wire in [
        b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\n".to_vec(),
        v2(0x21, 0x11, &v4_block([192, 0, 2, 1], 1, &[0xEA, 0, 1, 9])),
        v2(0x20, 0x00, &[7; 9]),
    ] {
        for end in 0..wire.len() {
            assert_eq!(parse(&wire[..end]), Ok(Parse::Incomplete), "{end}");
        }
        assert!(matches!(parse(&wire), Ok(Parse::Header(_))));
    }
}

#[test]
fn other_inputs_are_not_proxy_headers() {
    for input in [
        &b"\0\x1d\x12\x34"[..],
        b"POST /",
        b"PROXX",
        b"\r\n\r\n\0\r\nQUIX",
        b"\x16\x03\x01",
    ] {
        assert_eq!(parse(input), Ok(Parse::NotProxy), "{input:02x?}");
    }
}

#[test]
fn single_octet_mutations_never_panic_or_overrun() {
    for wire in [
        b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\n".to_vec(),
        b"PROXY TCP6 2001:db8::1 2001:db8::53 1 2\r\n".to_vec(),
        v2(
            0x21,
            0x12,
            &v4_block([192, 0, 2, 1], 1, &[0xEA, 0, 1, 9, 4, 0, 0]),
        ),
        v2(0x20, 0x00, &[7; 9]),
    ] {
        for index in 0..wire.len() {
            for value in 0..=255u8 {
                let mut mutated = wire.clone();
                mutated[index] = value;
                if let Ok(Parse::Header(parsed)) = parse(&mutated) {
                    assert!(parsed.length <= mutated.len());
                    let mut hex = String::new();
                    tlv_hex(parsed.tlvs, &mut hex);
                }
            }
        }
    }
}

fn hex_of(tlvs: &[u8]) -> Option<String> {
    let mut out = String::from("stale");
    tlv_hex(tlvs, &mut out).then_some(out)
}

#[test]
fn tlv_hex_encodes_the_vector_in_lower_case() {
    assert_eq!(
        hex_of(&[0xEA, 0, 2, 0xCA, 0xFE]).as_deref(),
        Some("ea0002cafe")
    );
}

#[test]
fn tlv_hex_keeps_several_records_in_order() {
    let raw = [0x02, 0, 3, b'a', b'b', b'c', 0xEA, 0, 1, 7];
    assert_eq!(hex_of(&raw).as_deref(), Some("020003616263ea000107"));
}

#[test]
fn tlv_hex_drops_noop_padding_but_keeps_the_record() {
    assert_eq!(
        hex_of(&[0x04, 0, 2, 0xAA, 0xBB, 0xEA, 0, 1, 1]).as_deref(),
        Some("040000ea000101")
    );
}

#[test]
fn tlv_hex_publishes_nothing_for_an_empty_vector() {
    assert_eq!(hex_of(&[]), None);
}

#[test]
fn tlv_hex_publishes_nothing_for_a_truncated_vector() {
    for raw in [
        &[0xEA][..],
        &[0xEA, 0],
        &[0xEA, 0, 2, 1],
        &[0xEA, 0, 0, 0xEA, 0],
    ] {
        assert_eq!(hex_of(raw), None, "{raw:02x?}");
    }
}

#[test]
fn tlv_hex_accepts_a_zero_length_record() {
    assert_eq!(hex_of(&[0xEA, 0, 0]).as_deref(), Some("ea0000"));
}
