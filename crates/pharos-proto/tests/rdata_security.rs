#![forbid(unsafe_code)]

use pharos_proto::{
    BuildError, Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type,
};
use proptest::prelude::*;

#[test]
fn security_data_uses_miekg_hex_casing() {
    assert_eq!(
        Rdata::parse(Type::TLSA, &[3, 1, 1, 0xab, 0xcd])
            .unwrap()
            .to_string(),
        "3 1 1 abcd"
    );
    assert_eq!(
        Rdata::parse(Type::SSHFP, &[1, 1, 0xab, 0xcd])
            .unwrap()
            .to_string(),
        "1 1 ABCD"
    );
    assert_eq!(
        Rdata::parse(
            Type::ZONEMD,
            &[
                0, 0, 0, 1, 1, 1, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab,
                0xcd
            ]
        )
        .unwrap()
        .to_string(),
        "1 1 1 abcdabcdabcdabcdabcdabcd"
    );
}

#[test]
fn security_data_rejects_truncated_headers() {
    for (rtype, min) in [(Type::TLSA, 3), (Type::SSHFP, 2), (Type::ZONEMD, 6)] {
        for len in 0..min {
            assert!(
                Rdata::parse(rtype, &[0; 6][..len]).is_err(),
                "{rtype} {len}"
            );
        }
    }
}

#[test]
fn tsig_rejects_truncated_fields_and_bad_lengths() {
    // Root algorithm, time=0, fudge=0, empty MAC, ID=0, error=0, empty other.
    let wire = [0; 17];
    assert!(Rdata::parse(Type::TSIG, &wire).is_ok());
    for len in 0..wire.len() {
        assert!(Rdata::parse(Type::TSIG, &wire[..len]).is_err(), "{len}");
    }
    let mut oversized_mac = wire;
    oversized_mac[10] = 1;
    assert!(Rdata::parse(Type::TSIG, &oversized_mac).is_err());
    let mut oversized_other = wire;
    oversized_other[16] = 1;
    assert!(Rdata::parse(Type::TSIG, &oversized_other).is_err());
}

fn hex(input: &str) -> Vec<u8> {
    assert!(input.len().is_multiple_of(2));
    input
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// Adapted from miekg/dns v1.1.73 parse_test.go.
#[test]
fn miekg_examples_and_empty_tails() {
    for (rtype, prefix, digest, expected) in [
        (
            Type::TLSA,
            vec![1, 1, 1],
            "c22be239f483c08957bc106219cc2d3ac1a308dfbbdd0a365f17b9351234cf00",
            "1 1 1 c22be239f483c08957bc106219cc2d3ac1a308dfbbdd0a365f17b9351234cf00",
        ),
        (
            Type::TLSA,
            vec![2, 1, 2],
            "4e85f45179e9cd6e0e68e2eb5be2e85ec9b92d91c609caf3ef0315213e3f92ece92c38397a607214de95c7fadc0ad0f1c604a469a0387959745032c0d51492f3",
            "2 1 2 4e85f45179e9cd6e0e68e2eb5be2e85ec9b92d91c609caf3ef0315213e3f92ece92c38397a607214de95c7fadc0ad0f1c604a469a0387959745032c0d51492f3",
        ),
        (
            Type::TLSA,
            vec![3, 0, 2],
            "69ec8d2277360b215d0cd956b0e2747108dff34b27d461a41c800629e38ee6c2d1230cc9e8e36711330adc6766e6ff7c5fbb37f106f248337c1a20ad682888d2",
            "3 0 2 69ec8d2277360b215d0cd956b0e2747108dff34b27d461a41c800629e38ee6c2d1230cc9e8e36711330adc6766e6ff7c5fbb37f106f248337c1a20ad682888d2",
        ),
        (
            Type::SSHFP,
            vec![1, 2],
            "bc6533cdc95a79078a39a56ea7635984ed655318ada9b6159e30723665da95bb",
            "1 2 BC6533CDC95A79078A39A56EA7635984ED655318ADA9B6159E30723665DA95BB",
        ),
        (
            Type::ZONEMD,
            [2018031900u32.to_be_bytes().as_slice(), &[1, 1]].concat(),
            "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c",
            "2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c",
        ),
    ] {
        let mut bytes = prefix;
        bytes.extend(hex(digest));
        let data = Rdata::parse(rtype, &bytes).unwrap();
        assert_eq!(data.to_string(), expected);
        assert_eq!(data.rtype(), rtype);
        let name: Name = ".".parse().unwrap();
        let root = NameRef::parse(name.as_wire(), 0).unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record_with(Section::Answer, root, rtype, Class::IN, 0, |w| {
                data.write(w)
            })
            .unwrap();
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(record.rdata, bytes);
        assert_eq!(record.data().unwrap(), data);
    }
    for (rtype, bytes, expected) in [
        (Type::TLSA, &[1, 2, 3][..], "1 2 3 "),
        (Type::SSHFP, &[1, 2][..], "1 2 "),
    ] {
        assert_eq!(Rdata::parse(rtype, bytes).unwrap().to_string(), expected);
    }
}

// Fixed signed message from miekg/dns v1.1.73 tsig_test.go.
#[test]
fn miekg_tsig_wire_and_pseudosection() {
    let wire = hex(concat!(
        "c60028000001000000010001076578616d706c6503636f6d00000600010161c00c0001000100000e100004c0000201077465",
        "73746b65790000fa00ff00000000003d0b686d61632d73686132353600",
        "00005f0f9043",
        "012c00208cf23e0081d915478a182edcea7ff48ad102948e6c7ef8e887536957d1fa5616c60000000000"
    ));
    let record = Message::parse(&wire).unwrap().additionals().next().unwrap();
    let data = record.data().unwrap();
    assert_eq!(
        data.to_string(),
        "hmac-sha256. 20200715232451 300 32 8CF23E0081D915478A182EDCEA7FF48AD102948E6C7EF8E887536957D1FA5616 50688 0 0 "
    );
    assert_eq!(
        record.display_tsig().unwrap().to_string(),
        "\n;; TSIG PSEUDOSECTION:\n; testkey.\t0\tCLASS255\tTSIG\t hmac-sha256. 20200715232451 300 32 8CF23E0081D915478A182EDCEA7FF48AD102948E6C7EF8E887536957D1FA5616 50688 0 0 "
    );
    let mut out = Vec::new();
    let mut b = MessageBuilder::new(&mut out, 512, 0, 0).unwrap();
    b.record_with(
        Section::Additional,
        record.name,
        Type::TSIG,
        record.class,
        0,
        |w| data.write(w),
    )
    .unwrap();
    let rebuilt = Message::parse(b.finish())
        .unwrap()
        .additionals()
        .next()
        .unwrap();
    assert_eq!(rebuilt.rdata, record.rdata);
}

#[test]
fn tsig_presentation_boundaries_and_invalid_manual_values() {
    let name: Name = "key.example.".parse().unwrap();
    let root = NameRef::parse(name.as_wire(), 0).unwrap();
    for (time_signed, mac, other, expected) in [
        (
            0,
            &b""[..],
            &b""[..],
            "key.example. 19700101000000 300 0  42 18 0 ",
        ),
        (
            0xffff_ffff_ffff,
            &b"\xab\xcd"[..],
            &b"\xef"[..],
            "key.example. 89215561207104415 300 2 ABCD 42 18 1 ef",
        ),
    ] {
        let data = Rdata::Tsig {
            algorithm: root,
            time_signed,
            fudge: 300,
            mac,
            original_id: 42,
            error: 18,
            other,
        };
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        b.record_with(Section::Additional, root, Type::TSIG, Class::ANY, 17, |w| {
            data.write(w)
        })
        .unwrap();
        let record = Message::parse(b.finish())
            .unwrap()
            .additionals()
            .next()
            .unwrap();
        assert_eq!(record.data().unwrap().to_string(), expected);
        assert_eq!(
            record.display_tsig().unwrap().to_string(),
            format!("\n;; TSIG PSEUDOSECTION:\n; key.example.\t17\tCLASS255\tTSIG\t {expected}")
        );
    }
    let too_long = vec![0; 65536];
    for (time_signed, mac, other) in [
        (1 << 48, &[][..], &[][..]),
        (0, &too_long[..], &[][..]),
        (0, &[][..], &too_long[..]),
        (u64::MAX, &[][..], &[][..]),
    ] {
        let data = Rdata::Tsig {
            algorithm: root,
            time_signed,
            fudge: 0,
            mac,
            original_id: 0,
            error: 0,
            other,
        };
        let _ = data.to_string();
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            b.record_with(Section::Answer, root, Type::TSIG, Class::IN, 0, |w| data
                .write(w)),
            Err(BuildError::InvalidRdata)
        );
    }
    for rtype in [Type::TLSA, Type::SSHFP, Type::ZONEMD, Type::TSIG] {
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            b.record_with(Section::Answer, root, rtype, Class::IN, 0, |w| {
                Rdata::Unknown(rtype, &[]).write(w)
            }),
            Err(BuildError::InvalidRdata)
        );
        assert!(Rdata::parse(rtype, &too_long).is_err());
    }
    for data in [
        Rdata::Tlsa {
            usage: 0,
            selector: 0,
            matching_type: 0,
            certificate: &too_long[..65533],
        },
        Rdata::Sshfp {
            algorithm: 0,
            fingerprint_type: 0,
            fingerprint: &too_long[..65534],
        },
        Rdata::Zonemd {
            serial: 0,
            scheme: 0,
            hash_algorithm: 0,
            digest: &too_long[..65530],
        },
        Rdata::Tsig {
            algorithm: root,
            time_signed: 0,
            fudge: 0,
            mac: &too_long[..65520],
            original_id: 0,
            error: 0,
            other: &[],
        },
    ] {
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            b.record_with(Section::Answer, root, data.rtype(), Class::IN, 0, |w| data
                .write(w)),
            Err(BuildError::InvalidRdata)
        );
    }
}

#[test]
fn tsig_pointer_relocation_and_rdlength_boundaries() {
    let name: Name = "hmac.example.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    b.question(name, Type::TSIG, Class::IN).unwrap();
    b.record_with(Section::Answer, name, Type::TSIG, Class::ANY, 0, |w| {
        w.write_name(name)?;
        w.write_bytes(&[0; 16])
    })
    .unwrap();
    let record = Message::parse(b.finish())
        .unwrap()
        .answers()
        .next()
        .unwrap();
    assert_eq!(&record.rdata[..2], &[0xc0, 12]);
    let data = record.data().unwrap();
    let mut rebuilt = Vec::new();
    let mut b = MessageBuilder::new(&mut rebuilt, 512, 0, 0).unwrap();
    b.question(name, Type::TSIG, Class::IN).unwrap();
    b.record_with(Section::Answer, name, Type::TSIG, Class::ANY, 0, |w| {
        data.write(w)
    })
    .unwrap();
    let record = Message::parse(b.finish())
        .unwrap()
        .answers()
        .next()
        .unwrap();
    assert_eq!(&record.rdata[..name.wire_len()], name.to_name().as_wire());
    assert_eq!(record.data().unwrap().to_string(), data.to_string());
    for bytes in [
        &[0xc0][..],
        &[0xc0, 0][..],
        &[0xc0, 2][..],
        &[1, b'x'][..],
        &[0, 0, 0][..],
    ] {
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        b.record(Section::Answer, name, Type::TSIG, Class::ANY, 0, bytes)
            .unwrap();
        b.record(Section::Answer, name, Type::A, Class::IN, 0, &[0; 4])
            .unwrap();
        let record = Message::parse(b.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert!(record.data().is_err(), "{bytes:02x?}");
        assert!(record.display_tsig().is_err());
    }
    let mut trailing = vec![0; 17];
    trailing.push(0);
    assert!(Rdata::parse(Type::TSIG, &trailing).is_err());
    let mut wire = vec![0; 12];
    wire[7] = 2;
    wire.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 1, 0xc0]);
    wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0]);
    let record = Message::parse(&wire).unwrap().answers().next().unwrap();
    assert!(record.data().is_err());
    assert!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .nth(1)
            .unwrap()
            .display_tsig()
            .is_err()
    );
}

proptest! {
    #[test]
    fn arbitrary_security_data_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        for rtype in [Type::TLSA, Type::SSHFP, Type::ZONEMD, Type::TSIG] {
            if let Ok(data) = Rdata::parse(rtype, &bytes) { let _ = data.to_string(); }
        }
    }
}
