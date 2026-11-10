use pharos_proto::{
    Class, EdnsOptions, Message, MessageBuilder, MessageError, Name, NameRef, Opt, Rcode, Section,
    Type, normalized_udp_size,
};

fn message(section: usize, records: &[&[u8]]) -> Vec<u8> {
    let mut wire = vec![0; 12];
    wire[4 + section * 2..6 + section * 2].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        wire.extend_from_slice(record);
    }
    wire
}

#[test]
fn size_and_version_follow_coredns() {
    for (size, expected) in [
        (0, 512),
        (511, 512),
        (512, 512),
        (1232, 1232),
        (65535, 65535),
    ] {
        assert_eq!(normalized_udp_size(size, false), expected);
        assert_eq!(normalized_udp_size(size, true), 65535);
    }
    let empty = EdnsOptions::parse(&[]).unwrap();
    assert!(!Opt::new(512, 0, 0, 0, empty).bad_version());
    assert!(Opt::new(512, 0, 1, 0, empty).bad_version());
    let badvers = Opt::badvers();
    assert_eq!(badvers.udp_payload_size(), 0);
    assert_eq!(badvers.extended_rcode(), 1);
    assert_eq!(badvers.version(), 0);
    assert_eq!(badvers.flags(), 0);
}

#[test]
fn badvers_response_preserves_question_and_query_flags() {
    let query = [
        0x12, 0x34, 1, 0x10, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'x', 0, 0, 1, 0, 1, 0, 0, 41, 2, 0, 0, 2,
        0x80, 0, 0, 0,
    ];
    let query = Message::parse(&query).unwrap();
    let mut wire = Vec::new();
    let result = query.badvers_response(&mut wire).unwrap().unwrap();
    let response = Message::parse(result).unwrap();
    assert_eq!(response.id(), 0x1234);
    assert!(response.qr() && response.rd() && response.cd());
    assert_eq!(response.question_count(), 1);
    assert_eq!(response.rcode(), Rcode::BADVERS);
    let opt = response.opt().unwrap();
    assert_eq!(
        (opt.udp_payload_size(), opt.version(), opt.flags()),
        (0, 0, 0)
    );

    let no_opt = [0; 12];
    assert!(
        Message::parse(&no_opt)
            .unwrap()
            .badvers_response(&mut wire)
            .unwrap()
            .is_none()
    );
}

#[test]
fn response_existing_opt_keeps_its_options_and_high_flags() {
    let query = Opt::new(4096, 0, 0, 0, EdnsOptions::parse(&[]).unwrap());
    let existing = Opt::new(
        1232,
        4,
        9,
        0xc1ff,
        EdnsOptions::parse(&[0, 3, 0, 1, b'x']).unwrap(),
    );
    let response = query.response(Some(existing), &[], Rcode::BADVERS);
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0x8000).unwrap();
    builder.reserve_response_opt(&response).unwrap();
    let msg = Message::parse(builder.finish_with_response_opt(&response).unwrap()).unwrap();
    assert_eq!(msg.rcode(), Rcode::BADVERS);
    let opt = msg.opt().unwrap();
    assert_eq!(opt.udp_payload_size(), 4096);
    assert_eq!(opt.flags(), 0xc100);
    assert_eq!(opt.options().as_bytes(), &[0, 3, 0, 1, b'x']);
    assert_eq!(
        opt.to_string(),
        "\n;; OPT PSEUDOSECTION:\n; EDNS: version 0; flags: do co; MBZ: 0x0100, udp: 4096\n; NSID: 78  (x)"
    );
}

#[test]
fn response_opt_keeps_registered_options_and_fits_after_truncation() {
    let options = EdnsOptions::parse(&[0, 3, 0, 1, 42, 0, 10, 0, 1, 43]).unwrap();
    let query = Opt::new(400, 0, 1, 0x80ff, options);
    let response = query.response(None, &[10], Rcode::NOERROR);
    let mut wire = Vec::new();
    let root: Name = ".".parse().unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
    builder.reserve_response_opt(&response).unwrap();
    assert!(
        !builder
            .record(
                Section::Answer,
                NameRef::parse(root.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                0,
                &[0; 500]
            )
            .unwrap()
    );
    let message = Message::parse(builder.finish_with_response_opt(&response).unwrap()).unwrap();
    assert!(message.tc());
    let opt = message.opt().unwrap();
    assert_eq!(opt.udp_payload_size(), 400);
    assert_eq!(opt.version(), 0);
    assert_eq!(opt.flags(), 0x8000);
    assert_eq!(opt.options().as_bytes(), &[0, 10, 0, 1, 43]);
}

#[test]
fn opt_fields_and_extended_rcode_are_borrowed_from_message() {
    let opt = [0, 0, 41, 0x04, 0xd0, 1, 2, 0x80, 0x55, 0, 0];
    let mut wire = message(3, &[&opt]);
    wire[3] = 3;
    let query = Message::parse(&wire).unwrap();
    let opt = query.opt().unwrap();
    assert_eq!(opt.udp_payload_size(), 1232);
    assert_eq!(opt.extended_rcode(), 1);
    assert_eq!(opt.version(), 2);
    assert!(opt.dnssec_ok());
    assert_eq!(opt.flags(), 0x8055);
    assert_eq!(query.rcode(), Rcode(19));
    assert_eq!(opt.options().iter().count(), 0);
}

#[test]
fn malformed_opt_requires_formerr() {
    let opt = [0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0];
    let non_root = [1, b'x', 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0];
    let bad_option = [0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 1];
    for wire in [
        message(3, &[&opt, &opt]),
        message(1, &[&opt]),
        message(2, &[&opt]),
        message(3, &[&non_root]),
        message(3, &[&bad_option]),
    ] {
        assert!(matches!(
            Message::parse(&wire),
            Err(MessageError::InvalidOpt)
        ));
    }
}
