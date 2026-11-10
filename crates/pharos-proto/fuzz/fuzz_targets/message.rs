#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_proto::{EdnsOptions, Message, MessageMut};

fuzz_target!(|wire: &[u8]| {
    if let Ok(options) = EdnsOptions::parse(wire) {
        assert_eq!(options.as_bytes(), wire);
        assert!(options.iter().eq(options.iter()));
        let mut raw = wire;
        for option in options.iter() {
            assert_eq!(option.code(), u16::from_be_bytes([raw[0], raw[1]]));
            let len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
            raw = &raw[4 + len..];
        }
        assert!(raw.is_empty());
    }
    if let Ok(message) = Message::parse(wire) {
        assert_eq!(
            message.questions().count(),
            usize::from(message.question_count())
        );
        for record in message
            .answers()
            .chain(message.authorities())
            .chain(message.additionals())
        {
            assert_eq!(
                &wire[record.rdata_offset..record.rdata_offset + record.rdata.len()],
                record.rdata
            );
            let _ = record.name.to_name();
            if let Ok(data) = record.data() {
                let _ = data.to_string();
            }
        }
        if let Some(opt) = message.opt() {
            let options = opt.options();
            assert!(
                options
                    .iter()
                    .eq(EdnsOptions::parse(options.as_bytes()).unwrap().iter())
            );
        }
        let mut copy = wire.to_vec();
        MessageMut::parse(&mut copy)
            .unwrap()
            .rewrite_ttls(|ttl| ttl.saturating_sub(1));
    }
});
