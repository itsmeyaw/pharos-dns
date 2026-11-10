#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_proto::{Message, MessageMut};

fuzz_target!(|wire: &[u8]| {
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
        }
        let mut copy = wire.to_vec();
        MessageMut::parse(&mut copy)
            .unwrap()
            .rewrite_ttls(|ttl| ttl.saturating_sub(1));
    }
});
