#![forbid(unsafe_code)]
#![cfg(feature = "plugin-loadbalance")]
#![recursion_limit = "512"]

#[path = "support/loadbalance_fixtures.rs"]
mod fixtures;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rdata};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Reply<'a>(&'a [u8]);
impl Next for Reply<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.response.clear();
        cx.response.extend_from_slice(self.0);
        Outcome::Response
    }
}

async fn response(chain: &Chain, wire: &[u8], output: &mut Vec<u8>) {
    let root: Name = ".".parse().unwrap();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: output,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .loadbalance
            .as_ref()
            .unwrap()
            .serve(&mut cx, Reply(wire))
            .await,
        Outcome::Response
    );
}

fn chain() -> Chain {
    let blocks = parse("Corefile", ".:53 {\n loadbalance\n}").unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
}

#[tokio::test]
async fn compressed_cname_targets_shuffle_and_preserve_names() {
    let wire = fixtures::cdn_response();
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    let mut first = std::collections::BTreeSet::new();
    for _ in 0..100 {
        response(&chain, &wire, &mut output).await;
        let message = Message::parse(&output).unwrap();
        let mut answers = message.answers();
        assert!(
            matches!(answers.next().unwrap().data().unwrap(), Rdata::Cname(name) if name.to_string() == "cdn.example.net.")
        );
        let records: Vec<_> = answers.collect();
        assert_eq!(records.len(), 4);
        for rr in &records {
            assert_eq!(rr.name.to_string(), "cdn.example.net.");
        }
        first.insert(records[0].rdata[3]);
    }
    assert!(
        first.len() > 1,
        "CNAME-compressed addresses were not shuffled"
    );
}

#[tokio::test]
async fn pointers_follow_a_cname_record_that_moves() {
    let mut wire = fixtures::cdn_response();
    wire[7] = 6;
    let extra = [0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 30, 0, 2, 1, b'x'];
    wire.splice(33..33, extra);
    let target = 33 + extra.len() + 12;
    let first_address = target + 17;
    for index in 0..4 {
        wire[first_address + index * 16 + 1] = target as u8;
    }
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    response(&chain, &wire, &mut output).await;
    assert_ne!(output, wire, "CNAME was not moved ahead of TXT");
    let message = Message::parse(&output).unwrap();
    let records: Vec<_> = message.answers().collect();
    assert!(
        matches!(records[0].data().unwrap(), Rdata::Cname(name) if name.to_string() == "cdn.example.net.")
    );
    assert_eq!(records[1].rtype, pharos_proto::Type::TXT);
    assert!(
        records[2..]
            .iter()
            .all(|rr| rr.name.to_string() == "cdn.example.net.")
    );
}

#[tokio::test]
async fn transitive_owner_pointers_follow_moved_records() {
    let mut wire = fixtures::cdn_response();
    let first_address = 33 + 12 + 17;
    wire[first_address + 16..first_address + 18].copy_from_slice(&[0xc0, first_address as u8]);
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    let mut moved_target = 0;
    for _ in 0..200 {
        response(&chain, &wire, &mut output).await;
        let message = Message::parse(&output).unwrap();
        let mut positions = [0; 2];
        for (index, rr) in message.answers().skip(1).enumerate() {
            assert_eq!(rr.name.to_string(), "cdn.example.net.");
            if rr.rdata[3] <= 2 {
                positions[usize::from(rr.rdata[3] - 1)] = index;
            }
        }
        assert!(positions[0] < positions[1]);
        moved_target += usize::from(positions[0] > 0);
    }
    assert!(moved_target > 0, "no transitive pointer target was moved");
}

#[tokio::test]
async fn forward_pointer_after_partition_keeps_original_response() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x01\0\x01");
    let target = wire.len();
    wire.extend_from_slice(b"\x07example\x03org\0\0\x01\0\x01\0\0\0\x1e\0\x04\x01\x02\x03\x04");
    wire.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 2, 0xc0, target as u8]);
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    response(&chain, &wire, &mut output).await;
    assert_eq!(
        output, wire,
        "a forward pointer must leave the entire Response unchanged"
    );
}

#[tokio::test]
async fn overlapping_pointer_bytes_cannot_be_rewritten_inconsistently() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 5, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x01\0\x01");
    wire.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 30, 0, 160]);
    wire.extend_from_slice(&[0; 160]);
    wire.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, 2, 0xc0, 12]);
    wire.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 30, 0, 4, 0, 10, 0xc0, 192]);
    let overlapping = wire.len() - 1;
    wire.push(12);
    wire.extend_from_slice(b"xxxxxxxxxxxx\0");
    wire.extend_from_slice(&[0, 15, 0, 1, 0, 0, 0, 30, 0, 4, 0, 20, 0xc0, 12]);
    wire.extend_from_slice(&[
        0xc0,
        overlapping as u8,
        0,
        15,
        0,
        1,
        0,
        0,
        0,
        30,
        0,
        4,
        0,
        30,
        0xc0,
        12,
    ]);
    let message = Message::parse(&wire).unwrap();
    assert!(message.answers().all(|rr| rr.data().is_ok()));
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    for _ in 0..200 {
        response(&chain, &wire, &mut output).await;
        assert_eq!(
            output, wire,
            "overlapping pointers must not be rewritten inconsistently"
        );
    }
}

#[tokio::test]
async fn pointer_shaped_ipv4_bytes_do_not_prevent_shuffle() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 10, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x01\0\x01");
    for last in 1..=10 {
        wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 168, 0, last]);
    }
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    let mut first = std::collections::BTreeSet::new();
    for _ in 0..100 {
        response(&chain, &wire, &mut output).await;
        let message = Message::parse(&output).unwrap();
        assert_eq!(message.answer_count(), 10);
        first.insert(message.answers().next().unwrap().rdata[3]);
    }
    assert!(first.len() > 1, "192.168 addresses were not shuffled");
}

#[tokio::test]
async fn compressed_mx_exchanges_shuffle_when_pointers_remain_backward() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x0f\0\x01");
    wire.extend_from_slice(b"\xc0\x0c\0\x0f\0\x01\0\0\0\x1e\0\x14\0\x0a");
    let target = wire.len();
    wire.extend_from_slice(b"\x04mail\x07example\x03org\0");
    wire.extend_from_slice(b"\xc0\x0c\0\x0f\0\x01\0\0\0\x1e\0\x04\0\x14");
    wire.extend_from_slice(&[0xc0, target as u8]);
    wire.extend_from_slice(b"\xc0\x0c\0\x0f\0\x01\0\0\0\x1e\0\x04\0\x1e\xc0\x0c");
    let chain = chain();
    let mut output = Vec::with_capacity(512);
    let mut changed = 0;
    let mut moved_target = 0;
    for _ in 0..200 {
        response(&chain, &wire, &mut output).await;
        changed += usize::from(output != wire);
        let message = Message::parse(&output).unwrap();
        let mut positions = [0; 3];
        for (index, rr) in message.answers().enumerate() {
            let Rdata::Mx {
                preference,
                exchange,
            } = rr.data().unwrap()
            else {
                panic!("expected MX")
            };
            let slot = usize::from(preference / 10 - 1);
            positions[slot] = index;
            assert_eq!(
                exchange.to_string(),
                if slot == 2 {
                    "example.org."
                } else {
                    "mail.example.org."
                }
            );
        }
        assert!(positions[0] < positions[1], "forward exchange pointer");
        moved_target += usize::from(positions[0] > 0);
    }
    assert!(changed > 0, "all valid MX permutations were skipped");
    assert!(moved_target > 0, "no MX pointer target was relocated");
}
