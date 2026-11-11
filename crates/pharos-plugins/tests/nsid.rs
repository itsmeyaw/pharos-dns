#![cfg(all(feature = "plugin-nsid", feature = "plugin-whoami", feature = "plugin-cache"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{EdnsOption, Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

fn configured(directives_text: &str) -> Result<Chain, String> {
    let source = format!(".:53 {{\n{directives_text}\n}}");
    let blocks = parse("Corefile", &source).map_err(|e| e.to_string())?;
    let mut blocks = configure::<Chain>(&blocks, directives()).map_err(|e| e.to_string())?;
    Ok(blocks.remove(0).config)
}

#[test]
fn coredns_setup_accepts_data_and_rejects_duplicate() {
    for text in ["nsid", "nsid ps0", "nsid worker1", "nsid \"tf 2\"", "nsid Use The Force"] {
        assert!(configured(text).is_ok(), "{text}");
    }
    assert!(configured("nsid\nnsid").is_err());
}

async fn query(directives_text: &str, options: Option<&[u8]>) -> Vec<u8> {
    let chain = configured(directives_text).unwrap();
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(options.is_some()), 0, 0, 1, 0, 1];
    if let Some(options) = options {
        wire.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(&(options.len() as u16).to_be_bytes());
        wire.extend_from_slice(options);
    }
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [None; 8];
    let mut context = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert_eq!(chain.serve(&mut context).await, Outcome::Response);
    response
}

#[tokio::test]
async fn coredns_nsid_and_cache_return_requested_identifier() {
    for config in ["nsid NSID\nwhoami", "cache\nnsid NSID\nwhoami"] {
        let response = query(config, Some(&[0, 3, 0, 0])).await;
        let message = Message::parse(&response).unwrap();
        let opt = message.opt().unwrap();
        assert_eq!(opt.udp_payload_size(), 4096);
        assert_eq!(opt.options().iter().collect::<Vec<_>>(), [EdnsOption::Nsid(b"NSID")]);
    }
}

#[tokio::test]
async fn no_nsid_is_added_without_an_nsid_query() {
    for options in [None, Some(&[][..]), Some(&[0, 12, 0, 0][..])] {
        let response = query("nsid NSID\nwhoami", options).await;
        let message = Message::parse(&response).unwrap();
        assert!(!message.opt().is_some_and(|opt| opt.options().iter().any(|o| matches!(o, EdnsOption::Nsid(_)))));
    }
}
