#![forbid(unsafe_code)]
#![cfg(all(
    feature = "plugin-nsid",
    feature = "plugin-whoami",
    feature = "plugin-cache"
))]
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
    for text in [
        "nsid",
        "nsid ps0",
        "nsid worker1",
        "nsid \"tf 2\"",
        "nsid Use The Force",
    ] {
        assert!(configured(text).is_ok(), "{text}");
    }
    assert!(configured("nsid\nnsid").is_err());
    assert!(configured("nsid {\n foo\n}").is_err());
    assert!(configured("nsid {\n}").is_err());
}

async fn query(chain: &Chain, options: Option<&[u8]>) -> Vec<u8> {
    let mut wire = vec![
        0,
        1,
        1,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        u8::from(options.is_some()),
        0,
        0,
        1,
        0,
        1,
    ];
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
        let mut chain = configured(config).unwrap();
        for iteration in 0..2 {
            let response = query(&chain, Some(&[0, 3, 0, 0])).await;
            let message = Message::parse(&response).unwrap();
            let opt = message.opt().unwrap();
            assert_eq!(opt.udp_payload_size(), 4096);
            assert_eq!(
                opt.options().iter().collect::<Vec<_>>(),
                [EdnsOption::Nsid(b"NSID")]
            );
            if iteration == 0 && config.starts_with("cache") {
                chain.whoami = None;
                let response = query(&chain, Some(&[])).await;
                let message = Message::parse(&response).unwrap();
                assert!(!message.opt().is_some_and(|opt| {
                    opt.options()
                        .iter()
                        .any(|option| matches!(option, EdnsOption::Nsid(_)))
                }));
            }
        }
    }
}

#[tokio::test]
async fn query_nsid_payload_is_ignored() {
    let chain = configured("nsid NSID\nwhoami").unwrap();
    let response = query(&chain, Some(&[0, 3, 0, 3, 1, 2, 3])).await;
    let message = Message::parse(&response).unwrap();
    assert_eq!(
        message.opt().unwrap().options().iter().next(),
        Some(EdnsOption::Nsid(b"NSID"))
    );
}

#[tokio::test]
async fn oversized_nsid_returns_servfail_after_listener_scrubbing() {
    let chain = configured(&format!("nsid {}\nwhoami", "x".repeat(500))).unwrap();
    let mut response = query(&chain, Some(&[0, 3, 0, 0])).await;
    let wire = [
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 4, 0, 3,
        0, 0,
    ];
    let query = Message::parse(&wire).unwrap();
    assert_eq!(
        pharos_server::finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            |_| {}
        ),
        pharos_server::Action::Respond
    );
    assert_eq!(
        Message::parse(&response).unwrap().rcode(),
        pharos_proto::Rcode::SERVFAIL
    );
}

#[tokio::test]
async fn no_nsid_is_added_without_an_nsid_query() {
    let chain = configured("nsid NSID\nwhoami").unwrap();
    for options in [None, Some(&[][..]), Some(&[0, 12, 0, 0][..])] {
        let response = query(&chain, options).await;
        let message = Message::parse(&response).unwrap();
        assert!(!message.opt().is_some_and(|opt| {
            opt.options()
                .iter()
                .any(|o| matches!(o, EdnsOption::Nsid(_)))
        }));
    }
}

#[tokio::test]
async fn default_identifier_is_the_hostname() {
    let chain = configured("nsid\nwhoami").unwrap();
    let response = query(&chain, Some(&[0, 3, 0, 0])).await;
    let message = Message::parse(&response).unwrap();
    let expected = nix::unistd::gethostname()
        .map(|s| s.into_encoded_bytes())
        .unwrap_or_else(|_| b"localhost".to_vec());
    assert_eq!(
        message.opt().unwrap().options().iter().collect::<Vec<_>>(),
        [EdnsOption::Nsid(&expected)]
    );
}

#[tokio::test]
async fn coredns_setup_values_are_returned_verbatim() {
    for (directive, expected) in [
        ("nsid ps0", "ps0"),
        ("nsid worker1", "worker1"),
        ("nsid \"tf 2\"", "tf 2"),
        ("nsid Use The Force", "Use The Force"),
        ("nsid \"\"", ""),
    ] {
        let chain = configured(&format!("{directive}\nwhoami")).unwrap();
        let response = query(&chain, Some(&[0, 3, 0, 0])).await;
        let message = Message::parse(&response).unwrap();
        assert_eq!(
            message.opt().unwrap().options().iter().next(),
            Some(EdnsOption::Nsid(expected.as_bytes())),
            "{directive}"
        );
    }
}
