#![forbid(unsafe_code)]
#![cfg(feature = "plugin-hosts")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Error, Metadata, Outcome, Phase, Protocol, Transport};
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

// CoreDNS plugin/hosts/hosts_test.go hostsExample.
const HOSTS: &str = "\
127.0.0.1 localhost localhost.domain
::1 localhost localhost.domain
10.0.0.1 example.org
::FFFF:10.0.0.2 example.com
10.0.0.3 fallthrough-example.org
1.2.3.4 aa.example.com
5.6.7.8 *.apps.example.com
reload 5s
timeout 3600
";

struct HostsFile(PathBuf);

impl HostsFile {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "pharos-hosts-ported-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(HOSTS.as_bytes()).unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating hosts fixture: {error}"),
            }
        }
    }
}

impl Drop for HostsFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn chain(file: &HostsFile, options: &str) -> Chain {
    let path = file.0.to_str().unwrap().replace('"', "\\\"");
    let corefile = format!(".:0 {{\n hosts \"{path}\" {{\n reload 0\n {options}\n }}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
}

async fn query(chain: &Chain, qname: &str, qtype: Type) -> (Outcome, Vec<u8>) {
    let name: Name = qname.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = chain.serve(&mut context).await;
    (outcome, response)
}

// CoreDNS TestLookupA: values, owners, classes, TTLs, and reverse aliases.
#[tokio::test]
async fn coredns_lookup_cases() {
    let file = HostsFile::new();
    let chain = chain(&file, "fallthrough");
    chain.lifecycle.run(Phase::Startup).await.unwrap();

    for (name, qtype, expected) in [
        ("example.org.", Type::A, vec![10, 0, 0, 1]),
        ("example.com.", Type::A, vec![10, 0, 0, 2]),
        (
            "localhost.",
            Type::AAAA,
            std::net::Ipv6Addr::LOCALHOST.octets().to_vec(),
        ),
        ("aa.example.com.", Type::A, vec![1, 2, 3, 4]),
        ("www.apps.example.com.", Type::A, vec![5, 6, 7, 8]),
    ] {
        let (outcome, wire) = query(&chain, name, qtype).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert!(response.aa(), "{name}");
        assert_eq!(response.answer_count(), 1, "{name}");
        let answer = response.answers().next().unwrap();
        assert_eq!(answer.name.to_string(), name);
        assert_eq!(
            (answer.rtype, answer.class, answer.ttl),
            (qtype, Class::IN, 3600)
        );
        assert_eq!(answer.rdata, expected, "{name}");
    }

    for (name, expected) in [
        ("1.0.0.10.in-addr.arpa.", vec!["example.org."]),
        ("2.0.0.10.in-addr.arpa.", vec!["example.com."]),
        (
            "1.0.0.127.in-addr.arpa.",
            vec!["localhost.", "localhost.domain."],
        ),
    ] {
        let (outcome, wire) = query(&chain, name, Type::PTR).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert!(response.aa(), "{name}");
        let mut names = Vec::new();
        for answer in response.answers() {
            assert_eq!(answer.name.to_string(), name);
            assert_eq!(
                (answer.rtype, answer.class, answer.ttl),
                (Type::PTR, Class::IN, 3600)
            );
            names.push(NameRef::parse(answer.rdata, 0).unwrap().to_string());
        }
        names.sort();
        assert_eq!(names, expected, "{name}");
    }

    for (name, qtype) in [
        ("example.org.", Type::AAAA),
        ("example.org.", Type::MX),
        ("fallthrough-example.org.", Type::AAAA),
    ] {
        let (outcome, wire) = query(&chain, name, qtype).await;
        assert_eq!(outcome, Outcome::Response, "{name} {qtype:?}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert!(response.aa());
        assert_eq!(response.answer_count(), 0);
        assert_eq!(response.authority_count(), 0);
        assert_eq!(response.additional_count(), 0);
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

// The parent does not match the wildcard; TestLookupA does not check its absent response.
#[tokio::test]
async fn coredns_wildcard_parent_case() {
    let file = HostsFile::new();
    let chain = chain(&file, "");
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let (outcome, wire) = query(&chain, "apps.example.com.", Type::A).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
    assert!(wire.is_empty());
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

// CoreDNS TestFallthroughUnsupportedType, using the chain's terminal error as next handler.
#[tokio::test]
async fn coredns_fallthrough_unsupported_cases() {
    let file = HostsFile::new();
    for (options, name, falls_through) in [
        ("fallthrough", "example.org.", false),
        (
            "fallthrough\n fallthrough_unsupported",
            "example.org.",
            true,
        ),
        (
            "fallthrough example.net\n fallthrough_unsupported",
            "example.org.",
            false,
        ),
        ("fallthrough", "missing.example.org.", true),
    ] {
        let chain = chain(&file, options);
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let (outcome, wire) = query(&chain, name, Type::TXT).await;
        if falls_through {
            assert_eq!(
                outcome,
                Outcome::Error(Error::NoNextPlugin),
                "{options}: {name}"
            );
            assert!(wire.is_empty(), "hosts wrote a response before fallthrough");
        } else {
            assert_eq!(outcome, Outcome::Response, "{options}: {name}");
            let response = Message::parse(&wire).unwrap();
            assert_eq!(response.rcode(), Rcode::NOERROR);
            assert!(response.aa());
            assert_eq!(response.answer_count(), 0);
            assert_eq!(response.authority_count(), 0);
            assert_eq!(response.additional_count(), 0);
        }
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
}

#[tokio::test]
async fn missing_names_without_fallthrough_return_servfail() {
    let file = HostsFile::new();
    let chain = chain(&file, "");
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    for qtype in [Type::A, Type::AAAA, Type::MX, Type::TXT] {
        let (outcome, wire) = query(&chain, "missing.example.org.", qtype).await;
        assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL), "{qtype:?}");
        assert!(wire.is_empty());
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}
