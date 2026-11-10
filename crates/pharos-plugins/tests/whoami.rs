#![cfg(feature = "plugin-whoami")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

fn run<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("whoami should be ready immediately"),
    }
}

#[test]
fn corefile_whoami_answers_in_additional_for_both_families_and_protocols() {
    let blocks = parse("Corefile", ".:53 {\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    for (address, protocol, name, kind) in [
        ("192.0.2.8:1234", Protocol::Udp, "Example.COM.", Type::A),
        ("[2001:db8::8]:53", Protocol::Tcp, ".", Type::AAAA),
        ("192.0.2.8:1234", Protocol::Tcp, "Example.COM.", Type::TXT),
        (
            "[2001:db8::8]:53",
            Protocol::Udp,
            "Example.COM.",
            Type::AAAA,
        ),
    ] {
        let parsed: Name = name.parse().unwrap();
        let name_ref = NameRef::parse(parsed.as_wire(), 0).unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0110).unwrap();
        builder.question(name_ref, kind, Class::CH).unwrap();
        let _ = builder.finish();
        let query = Message::parse(&wire).unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut ctx = Context {
            query,
            client: address.parse().unwrap(),
            transport: Transport::Dns,
            protocol,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(run(configured[0].config.serve(&mut ctx)), Outcome::Response);
        let reply = Message::parse(&response).unwrap();
        assert_eq!(reply.id(), 0x1234);
        assert!(reply.qr() && reply.aa() && reply.rd() && reply.cd());
        assert_eq!(
            (
                reply.question_count(),
                reply.answer_count(),
                reply.authority_count(),
                reply.additional_count()
            ),
            (1, 0, 0, 2)
        );
        let mut extra = reply.additionals();
        let ip = extra.next().unwrap();
        assert_eq!(ip.name.to_string(), name);
        assert_eq!((ip.class, ip.ttl), (Class::CH, 0));
        let socket: std::net::SocketAddr = address.parse().unwrap();
        match socket.ip() {
            std::net::IpAddr::V4(ipv4) => {
                assert_eq!(ip.rtype, Type::A);
                assert_eq!(ip.rdata, ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                assert_eq!(ip.rtype, Type::AAAA);
                assert_eq!(ip.rdata, ipv6.octets());
            }
        }
        let srv = extra.next().unwrap();
        let prefix = if protocol == Protocol::Udp {
            "_udp."
        } else {
            "_tcp."
        };
        assert_eq!(
            srv.name.to_string(),
            if name == "." {
                prefix.to_owned()
            } else {
                format!("{prefix}{name}")
            }
        );
        assert_eq!((srv.rtype, srv.class, srv.ttl), (Type::SRV, Class::CH, 0));
        assert_eq!(
            srv.rdata,
            &[
                0,
                0,
                0,
                0,
                (socket.port() >> 8) as u8,
                socket.port() as u8,
                0
            ]
        );
    }
}

#[test]
fn insufficient_preallocated_buffer_is_an_error() {
    let blocks = parse("Corefile", ". {\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let query = Message::parse(&[0; 12]).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::new();
    let mut slots = [];
    let mut context = Context {
        query,
        client: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        run(configured[0].config.serve(&mut context)),
        Outcome::Error(pharos_server::Error::ResponseBufferTooSmall)
    );
}

#[test]
fn generated_chain_future_is_send_and_small() {
    fn assert_send<T: Send>(_: &T) {}
    let blocks = parse("Corefile", ". {\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(&[0; 12]).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let future = configured[0].config.serve(&mut context);
    assert_send(&future);
    let size = std::mem::size_of_val(&future);
    println!("chain future: {size} bytes");
    // Future size grows with the number of compiled Plugins.
    if directives().len() == 1 {
        assert!(size < 1024, "whoami-only future is {size} bytes");
    }
    assert_eq!(run(future), Outcome::Response);
}

#[test]
fn empty_chain_reports_no_next_plugin() {
    let chain = Chain::default();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(&[0; 12]).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        run(chain.serve(&mut context)),
        Outcome::Error(pharos_server::Error::NoNextPlugin)
    );
    assert_eq!(
        pharos_server::Error::NoNextPlugin.to_string(),
        "no next plugin found"
    );
}
