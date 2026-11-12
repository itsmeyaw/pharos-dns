#![cfg(feature = "plugin-template")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Outcome, Protocol, Transport};
use std::sync::Arc;

enum Route {
    Template(Box<Chain>),
    TruncatedTarget,
}

impl pharos_server::Chain for Route {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        match self {
            Self::Template(chain) => chain.serve(cx).await,
            Self::TruncatedTarget => {
                let question = cx.query.questions().next().unwrap();
                // RFC 1035 §4.1.1: TC marks a Response truncated on this channel.
                let mut reply =
                    MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8200).unwrap();
                reply
                    .question(question.name, question.qtype, question.qclass)
                    .unwrap();
                reply
                    .record(
                        Section::Answer,
                        question.name,
                        Type::A,
                        Class::IN,
                        600,
                        &[1, 2, 3, 4],
                    )
                    .unwrap();
                let _ = reply.finish();
                Outcome::Response
            }
        }
    }

    fn is_empty(&self) -> bool {
        false
    }
}

// Derived from CoreDNS TestTruncatedCNAME.
#[tokio::test]
async fn coredns_cname_lookup_preserves_truncation_and_answers() {
    let config =
        ".:53 {\n template IN A foogle.com {\n answer \"foogle.com 60 IN CNAME google.com\"\n }\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let key = pharos_server::ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = pharos_server::Router::default();
    router.add(
        key,
        "foogle.com.".parse().unwrap(),
        Some(Route::Template(Box::new(chain))),
        vec![],
    );
    router.add(
        key,
        "google.com.".parse().unwrap(),
        Some(Route::TruncatedTarget),
        vec![],
    );
    let server = Arc::new(pharos_server::Server::new(router, key));
    let name: Name = "foogle.com.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 42, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        pharos_server::Handler::handle_shared(
            &server,
            &query,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await,
        pharos_server::Action::Respond
    );
    let response = Message::parse(&response).unwrap();
    assert!(response.tc());
    let mut answers = response.answers();
    let alias = answers.next().unwrap();
    assert_eq!(
        (alias.name.to_string().as_str(), alias.rtype, alias.ttl),
        ("foogle.com.", Type::CNAME, 60)
    );
    let address = answers.next().unwrap();
    assert_eq!(
        (
            address.name.to_string().as_str(),
            address.rtype,
            address.ttl
        ),
        ("google.com.", Type::A, 600)
    );
    assert_eq!(address.rdata, &[1, 2, 3, 4]);
    assert!(answers.next().is_none());
}
