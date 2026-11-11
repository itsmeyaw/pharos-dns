#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct AliasChain(pharos_plugins::rewrite::Rewrite, &'static str);
impl pharos_server::Chain for AliasChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, AliasBackend(self.1)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct AliasBackend(&'static str);
impl Next for AliasBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let original = q.name.to_string() == "alias.example.";
        let target: Name = "old.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if original {
            b.record_with(Section::Answer, q.name, Type::CNAME, Class::IN, 30, |w| {
                w.write_name(NameRef::parse(target.as_wire(), 0).unwrap())
            })
            .unwrap();
        } else {
            assert_eq!(q.name.to_string(), self.0);
            b.record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 1],
            )
            .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go.
#[tokio::test]
async fn coredns_cname_rewrite_follows_target_through_self_lookup() {
    for (rule, expected) in [
        ("rewrite cname old.example. new.example.", "new.example."),
        (
            "rewrite continue cname old.example. new.example.\n rewrite cname missing.example. unused.example.",
            "new.example.",
        ),
        ("rewrite cname suffix .example. .other.", "old.other."),
        ("rewrite cname prefix old new", "new.example."),
        ("rewrite cname substring ld.ex k.ex", "ok.example."),
        (
            r"rewrite cname regex (.*)\.example\. {1}.other.",
            "old.other.",
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let mut chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
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
            ".".parse().unwrap(),
            Some(AliasChain(chain.rewrite.take().unwrap(), expected)),
            vec![],
        );
        let server = pharos_server::Server::new(router, key);
        let name: Name = "alias.example.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            pharos_server::Handler::handle(
                &server,
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
            pharos_server::Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        let mut answers = message.answers();
        let pharos_proto::Rdata::Cname(target) = answers.next().unwrap().data().unwrap() else {
            panic!("expected CNAME")
        };
        assert_eq!(target.to_string(), expected);
        let answer = answers.next().unwrap();
        assert_eq!(answer.name.to_string(), expected);
        assert_eq!(answer.rdata, &[192, 0, 2, 1]);
    }
}

struct Answer;
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            q.name,
            Type::A,
            Class::IN,
            5,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct Unanswered(Rcode);
impl Next for Unanswered {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(self.0)
    }
}

struct RcodeChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for RcodeChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, Unanswered(Rcode::SERVFAIL)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct RewriteAnswerChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for RewriteAnswerChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, Answer).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn edns_rewrite_does_not_add_opt_for_non_edns_client() {
    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        ".".parse().unwrap(),
        Some(RewriteAnswerChain(chain.rewrite.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "example.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        pharos_server::Handler::handle(
            &server,
            &wire,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        pharos_server::Action::Respond
    );
    // RFC 6891 §7: a non-EDNS Query must not receive an OPT record.
    assert!(Message::parse(&response).unwrap().opt().is_none());
}

#[tokio::test]
async fn coredns_rcode_rewrite_returns_a_response_for_unanswered_success() {
    let config = ".:53 {\n rewrite rcode example. SERVFAIL NOERROR\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        ".".parse().unwrap(),
        Some(RcodeChain(chain.rewrite.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "example.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        pharos_server::Handler::handle(
            &server,
            &wire,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        pharos_server::Action::Respond
    );
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.question_count(), 1);
}

#[tokio::test]
async fn coredns_edns_revert_survives_unanswered_error_response() {
    for (config, expected) in [
        (
            ".:53 {\n rewrite edns0 local set 0xffee new revert\n}",
            &b"\xff\xee\0\x03old"[..],
        ),
        (
            ".:53 {\n rewrite continue edns0 local set 0xffee new\n}",
            &b"\xff\xee\0\x03new"[..],
        ),
    ] {
        let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
            ".".parse().unwrap(),
            Some(RcodeChain(chain.rewrite.take().unwrap())),
            vec![],
        );
        let server = pharos_server::Server::new(router, key);
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let original = b"\xff\xee\0\x03old";
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(1232),
            0,
            original,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            pharos_server::Handler::handle(
                &server,
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
            pharos_server::Action::Respond
        );
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::SERVFAIL);
        assert_eq!(response.opt().unwrap().options().as_bytes(), expected);
    }
}

struct InspectQuestion(Type, Class);
impl Next for InspectQuestion {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!((q.qtype, q.qclass), (self.0, self.1));
        let mut copy = Vec::with_capacity(512);
        cx.query.copy_wire(&mut copy);
        let parsed = Message::parse(&copy).unwrap();
        let copied = parsed.questions().next().unwrap();
        assert_eq!((copied.qtype, copied.qclass), (self.0, self.1));
        Outcome::Drop
    }
}

struct InspectLocalOption;
impl Next for InspectLocalOption {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let opt = cx.query.opt().expect("rewrite created OPT");
        assert!(opt.options().iter().any(|option| matches!(
            option,
            pharos_proto::EdnsOption::Unknown {
                code: 0xffee,
                data: b"abcd"
            }
        )));
        Outcome::Drop
    }
}

struct InspectOptionBytes(&'static [u8]);
impl Next for InspectOptionBytes {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.query.opt().unwrap().options().as_bytes(), self.0);
        Outcome::Drop
    }
}

#[tokio::test]
async fn coredns_edns_local_append_replace_and_unset() {
    let initial = b"\xff\xee\0\x01a";
    for (rule, input, expected) in [
        (
            "rewrite edns0 local append 0xffee b",
            &initial[..],
            &b"\xff\xee\0\x01a\xff\xee\0\x01b"[..],
        ),
        (
            "rewrite edns0 local replace 0xffee b",
            &initial[..],
            &b"\xff\xee\0\x01b"[..],
        ),
        ("rewrite edns0 local replace 0xffee b", &b""[..], &b""[..]),
        ("rewrite edns0 local unset 0xffee", &initial[..], &b""[..]),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(4096),
            0,
            input,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectOptionBytes(expected))
                .await,
            Outcome::Drop,
            "{rule}"
        );
    }
}

#[tokio::test]
async fn coredns_ignored_edns_replace_does_not_stop_later_rules() {
    let config = ".:53 {\n rewrite edns0 local replace 0xffee data\n rewrite ttl example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_ignored_edns_replace_does_not_block_name_reversion() {
    let config =
        ".:53 {\n rewrite edns0 local replace 0xffee data\n rewrite name a.example. b.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "a.example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, ExpectNameAnswer("b.example."))
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "a.example."
    );
}

#[tokio::test]
async fn coredns_edns_nsid_and_subnet_rewrite() {
    for (rule, expected) in [
        ("rewrite edns0 nsid set", &b"\0\x03\0\0"[..]),
        (
            "rewrite edns0 subnet set 24 56",
            &b"\0\x08\0\x07\0\x01\x18\0\xc0\0\x02"[..],
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "192.0.2.129:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectOptionBytes(expected))
                .await,
            Outcome::Drop,
            "{rule}"
        );
    }
}

struct InspectMaybeOptions(Option<&'static [u8]>);
impl Next for InspectMaybeOptions {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.query.opt().map(|opt| opt.options().as_bytes()), self.0);
        Outcome::Drop
    }
}

struct EchoOptions;
impl Next for EchoOptions {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let query = cx.query;
        let q = query.questions().next().unwrap();
        let opt = query.opt().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(opt.udp_payload_size()),
            0,
            opt.options().as_bytes(),
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct MultiAnswerEcho;
impl Next for MultiAnswerEcho {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let query = cx.query;
        let q = query.questions().next().unwrap();
        let opt = query.opt().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        for ip in [[192, 0, 2, 1], [192, 0, 2, 2]] {
            b.record(Section::Answer, q.name, Type::A, Class::IN, 30, &ip)
                .unwrap();
        }
        b.record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(opt.udp_payload_size()),
            0,
            opt.options().as_bytes(),
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_edns_reverter_applies_once_for_each_response_record() {
    let config = ".:53 {\n rewrite edns0 local append 0xffee c revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        b"\xff\xee\0\x01a\xff\xee\0\x01b",
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, MultiAnswerEcho)
            .await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .opt()
            .unwrap()
            .options()
            .as_bytes(),
        b""
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/edns0_test.go.
#[tokio::test]
async fn coredns_edns_revert_restores_original_or_removes_injected_option() {
    for original in [&b""[..], &b"\xff\xee\0\x03old"[..]] {
        let config = ".:53 {\n rewrite edns0 local set 0xffee new revert\n}";
        let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(4096),
            0,
            original,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, EchoOptions)
                .await,
            Outcome::Response
        );
        let response = Message::parse(cx.response).unwrap();
        assert_eq!(response.opt().unwrap().options().as_bytes(), original);
    }
}

#[tokio::test]
async fn coredns_edns_revert_restores_previous_rewrite_value() {
    let config = ".:53 {\n rewrite continue edns0 local set 0xffee abcd\n rewrite edns0 local replace 0xffee bcde revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        &[],
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, EchoOptions)
            .await,
        Outcome::Response
    );
    let response = Message::parse(cx.response).unwrap();
    assert_eq!(
        response.opt().unwrap().options().as_bytes(),
        b"\xff\xee\0\x04abcd"
    );
}

#[tokio::test]
async fn coredns_edns_revert_applies_when_next_omits_opt() {
    let config = ".:53 {\n rewrite continue edns0 local set 0xffee abcd\n rewrite edns0 local replace 0xffee bcde revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        &[],
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let response = Message::parse(cx.response).unwrap();
    assert_eq!(
        response.opt().unwrap().options().as_bytes(),
        b"\xff\xee\0\x04abcd"
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewriteEDNS0LocalVariable.
#[tokio::test]
async fn coredns_edns_local_variables_and_metadata() {
    for (variable, value, expected) in [
        ("qname", None, Some(&b"\xff\xee\0\x08example."[..])),
        ("qtype", None, Some(&b"\xff\xee\0\x02\0\x01"[..])),
        (
            "client_ip",
            None,
            Some(&b"\xff\xee\0\x04\xc0\0\x02\x81"[..]),
        ),
        ("client_port", None, Some(&b"\xff\xee\0\x02\x04\xd2"[..])),
        ("server_ip", None, Some(&b"\xff\xee\0\x04\x7f\0\0\x01"[..])),
        ("server_port", None, Some(&b"\xff\xee\0\x02\0\x35"[..])),
        ("protocol", None, Some(&b"\xff\xee\0\x03udp"[..])),
        (
            "test/label",
            Some("Team-A"),
            Some(&b"\xff\xee\0\x06Team-A"[..]),
        ),
        ("test/label", None, None),
    ] {
        let config = format!(".:53 {{\n rewrite edns0 local set 0xffee {{{variable}}}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "192.0.2.129:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        if let Some(value) = value {
            cx.metadata.insert("test/label", value);
        }
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectMaybeOptions(expected))
                .await,
            Outcome::Drop,
            "{variable}"
        );
    }
}

struct WaitForever;
impl Next for WaitForever {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        std::future::pending().await
    }
}

#[test]
fn edns_buffer_is_released_when_a_query_is_cancelled() {
    use std::{
        future::Future,
        task::{Context as TaskContext, Poll, Waker},
    };
    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let plugin = chain.rewrite.as_ref().unwrap();
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut first_response = Vec::with_capacity(512);
    let mut second_response = Vec::with_capacity(512);
    let mut first_slots = [];
    let mut second_slots = [];
    let mut first = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut first_slots),
        response: &mut first_response,
        max_response_size: 512,
    };
    let mut second = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut second_slots),
        response: &mut second_response,
        max_response_size: 512,
    };
    let mut first_future = Box::pin(plugin.serve(&mut first, WaitForever));
    let mut second_future = Box::pin(plugin.serve(&mut second, InspectLocalOption));
    let mut task = TaskContext::from_waker(Waker::noop());
    assert_eq!(first_future.as_mut().poll(&mut task), Poll::Pending);
    assert_eq!(second_future.as_mut().poll(&mut task), Poll::Pending);
    drop(first_future);
    assert_eq!(
        second_future.as_mut().poll(&mut task),
        Poll::Ready(Outcome::Drop)
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go.
#[tokio::test]
async fn coredns_edns_local_set_reaches_next_without_original_opt() {
    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectLocalOption)
            .await,
        Outcome::Drop
    );
    assert!(cx.query.opt().is_none());
}

struct InspectName(&'static str);
impl Next for InspectName {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        Outcome::Drop
    }
}

struct ExpectNameAnswer(&'static str);
impl Next for ExpectNameAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        Answer.run(cx).await
    }
}

struct NoQuestionAnswer;
impl Next for NoQuestionAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.record(
            Section::Answer,
            q.name,
            Type::A,
            Class::IN,
            5,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go.
#[tokio::test]
async fn coredns_reverter_restores_a_missing_question() {
    let config = ".:53 {\n rewrite ttl example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, NoQuestionAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "example."
    );
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_continue_applies_and_reverts_names_in_order() {
    let config = ".:53 {\n rewrite continue name a.example. b.example.\n rewrite name b.example. c.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "a.example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, ExpectNameAnswer("c.example."))
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "a.example."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "a.example."
    );
}

#[tokio::test]
async fn coredns_ttl_rule_matches_name_rewritten_by_previous_rule() {
    let config =
        ".:53 {\n rewrite continue name a.example. b.example.\n rewrite ttl b.example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "a.example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, ExpectNameAnswer("b.example."))
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_response_rules_restore_the_original_question_type() {
    let config = ".:53 {\n rewrite continue type A AAAA\n rewrite ttl example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.questions().next().unwrap().qtype, Type::A);
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_non_regex_name_rewrite_modes() {
    for (rule, incoming, expected) in [
        (
            "rewrite name prefix ftp web",
            "ftp.example.",
            "web.example.",
        ),
        (
            "rewrite name suffix .schmoogle.com. .google.com.",
            "www.schmoogle.com.",
            "www.google.com.",
        ),
        (
            "rewrite name substring service.us-west-1.example.org service.us-west-1.consul",
            "ftp.service.us-west-1.example.org.",
            "ftp.service.us-west-1.consul.",
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = incoming.parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectName(expected))
                .await,
            Outcome::Drop,
            "{rule}"
        );
    }
}

#[tokio::test]
async fn coredns_regex_name_capture_rewrite() {
    let config = r".:53 {
 rewrite name regex (.*)-(us-west-1)\.example\.org {1}.service.{2}.consul
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "ftp-us-west-1.example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectName("ftp.service.us-west-1.consul."))
            .await,
        Outcome::Drop
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go.
#[tokio::test]
async fn coredns_regex_name_metadata_and_missing_labels() {
    let config = r".:53 {
 rewrite name regex ^([^.]+)\.example\.$ {1}.{kubernetes/client-namespace}.svc.cluster.local. metadata
}";
    for (value, expected) in [
        (Some("Team-A"), "web.team-a.svc.cluster.local."),
        (None, "web.example."),
    ] {
        let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "web.example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        if let Some(value) = value {
            cx.metadata.insert("kubernetes/client-namespace", value);
        }
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectName(expected))
                .await,
            Outcome::Drop
        );
    }
}

#[tokio::test]
async fn coredns_invalid_metadata_name_restores_original_question() {
    let config = r".:53 {
 rewrite continue name a.example. b.example.
 rewrite name regex ^([^.]+)\.example\.$ {1}.{test/value}. metadata
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "a.example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    cx.metadata.insert("test/value", "invalid..name");
    assert!(matches!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectName("must-not-run"))
            .await,
        Outcome::Error(_)
    ));
    assert_eq!(
        cx.query.questions().next().unwrap().name.to_string(),
        "a.example."
    );
}

struct AliasedAnswer;
impl Next for AliasedAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "internal.example.");
        let owner: Name = "alias.internal.example.".parse().unwrap();
        let target: Name = "other.internal.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record_with(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::CNAME,
            Class::IN,
            60,
            |writer| writer.write_name(NameRef::parse(target.as_wire(), 0).unwrap()),
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct DnameAnswer;
impl Next for DnameAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let target: Name = "other.internal.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record_with(Section::Answer, q.name, Type::DNAME, Class::IN, 60, |w| {
            w.write_uncompressed_name(NameRef::parse(target.as_wire(), 0).unwrap())
        })
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go.
#[tokio::test]
async fn coredns_auto_rewrites_dname_values() {
    let config = ".:53 {\n rewrite name example.com. internal.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, DnameAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    let rr = message.answers().next().unwrap();
    assert_eq!(
        NameRef::parse(rr.rdata, 0).unwrap().to_string(),
        "other.example.com."
    );
}

struct SuffixAnswer;
impl Next for SuffixAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "www.internal.");
        let owner: Name = "other.internal.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct ChainedSuffixAnswer;
impl Next for ChainedSuffixAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "www.c.");
        let owner: Name = "other.c.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_continue_reverts_each_suffix_rule_in_reverse() {
    let config = ".:53 {\n rewrite continue name suffix .a. .b. answer auto\n rewrite name suffix .b. .c. answer auto\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "www.a.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, ChainedSuffixAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "www.a."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "other.a."
    );
}

#[tokio::test]
async fn coredns_suffix_answer_auto_rewrites_entire_suffix() {
    let config = ".:53 {\n rewrite name suffix .external. .internal. answer auto\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "www.external.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, SuffixAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "www.external."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "other.external."
    );
}

#[tokio::test]
async fn coredns_exact_auto_rewrites_subdomain_owners_and_values() {
    let config = ".:53 {\n rewrite name example.com. internal.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, AliasedAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    let rr = message.answers().next().unwrap();
    assert_eq!(rr.name.to_string(), "alias.example.com.");
    let pharos_proto::Rdata::Cname(target) = rr.data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "other.example.com.");
}

#[tokio::test]
async fn coredns_explicit_answer_name_and_value_rules() {
    let config = r".:53 {
 rewrite name exact example.com. internal.example. answer name (.*)\.internal\.example\. {1}.external.test. answer value (.*)\.internal\.example\. {1}.external.test.
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, AliasedAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    let rr = message.answers().next().unwrap();
    assert_eq!(rr.name.to_string(), "alias.external.test.");
    let pharos_proto::Rdata::Cname(target) = rr.data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "other.external.test.");
}

#[tokio::test]
async fn coredns_type_and_class_rewrite_question() {
    for (rules, expected_type, expected_class) in [
        ("rewrite type A AAAA", Type::AAAA, Class::IN),
        ("rewrite type AAAA HINFO", Type::A, Class::IN),
        ("rewrite class IN CH", Type::A, Class::CH),
        (
            "rewrite continue type A AAAA\n rewrite class IN CH",
            Type::AAAA,
            Class::CH,
        ),
    ] {
        let config = format!(".:53 {{\n {rules}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
        let root: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectQuestion(expected_type, expected_class))
                .await,
            Outcome::Drop
        );
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go.
#[tokio::test]
async fn coredns_exact_name_rewrites_query_and_auto_reverts_response() {
    let config = ".:53 {\n rewrite name example.com. internal.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "example.com."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "example.com."
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go.
#[tokio::test]
async fn coredns_rcode_rewrites_unanswered_response() {
    for code in [
        Rcode::FORMERR,
        Rcode::SERVFAIL,
        Rcode::REFUSED,
        Rcode::NOTIMP,
    ] {
        let text = format!(".:53 {{\n rewrite rcode example. {} NOERROR\n}}", code.0);
        let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, Unanswered(code))
            .await;
        assert!(
            outcome == Outcome::Unanswered(Rcode::NOERROR)
                || (outcome == Outcome::Response
                    && Message::parse(cx.response).unwrap().rcode() == Rcode::NOERROR)
        );
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go.
#[tokio::test]
async fn coredns_ttl_exact_and_ranges() {
    for (rule, name, ttl) in [
        ("rewrite ttl srv1.coredns.rocks 1", "srv1.coredns.rocks.", 1),
        (
            "rewrite ttl range.example.com. 30-300",
            "range.example.com.",
            30,
        ),
        ("rewrite ttl ceil.example.com. -11", "ceil.example.com.", 5),
        (
            "rewrite ttl floor.example.com. 10-",
            "floor.example.com.",
            10,
        ),
        ("rewrite ttl other.example. 1", "example.com.", 5),
        (
            "rewrite ttl exact srv15.coredns.rocks 15",
            "srv15.coredns.rocks.",
            15,
        ),
        ("rewrite ttl prefix srv30 30", "srv30.coredns.rocks.", 30),
        (
            "rewrite ttl suffix 45.coredns.rocks 45",
            "srv45.coredns.rocks.",
            45,
        ),
        ("rewrite ttl substring rv50 50", "srv50.coredns.rocks.", 50),
        (
            r"rewrite ttl regex (srv10)\.(coredns)\.(rocks) 10",
            "srv10.coredns.rocks.",
            10,
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = name.parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
            Outcome::Response
        );
        assert_eq!(
            Message::parse(cx.response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .ttl,
            ttl,
            "{rule}"
        );
    }
}
