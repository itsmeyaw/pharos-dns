use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[tokio::test]
async fn template_evaluates_many_chained_variables() {
    let variables = (0..40)
        .map(|i| {
            if i == 0 {
                "var v0 1\n".to_owned()
            } else {
                format!("var v{i} v{} + 1\n", i - 1)
            }
        })
        .collect::<String>();
    let text = format!(
        ".:53 {{\n template IN A {{\n {variables} expr v39 == 40\n answer \"{{{{ .Name }}}} 60 IN A 192.0.2.{{{{ .Var.v39 }}}}\"\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
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
        configured[0].config.serve(&mut context).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        &[192, 0, 2, 40]
    );
}

#[tokio::test]
async fn template_evaluates_many_variables_and_capture_groups() {
    let pattern = format!("^{}(?P<last>x)[.]$", "()".repeat(128));
    let variables = (0..40)
        .map(|i| {
            if i == 0 {
                "var v0 group('last')\n".to_owned()
            } else {
                format!("var v{i} v{} + 'a'\n", i - 1)
            }
        })
        .collect::<String>();
    let text = format!(
        ".:53 {{\n template IN A {{\n match {pattern}\n {variables} expr group(129) == 'x' && v39 == 'x{}'\n answer \"{{{{ .Name }}}} 60 IN TXT \\\"{{{{ index .Match 129 }}}}:{{{{ .Group.last }}}}:{{{{ .Group.129 }}}}\\\"\"\n }}\n}}",
        "a".repeat(39)
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
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
        configured[0].config.serve(&mut context).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        b"\x05x:x:x"
    );
}

#[test]
fn template_renders_concurrently_on_multiple_threads() {
    let text = ".:53 {\n template IN A {\n match ^(?P<host>[0-9]+)[.]example[.]$\n var host group('host')\n expr host matches '^[0-9]+$'\n answer \"{{ .Name }} 60 IN A 192.0.2.{{ .Var.host }}\"\n }\n}";
    let configured = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let chain = &configured[0].config;
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for i in 1..=8 {
            let barrier = &barrier;
            scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                let root: Name = ".".parse().unwrap();
                let name: Name = format!("{i}.example.").parse().unwrap();
                let mut wire = Vec::with_capacity(512);
                let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
                builder
                    .question(
                        NameRef::parse(name.as_wire(), 0).unwrap(),
                        Type::A,
                        Class::IN,
                    )
                    .unwrap();
                let _ = builder.finish();
                let mut response = Vec::with_capacity(512);
                let mut slots = [];
                let mut context = Context {
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
                barrier.wait();
                for _ in 0..20 {
                    assert_eq!(
                        runtime.block_on(chain.serve(&mut context)),
                        Outcome::Response
                    );
                    assert_eq!(
                        Message::parse(context.response)
                            .unwrap()
                            .answers()
                            .next()
                            .unwrap()
                            .rdata,
                        &[192, 0, 2, i]
                    );
                    context.response.clear();
                }
            });
        }
    });
}

#[tokio::test]
async fn template_variables_share_one_expression_scratch() {
    for (length, expected) in [
        (32_000, Outcome::Response),
        (33_000, Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)),
    ] {
        let value = "a".repeat(length);
        let text = format!(
            ".:53 {{\n template IN A {{\n var alpha '{value}' + 'b'\n var beta '{value}' + 'c'\n expr alpha != beta\n rcode NXDOMAIN\n }}\n}}"
        );
        let configured =
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
        let root: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut context = Context {
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
        assert_eq!(configured[0].config.serve(&mut context).await, expected);
    }
}

#[tokio::test]
async fn template_expressions_share_rule_scratch_budget() {
    let value = "a".repeat(33_000);
    let text = format!(
        ".:53 {{\n template IN A {{\n expr '{value}' + 'b' == '{value}b'\n expr '{value}' + 'b' == '{value}b'\n rcode NXDOMAIN\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
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
        configured[0].config.serve(&mut context).await,
        Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
    );
}

#[tokio::test]
async fn template_expression_scratch_accepts_large_values_and_rejects_exhaustion() {
    for (length, expected) in [
        (5000, Outcome::Response),
        (65_534, Outcome::Response),
        (65_535, Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)),
    ] {
        let value = "a".repeat(length);
        let text = format!(
            ".:53 {{\n template IN A {{\n var value '{value}' + 'b'\n expr value == '{value}b'\n rcode NXDOMAIN\n }}\n}}"
        );
        let configured =
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
        let root: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut context = Context {
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
        assert_eq!(configured[0].config.serve(&mut context).await, expected);
        if expected == Outcome::Response {
            assert_eq!(
                Message::parse(&response).unwrap().rcode(),
                pharos_proto::Rcode::NXDOMAIN
            );
        }
    }
}

// Derived from CoreDNS v1.15.0 plugin/template/setup_test.go.
#[test]
fn template_setup_validates_options() {
    for (directive, valid) in [
        ("template IN A", true),
        ("template ANY ANY {\n rcode NXDOMAIN\n}", true),
        ("template IN A {\n match [\n}", false),
        ("template IN A {\n ederror 65536\n}", false),
        ("template IN A {\n answer\n}", false),
        ("template IN A {\n additional\n}", false),
        ("template IN A {\n authority\n}", false),
        ("template IN A {\n rcode\n}", false),
        ("template IN A {\n rcode UNDEFINED\n}", false),
        ("template IN A {\n answer \"{{\"\n}", false),
        ("template IN A {\n unknown\n}", false),
        (
            "template IN A {\n var value 1\n var next value + 1\n expr next == 2\n}",
            true,
        ),
        ("template IN A {\n var 1value 1\n}", false),
        ("template IN A {\n var name 1\n}", false),
        ("template IN A {\n var value missing + 1\n}", false),
        ("template BAD A", false),
        ("template IN", false),
    ] {
        let text = format!(".:53 {{\n {directive}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}

#[tokio::test]
async fn template_answers_captures_and_sections() {
    let text = ".:53 {\n template IN A example {\n  match ^(?P<ip>[0-9]+)[.]example[.]$\n  answer \"{{ .Name }} 60 IN A 192.0.2.{{ .Group.ip }}\"\n  authority \"example. 60 IN NS ns.example.\"\n  additional \"ns.example. 60 IN A 192.0.2.1\"\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let root: Name = ".".parse().unwrap();
    let name: Name = "5.example.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut context = Context {
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
        configured[0].config.serve(&mut context).await,
        Outcome::Response
    );
    let response = Message::parse(&response).unwrap();
    assert!(response.aa());
    assert_eq!(response.answers().next().unwrap().rdata, &[192, 0, 2, 5]);
    assert_eq!(response.authorities().count(), 1);
    assert_eq!(response.additionals().count(), 1);
}
