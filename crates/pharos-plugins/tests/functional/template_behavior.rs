use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

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
