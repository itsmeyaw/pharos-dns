#![forbid(unsafe_code)]
#![cfg(feature = "plugin-template")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, EdnsOption, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Error, Metadata, Outcome, Protocol, Transport};

fn chain(directives_text: &str) -> Chain {
    let text = format!(".:53 {{\n{directives_text}\n}}");
    configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
        .unwrap_or_else(|error| panic!("{directives_text}: {error}"))
        .remove(0)
        .config
}

async fn query(
    chain: &Chain,
    qname: &str,
    qtype: Type,
    qclass: Class,
    metadata: &[(&str, &str)],
) -> (Outcome, Vec<u8>) {
    let name: Name = qname.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, qclass)
        .unwrap();
    let _ = builder.finish();

    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(4096);
    let mut slots = [None; 8];
    let mut values = Metadata::new(&mut slots);
    for &(key, value) in metadata {
        assert!(values.insert(key, value));
    }
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "10.240.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: values,
        response: &mut response,
        max_response_size: 4096,
    };
    // Keep the unmeasured Chain future out of the template fixture's stack.
    let outcome = Box::pin(chain.serve(&mut cx)).await;
    (outcome, response)
}

fn assert_servfail(outcome: Outcome, wire: &[u8]) {
    match outcome {
        Outcome::Unanswered(Rcode::SERVFAIL) => assert!(wire.is_empty()),
        Outcome::Error(error) => {
            assert!(!matches!(
                error,
                Error::NoNextPlugin | Error::NotImplemented | Error::PluginPanic
            ));
            assert!(wire.is_empty());
        }
        Outcome::Response => assert_eq!(Message::parse(wire).unwrap().rcode(), Rcode::SERVFAIL),
        other => panic!("expected SERVFAIL, got {other:?}"),
    }
}

// Derived from CoreDNS v1.15.0 plugin/template/setup_test.go.
#[test]
fn coredns_setup_cases() {
    for (directive, valid) in [
        ("template", false),
        ("template X", false),
        ("template ANY", false),
        ("template ANY X", false),
        ("template ANY ANY", true),
        ("template ANY ANY {\n}", true),
        ("template ANY ANY (?P<x>", true),
        ("template ANY ANY {\n rcode NXDOMAIN\n}", true),
        ("template ANY ANY {\n unknown\n}", false),
        ("template ANY ANY {\n match\n}", false),
        ("template ANY ANY {\n match [\n}", false),
        ("template ANY ANY {\n answer\n}", false),
        ("template ANY ANY {\n additional\n}", false),
        ("template ANY ANY {\n authority\n}", false),
        ("template ANY ANY {\n rcode\n}", false),
        ("template ANY ANY {\n rcode UNDEFINED\n}", false),
        ("template ANY ANY {\n answer \"{{\"\n}", false),
        ("template ANY ANY {\n additional \"{{\"\n}", false),
        ("template ANY ANY {\n authority \"{{\"\n}", false),
        (
            "template ANY ANY {\n answer \"{{ notAFunction }}\"\n}",
            false,
        ),
        ("template ANY ANY {\n answer \"{{ parseInt }}\"\n}", true),
        (
            "template ANY ANY {\n answer \"{{ parseInt }}\"\n additional \"{{ parseInt }}\"\n authority \"{{ parseInt }}\"\n}",
            true,
        ),
        (
            r#"template IN ANY example.com {
 match "[.](example[.]com[.]dc1[.]example[.]com[.])$"
 rcode NXDOMAIN
 authority "{{ index .Match 1 }} 60 IN SOA ns.{{ index .Match 1 }} hostmaster.example.com (1 60 60 60 60)"
 fallthrough example.com
}"#,
            true,
        ),
        (
            r#"template ANY A example.com {
 match ip-(?P<a>[0-9]*)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]com
 answer "{{ .Name }} A {{ .Group.a }}.{{ .Group.b }}.{{ .Group.c }}.{{ .Grup.d }}."
 fallthrough
}"#,
            true,
        ),
        (
            r#"template ANY AAAA example.com {
 match ip-(?P<a>[0-9]*)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]com
 authority "example.com 60 IN SOA ns.example.com hostmaster.example.com (1 60 60 60 60)"
 fallthrough
}"#,
            true,
        ),
        (
            "template ANY ANY invalid {\n rcode NXDOMAIN\n ederror 21 \"Blocked according to RFC2606\"\n}",
            true,
        ),
        (
            "template ANY ANY invalid {\n ederror invalid \"Blocked\"\n}",
            false,
        ),
        ("template ANY ANY invalid {\n ederror 21 too many\n}", false),
        ("template ANY ANY invalid {\n ederror 65536\n}", false),
        (
            "template IN A example. {\n var ttl 60\n expr ttl == 60\n answer \"{{ .Name }} {{ .Var.ttl }} IN A 10.0.0.1\"\n}",
            true,
        ),
        ("template ANY ANY example. {\n var a 1\n}", true),
        (
            "template IN A example. {\n var a 1\n var b a + 1\n var c 'x' + name()\n}",
            true,
        ),
        (
            "template IN A example. {\n match ^(?P<a>[a-z]+)[.]example[.]$\n var a group('a') + group(1) + group(0)\n}",
            true,
        ),
        ("template IN A example. {\n var\n}", false),
        ("template IN A example. {\n var a\n}", false),
        ("template IN A example. {\n var 1a 1\n}", false),
        ("template IN A example. {\n var a-b 1\n}", false),
        ("template IN A example. {\n var name 1\n}", false),
        ("template IN A example. {\n var group 1\n}", false),
        ("template IN A example. {\n var len 1\n}", false),
        ("template IN A example. {\n var true 1\n}", false),
        ("template IN A example. {\n var let 1\n}", false),
        ("template IN A example. {\n var a 1 +\n}", false),
        (
            "template IN A example. {\n var a invalid expression\n}",
            false,
        ),
        ("template IN A example. {\n var a b + 1\n var b 1\n}", false),
        ("template IN A example. {\n var a undefined\n}", false),
        ("template IN A example. {\n var a 1\n var a 2\n}", false),
        (
            "template IN A example. {\n var a 1\n var b a + 1\n var c 'x' + b\n}",
            false,
        ),
        (
            "template IN A example. {\n expr name() == 'a.example.'\n expr incidr(client_ip(), '10.0.0.0/8')\n}",
            true,
        ),
        (
            "template ANY ANY example. {\n match ^(?P<a>[a-z]+)[.]example[.]$\n expr group('a') != ''\n}",
            true,
        ),
        ("template IN A example. {\n expr 1\n}", true),
        ("template IN A example. {\n expr\n}", false),
        ("template IN A example. {\n expr name() ==\n}", false),
        (
            "template IN A example. {\n expr invalid expression\n}",
            false,
        ),
        ("template IN A example. {\n expr undefined == 1\n}", false),
        (
            "template IN A example. {\n var a 1\n expr a + 'x'\n}",
            false,
        ),
    ] {
        let text = format!(".:53 {{\n{directive}\n}}");
        let result = parse("Corefile", &text)
            .map(|blocks| configure::<Chain>(&blocks, directives()).is_ok())
            .unwrap_or(false);
        assert_eq!(result, valid, "{directive}");
    }

    let directive = format!(
        "template ANY A example.com {{\n match {}\n}}",
        "a".repeat(10_001)
    );
    let text = format!(".:53 {{\n{directive}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    assert!(configure::<Chain>(&blocks, directives()).is_err());
}

// Derived from CoreDNS TestHandler and TestMultiSection.
#[tokio::test]
async fn coredns_captures_parse_int_and_record_sections() {
    let chain = chain(
        r#"
template IN A example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
 authority "example. 60 IN NS ns0.example."
 additional "ns0.example. 60 IN A 203.0.113.8"
 fallthrough
}
template IN A example. {
 match ^ip0a(?P<b>[a-f0-9]{2})(?P<c>[a-f0-9]{2})(?P<d>[a-f0-9]{2})[.]example[.]$
 answer "{{ .Name }} 3600 IN A 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }}"
}
"#,
    );
    for (name, address, ttl, sections) in [
        ("ip-10-95-12-8.example.", [10, 95, 12, 8], 60, true),
        ("ip0a5f0c09.example.", [10, 95, 12, 9], 3600, false),
    ] {
        let (outcome, wire) = query(&chain, name, Type::A, Class::IN, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert!(response.aa());
        assert_eq!(response.answer_count(), 1);
        let answer = response.answers().next().unwrap();
        assert_eq!(answer.name.to_string(), name);
        assert_eq!(
            (answer.rtype, answer.class, answer.ttl),
            (Type::A, Class::IN, ttl)
        );
        assert_eq!(answer.rdata, address);
        assert_eq!(response.authority_count(), u16::from(sections));
        assert_eq!(response.additional_count(), u16::from(sections));
        if sections {
            assert_eq!(response.authorities().next().unwrap().rtype, Type::NS);
            let extra = response.additionals().next().unwrap();
            assert_eq!(extra.name.to_string(), "ns0.example.");
            assert_eq!(extra.rdata, &[203, 0, 113, 8]);
        }
    }
}

#[tokio::test]
async fn coredns_mx_additional_nxdomain_and_cname() {
    let chain = chain(
        r#"
template IN MX example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Name }} 60 IN MX 10 {{ .Name }}"
 additional "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
}

template ANY ANY invalid. {
 rcode NXDOMAIN
 answer "invalid. 60 {{ .Class }} SOA a.invalid. b.invalid. (1 60 60 60 60)"
}
template IN A example.net. {
 answer "example.net. 60 IN CNAME target.example.com."
}
"#,
    );
    let (outcome, wire) = query(&chain, "ip-10-95-12-8.example.", Type::MX, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.answer_count(), 1);
    let Rdata::Mx {
        preference,
        exchange,
    } = response.answers().next().unwrap().data().unwrap()
    else {
        panic!("expected MX");
    };
    assert_eq!(preference, 10);
    assert_eq!(exchange.to_string(), "ip-10-95-12-8.example.");
    assert_eq!(
        response.additionals().next().unwrap().rdata,
        &[10, 95, 12, 8]
    );

    let (outcome, wire) = query(&chain, "test.invalid.", Type::MX, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert_eq!(response.answers().next().unwrap().rtype, Type::SOA);

    let (outcome, wire) = query(&chain, "example.net.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.answer_count(), 1);
    let Rdata::Cname(target) = response.answers().next().unwrap().data().unwrap() else {
        panic!("expected CNAME");
    };
    assert_eq!(target.to_string(), "target.example.com.");
}

// Derived from CoreDNS v1.15.0 plugin/template/setup_test.go TestSetupParse.
#[tokio::test]
async fn coredns_setup_multiple_records_preserves_sections_and_order() {
    let configured = chain(
        r#"template IN MX example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Name }} 60 IN MX 10 {{ .Name }}"
 additional "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
 authority "example. 60 IN NS ns0.example."
 authority "example. 60 IN NS ns1.example."
 additional "ns0.example. 60 IN A 203.0.113.8"
 additional "ns1.example. 60 IN A 198.51.100.8"
}"#,
    );
    let (outcome, wire) = query(
        &configured,
        "ip-10-95-12-8.example.",
        Type::MX,
        Class::IN,
        &[],
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(
        (
            response.answer_count(),
            response.authority_count(),
            response.additional_count()
        ),
        (1, 2, 3)
    );
    let authorities: Vec<_> = response
        .authorities()
        .map(|record| match record.data().unwrap() {
            Rdata::Ns(target) => target.to_string(),
            _ => panic!("expected NS"),
        })
        .collect();
    assert_eq!(authorities, ["ns0.example.", "ns1.example."]);
    let additionals: Vec<_> = response
        .additionals()
        .map(|record| record.rdata.to_vec())
        .collect();
    assert_eq!(
        additionals,
        [
            vec![10, 95, 12, 8],
            vec![203, 0, 113, 8],
            vec![198, 51, 100, 8]
        ]
    );
}

// CoreDNS treats class/type mismatches as trying the next template, but a failed match
// in an applicable template requires an allowed fallthrough zone.
#[tokio::test]
async fn coredns_template_order_class_type_zone_and_fallthrough() {
    let chain = chain(
        r#"
template IN A test. {
 rcode REFUSED
}
template CH TXT coredns.invalid. {
 answer "{{ .Name }} 60 CH TXT \"test\""
}
template IN A example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
 fallthrough
}
template IN MX example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Name }} 60 IN MX 10 {{ .Name }}"
}
"#,
    );
    let (outcome, wire) = query(&chain, "some.test.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&wire).unwrap().rcode(), Rcode::REFUSED);

    let (outcome, wire) = query(&chain, "coredns.invalid.", Type::TXT, Class::CH, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    let txt = response.answers().next().unwrap();
    assert_eq!((txt.rtype, txt.class, txt.ttl), (Type::TXT, Class::CH, 60));
    assert_eq!(txt.rdata, b"\x04test");

    let (outcome, wire) = query(&chain, "something.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
    let (outcome, wire) = query(&chain, "something.example.", Type::MX, Class::IN, &[]).await;
    assert_servfail(outcome, &wire);
    let (outcome, wire) = query(&chain, "elsewhere.invalid.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

// CoreDNS template.match accepts ANY Questions and tries each match pattern.
#[tokio::test]
async fn coredns_any_question_and_multiple_match_patterns() {
    let chain = chain(
        r#"
template IN A example. {
 match ^first[.]example[.]$ ^second[.]example[.]$
 answer "{{ .Name }} 60 {{ .Class }} {{ .Type }} 192.0.2.5"
 fallthrough
}
"#,
    );
    for (name, qtype, qclass) in [
        ("first.example.", Type::A, Class::IN),
        ("second.example.", Type::ANY, Class::IN),
        ("second.example.", Type::A, Class::ANY),
        ("second.example.", Type::ANY, Class::ANY),
    ] {
        let (outcome, wire) = query(&chain, name, qtype, qclass, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{name} {qtype:?} {qclass:?}");
        let response = Message::parse(&wire).unwrap();
        let answer = response.answers().next().unwrap();
        assert_eq!(
            (answer.rtype, answer.class, answer.ttl),
            (Type::A, Class::IN, 60)
        );
        assert_eq!(answer.rdata, &[192, 0, 2, 5]);
    }
    let (outcome, wire) = query(&chain, "third.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

// Derived from CoreDNS TestVar and TestExpr.
#[tokio::test]
async fn coredns_variables_expressions_and_metadata() {
    let chain = chain(
        r#"
metadata
template IN A example. {
 match ^(?P<n>[0-9]+)[.]example[.]$
 var num int(group('n'))
 var double num * 2
 var target 'ns0.example.'
 expr num > 1
 expr group('n') == '2' && group(0) == '2.example.'
 expr name() == '2.example.' && type() == 'A'
 expr incidr(client_ip(), '10.0.0.0/8')
 expr metadata('test/region') == 'eu'
 answer "{{ .Name }} 60 IN A 10.0.{{ .Var.num }}.{{ .Var.double }}"
 authority "example. 60 IN NS {{ .Var.target }}"
 additional "{{ .Var.target }} 60 IN A {{ .Remote }}"
 fallthrough
}
"#,
    );
    let (outcome, wire) = query(
        &chain,
        "2.example.",
        Type::A,
        Class::IN,
        &[("test/region", "eu")],
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.answers().next().unwrap().rdata, &[10, 0, 2, 4]);
    assert_eq!(response.authorities().next().unwrap().rtype, Type::NS);
    let extra = response.additionals().next().unwrap();
    assert_eq!(extra.name.to_string(), "ns0.example.");
    assert_eq!(extra.rdata, &[10, 240, 0, 1]);
    for (name, region) in [("1.example.", "eu"), ("2.example.", "us")] {
        let (outcome, wire) =
            query(&chain, name, Type::A, Class::IN, &[("test/region", region)]).await;
        assert_eq!(
            outcome,
            Outcome::Error(Error::NoNextPlugin),
            "{name} {region}"
        );
        assert!(wire.is_empty());
    }
}

#[tokio::test]
async fn coredns_named_and_numbered_groups_and_template_metadata() {
    let chain = chain(
        r#"
metadata
template IN A example. {
 match ^(?P<a>[0-9]+)-(?P<b>[0-9]+)[.]example[.]$
 var a group('a')
 var b group(2)
 var whole group(0)
 answer "{{ .Meta \"test/region\" }}.{{ .Var.whole }} 60 IN A 10.0.{{ .Var.a }}.{{ .Var.b }}"
 additional "{{ index .Match 1 }}.example. 60 IN A 192.0.2.1"
}

"#,
    );
    let (outcome, wire) = query(
        &chain,
        "12-34.example.",
        Type::A,
        Class::IN,
        &[("test/region", "eu")],
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    let answer = response.answers().next().unwrap();
    assert_eq!(answer.name.to_string(), "eu.12-34.example.");
    assert_eq!(answer.rdata, &[10, 0, 12, 34]);
    assert_eq!(
        response.additionals().next().unwrap().name.to_string(),
        "12.example."
    );
}

#[tokio::test]
async fn coredns_group_map_contains_numeric_and_unmatched_groups() {
    let chain = chain(
        r#"
template IN TXT example. {
 match ^(?P<first>[a-z]+)(?:-(?P<second>[a-z]+))?[.]example[.]$
 answer "{{ .Name }} 60 IN TXT \"{{ index .Group \"0\" }}/{{ index .Group \"1\" }}/{{ .Group.first }}/{{ .Group.second }}\""
}
"#,
    );
    let (outcome, wire) = query(&chain, "first.example.", Type::TXT, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    let answer = response.answers().next().unwrap();
    let text = b"first.example./first/first/";
    assert_eq!(answer.rdata[0] as usize, text.len());
    assert_eq!(&answer.rdata[1..], text);
}

#[tokio::test]
async fn coredns_expression_false_scope_and_next_template() {
    for (fallthrough, name, falls_through) in [
        ("", "a.example.", false),
        ("fallthrough", "a.example.", true),
        ("fallthrough other.example.", "a.example.", false),
        ("fallthrough example.", "a.example.", true),
    ] {
        let directive = format!(
            "template IN A example. {{\n expr name() == 'b.example.'\n answer \"{{{{ .Name }}}} 60 IN A 10.0.0.1\"\n {fallthrough}\n}}"
        );
        let (outcome, wire) = query(&chain(&directive), name, Type::A, Class::IN, &[]).await;
        if falls_through {
            assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
            assert!(wire.is_empty());
        } else {
            assert_servfail(outcome, &wire);
        }
    }
    let next_chain = chain(
        r#"
template IN A example. {
 expr name() == 'b.example.'
 answer "{{ .Name }} 60 IN A 10.0.0.1"
 fallthrough
}
template IN A example. {
 answer "{{ .Name }} 60 IN A 10.0.0.2"
}
"#,
    );
    let (outcome, wire) = query(&next_chain, "a.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        &[10, 0, 0, 2]
    );

    let chain = chain("template IN A example. {\n expr 1\n fallthrough\n}");
    let (outcome, wire) = query(&chain, "a.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

#[tokio::test]
async fn coredns_runtime_errors_do_not_fall_through() {
    for directive in [
        r#"template IN A example. {
 answer "{{ .Name }}"
 fallthrough
}"#,
        r#"template IN A example. {
 additional "{{ .Name }}"
 fallthrough
}"#,
        r#"template IN A example. {
 authority "{{ .Name }}"
 fallthrough
}"#,
        r#"template IN A example. {
 answer "{{ .Name }} 60 IN TXT \"{{ index .Match 2 }}\""
 fallthrough
}"#,
        r#"template IN A example. {
 var bad incidr('notanip', '10.0.0.0/8')
 fallthrough
}"#,
        r#"template IN A example. {
 expr incidr('notanip', '10.0.0.0/8')
 fallthrough
}"#,
        r#"template IN A example. {
 answer "{{ .Name }} 60 IN A 10.0.0.{{ parseInt \"gg\" 16 8 }}"
}"#,
    ] {
        let (outcome, wire) = query(&chain(directive), "a.example.", Type::A, Class::IN, &[]).await;
        assert_servfail(outcome, &wire);
    }

    let chain = chain(
        "template IN A example. {\n match ^a[.]example[.]$\n var bad incidr('notanip', '10.0.0.0/8')\n fallthrough\n}",
    );
    let (outcome, wire) = query(&chain, "b.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

// RFC 8914 §4: extended errors carry a two-octet code and optional text.
#[tokio::test]
async fn coredns_extended_error_in_negative_response() {
    let chain = chain(
        r#"
template ANY ANY invalid. {
 rcode NXDOMAIN
 authority "invalid. 60 {{ .Class }} SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)"
 ederror 21 "Blocked due to RFC2606"
}
"#,
    );
    let (outcome, wire) = query(&chain, "test.invalid.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert_eq!(response.authorities().next().unwrap().rtype, Type::SOA);
    assert!(response.opt().unwrap().options().iter().any(|option| option
        == EdnsOption::ExtendedError {
            info_code: 21,
            extra_text: b"Blocked due to RFC2606",
        }));
}

// Derived from CoreDNS TestVar: GroupMissing, QueryFunctions, BoolInTemplateCondition and NoVars.
#[tokio::test]
async fn coredns_variable_values_in_templates() {
    let cases = [
        (
            r#"template IN A example. {
 var a 1
 var b a + 1
 var c b * 10
 answer "{{ .Name }} 60 IN A 10.{{ .Var.a }}.{{ .Var.b }}.{{ .Var.c }}"
}"#,
            Type::A,
            &[10, 1, 2, 20][..],
        ),
        (
            r#"template IN TXT example. {
 match ^(?P<a>[a-z]+)[.]example[.]$
 var missing group('nosuchgroup') + group(9)
 answer "{{ .Name }} 60 IN TXT \"empty={{ eq .Var.missing \"\" }}\""
}"#,
            Type::TXT,
            b"\x0aempty=true".as_slice(),
        ),
        (
            r#"template IN A example. {
 var local incidr(client_ip(), '10.0.0.0/8')
 answer "{{ .Name }} 60 IN A {{ if .Var.local }}10.0.0.1{{ else }}192.0.2.1{{ end }}"
}"#,
            Type::A,
            &[10, 0, 0, 1],
        ),
        (
            r#"template IN TXT example. {
 answer "{{ .Name }} 60 IN TXT \"{{ len .Var }}\""
}"#,
            Type::TXT,
            b"\x010".as_slice(),
        ),
    ];
    for (directive, qtype, expected) in cases {
        let (outcome, wire) = query(&chain(directive), "a.example.", qtype, Class::IN, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{directive}");
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            expected
        );
    }

    let chain = chain(
        r#"template IN A example. {
 var n name()
 var t type()
 var ip client_ip()
 answer "{{ .Var.n }} 60 IN A {{ .Var.ip }}"
 additional "{{ .Var.n }} 60 IN TXT \"{{ .Var.t }}\""
}"#,
    );
    let (outcome, wire) = query(&chain, "a.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.answers().next().unwrap().rdata, &[10, 240, 0, 1]);
    assert_eq!(response.additionals().next().unwrap().rdata, b"\x01A");
}

// Derived from CoreDNS TestVar, TestMultiSection and TestHandler.
#[tokio::test]
async fn coredns_variable_scope_metadata_and_servfail() {
    let configured = chain(
        r#"metadata
template IN A example. {
 match ^a[.]example[.]$
 var region metadata('test/region')
 answer "{{ .Var.region }}.{{ .Name }} 60 IN A 10.0.0.1"
 fallthrough
}
template IN A example. {
 answer "{{ .Name }} 60 IN TXT \"{{ len .Var }}\""
}"#,
    );
    let (outcome, wire) = query(
        &configured,
        "a.example.",
        Type::A,
        Class::IN,
        &[("test/region", "eu")],
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .name
            .to_string(),
        "eu.a.example."
    );
    let (outcome, wire) = query(&configured, "b.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        b"\x010"
    );

    let configured = chain("template IN A example. {\n rcode SERVFAIL\n}");
    let (outcome, wire) = query(&configured, "a.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
    assert!(wire.is_empty());
    let configured =
        chain("template IN TXT example. {\n match $^\n rcode SERVFAIL\n fallthrough\n}");
    let (outcome, wire) = query(&configured, "a.example.", Type::TXT, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

// Derived from CoreDNS v1.15.0 plugin/template/var_test.go TestVarMatch.
#[tokio::test]
async fn coredns_var_match_preserves_all_value_types() {
    let configured = chain(
        r#"template IN A example. {
 match ^(?P<n>[0-9]+)[.]example[.]$
 var num int(group('n'))
 var double num * 2
 var label 'x' + group('n')
 var flag num > 1
 answer "{{ .Name }} 60 IN TXT \"{{ len .Var }}/{{ .Var.num }}/{{ .Var.double }}/{{ .Var.label }}/{{ .Var.flag }}\""
}"#,
    );
    let (outcome, wire) = query(&configured, "2.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.answer_count(), 1);
    assert_eq!(
        response.answers().next().unwrap().rdata,
        b"\x0d4/2/4/x2/true"
    );
}

// Derived from CoreDNS v1.15.0 plugin/template/expr_test.go TestExprMatch.
#[tokio::test]
async fn coredns_first_false_expression_short_circuits_later_error() {
    let configured = chain(
        r#"template IN A example. {
 expr false
 expr incidr('notanip', '10.0.0.0/8')
 fallthrough
}"#,
    );
    let (outcome, wire) = query(&configured, "a.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());

    let configured = chain(
        r#"template IN A example. {
 expr name() == 'a.example.'
 expr type() == 'A'
 expr incidr(client_ip(), '192.0.2.0/24')
 fallthrough
}"#,
    );
    let (outcome, wire) = query(&configured, "a.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

// Derived from CoreDNS v1.15.0 plugin/template/template_test.go TestHandler mdMissing.
#[tokio::test]
async fn coredns_missing_metadata_renders_empty_with_or_without_other_metadata() {
    let configured = chain(
        r#"metadata
template IN A example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Meta \"foofoo\" }}{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
}"#,
    );
    for values in [&[][..], &[("foo", "myfoo")][..]] {
        let (outcome, wire) = query(
            &configured,
            "ip-10-95-12-8.example.",
            Type::A,
            Class::IN,
            values,
        )
        .await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        let answer = response.answers().next().unwrap();
        assert_eq!(answer.name.to_string(), "ip-10-95-12-8.example.");
        assert_eq!(answer.rdata, &[10, 95, 12, 8]);
    }
}

// Derived from CoreDNS v1.15.0 plugin/template/template_test.go TestHandler mdMatch.
#[tokio::test]
async fn coredns_metadata_renders_in_all_record_sections() {
    let configured = chain(
        r#"metadata
template IN A example. {
 match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
 answer "{{ .Meta \"foo\" }}-{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
 additional "{{ .Meta \"bar\" }}.example. 60 IN A 203.0.113.8"
 authority "example. 60 IN NS {{ .Meta \"bar\" }}.example.com."
}"#,
    );
    let (outcome, wire) = query(
        &configured,
        "ip-10-95-12-8.example.",
        Type::A,
        Class::IN,
        &[("foo", "myfoo"), ("bar", "mybar")],
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(
        (
            response.answer_count(),
            response.authority_count(),
            response.additional_count()
        ),
        (1, 1, 1)
    );
    let answer = response.answers().next().unwrap();
    assert_eq!(answer.name.to_string(), "myfoo-ip-10-95-12-8.example.");
    assert_eq!(answer.rdata, &[10, 95, 12, 8]);
    let additional = response.additionals().next().unwrap();
    assert_eq!(additional.name.to_string(), "mybar.example.");
    assert_eq!(additional.rdata, &[203, 0, 113, 8]);
    let Rdata::Ns(target) = response.authorities().next().unwrap().data().unwrap() else {
        panic!("expected NS");
    };
    assert_eq!(target.to_string(), "mybar.example.com.");
}

// Derived from CoreDNS v1.15.0 plugin/template/expr_test.go TestExpr NoMatchNoEvaluation.
#[tokio::test]
async fn coredns_unmatched_pattern_skips_expression_evaluation() {
    let configured = chain(
        r#"template IN A example. {
 match ^a[.]example[.]$
 expr incidr('notanip', '10.0.0.0/8')
 fallthrough
}"#,
    );
    let (outcome, wire) = query(&configured, "b.example.", Type::A, Class::IN, &[]).await;
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(wire.is_empty());
}

// Derived from CoreDNS v1.15.0 plugin/template/var_test.go TestVar PerTemplateScope.
#[tokio::test]
async fn coredns_variables_do_not_leak_after_expression_fallthrough() {
    let configured = chain(
        r#"template IN A example. {
 var v '1'
 expr name() == 'a.example.'
 answer "{{ .Name }} 60 IN A 10.0.0.{{ .Var.v }}"
 fallthrough
}
template IN A example. {
 answer "{{ .Name }} 60 IN TXT \"{{ len .Var }}\""
}"#,
    );
    for (name, expected) in [
        ("a.example.", &[10, 0, 0, 1][..]),
        ("b.example.", &b"\x010"[..]),
    ] {
        let (outcome, wire) = query(&configured, name, Type::A, Class::IN, &[]).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.answer_count(), 1);
        assert_eq!(response.answers().next().unwrap().rdata, expected, "{name}");
    }
}
