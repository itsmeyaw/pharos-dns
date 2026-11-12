#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch};
use pharos_plugins::gotemplate::{Data, Template};
use pharos_proto::Message;
use pharos_server::Metadata;
use pharos_server::Protocol;

#[test]
fn template_renders_query_name_and_metadata() {
    let mut slots = [None; 1];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/region", "eu"));
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile("{{ .Meta \"test/region\" }}-{{ .Name }} 60 IN A 10.0.0.1").unwrap();
    let mut output = String::with_capacity(64);
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "eu-example. 60 IN A 10.0.0.1");
}

#[test]
fn template_renders_coredns_capture_and_parse_int_examples() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("ip0a7b7b7b.example.", &metadata);
    data.zone = "example.";
    data.class = "IN";
    data.qtype = "A";
    data.matches = &["ip0a7b7b7b.example.", "7b"];
    data.groups = &[("b", "7b"), ("c", "7b"), ("d", "7b")];
    let template = Template::compile("{{ .Name }} 60 {{ .Class }} {{ .Type }} 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }} {{ index .Match 1 }} {{ .Zone }}").unwrap();
    let mut output = String::with_capacity(100);
    template.render(&data, &mut output).unwrap();
    assert_eq!(
        output,
        "ip0a7b7b7b.example. 60 IN A 10.123.123.123 7b example."
    );
}

#[test]
fn parse_int_accepts_literal_and_reports_invalid_values_at_render_time() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let mut output = String::new();
    Template::compile("{{ parseInt \"0xff\" 0 8 }}")
        .unwrap()
        .render(&data, &mut output)
        .unwrap();
    assert_eq!(output, "255");
    assert!(
        Template::compile("{{ parseInt \"gg\" 16 8 }}")
            .unwrap()
            .render(&data, &mut output)
            .is_err()
    );
}

#[test]
fn template_rejects_unsupported_quoted_string_escapes() {
    assert!(Template::compile(r#"{{ .Meta "a\nb" }}"#).is_err());
    assert!(Template::compile(r#"{{ parseInt "1\x32" 10 8 }}"#).is_err());
}

#[test]
fn expression_values_are_available_as_template_variables() {
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x07example\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let expression = Expression::compile("1 + 59").unwrap();
    let mut scratch_bytes = [0; 128];
    let mut scratch = Scratch::new(&mut scratch_bytes);
    let value = expression
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap();
    let variables = [("ttl", value)];
    let mut data = Data::new("a.example.", &metadata);
    data.variables = &variables;
    let template = Template::compile("{{ .Name }} {{ .Var.ttl }} IN A 10.0.0.1").unwrap();
    let mut output = String::with_capacity(64);
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "a.example. 60 IN A 10.0.0.1");
}

#[test]
fn coredns_if_else_uses_expression_variable_truth() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let template = Template::compile(
        "{{ .Name }} 60 IN A {{ if .Var.local }}10.0.0.1{{ else }}192.0.2.1{{ end }}",
    )
    .unwrap();
    for (local, expected) in [
        (true, "a.example. 60 IN A 10.0.0.1"),
        (false, "a.example. 60 IN A 192.0.2.1"),
    ] {
        let variables = [("local", pharos_plugins::expression::Value::Bool(local))];
        let mut data = Data::new("a.example.", &metadata);
        data.variables = &variables;
        let mut output = String::new();
        template.render(&data, &mut output).unwrap();
        assert_eq!(output, expected);
    }
    assert!(Template::compile("{{ if .Name }}missing end").is_err());
    assert!(Template::compile("{{ else }}").is_err());
}
