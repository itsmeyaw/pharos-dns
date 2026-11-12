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
fn template_decodes_quoted_strings_and_rejects_invalid_escapes() {
    assert!(Template::compile(r#"{{ .Meta "a\nb" }}"#).is_ok());
    assert!(Template::compile(r#"{{ parseInt "1\x32" 10 8 }}"#).is_ok());
    assert!(Template::compile(r#"{{ "\q" }}"#).is_err());
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

#[test]
fn trim_markers_remove_go_template_whitespace() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(
        "prefix \t{{- .Name -}}\r\n suffix {{ if .Name -}} \n yes {{- else }} no {{- end }}",
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "prefixexample.suffix yes");
    assert!(Template::compile("{{-.Name}}").is_err());
}

#[test]
fn range_visits_matches_and_uses_else_for_empty_input() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let template =
        Template::compile("{{ range .Match }}[{{ . }}:{{ $.Name }}]{{ else }}empty{{ end }}")
            .unwrap();
    let mut data = Data::new("example.", &metadata);
    data.matches = &["whole", "capture"];
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "[whole:example.][capture:example.]");
    data.matches = &[];
    output.clear();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "empty");
}

#[test]
fn coredns_variable_examples_use_eq_and_len_builtins() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("a.example.", &metadata);
    let vars = [("missing", Value::String(""))];
    data.variables = &vars;
    let template = Template::compile(
        "{{ .Name }} 60 IN TXT \"empty={{ eq .Var.missing \"\" }},count={{ len .Var }}\"",
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "a.example. 60 IN TXT \"empty=true,count=1\"");
}

#[test]
fn pipelines_pass_the_previous_value_as_last_argument() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("a.example.", &metadata);
    let vars = [
        ("region", Value::String("eu")),
        ("local", Value::Bool(false)),
    ];
    data.variables = &vars;
    let template = Template::compile("{{ .Var.region | eq \"eu\" }} {{ 8 | parseInt \"ff\" 16 }} {{ if .Var.local | not }}remote{{ else }}local{{ end }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "true 255 remote");
}

#[test]
fn go_logical_and_comparison_builtins_preserve_values() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ and true \"yes\" }}|{{ or false .Name }}|{{ not 0 }}|{{ ne 1 2 }}|{{ lt 1 2 }}|{{ le 2 2 }}|{{ gt 3 2 }}|{{ ge 2 2 }}|{{ if eq .Name \"example.\" }}ok{{ end }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "yes|example.|true|true|true|true|true|true|ok");
}

#[test]
fn coredns_accepts_known_functions_with_wrong_arity_until_rendering() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ parseInt }}").unwrap();
    assert!(template.render(&data, &mut String::new()).is_err());
    assert!(Template::compile("{{ notAFunction }}").is_err());
}

#[test]
fn nested_pipelines_index_borrowed_captures_and_maps() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["whole", "east region"];
    data.groups = &[("zone", "east")];
    let template = Template::compile("{{ if eq (index .Match 1) \"east region\" }}yes{{ end }}|{{ index .Match 1 | len }}|{{ index .Group \"absent\" | eq \"\" }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "yes|11|true");
}

#[test]
fn excessive_pipeline_nesting_is_rejected_at_compile_time() {
    let source = format!("{{{{ {}.Name{} }}}}", "(".repeat(300), ")".repeat(300));
    assert!(Template::compile(&source).is_err());
}

#[test]
fn quoted_strings_can_contain_delimiters_and_go_escapes() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(
        r#"{{ "a}}b\n" | len }}|{{ eq "\x41 \u263a" "A ☺" }}|{{ 'A' }}|{{ `a b` }}"#,
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "5|true|65|a b");
}

#[test]
fn coredns_accepts_unknown_fields_until_execution() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ .Name }} A {{ .Grup.d }}").unwrap();
    assert!(template.render(&data, &mut String::new()).is_err());
}

#[test]
fn range_visits_group_and_variable_maps_in_go_key_order() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.groups = &[("z", "last"), ("a", "first")];
    data.variables = &[("z", Value::Int(2)), ("a", Value::Int(1))];
    let template =
        Template::compile("{{ range .Group }}[{{ . }}]{{ end }}|{{ range .Var }}{{ . }}{{ end }}")
            .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "[first][last]|12");
}

#[test]
fn else_if_selects_first_truthy_branch() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.variables = &[("a", Value::Bool(false)), ("b", Value::Bool(true))];
    let template =
        Template::compile("{{ if .Var.a }}first{{ else if .Var.b }}second{{ else }}third{{ end }}")
            .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "second");
}

#[test]
fn slice_builtin_slices_strings_and_capture_lists() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["whole", "first", "second"];
    let template = Template::compile(
        "{{ slice .Name 0 7 }}|{{ slice .Match 1 3 | len }}|{{ index (slice .Match 1) 0 }}",
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "example|2|first");
}

#[test]
fn print_and_printf_produce_pipeline_strings() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ print .Name \":\" 53 }}|{{ printf \"%s:%d\" .Name 53 }}|{{ println \"a\" 2 \"b\" }}|{{ print .Name \"x\" | len }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "example.:53|example.:53|a 2 b\n|9");
}

#[test]
fn go_escaping_builtins_return_pipeline_strings() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(r#"{{ html "<a&'\"" }}|{{ js "<>&=\n" }}|{{ urlquery "a+b c/é" }}|{{ html "<" | eq "&lt;" }}"#).unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(
        output,
        "&lt;a&amp;&#39;&#34;|\\u003C\\u003E\\u0026\\u003D\\u000A|a%2Bb+c%2F%C3%A9|true"
    );
}

#[test]
fn js_escapes_non_printable_unicode_like_go() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ js \"\\uE000é\\u00A0\" }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "\\uE000é\\u00A0");
}
