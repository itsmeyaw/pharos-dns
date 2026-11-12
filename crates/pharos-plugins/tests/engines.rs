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

#[test]
fn template_reads_borrowed_message_and_question_fields() {
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.org.", &metadata);
    data.message = Some(&message);
    let template = Template::compile("{{ .Message.Id }}|{{ .Message.Opcode }}|{{ .Message.RecursionDesired }}|{{ .Question.Name }}|{{ .Question.Qtype }}|{{ .Question.Qclass }}|{{ if .Message.RecursionDesired }}yes{{ end }}|{{ .Question.Name | eq \"Example.Org.\" }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "1053|0|true|Example.Org.|1|1|yes|true");
}

#[test]
fn template_meta_hides_values_when_metadata_is_disabled() {
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("region", "eu"));
    metadata.set_enabled(false);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ .Meta \"region\" }}{{ .Name }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "example.");
}

#[test]
fn range_binds_index_value_and_outer_variables() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["one", "two"];
    data.groups = &[("z", "last"), ("a", "first")];
    let template = Template::compile("{{ range $i, $v := .Match }}{{$i}}={{$v}}:{{ range $key, $value := $.Group }}{{$i}}/{{$key}}/{{$value}};{{ end }}{{ end }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "0=one:0/a/first;0/z/last;1=two:1/a/first;1/z/last;");
}

#[test]
fn range_variables_are_scoped_and_undefined_names_fail_at_setup() {
    assert!(Template::compile("{{ $missing }}").is_err());
    assert!(Template::compile("{{ range $v := .Match }}{{ $v }}{{ end }}{{ $v }}").is_err());
    assert!(
        Template::compile("{{ range $v := .Match }}{{ if eq $v \"x\" }}yes{{ end }}{{ end }}")
            .is_ok()
    );
}

#[test]
fn range_accepts_pipelines_and_integer_counts() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["whole", "one", "two"];
    let template = Template::compile("{{ range $i, $v := slice .Match 1 }}{{$i}}={{$v}};{{ end }}|{{ range $n := 3 }}{{$n}}{{ else }}empty{{ end }}|{{ range .Var.missing }}bad{{ else }}empty{{ end }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "0=one;1=two;|012|empty");
}

#[test]
fn printf_supports_go_numeric_string_and_type_formats() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile(r#"{{ printf "%04x:%g:%q:%T:%t" 127 3.5 "a\nb" 0xef true }}"#).unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "007f:3.5:\"a\\nb\":int:true");
}

#[test]
fn metadata_method_accepts_variable_and_pipeline_arguments() {
    use pharos_plugins::expression::Value;
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("region", "eu"));
    let mut data = Data::new("example.", &metadata);
    data.variables = &[("key", Value::String("region"))];
    let template = Template::compile("{{ .Meta .Var.key }}|{{ \"region\" | .Meta }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "eu|eu");
}

#[test]
fn range_over_message_questions_exposes_original_question_fields() {
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.org.", &metadata);
    data.message = Some(&message);
    let template = Template::compile("{{ range .Message.Question }}{{ .Name }}/{{ .Qtype }}/{{ .Qclass }}{{ end }}|{{ len .Message.Question }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "Example.Org./1/1|1");
}

#[test]
fn question_range_variables_and_indexed_fields_are_borrowed() {
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.org.", &metadata);
    data.message = Some(&message);
    let template = Template::compile("{{ range $i, $q := .Message.Question }}{{$i}}={{$q.Name}}/{{$q.Qtype}}{{ end }}|{{ (index .Message.Question 0).Name }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "0=Example.Org./1|Example.Org.");
}

#[test]
fn call_invokes_a_query_function_stored_in_expression_variables() {
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let expression = Expression::compile("name").unwrap();
    let mut bytes = [0; 2048];
    let mut scratch = Scratch::new(&mut bytes);
    let function = expression
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap();
    let variables = [("f", function)];
    let mut data = Data::new("example.org.", &metadata);
    data.variables = &variables;
    let template = Template::compile("{{ call .Var.f }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "example.org.");
}

#[test]
fn call_invokes_bound_metadata_group_and_cidr_functions_with_arguments() {
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.groups = &[("region", "eu")];
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("region", "west"));
    let metadata_fn = Expression::compile("metadata").unwrap();
    let cidr_fn = Expression::compile("incidr").unwrap();
    let group_fn = Expression::compile("group").unwrap();
    let mut b1 = [0; 128];
    let mut s1 = Scratch::new(&mut b1);
    let mut b2 = [0; 128];
    let mut s2 = Scratch::new(&mut b2);
    let mut b3 = [0; 128];
    let mut s3 = Scratch::new(&mut b3);
    let variables = [
        (
            "m",
            metadata_fn.evaluate(&query, &metadata, &mut s1).unwrap(),
        ),
        ("c", cidr_fn.evaluate(&query, &metadata, &mut s2).unwrap()),
        ("g", group_fn.evaluate(&query, &metadata, &mut s3).unwrap()),
    ];
    let mut other_slots = [];
    let other_metadata = Metadata::new(&mut other_slots);
    let mut data = Data::new("example.org.", &other_metadata);
    data.variables = &variables;
    let template = Template::compile("{{ call .Var.m (print \"reg\" \"ion\") }}|{{ call .Var.c \"10.0.0.1\" \"10.0.0.0/8\" }}|{{ call .Var.g \"region\" }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "west|true|eu");
}

#[test]
fn empty_range_else_keeps_outer_dot_and_binds_pipeline_value() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(
        "{{ range $i, $v := .Match }}bad{{ else }}{{ .Name }}:{{ len $i }}:{{ len $v }}{{ end }}",
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "example.:0:0");
}

#[test]
fn printf_supports_common_flags_precision_and_radices() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile(r#"{{ printf "%-8s|%+.2f|%#x|%o|%b|%c" "go" 3.5 255 8 5 65 }}"#).unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "go      |+3.50|0xff|10|101|A");
}

#[test]
fn coredns_readme_expression_variables_feed_answer_template() {
    use pharos_plugins::expression::{Value, ValueType};
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.groups = &[("ip", "192-168-1-2")];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let ip = Expression::compile("replace(group('ip'), '-', '.')").unwrap();
    let mut first_bytes = [0; 2048];
    let mut first_scratch = Scratch::new(&mut first_bytes);
    let value = ip.evaluate(&query, &metadata, &mut first_scratch).unwrap();
    let variables = [("ip", value)];
    let mut filtered = Query::new(&message, query.client, query.local, query.protocol);
    filtered.variables = &variables;
    let filter = Expression::compile_with_variables(
        "any(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'], incidr(ip, #))",
        &[("ip", ValueType::String)],
    )
    .unwrap();
    let mut second_bytes = [0; 2048];
    let mut second_scratch = Scratch::new(&mut second_bytes);
    assert_eq!(
        filter
            .evaluate(&filtered, &metadata, &mut second_scratch)
            .unwrap(),
        Value::Bool(true)
    );
    let mut data = Data::new("example.org.", &metadata);
    data.variables = &variables;
    let template = Template::compile("{{ .Name }} 60 IN A {{ .Var.ip }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "example.org. 60 IN A 192.168.1.2");
}

#[test]
fn slicing_message_questions_uses_borrowed_question_views() {
    let mut wire =
        b"\x04\x1d\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01"
            .to_vec();
    wire.extend_from_slice(b"\xc0\x0c\x00\x1c\x00\x01");
    let message = Message::parse(&wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.org.", &metadata);
    data.message = Some(&message);
    let template = Template::compile("{{ range slice .Message.Question 1 }}{{ .Qtype }}{{ end }}|{{ len (slice .Message.Question 1) }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "28|1");
}

#[test]
fn printf_emits_go_diagnostics_for_bad_or_missing_arguments() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(r#"{{ printf "%d" "x" }}|{{ printf "%d" }}|{{ printf "%z" 1 }}|{{ printf "%s" "x" 1 "y" }}"#).unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(
        output,
        "%!d(string=x)|%!d(MISSING)|%!z(int=1)|x%!(EXTRA int=1, string=y)"
    );
}

#[test]
fn caller_scratch_supports_large_intermediate_pipelines() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let long = "x".repeat(60_000);
    let vars = [("text", Value::String(long.as_str()))];
    let mut data = Data::new("example.", &metadata);
    data.variables = &vars;
    let template = Template::compile("{{ print .Var.text | print | len }}").unwrap();
    let mut output = String::new();
    assert!(template.render(&data, &mut output).is_err());
    output.clear();
    let mut scratch = vec![0; 130_000];
    template
        .render_with_scratch(&data, &mut output, &mut scratch)
        .unwrap();
    assert_eq!(output, "60000");
}

#[test]
fn default_and_print_format_capture_lists_and_maps_like_go() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["one", "two"];
    data.groups = &[("z", "last"), ("a", "first")];
    data.variables = &[("b", Value::String("two")), ("a", Value::Int(1))];
    let template = Template::compile("{{ .Match }}|{{ print .Group }}|{{ print .Var }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "[one two]|map[a:first z:last]|map[a:1 b:two]");
}

#[test]
fn index_and_slice_without_indices_keep_the_input() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["one", "two"];
    let template = Template::compile("{{ len (index .Match) }}|{{ len (slice .Match) }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "2|2");
    let invalid = Template::compile("{{ index .Var.missing }}").unwrap();
    assert!(invalid.render(&data, &mut String::new()).is_err());
}

#[test]
fn index_rejects_map_keys_with_the_wrong_type() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.groups = &[("1", "one")];
    for source in ["{{ index .Group 1 }}", "{{ index .Var 1 }}"] {
        assert!(
            Template::compile(source)
                .unwrap()
                .render(&data, &mut String::new())
                .is_err(),
            "{source}"
        );
    }
}

#[test]
fn template_logical_builtins_short_circuit_nested_errors() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile("{{ or true (index .Match 99) }}|{{ and false (index .Match 99) }}")
            .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "true|false");
}

#[test]
fn nil_is_an_argument_but_not_a_standalone_command() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    assert!(
        Template::compile("{{ nil }}")
            .unwrap()
            .render(&data, &mut String::new())
            .is_err()
    );
    let template = Template::compile("{{ printf \"%v\" nil }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "<nil>");
}

#[test]
fn printf_applies_width_and_integer_precision_to_common_verbs() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(
        r#"{{ printf "%5t|%5c|%5q|%5T|%5v|%08g|%.3d" true 65 "x" 1 "x" -3.5 7 }}"#,
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, " true|    A|  \"x\"|  int|    x|-00003.5|007");
}

#[test]
fn control_actions_accept_go_whitespace_and_comments() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.matches = &["x"];
    let template = Template::compile("a {{- /* comment with }} text */ -}} \n {{ if\t.Name }}{{ range\t.Match }}{{ . }}{{ end }}{{ else\tif .Zone }}wrong{{ end }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "ax");
    assert!(Template::compile("{{ /* not a Go comment */ }}").is_err());
    assert!(Template::compile("{{/* comment */ }}").is_err());
    assert!(Template::compile("{{/* comment */}}").is_ok());
}

#[test]
fn question_pointer_renders_like_miekg_and_supports_printf() {
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.org.", &metadata);
    data.message = Some(&message);
    let template = Template::compile("{{ .Question }}|{{ .Question | printf \"%s\" }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, ";Example.Org.\tIN\t A|;Example.Org.\tIN\t A");
}

#[test]
fn printf_g_precision_uses_go_significant_digit_rules() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(
        r#"{{ printf "%.3g|%.3g|%.2g|%.2g|%.0g" 12345.6 12.3456 0.00012345 0.000012345 3.5 }}"#,
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "1.23e+04|12.3|0.00012|1.2e-05|4");
}

#[test]
fn printf_alternate_g_retains_decimal_point_and_zeros() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile(r#"{{ printf "%#g|%#.3g|%#.0g" 1.2 12000.0 4.0 }}"#).unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "1.20000|1.20e+04|4.");
}

#[test]
fn printf_scientific_and_uppercase_float_verbs_match_go() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile(r#"{{ printf "%+011.2e|%E|%F|%G|%#.0e" 1234.0 1.0 1.0 1000000.0 1.0 }}"#)
            .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "+001.23e+03|1.000000E+00|1.000000|1E+06|1.e+00");
}

#[test]
fn printf_q_escapes_non_printable_unicode_like_go() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ printf \"%q\" \"\\uE000\\u00A0é\" }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "\"\\ue000\\u00a0é\"");
}

#[test]
fn printf_q_supports_ascii_raw_precision_and_runes() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile(r#"{{ printf "%+q|%#q|%.2q|%q" "é" "a b" "héllo" 65 }}"#).unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "\"\\u00e9\"|`a b`|\"hé\"|'A'");
}

#[test]
fn printf_and_variable_floats_follow_go_width_and_exponents() {
    use pharos_plugins::expression::Value;
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.variables = &[("big", Value::Float(1_000_000.0))];
    let template = Template::compile(
        r#"{{ printf "%05.3s|%-8.2f|%g|%g" "éclair" 3.5 1000000.0 0.00001 }}|{{ .Var.big }}"#,
    )
    .unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "00écl|3.50    |1e+06|1e-05|1e+06");
}
