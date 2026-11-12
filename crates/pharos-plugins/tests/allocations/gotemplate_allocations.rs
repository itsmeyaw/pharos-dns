#![forbid(unsafe_code)]

use pharos_plugins::gotemplate::{Data, Template};
use pharos_server::Metadata;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};

#[test]
fn renders_fields_and_numbers_without_allocating() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::renders_fields_and_numbers_without_allocating",
    ) {
        return;
    }
    let mut slots = [None; 1];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/region", "eu"));
    let mut data = Data::new("example.", &metadata);
    data.groups = &[("b", "7b")];
    data.matches = &["example."];
    let template = Template::compile(
        "{{ .Name }} {{ .Meta \"test/region\" }} {{ parseInt .Group.b 16 8 }} {{ index .Match 0 }}",
    )
    .unwrap();
    let mut output = String::with_capacity(100);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "example. eu 123 example.");
}

#[test]
fn rendering_pipelines_and_conditionals_does_not_allocate() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::rendering_pipelines_and_conditionals_does_not_allocate",
    ) {
        return;
    }
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let vars = [("local", pharos_plugins::expression::Value::Bool(false))];
    let mut data = Data::new("example.", &metadata);
    data.variables = &vars;
    let template =
        Template::compile("{{ 8 | parseInt \"ff\" 16 }} {{ if .Var.local | not }}remote{{ end }}")
            .unwrap();
    let mut output = String::with_capacity(64);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "255 remote");
}

#[test]
fn formatting_pipelines_use_no_heap_allocation() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::formatting_pipelines_use_no_heap_allocation",
    ) {
        return;
    }
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template =
        Template::compile("{{ printf \"%s:%d\" .Name 53 }} {{ print .Name \"x\" | len }}").unwrap();
    let mut output = String::with_capacity(64);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "example.:53 9");
}

#[test]
fn escape_builtins_do_not_allocate_on_first_render() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::escape_builtins_do_not_allocate_on_first_render",
    ) {
        return;
    }
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("é<&", &metadata);
    let template =
        Template::compile("{{ js .Name }}|{{ html .Name }}|{{ urlquery .Name }}").unwrap();
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "é\\u003C\\u0026|é&lt;&amp;|%C3%A9%3C%26");
}

#[test]
fn borrowed_question_fields_render_without_allocating() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::borrowed_question_fields_render_without_allocating",
    ) {
        return;
    }
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = pharos_proto::Message::parse(wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.org.", &metadata);
    data.message = Some(&message);
    let template = Template::compile("{{ range .Message.Question }}{{ .Name }} {{ .Qtype }}{{ end }}|{{ .Question.Name | eq \"Example.Org.\" }}|{{ slice .Message.Question 0 | len }}").unwrap();
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "Example.Org. 1|true|1");
}

#[test]
fn calling_a_bound_query_function_does_not_allocate() {
    use pharos_plugins::expression::{Expression, Query, Scratch};
    use pharos_server::Protocol;
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::calling_a_bound_query_function_does_not_allocate",
    ) {
        return;
    }
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = pharos_proto::Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let expression = Expression::compile("name").unwrap();
    let mut scratch_bytes = [0; 2048];
    let mut scratch = Scratch::new(&mut scratch_bytes);
    let value = expression
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap();
    let vars = [("f", value)];
    let mut data = Data::new("example.org.", &metadata);
    data.variables = &vars;
    let template = Template::compile("{{ call .Var.f }}").unwrap();
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "example.org.");
}

#[test]
fn calling_a_bound_metadata_function_does_not_allocate() {
    use pharos_plugins::expression::{Expression, Query, Scratch};
    use pharos_server::Protocol;
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::calling_a_bound_metadata_function_does_not_allocate",
    ) {
        return;
    }
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = pharos_proto::Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("region", "eu"));
    let expression = Expression::compile("metadata").unwrap();
    let mut scratch_bytes = [0; 128];
    let mut scratch = Scratch::new(&mut scratch_bytes);
    let value = expression
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap();
    let vars = [("f", value)];
    let mut data = Data::new("example.org.", &metadata);
    data.variables = &vars;
    let template = Template::compile("{{ call .Var.f (print \"reg\" \"ion\") }}").unwrap();
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "eu");
}

#[test]
fn floating_point_formatting_does_not_allocate() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::floating_point_formatting_does_not_allocate",
    ) {
        return;
    }
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("example.", &metadata);
    data.variables = &[("v", pharos_plugins::expression::Value::Float(1_000_000.0))];
    let template = Template::compile("{{ .Var.v }} {{ printf \"%g\" .Var.v }}").unwrap();
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "1e+06 1e+06");
}

#[test]
fn caller_provided_scratch_does_not_allocate() {
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::caller_provided_scratch_does_not_allocate",
    ) {
        return;
    }
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let data = Data::new("example.", &metadata);
    let template = Template::compile("{{ printf \"%s:%d\" .Name 53 }}").unwrap();
    let mut output = String::with_capacity(128);
    let mut scratch = [0; 128];
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template
        .render_with_scratch(&data, &mut output, &mut scratch)
        .unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "example.:53");
}

#[test]
fn expression_variables_and_template_render_without_allocating() {
    use pharos_plugins::expression::{Expression, Query, Scratch};
    use pharos_server::Protocol;
    if crate::run_isolated(
        "gotemplate::gotemplate_allocations::expression_variables_and_template_render_without_allocating",
    ) {
        return;
    }
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = pharos_proto::Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.groups = &[("ip", "192-168-1-2")];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let expression = Expression::compile("replace(group('ip'), '-', '.')").unwrap();
    let template = Template::compile("{{ .Name }} 60 IN A {{ .Var.ip }}").unwrap();
    let mut expression_bytes = [0; 256];
    let mut expression_scratch = Scratch::new(&mut expression_bytes);
    let mut template_scratch = [0; 256];
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let value = expression
        .evaluate(&query, &metadata, &mut expression_scratch)
        .unwrap();
    let variables = [("ip", value)];
    let mut data = Data::new("example.org.", &metadata);
    data.variables = &variables;
    template
        .render_with_scratch(&data, &mut output, &mut template_scratch)
        .unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "example.org. 60 IN A 192.168.1.2");
}
