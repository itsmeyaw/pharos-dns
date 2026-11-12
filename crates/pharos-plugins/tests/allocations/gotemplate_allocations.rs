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
    let template = Template::compile("{{ range .Message.Question }}{{ .Name }} {{ .Qtype }}{{ end }}|{{ .Question.Name | eq \"Example.Org.\" }}").unwrap();
    let mut output = String::with_capacity(128);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    template.render(&data, &mut output).unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(output, "Example.Org. 1|true");
}
