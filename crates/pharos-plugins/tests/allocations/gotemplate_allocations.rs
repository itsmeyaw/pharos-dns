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
