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
