#![forbid(unsafe_code)]

use pharos_plugins::gotemplate::{Data, Template};
use pharos_server::Metadata;

#[test]
fn template_renders_query_name_and_metadata() {
    let mut slots = [None; 1];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/region", "eu"));
    let data = Data {
        name: "example.",
        metadata: &metadata,
    };
    let template =
        Template::compile("{{ .Meta \"test/region\" }}-{{ .Name }} 60 IN A 10.0.0.1").unwrap();
    let mut output = String::with_capacity(64);
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "eu-example. 60 IN A 10.0.0.1");
}
