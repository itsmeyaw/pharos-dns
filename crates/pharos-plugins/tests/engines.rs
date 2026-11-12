#![forbid(unsafe_code)]

use pharos_plugins::gotemplate::{Data, Template};
use pharos_server::Metadata;

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
