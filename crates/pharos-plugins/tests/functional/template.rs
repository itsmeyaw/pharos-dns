use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn nxdomain_readme_corefile_is_accepted() {
    let blocks = parse(
        "Corefile",
        ". {\n template ANY ANY {\n  rcode NXDOMAIN\n }\n}",
    )
    .expect("valid Corefile");
    configure::<Chain>(&blocks, directives()).expect("template Directive is supported");
}
