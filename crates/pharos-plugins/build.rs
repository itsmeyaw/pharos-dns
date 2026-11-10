#![forbid(unsafe_code)]

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=plugin.cfg");
    let source = fs::read_to_string("plugin.cfg").expect("plugin.cfg");
    let enabled: Vec<_> = source
        .lines()
        .filter_map(|line| {
            let (name, _) = line.split_once(':')?;
            if name.starts_with('#') {
                return None;
            }
            let feature = format!("CARGO_FEATURE_PLUGIN_{}", name.to_ascii_uppercase());
            env::var_os(feature).map(|_| name)
        })
        .collect();
    let variant = |name: &str| -> String {
        name.split('_')
            .map(|part| {
                let mut chars = part.chars();
                chars.next().unwrap().to_ascii_uppercase().to_string() + chars.as_str()
            })
            .collect()
    };
    let mut code = String::from("#[derive(Debug)]\npub enum Plugin {\n");
    for name in &enabled {
        code.push_str(&format!("{},\n", variant(name)));
    }
    code.push_str(
        "}\npub static DIRECTIVES: &[pharos_corefile::Directive<'static, Vec<Plugin>>] = &[\n",
    );
    for name in &enabled {
        let setup = if *name == "whoami" {
            "setup_whoami"
        } else {
            "setup_unimplemented"
        };
        code.push_str(&format!(
            "pharos_corefile::Directive {{ name: {name:?}, once: false, setup: {setup} }},\n"
        ));
    }
    code.push_str("];\n");
    let mut sorted = enabled.clone();
    sorted.sort_unstable();
    let listing = sorted.join("\n") + "\n\n";
    code.push_str(&format!("pub const PLUGINS_LISTING: &str = {listing:?};\n"));
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("plugins.rs"),
        code,
    )
    .unwrap();
}
