#![forbid(unsafe_code)]

use std::{env, fmt::Write, fs, path::PathBuf};

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

    let mut code = String::from(
        "#[derive(Debug, Default)]\npub struct Chain {\npub lifecycle: pharos_server::Lifecycle,\n",
    );
    for name in &enabled {
        let ty = match *name {
            "cache" => "cache::Cache",
            "whoami" => "whoami::Whoami",
            "log" => "log::Log",
            "prometheus" => "prometheus::Prometheus",
            "ready" => "ready::Ready",
            "forward" => "forward::Forward",
            "health" => "health::Health",
            "reload" => "reload::Reload",
            "errors" => "errors::Errors",
            _ => "Unimplemented",
        };
        writeln!(code, "pub r#{name}: Option<{ty}>,").unwrap();
    }
    code.push_str("}\npub static DIRECTIVES: &[pharos_corefile::Directive<'static, Chain>] = &[\n");
    for name in &enabled {
        let setup = match *name {
            "cache" => "setup_cache",
            "whoami" => "setup_whoami",
            "log" => "setup_log",
            "prometheus" => "setup_prometheus",
            "ready" => "setup_ready",
            "forward" => "setup_forward",
            "health" => "setup_health",
            "reload" => "setup_reload",
            "errors" => "setup_errors",
            _ => "setup_unimplemented",
        };
        let once = matches!(*name, "cache" | "prometheus" | "ready" | "errors" | "reload");
        writeln!(
            code,
            "pharos_corefile::Directive {{ name: {name:?}, once: {once}, setup: {setup} }},"
        )
        .unwrap();
    }
    code.push_str("];\n");
    let mut sorted = enabled.clone();
    sorted.sort_unstable();
    let listing = if sorted.is_empty() {
        "\n".to_owned()
    } else {
        sorted.join("\n") + "\n\n"
    };
    writeln!(code, "pub const PLUGINS_LISTING: &str = {listing:?};").unwrap();

    code.push_str("impl Chain {\n");
    if enabled.contains(&"ready") {
        code.push_str(
            "fn collect_readiness(self: &std::sync::Arc<Self>, state: &ready::State) {\nlet _ = state;\n",
        );
        for name in &enabled {
            if matches!(*name, "ready" | "health" | "reload") {
                continue;
            }
            writeln!(code, "if self.r#{name}.as_ref().and_then(pharos_server::Plugin::readiness).is_some() {{ let chain = std::sync::Arc::clone(self); state.append({name:?}, move || chain.r#{name}.as_ref().and_then(pharos_server::Plugin::readiness).is_some_and(pharos_server::Readiness::ready)); }}").unwrap();
        }
        code.push_str("}\n");
    }
    code.push_str("// shortcut: Self Lookup (#35) must Box::pin re-entry and cap depth at 10.\n");
    code.push_str("pub fn serve(&self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { self.serve_0(cx) }\n");
    if let Some(index) = enabled.iter().position(|name| *name == "cache") {
        writeln!(code, "async fn cache_refresh_next(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ self.serve_{}(cx).await }}", index + 1).unwrap();
    }
    for (i, name) in enabled.iter().enumerate() {
        let next = i + 1;
        if matches!(*name, "ready" | "health" | "reload") {
            writeln!(code, "async fn serve_{i}(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ self.serve_{next}(cx).await }}").unwrap();
            continue;
        }
        writeln!(code, "async fn serve_{i}(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ match &self.r#{name} {{ Some(plugin) => {{ let outcome = pharos_server::Plugin::serve(plugin, cx, Next{i}(self)).await; if outcome == pharos_server::Outcome::Response && cx.metadata.get(pharos_server::metrics::WRITER_METADATA).is_none_or(str::is_empty) {{ cx.metadata.insert(pharos_server::metrics::WRITER_METADATA, {name:?}); }} else if matches!(outcome, pharos_server::Outcome::Error(_)) && cx.metadata.get(pharos_server::logging::PLUGIN_METADATA).is_none_or(str::is_empty) {{ cx.metadata.insert(pharos_server::logging::PLUGIN_METADATA, {name:?}); }} outcome }}, None => self.serve_{next}(cx).await, }} }}").unwrap();
    }
    writeln!(code, "async fn serve_{}(&self, _cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ pharos_server::Outcome::Error(pharos_server::Error::NoNextPlugin) }}", enabled.len()).unwrap();
    code.push_str("}\n");
    code.push_str("impl pharos_server::Chain for Chain {\nfn serve(&self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { Chain::serve(self, cx) }\nfn is_empty(&self) -> bool { true");
    for name in &enabled {
        if !matches!(*name, "ready" | "health" | "reload") {
            write!(code, " && self.r#{name}.is_none()").unwrap();
        }
    }
    code.push_str(
        " }\nfn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {\nlet _ = &visit;\n",
    );
    for name in &enabled {
        if !matches!(*name, "ready" | "health" | "reload") {
            writeln!(code, "if self.r#{name}.is_some() {{ visit({name:?}); }}").unwrap();
        }
    }
    code.push_str("}\n");
    if enabled.contains(&"prometheus") {
        code.push_str("fn metrics_enabled(&self) -> bool { self.prometheus.is_some() }\n");
    } else {
        code.push_str("fn metrics_enabled(&self) -> bool { false }\n");
    }
    if enabled.contains(&"errors") {
        code.push_str("fn stacktrace(&self) -> bool { self.errors.as_ref().is_some_and(|plugin| plugin.stacktrace) }\n");
    }
    code.push_str("}\n");
    for (i, name) in enabled.iter().enumerate() {
        if matches!(*name, "ready" | "health" | "reload") {
            continue;
        }
        let next = i + 1;
        writeln!(code, "struct Next{i}<'a>(&'a Chain);\nimpl pharos_server::Next for Next{i}<'_> {{ async fn run(self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ self.0.serve_{next}(cx).await }} }}").unwrap();
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("plugins.rs"),
        code,
    )
    .unwrap();
}
