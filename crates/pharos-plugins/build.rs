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
            "acl" => "acl::Acl",
            "dns64" => "dns64::Dns64",
            "any" => "any::Any",
            "chaos" => "chaos::Chaos",
            "cache" => "cache::Cache",
            "bind" => "()",
            "bufsize" => "bufsize::Bufsize",
            "header" => "header::Header",
            "minimal" => "minimal::Minimal",
            "multisocket" => "Option<usize>",
            "whoami" => "whoami::Whoami",
            "log" => "log::Log",
            "metadata" => "metadata::Metadata",
            "loop" => "r#loop::Loop",
            "prometheus" => "prometheus::Prometheus",
            "ready" => "ready::Ready",
            "forward" => "forward::Forward",
            "health" => "health::Health",
            "hosts" => "hosts::Hosts",
            "kubernetes" => "kubernetes::Kubernetes",
            "loadbalance" => "loadbalance::LoadBalance",
            "local" => "local::Local",
            "nsid" => "nsid::Nsid",
            "reload" => "reload::Reload",
            "errors" => "errors::Errors",
            _ => "Unimplemented",
        };
        writeln!(code, "pub r#{name}: Option<{ty}>,").unwrap();
    }
    code.push_str("#[cfg(all(test, feature = \"plugin-cache\", feature = \"plugin-hosts\"))] pub self_lookup_test: Option<self_lookup_test::TestPlugin>,\n");
    code.push_str("}\npub static DIRECTIVES: &[pharos_corefile::Directive<'static, Chain>] = &[\n");
    for name in &enabled {
        let setup = match *name {
            "acl" => "setup_acl",
            "dns64" => "setup_dns64",
            "any" => "setup_any",
            "chaos" => "setup_chaos",
            "cache" => "setup_cache",
            "bind" => "setup_bind",
            "bufsize" => "setup_bufsize",
            "header" => "setup_header",
            "minimal" => "setup_minimal",
            "multisocket" => "setup_multisocket",
            "whoami" => "setup_whoami",
            "log" => "setup_log",
            "metadata" => "setup_metadata",
            "loop" => "setup_loop",
            "prometheus" => "setup_prometheus",
            "ready" => "setup_ready",
            "forward" => "setup_forward",
            "health" => "setup_health",
            "hosts" => "setup_hosts",
            "loadbalance" => "setup_loadbalance",
            "local" => "setup_local",
            "nsid" => "setup_nsid",
            "reload" => "setup_reload",
            "errors" => "setup_errors",
            "kubernetes" => "setup_kubernetes",
            _ => "setup_unimplemented",
        };
        let once = matches!(
            *name,
            "cache"
                | "metadata"
                | "prometheus"
                | "ready"
                | "errors"
                | "reload"
                | "hosts"
                | "loop"
                | "nsid"
                | "kubernetes"
        );
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
            if matches!(
                *name,
                "bind" | "multisocket" | "ready" | "health" | "reload"
            ) {
                continue;
            }
            writeln!(code, "if self.r#{name}.as_ref().and_then(pharos_server::Plugin::readiness).is_some() {{ let chain = std::sync::Arc::clone(self); state.append({name:?}, move || chain.r#{name}.as_ref().and_then(pharos_server::Plugin::readiness).is_some_and(pharos_server::Readiness::ready)); }}").unwrap();
        }
        code.push_str("}\n");
    }
    code.push_str("pub fn serve(&self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { ");
    if enabled.contains(&"metadata") {
        code.push_str("cx.metadata.set_enabled(self.metadata.is_some()); ");
    } else {
        code.push_str("cx.metadata.set_enabled(false); ");
    }
    if enabled.contains(&"metadata") && enabled.contains(&"kubernetes") {
        code.push_str("if self.metadata.as_ref().is_some_and(|plugin| plugin.matches(cx)) && let Some(plugin) = &self.kubernetes { plugin.collect_metadata(cx); } ");
    }
    code.push_str("self.serve_0(cx) }\n");
    if let Some(index) = enabled.iter().position(|name| *name == "cache") {
        writeln!(code, "async fn cache_refresh_next(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ #[cfg(all(test, feature = \"plugin-cache\", feature = \"plugin-hosts\"))] if let Some(plugin) = &self.self_lookup_test {{ return plugin.serve(cx).await; }} self.serve_{}(cx).await }}", index + 1).unwrap();
    }
    for (i, name) in enabled.iter().enumerate() {
        let next = i + 1;
        if matches!(
            *name,
            "bind" | "multisocket" | "ready" | "health" | "reload"
        ) {
            writeln!(code, "async fn serve_{i}(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ self.serve_{next}(cx).await }}").unwrap();
            continue;
        }
        writeln!(code, "async fn serve_{i}(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ match &self.r#{name} {{ Some(plugin) => {{ let outcome = pharos_server::Plugin::serve(plugin, cx, Next{i}(self)).await; if outcome == pharos_server::Outcome::Response && cx.metadata.get(pharos_server::metrics::WRITER_METADATA).is_none_or(str::is_empty) {{ cx.metadata.insert(pharos_server::metrics::WRITER_METADATA, {name:?}); }} else if matches!(outcome, pharos_server::Outcome::Error(_)) && cx.metadata.get(pharos_server::logging::PLUGIN_METADATA).is_none_or(str::is_empty) {{ cx.metadata.insert(pharos_server::logging::PLUGIN_METADATA, {name:?}); }} outcome }}, None => self.serve_{next}(cx).await, }} }}").unwrap();
    }
    writeln!(code, "async fn serve_{}(&self, _cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ pharos_server::Outcome::Error(pharos_server::Error::NoNextPlugin) }}", enabled.len()).unwrap();
    code.push_str("}\n");
    code.push_str("impl pharos_server::Chain for Chain {\nfn serve(&self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { Chain::serve(self, cx) }\nfn is_empty(&self) -> bool { true");
    for name in &enabled {
        if !matches!(
            *name,
            "bind" | "multisocket" | "ready" | "health" | "reload"
        ) {
            write!(code, " && self.r#{name}.is_none()").unwrap();
        }
    }
    code.push_str(
        " }\nfn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {\nlet _ = &visit;\n",
    );
    for name in &enabled {
        if !matches!(
            *name,
            "bind" | "multisocket" | "ready" | "health" | "reload"
        ) {
            writeln!(code, "if self.r#{name}.is_some() {{ visit({name:?}); }}").unwrap();
        }
    }
    code.push_str("}\n");
    if enabled.contains(&"loop") {
        code.push_str("fn parallel_query(&self, query: &pharos_proto::Message<'_>) -> Option<tokio::sync::watch::Receiver<bool>> { self.r#loop.as_ref().and_then(|plugin| plugin.parallel_query(query)) }\n");
    }
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
        if matches!(
            *name,
            "bind" | "multisocket" | "ready" | "health" | "reload"
        ) {
            continue;
        }
        let next = i + 1;
        let test_hook = if *name == "cache" {
            "#[cfg(all(test, feature = \"plugin-cache\", feature = \"plugin-hosts\"))] if let Some(plugin) = &self.0.self_lookup_test { return plugin.serve(cx).await; }"
        } else {
            ""
        };
        writeln!(code, "struct Next{i}<'a>(&'a Chain);\nimpl pharos_server::Next for Next{i}<'_> {{ async fn run(self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ {test_hook} self.0.serve_{next}(cx).await }} }}").unwrap();
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("plugins.rs"),
        code,
    )
    .unwrap();
}
