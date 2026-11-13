#![forbid(unsafe_code)]

use std::{env, fmt::Write, fs, path::PathBuf};

fn config_only(name: &str) -> bool {
    // View's pass-through handler is redundant once the Listener routes the Query.
    matches!(
        name,
        "root"
            | "timeouts"
            | "debug"
            | "bind"
            | "multisocket"
            | "ready"
            | "health"
            | "reload"
            | "view"
    )
}

fn next_plugin(enabled: &[&str], start: usize) -> usize {
    (start..enabled.len())
        .find(|&index| !config_only(enabled[index]))
        .unwrap_or(enabled.len())
}

fn transferer(name: &str) -> bool {
    // Add each implemented Transferer here; enabled retains Plugin Order.
    matches!(
        name,
        "k8s_external" | "kubernetes" | "file" | "auto" | "secondary"
    )
}

fn registered_handler(name: &str) -> bool {
    !config_only(name) || name == "view"
}

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
            "dnssec" => "dnssec::Dnssec",
            "siit" => "siit::Siit",
            "tsig" => "tsig::Tsig",
            "transfer" => "transfer::Transfer",
            "rewrite" => "rewrite::Rewrite",
            "template" => "template::Template",
            "autopath" => "autopath::AutoPath",
            "root" => "std::path::PathBuf",
            "cancel" => "cancel::Cancel",
            "timeouts" => "timeouts::Timeouts",
            "debug" => "()",
            "shed" => "shed::Shed",
            "any" => "any::Any",
            "chaos" => "chaos::Chaos",
            "cache" => "cache::Cache",
            "bind" => "()",
            "bufsize" => "bufsize::Bufsize",
            "header" => "header::Header",
            "minimal" => "minimal::Minimal",
            "multisocket" => "Option<usize>",
            "whoami" => "whoami::Whoami",
            "view" => "view::View",
            "log" => "log::Log",
            "metadata" => "metadata::Metadata",
            "loop" => "r#loop::Loop",
            "prometheus" => "prometheus::Prometheus",
            "ready" => "ready::Ready",
            "forward" => "forward::Forward",
            "health" => "health::Health",
            "hosts" => "hosts::Hosts",
            "k8s_external" => "k8s_external::External",
            "kubernetes" => "kubernetes::Kubernetes",
            "loadbalance" => "loadbalance::LoadBalance",
            "local" => "local::Local",
            "nsid" => "nsid::Nsid",
            "reload" => "reload::Reload",
            "errors" => "errors::Errors",
            "file" => "file::File",
            "auto" => "auto::Auto",
            "secondary" => "secondary::Secondary",
            "erratic" => "erratic::Erratic",
            _ => "Unimplemented",
        };
        writeln!(code, "pub r#{name}: Option<{ty}>,").unwrap();
    }
    code.push_str("#[cfg(all(test, feature = \"plugin-cache\", feature = \"plugin-hosts\"))] pub self_lookup_test: Option<self_lookup_test::TestPlugin>,\n");
    if enabled.contains(&"transfer") {
        code.push_str("#[cfg(test)] pub(crate) transfer_test_first: Option<transfer::tests::TestProvider>,\n#[cfg(test)] pub(crate) transfer_test_second: Option<transfer::tests::TestProvider>,\n");
    }
    code.push_str("}\npub static DIRECTIVES: &[pharos_corefile::Directive<'static, Chain>] = &[\n");
    for name in &enabled {
        let setup = match *name {
            "acl" => "acl::setup::setup",
            "dns64" => "dns64::setup::setup",
            "dnssec" => "dnssec::setup::setup",
            "siit" => "siit::setup::setup",
            "tsig" => "tsig::setup::setup",
            "transfer" => "transfer::setup::setup",
            "rewrite" => "rewrite::setup::setup",
            "template" => "template::setup::setup",
            "autopath" => "autopath::setup::setup",
            "root" => "root::setup::setup",
            "cancel" => "cancel::setup::setup",
            "timeouts" => "timeouts::setup::setup",
            "debug" => "debug::setup::setup",
            "shed" => "shed::setup::setup",
            "any" => "any::setup::setup",
            "chaos" => "chaos::setup::setup",
            "cache" => "cache::setup::setup",
            "bind" => "bind::setup::setup",
            "bufsize" => "bufsize::setup::setup",
            "header" => "header::setup::setup",
            "minimal" => "minimal::setup::setup",
            "multisocket" => "multisocket::setup::setup",
            "whoami" => "whoami::setup::setup",
            "view" => "view::setup::setup",
            "log" => "log::setup::setup",
            "metadata" => "metadata::setup::setup",
            "loop" => "r#loop::setup::setup",
            "prometheus" => "prometheus::setup::setup",
            "ready" => "ready::setup::setup",
            "forward" => "forward::setup::setup",
            "health" => "health::setup::setup",
            "hosts" => "hosts::setup::setup",
            "k8s_external" => "k8s_external::setup::setup",
            "loadbalance" => "loadbalance::setup::setup",
            "local" => "local::setup::setup",
            "nsid" => "nsid::setup::setup",
            "reload" => "reload::setup::setup",
            "errors" => "errors::setup::setup",
            "file" => "file::setup::setup",
            "auto" => "auto::setup::setup",
            "secondary" => "secondary::setup::setup",
            "erratic" => "erratic::setup::setup",
            "kubernetes" => "kubernetes::setup::setup",
            _ => "setup_unimplemented",
        };
        let once = matches!(
            *name,
            "cache"
                | "dnssec"
                | "tsig"
                | "shed"
                | "metadata"
                | "prometheus"
                | "ready"
                | "errors"
                | "reload"
                | "hosts"
                | "loop"
                | "nsid"
                | "kubernetes"
                | "view"
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

    if enabled.contains(&"transfer") {
        code.push_str("struct ChainTransferers<'a>(&'a Chain);\nimpl transfer::Transferer for ChainTransferers<'_> {\nfn transfer(&self, request: transfer::TransferRequest<'_>) -> Result<Option<pharos_server::Stream>, pharos_server::Error> {\n");
        code.push_str("#[cfg(test)] if let Some(plugin) = &self.0.transfer_test_first { match transfer::Transferer::transfer(plugin, request) { Ok(None) => {}, result => return result } }\n");
        for name in enabled.iter().copied().filter(|name| transferer(name)) {
            let call = if name == "auto" {
                "plugin.transfer_query(request)"
            } else {
                "transfer::Transferer::transfer(plugin, request)"
            };
            writeln!(code, "if let Some(plugin) = &self.0.r#{name} {{ match {call} {{ Ok(None) => {{}}, result => return result }} }}").unwrap();
        }
        code.push_str("#[cfg(test)] if let Some(plugin) = &self.0.transfer_test_second { match transfer::Transferer::transfer(plugin, request) { Ok(None) => {}, result => return result } }\nlet _ = (self.0, request);\nOk(None)\n}\n}\n");
    }

    code.push_str("impl Chain {\n");
    if enabled.contains(&"transfer") {
        code.push_str("fn bind_transferers(&self) {\n");
        for name in enabled.iter().copied().filter(|name| transferer(name)) {
            writeln!(code, "if let Some(plugin) = &self.r#{name} {{ transfer::Transferer::bind_transfer(plugin, self.transfer.as_ref()); }}").unwrap();
        }
        code.push_str("}\n");
    }
    if enabled.contains(&"ready") {
        code.push_str(
            "fn collect_readiness(self: &std::sync::Arc<Self>, state: &ready::State) {\nlet _ = state;\n",
        );
        for name in &enabled {
            if config_only(name) {
                continue;
            }
            writeln!(code, "if self.r#{name}.as_ref().and_then(pharos_server::Plugin::readiness).is_some() {{ let chain = std::sync::Arc::clone(self); state.append({name:?}, move || chain.r#{name}.as_ref().and_then(pharos_server::Plugin::readiness).is_some_and(pharos_server::Readiness::ready)); }}").unwrap();
        }
        code.push_str("}\n");
    }
    code.push_str("pub fn serve(&self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { self.serve_routed(cx, false) }\nfn serve_routed(&self, cx: &mut pharos_server::Context<'_>, collected: bool) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { if !collected { ");
    if enabled.contains(&"metadata") {
        code.push_str("cx.metadata.set_enabled(self.metadata.is_some()); ");
    } else {
        code.push_str("cx.metadata.set_enabled(false); ");
    }
    if enabled.contains(&"metadata") && enabled.contains(&"kubernetes") {
        code.push_str("if self.metadata.as_ref().is_some_and(|plugin| plugin.matches(cx)) && let Some(plugin) = &self.kubernetes { plugin.collect_metadata(cx); } ");
    }
    writeln!(code, "}} self.serve_{}(cx) }}", next_plugin(&enabled, 0)).unwrap();
    if let Some(index) = enabled.iter().position(|name| *name == "cache") {
        writeln!(code, "async fn cache_refresh_next(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ #[cfg(all(test, feature = \"plugin-cache\", feature = \"plugin-hosts\"))] if let Some(plugin) = &self.self_lookup_test {{ return plugin.serve(cx).await; }} self.serve_{}(cx).await }}", next_plugin(&enabled, index + 1)).unwrap();
    }
    for (i, name) in enabled.iter().enumerate() {
        if config_only(name) {
            continue;
        }
        let next = next_plugin(&enabled, i + 1);
        let call = if *name == "transfer" {
            format!("plugin.serve_with(cx, Next{i}(self), Some(&ChainTransferers(self))).await")
        } else if *name == "file" || *name == "secondary" || *name == "auto" {
            let tail = enabled
                .iter()
                .skip(i + 1)
                .filter(|name| registered_handler(name))
                .map(|name| format!("self.r#{name}.is_some()"))
                .collect::<Vec<_>>()
                .join(" || ");
            let has_next = if tail.is_empty() { "false" } else { &tail };
            format!("plugin.serve_with(cx, Next{i}(self), {has_next}).await")
        } else {
            format!("pharos_server::Plugin::serve(plugin, cx, Next{i}(self)).await")
        };
        writeln!(code, "async fn serve_{i}(&self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ match &self.r#{name} {{ Some(plugin) => {{ let outcome = {call}; if outcome == pharos_server::Outcome::Response && cx.metadata.get(pharos_server::metrics::WRITER_METADATA).is_none_or(str::is_empty) {{ cx.metadata.insert(pharos_server::metrics::WRITER_METADATA, {name:?}); }} else if matches!(outcome, pharos_server::Outcome::Error(_)) && cx.metadata.get(pharos_server::logging::PLUGIN_METADATA).is_none_or(str::is_empty) {{ cx.metadata.insert(pharos_server::logging::PLUGIN_METADATA, {name:?}); }} outcome }}, None => self.serve_{next}(cx).await, }} }}").unwrap();
    }
    writeln!(code, "async fn serve_{}(&self, _cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ pharos_server::Outcome::Error(pharos_server::Error::NoNextPlugin) }}", enabled.len()).unwrap();
    code.push_str("}\n");
    code.push_str("impl pharos_server::Chain for Chain {\nfn serve(&self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { Chain::serve(self, cx) }\nfn is_empty(&self) -> bool { true");
    for name in &enabled {
        if registered_handler(name) {
            write!(code, " && self.r#{name}.is_none()").unwrap();
        }
    }
    code.push_str(
        " }\nfn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {\nlet _ = &visit;\n",
    );
    for name in &enabled {
        if registered_handler(name) {
            writeln!(code, "if self.r#{name}.is_some() {{ visit({name:?}); }}").unwrap();
        }
    }
    code.push_str("}\n");
    if enabled.contains(&"view") {
        code.push_str("fn has_view(&self) -> bool { self.view.is_some() }\nfn view_name(&self) -> &str { self.view.as_ref().map_or(\"\", |view| view.name.as_ref()) }\nfn matches_view(&self, cx: &pharos_server::Context<'_>) -> bool { self.view.as_ref().is_none_or(|view| view.matches(cx)) }\n");
    }
    if enabled.contains(&"metadata") {
        code.push_str("fn has_metadata_collector(&self) -> bool { self.metadata.is_some() }\nfn collect_metadata(&self, cx: &mut pharos_server::Context<'_>) { let _ = &cx; ");
        if enabled.contains(&"view") || enabled.contains(&"kubernetes") {
            code.push_str("if self.metadata.as_ref().is_some_and(|plugin| plugin.matches(cx)) { ");
            if enabled.contains(&"view") {
                code.push_str("if let Some(view) = &self.view { cx.metadata.set_view_name(std::sync::Arc::clone(&view.name)); }\n");
            }
            if enabled.contains(&"kubernetes") {
                code.push_str(
                    "if let Some(plugin) = &self.kubernetes { plugin.collect_metadata(cx); } ",
                );
            }
            code.push_str("} ");
        }
        code.push_str("}\n");
    }
    code.push_str("fn serve_routed(&self, cx: &mut pharos_server::Context<'_>, collected: bool) -> impl std::future::Future<Output = pharos_server::Outcome> + Send { Chain::serve_routed(self, cx, collected) }\n");
    if enabled.contains(&"loop") {
        code.push_str("fn parallel_query(&self, query: &pharos_proto::Message<'_>) -> Option<tokio::sync::watch::Receiver<bool>> { self.r#loop.as_ref().and_then(|plugin| plugin.parallel_query(query)) }\n");
    }
    if enabled.contains(&"prometheus") {
        code.push_str("fn metrics_enabled(&self) -> bool { self.prometheus.is_some() }\n");
    } else {
        code.push_str("fn metrics_enabled(&self) -> bool { false }\n");
    }
    if enabled.contains(&"auto") && enabled.contains(&"prometheus") {
        code.push_str("fn dynamic_metric_zones(&self) -> Option<&pharos_server::metrics::DynamicZones> { self.auto.as_ref().map(|plugin| plugin.metric_zones()) }\n");
    }
    if enabled.contains(&"errors") {
        code.push_str("fn stacktrace(&self) -> bool { self.errors.as_ref().is_some_and(|plugin| plugin.stacktrace) }\n");
    }
    if enabled.contains(&"shed") {
        code.push_str("fn shed_enabled(&self) -> bool { self.shed.is_some() }\n");
    }
    code.push_str("}\n");
    for (i, name) in enabled.iter().enumerate() {
        if config_only(name) {
            continue;
        }
        let next = next_plugin(&enabled, i + 1);
        let test_hook = if *name == "cache" {
            "#[cfg(all(test, feature = \"plugin-cache\", feature = \"plugin-hosts\"))] if let Some(plugin) = &self.0.self_lookup_test { return plugin.serve(cx).await; }"
        } else {
            ""
        };
        if test_hook.is_empty() {
            writeln!(code, "struct Next{i}<'a>(&'a Chain);\nimpl pharos_server::Next for Next{i}<'_> {{ fn run(self, cx: &mut pharos_server::Context<'_>) -> impl std::future::Future<Output = pharos_server::Outcome> + Send {{ self.0.serve_{next}(cx) }} }}").unwrap();
        } else {
            writeln!(code, "struct Next{i}<'a>(&'a Chain);\nimpl pharos_server::Next for Next{i}<'_> {{ async fn run(self, cx: &mut pharos_server::Context<'_>) -> pharos_server::Outcome {{ {test_hook} self.0.serve_{next}(cx).await }} }}").unwrap();
        }
    }
    let code = code.replace(
        "pharos_server::Context<'_>",
        "pharos_server::Context<'_, '_>",
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("plugins.rs"),
        code,
    )
    .unwrap();
}
