#![forbid(unsafe_code)]
#![recursion_limit = "512"]

#[cfg(feature = "plugin-kubernetes")]
#[path = "../../pharos/tests/support/mod.rs"]
mod support;

#[path = "functional"]
mod acl {
    #[path = "acl_metrics.rs"]
    mod acl_metrics;
    #[path = "acl_setup.rs"]
    mod acl_setup;
    #[path = "acl.rs"]
    mod cases;
}

#[path = "functional"]
mod any {
    #[path = "any.rs"]
    mod cases;
}

#[path = "functional"]
mod autopath {
    #[path = "autopath_setup.rs"]
    mod autopath_setup;
    #[path = "autopath.rs"]
    mod cases;
}

#[path = "functional"]
mod bind {
    #[path = "bind_listener.rs"]
    mod bind_listener;
    #[path = "bind_setup.rs"]
    mod bind_setup;
}

#[path = "functional"]
mod bufsize {
    #[path = "bufsize.rs"]
    mod cases;
}

#[path = "functional"]
mod cache {
    #[path = "cache_metrics.rs"]
    mod cache_metrics;
    #[path = "cache_setup.rs"]
    mod cache_setup;
    #[path = "cache_stale.rs"]
    mod cache_stale;
    #[path = "cache.rs"]
    mod cases;
}

#[path = "functional"]
mod cancel {
    #[path = "cancel_outcomes.rs"]
    mod cancel_outcomes;
    #[path = "cancel_setup.rs"]
    mod cancel_setup;
}

#[path = "functional"]
mod chaos {
    #[path = "chaos.rs"]
    mod cases;
}

#[path = "functional"]
mod debug {
    #[path = "debug_setup.rs"]
    mod debug_setup;
}

#[path = "functional"]
mod dns64 {
    #[path = "dns64.rs"]
    mod cases;
    #[path = "dns64_setup.rs"]
    mod dns64_setup;
}

#[path = "functional"]
mod dnssec {
    #[path = "dnssec.rs"]
    mod cases;
    #[path = "dnssec_metrics.rs"]
    mod metrics;
    #[path = "dnssec_setup.rs"]
    mod setup;
}

#[path = "functional"]
mod errors {
    #[path = "errors_outcomes.rs"]
    mod errors_outcomes;
    #[path = "errors_setup.rs"]
    mod errors_setup;
}

#[path = "functional"]
mod forward {
    #[path = "forward.rs"]
    mod cases;
    #[path = "forward_debug.rs"]
    mod forward_debug;
    #[path = "forward_ported.rs"]
    mod forward_ported;
}

#[path = "functional"]
mod header {
    #[path = "header.rs"]
    mod cases;
}

#[path = "functional"]
mod health {
    #[path = "health.rs"]
    mod cases;
    #[path = "health_setup.rs"]
    mod health_setup;
}

#[path = "functional"]
mod hosts {
    #[path = "hosts.rs"]
    mod cases;
    #[path = "hosts_ported.rs"]
    mod hosts_ported;
    #[path = "hosts_reload.rs"]
    mod hosts_reload;
    #[path = "hosts_setup.rs"]
    mod hosts_setup;
}

#[path = "functional"]
mod kubernetes {
    #[path = "kubernetes_coredns_handler.rs"]
    mod kubernetes_coredns_handler;
    #[path = "kubernetes_coredns_ns_reverse.rs"]
    mod kubernetes_coredns_ns_reverse;
    #[path = "kubernetes_coredns_records.rs"]
    mod kubernetes_coredns_records;
    #[path = "kubernetes_lifecycle.rs"]
    mod kubernetes_lifecycle;
    #[path = "kubernetes_setup.rs"]
    mod kubernetes_setup;
    #[path = "kubernetes_visibility.rs"]
    mod kubernetes_visibility;
}

#[path = "functional"]
mod loadbalance {
    #[path = "loadbalance.rs"]
    mod cases;
    #[path = "loadbalance_prefer.rs"]
    mod loadbalance_prefer;
    #[path = "loadbalance_relocation.rs"]
    mod loadbalance_relocation;
    #[path = "loadbalance_setup.rs"]
    mod loadbalance_setup;
    #[path = "loadbalance_weighted.rs"]
    mod loadbalance_weighted;
}

#[path = "functional"]
mod local {
    #[path = "local.rs"]
    mod cases;
    #[path = "local_debug.rs"]
    mod local_debug;
}

#[path = "functional"]
mod log {
    #[path = "log_outcomes.rs"]
    mod log_outcomes;
    #[path = "log_setup.rs"]
    mod log_setup;
}

#[path = "functional"]
mod r#loop {
    #[path = "loop_setup.rs"]
    mod loop_setup;
}

#[path = "functional"]
mod metadata {
    #[path = "metadata_collection.rs"]
    mod metadata_collection;
    #[path = "metadata_setup.rs"]
    mod metadata_setup;
}

#[path = "functional"]
mod minimal {
    #[path = "minimal.rs"]
    mod cases;
}

#[path = "functional"]
mod multisocket {
    #[path = "multisocket_setup.rs"]
    mod multisocket_setup;
}

#[path = "functional"]
mod nsid {
    #[path = "nsid.rs"]
    mod cases;
}

#[path = "functional"]
mod prometheus {
    #[path = "prometheus.rs"]
    mod cases;
    #[path = "prometheus_setup.rs"]
    mod prometheus_setup;
}

#[path = "functional"]
mod proxy {
    #[path = "proxy.rs"]
    mod cases;
    #[path = "proxy_throughput.rs"]
    mod proxy_throughput;
}

#[path = "functional"]
mod ready {
    #[path = "ready.rs"]
    mod cases;
    #[path = "ready_setup.rs"]
    mod ready_setup;
}

#[path = "functional"]
mod registry {
    #[path = "registry.rs"]
    mod cases;
}

#[path = "functional"]
mod reload {
    #[path = "reload_setup.rs"]
    mod reload_setup;
}

#[path = "functional"]
mod rewrite {
    #[path = "rewrite.rs"]
    mod cases;
    #[path = "rewrite_cname_port.rs"]
    mod rewrite_cname_port;
    #[path = "rewrite_edns_port.rs"]
    mod rewrite_edns_port;
    #[path = "rewrite_setup.rs"]
    mod rewrite_setup;
}

#[path = "functional"]
mod root {
    #[path = "root_setup.rs"]
    mod root_setup;
}

#[path = "functional"]
mod server {
    #[path = "server.rs"]
    mod cases;
}

#[path = "functional"]
mod shed {
    #[path = "shed_setup.rs"]
    mod shed_setup;
    #[path = "shed_udp.rs"]
    mod shed_udp;
}

#[path = "functional"]
mod siit {
    #[path = "siit.rs"]
    mod cases;
    #[path = "siit_setup.rs"]
    mod siit_setup;
}

#[path = "functional"]
mod timeouts {
    #[path = "timeouts_setup.rs"]
    mod timeouts_setup;
    #[path = "timeouts_tcp.rs"]
    mod timeouts_tcp;
}

#[path = "functional"]
mod whoami {
    #[path = "whoami.rs"]
    mod cases;
}
