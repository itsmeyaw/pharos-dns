#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{
    alloc::System,
    sync::{Mutex, MutexGuard},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn run_isolated(name: &str) -> bool {
    if std::env::var_os("PHAROS_ALLOCATION_CHILD").is_some() {
        return false;
    }
    // ADR-0007: isolate measurements from allocations by the parallel test harness.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("PHAROS_ALLOCATION_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

#[path = "allocations"]
mod acl {
    #[path = "acl_allocations.rs"]
    mod acl_allocations;
}

#[path = "allocations"]
mod whoami {
    #[path = "allocations.rs"]
    mod allocations;
}

#[path = "allocations"]
mod any {
    #[path = "any_allocations.rs"]
    mod any_allocations;
}

#[path = "allocations"]
mod autopath {
    #[path = "autopath_allocations.rs"]
    mod autopath_allocations;
}

#[path = "allocations"]
mod bufsize {
    #[path = "bufsize_allocations.rs"]
    mod bufsize_allocations;
}

#[path = "allocations"]
mod cache {
    #[path = "cache_allocations.rs"]
    mod cache_allocations;
}

#[path = "allocations"]
mod cancel {
    #[path = "cancel_allocations.rs"]
    mod cancel_allocations;
}

#[path = "allocations"]
mod chaos {
    #[path = "chaos_allocations.rs"]
    mod chaos_allocations;
}

#[path = "allocations"]
mod dns64 {
    #[path = "dns64_allocations.rs"]
    mod dns64_allocations;
}

#[path = "allocations"]
mod forward {
    #[path = "forward_allocations.rs"]
    mod forward_allocations;
}

#[path = "allocations"]
mod header {
    #[path = "header_allocations.rs"]
    mod header_allocations;
}

#[path = "allocations"]
mod hosts {
    #[path = "hosts_allocations.rs"]
    mod hosts_allocations;
}

#[path = "allocations"]
mod kubernetes {
    #[path = "kubernetes_allocations.rs"]
    mod kubernetes_allocations;
    #[path = "kubernetes_large_allocations.rs"]
    mod kubernetes_large_allocations;
    #[path = "kubernetes_services.rs"]
    mod kubernetes_services;
}

#[path = "allocations"]
mod loadbalance {
    #[path = "loadbalance_allocations.rs"]
    mod loadbalance_allocations;
    #[path = "loadbalance_cname_allocations.rs"]
    mod loadbalance_cname_allocations;
}

#[path = "allocations"]
mod local {
    #[path = "local_allocations.rs"]
    mod local_allocations;
}

#[path = "allocations"]
mod log {
    #[path = "log_format.rs"]
    mod log_format;
}

#[path = "allocations"]
mod minimal {
    #[path = "minimal_allocations.rs"]
    mod minimal_allocations;
}

#[path = "allocations"]
mod nsid {
    #[path = "nsid_allocations.rs"]
    mod nsid_allocations;
}

#[path = "allocations"]
mod proxy {
    #[path = "proxy_allocations.rs"]
    mod proxy_allocations;
    #[path = "proxy_tcp_allocations.rs"]
    mod proxy_tcp_allocations;
}

#[path = "allocations"]
mod rewrite {
    #[path = "rewrite_allocations.rs"]
    mod rewrite_allocations;
    #[path = "rewrite_regex_allocations.rs"]
    mod rewrite_regex_allocations;
}

#[path = "allocations"]
mod server {
    #[path = "server_allocations.rs"]
    mod server_allocations;
}

#[path = "allocations"]
mod siit {
    #[path = "siit_allocations.rs"]
    mod siit_allocations;
}
