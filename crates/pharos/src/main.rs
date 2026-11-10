#![forbid(unsafe_code)]

fn main() {
    println!(
        "Pharos-{}\nCoreDNS-1.15.0 compatible",
        env!("CARGO_PKG_VERSION")
    );
}
