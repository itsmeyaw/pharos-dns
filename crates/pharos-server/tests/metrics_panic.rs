#![forbid(unsafe_code)]

use pharos_server::{contain_panic, metrics::Registry, panics_total};

#[tokio::test]
async fn registry_exports_shared_panic_counter() {
    let registry = Registry::new("v", "r", "rust");
    let before = panics_total();
    let _ = contain_panic(async { panic!("test panic") }, false).await;
    assert_eq!(panics_total(), before + 1);
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(text.contains(&format!("pharos_panics_total {}\n", before + 1)));
}
