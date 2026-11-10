#![forbid(unsafe_code)]

use pharos_server::{Error, Outcome, contain_panic, panics_total};

#[tokio::test]
async fn panic_is_contained_and_debug_propagates() {
    let before = panics_total();
    let outcome = contain_panic(async { panic!("plugin panic") }, false).await;
    assert_eq!(outcome, Outcome::Error(Error::PluginPanic));
    assert_eq!(panics_total(), before + 1);
    let result = tokio::spawn(contain_panic(async { panic!("debug panic") }, true)).await;
    assert!(result.unwrap_err().is_panic());
    assert_eq!(panics_total(), before + 1);
}
