use std::{
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
};

use crate::{Error, Outcome};

static PANICS: AtomicU64 = AtomicU64::new(0);

/// Number of contained Plugin panics; metrics export is provided separately.
pub fn panics_total() -> u64 {
    PANICS.load(Ordering::Relaxed)
}

/// Catch a Plugin Chain panic while polling, unless debug mode is enabled.
pub async fn contain_panic(future: impl Future<Output = Outcome>, debug: bool) -> Outcome {
    if debug {
        return future.await;
    }
    let mut future = std::pin::pin!(future);
    poll_fn(
        |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(result) => result,
            Err(_) => {
                PANICS.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Outcome::Error(Error::PluginPanic))
            }
        },
    )
    .await
}
