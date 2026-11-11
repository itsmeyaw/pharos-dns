use std::{
    backtrace::Backtrace,
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Once,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
};

use crate::{Error, Outcome};

static PANICS: AtomicU64 = AtomicU64::new(0);
static STACKTRACE_HOOK: Once = Once::new();

thread_local! {
    static CAPTURE_STACKTRACE: Cell<bool> = const { Cell::new(false) };
    static STACKTRACE: RefCell<Option<Backtrace>> = const { RefCell::new(None) };
}

/// Number of contained Plugin panics; metrics export is provided separately.
pub fn panics_total() -> u64 {
    PANICS.load(Ordering::Relaxed)
}

/// Catch a Plugin Chain panic while polling, unless debug mode is enabled.
pub async fn contain_panic(future: impl Future<Output = Outcome>, debug: bool) -> Outcome {
    contain_panic_with_stacktrace(future, debug, false).await
}

pub(crate) fn prepare_stacktrace() {
    STACKTRACE_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if CAPTURE_STACKTRACE.try_with(Cell::get).unwrap_or(false) {
                let _ = STACKTRACE.try_with(|slot| {
                    *slot.borrow_mut() = Some(Backtrace::force_capture());
                });
            }
            previous(info);
        }));
    });
}

pub(crate) async fn contain_panic_with_stacktrace(
    future: impl Future<Output = Outcome>,
    debug: bool,
    stacktrace: bool,
) -> Outcome {
    if debug {
        return future.await;
    }
    if stacktrace {
        prepare_stacktrace();
    }
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        // Scope capture to this poll, including nested containment on the same thread.
        let previous_capture = CAPTURE_STACKTRACE.with(|slot| slot.replace(stacktrace));
        let previous_trace = STACKTRACE.with(|slot| slot.take());
        let result = catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)));
        CAPTURE_STACKTRACE.with(|slot| slot.set(previous_capture));
        let trace = STACKTRACE.with(|slot| slot.replace(previous_trace));
        match result {
            Ok(result) => result,
            Err(_) => {
                PANICS.fetch_add(1, Ordering::Relaxed);
                if let Some(trace) = trace {
                    crate::logging::log(
                        "ERROR",
                        "server",
                        &format!("Plugin panic stacktrace:\n{trace}"),
                    );
                }
                Poll::Ready(Outcome::Error(Error::PluginPanic))
            }
        }
    })
    .await
}
