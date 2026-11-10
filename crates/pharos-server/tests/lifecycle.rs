#![forbid(unsafe_code)]

use pharos_server::{Lifecycle, Phase};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn hooks_run_in_registration_order_for_each_phase() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut hooks = Lifecycle::default();
    for (phase, value) in [
        (Phase::Startup, 1),
        (Phase::Reload, 3),
        (Phase::Startup, 2),
        (Phase::Shutdown, 4),
    ] {
        let events = Arc::clone(&events);
        hooks.register(phase, move || {
            let events = Arc::clone(&events);
            async move {
                events.lock().unwrap().push(value);
                Ok(())
            }
        });
    }
    let sync_events = Arc::clone(&events);
    hooks.register_sync(Phase::Shutdown, move || {
        sync_events.lock().unwrap().push(5);
        Ok(())
    });
    hooks.run(Phase::Startup).await.unwrap();
    hooks.run(Phase::Reload).await.unwrap();
    hooks.run(Phase::Shutdown).await.unwrap();
    assert_eq!(*events.lock().unwrap(), [1, 2, 3, 4, 5]);
}
