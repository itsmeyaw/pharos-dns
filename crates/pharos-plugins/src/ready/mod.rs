//! Readiness endpoint configuration and state.

pub(crate) mod setup;

use std::{collections::BTreeMap, sync::Mutex};

use pharos_corefile::{Cursor, Error};

#[derive(Debug)]
pub struct Ready {
    pub address: String,
    pub continuous: bool,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Ready, Error> {
    cursor.next();
    let args = cursor.remaining_args();
    if args.len() > 1 {
        return Err(cursor.arg_err());
    }
    let address = args.first().map_or(":8181", String::as_str);
    if !crate::valid_http_address(address) {
        return Err(cursor.error("invalid ready address"));
    }
    let mut continuous = false;
    while cursor.next_block() {
        if cursor.val() != "monitor" {
            return Err(cursor.error(format!("unknown option: {}", cursor.val())));
        }
        let args = cursor.remaining_args();
        if args.len() != 1 {
            return Err(cursor.arg_err());
        }
        continuous = match args[0].as_str() {
            "until-ready" => false,
            "continuously" => true,
            _ => return Err(cursor.error("unsupported monitor type")),
        };
    }
    Ok(Ready {
        address: address.to_owned(),
        continuous,
    })
}

type Check = Box<dyn Fn() -> bool + Send + Sync>;

#[derive(Default)]
struct Inner {
    checks: BTreeMap<&'static str, Option<Check>>,
    continuous: bool,
    shutting_down: bool,
}

/// Shared process readiness. Shutdown is marked before block shutdown hooks run.
#[derive(Default)]
pub struct State(Mutex<Inner>);

impl State {
    pub fn append(&self, name: &'static str, check: impl Fn() -> bool + Send + Sync + 'static) {
        self.0
            .lock()
            .unwrap()
            .checks
            .insert(name, Some(Box::new(check)));
    }

    pub fn set_continuous(&self, continuous: bool) {
        self.0.lock().unwrap().continuous = continuous;
    }

    pub fn begin_shutdown(&self) {
        self.0.lock().unwrap().shutting_down = true;
    }

    pub fn response(&self) -> (u16, String) {
        let mut state = self.0.lock().unwrap();
        // RFC 9110 §15.6.4: 503 indicates temporary inability to handle requests.
        if state.shutting_down {
            return (503, "Shutting down".into());
        }
        let continuous = state.continuous;
        let mut not_ready = Vec::new();
        for (name, check) in &mut state.checks {
            if let Some(current) = check {
                if current() {
                    if !continuous {
                        *check = None;
                    }
                } else {
                    not_ready.push(*name);
                }
            }
        }
        if not_ready.is_empty() {
            (200, "OK".into())
        } else {
            (503, not_ready.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use pharos_server::Readiness;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Fake(AtomicBool);
    impl Readiness for Fake {
        fn ready(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn monitor_modes_sort_names_and_report_shutdown() {
        for continuous in [false, true] {
            let state = State::default();
            state.set_continuous(continuous);
            let fake = Arc::new(Fake(AtomicBool::new(false)));
            for name in ["zebra", "alpha"] {
                let fake = Arc::clone(&fake);
                state.append(name, move || fake.ready());
            }
            assert_eq!(state.response(), (503, "alpha,zebra".into()));
            fake.0.store(true, Ordering::SeqCst);
            assert_eq!(state.response(), (200, "OK".into()));
            fake.0.store(false, Ordering::SeqCst);
            assert_eq!(
                state.response(),
                if continuous {
                    (503, "alpha,zebra".into())
                } else {
                    (200, "OK".into())
                }
            );
            state.begin_shutdown();
            assert_eq!(state.response(), (503, "Shutting down".into()));
        }
    }

    #[test]
    fn later_plugin_with_same_name_replaces_earlier_one() {
        let state = State::default();
        state.append("same", || false);
        state.append("same", || true);
        assert_eq!(state.response(), (200, "OK".into()));
    }
}
