use regex_automata::nfa::thompson::{
    Builder, NFA, State, WhichCaptures,
    pikevm::{Cache, PikeVM},
};
use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

#[derive(Debug)]
pub(crate) struct Regex {
    vm: PikeVM,
    cache: Mutex<Cache>,
}

impl Regex {
    pub(crate) fn new(pattern: &str) -> Result<Self, String> {
        let (vm, warmer) = build(pattern)?;
        let cache = Mutex::new(warm_cache(&vm, &warmer));
        drop(cache.lock().map_err(|_| "regex cache lock poisoned")?);
        Ok(Self { vm, cache })
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.vm.is_match(
            &mut self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            text,
        )
    }
}

fn build(pattern: &str) -> Result<(PikeVM, PikeVM), String> {
    let vm = PikeVM::builder()
        .thompson(NFA::config().which_captures(WhichCaptures::None))
        .build(pattern)
        .map_err(|error| error.to_string())?;
    // Each NFA epsilon edge can enqueue at most once per closure.
    let stack_bound = 1 + vm
        .get_nfa()
        .states()
        .iter()
        .map(|state| match state {
            State::Union { alternates } => alternates.len().saturating_sub(1),
            State::BinaryUnion { .. } => 1,
            _ => 0,
        })
        .sum::<usize>();
    let mut builder = Builder::new();
    builder.start_pattern().map_err(|error| error.to_string())?;
    let fail = builder.add_fail().map_err(|error| error.to_string())?;
    let end = builder.add_match().map_err(|error| error.to_string())?;
    let mut alternatives = vec![fail; stack_bound];
    alternatives.push(end);
    let start = builder
        .add_union(alternatives)
        .map_err(|error| error.to_string())?;
    builder
        .finish_pattern(start)
        .map_err(|error| error.to_string())?;
    let nfa = builder
        .build(start, start)
        .map_err(|error| error.to_string())?;
    let warmer = PikeVM::new_from_nfa(nfa).map_err(|error| error.to_string())?;
    Ok((vm, warmer))
}

fn warm_cache(vm: &PikeVM, warmer: &PikeVM) -> Cache {
    let mut cache = warmer.create_cache();
    let _ = warmer.is_match(&mut cache, "");
    cache.reset(vm);
    cache
}

#[derive(Debug)]
pub(crate) struct ThreadRegex {
    vm: PikeVM,
    warmer: PikeVM,
    identity: Arc<()>,
}

thread_local! {
    static CACHES: RefCell<HashMap<usize, (Weak<()>, Cache)>> = RefCell::new(HashMap::new());
}

impl ThreadRegex {
    pub(crate) fn new(pattern: &str) -> Result<Self, String> {
        let (vm, warmer) = build(pattern)?;
        let regex = Self {
            vm,
            warmer,
            identity: Arc::new(()),
        };
        let _ = regex.is_match("");
        Ok(regex)
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        let key = Arc::as_ptr(&self.identity) as usize;
        CACHES.with(|caches| {
            let mut caches = caches.borrow_mut();
            if !caches.contains_key(&key) {
                caches.retain(|_, (owner, _)| owner.strong_count() != 0);
            }
            let (_, cache) = caches.entry(key).or_insert_with(|| {
                (
                    Arc::downgrade(&self.identity),
                    warm_cache(&self.vm, &self.warmer),
                )
            });
            self.vm.is_match(cache, text)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_regex_matches_concurrently() {
        let regex = ThreadRegex::new("^[a-z]+$").unwrap();
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let regex = &regex;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..20 {
                        assert!(regex.is_match("example"));
                        assert!(!regex.is_match("123"));
                    }
                });
            }
        });
    }
}
