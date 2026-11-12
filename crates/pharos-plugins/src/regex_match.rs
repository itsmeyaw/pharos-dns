use regex_automata::nfa::thompson::{
    Builder, NFA, State, WhichCaptures,
    pikevm::{Cache, PikeVM},
};
use std::sync::Mutex;

#[derive(Debug)]
pub(crate) struct Regex {
    vm: PikeVM,
    cache: Mutex<Cache>,
}

impl Regex {
    pub(crate) fn new(pattern: &str) -> Result<Self, String> {
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
        let mut cache = warmer.create_cache();
        let _ = warmer.is_match(&mut cache, "");
        cache.reset(&vm);
        let cache = Mutex::new(cache);
        drop(cache.lock().expect("new regex cache"));
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
