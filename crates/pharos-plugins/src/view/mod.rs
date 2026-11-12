//! Server Block selection using compiled expressions.

pub(crate) mod setup;

use crate::expression::{Expression, Query, Scratch, Value};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::cell::RefCell;

thread_local! {
    static SCRATCH: RefCell<[u8; 65_535]> = const { RefCell::new([0; 65_535]) };
}

pub struct View {
    pub name: String,
    pub expressions: Vec<Expression>,
}

impl View {
    /// Return whether every expression evaluates to boolean true.
    pub fn matches(&self, cx: &Context<'_, '_>) -> bool {
        let query = Query::new(&cx.query, cx.client, cx.local, cx.protocol);
        SCRATCH.with(|storage| {
            let Ok(mut storage) = storage.try_borrow_mut() else {
                return false;
            };
            let mut scratch = Scratch::new(&mut *storage);
            self.expressions.iter().all(|expression| {
                matches!(
                    expression.evaluate(&query, &cx.metadata, &mut scratch),
                    Ok(Value::Bool(true))
                )
            })
        })
    }
}

impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("View")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Plugin for View {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
