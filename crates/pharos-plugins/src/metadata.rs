//! Per-Query Metadata collection.

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::Name;
#[cfg(feature = "plugin-kubernetes")]
use pharos_proto::NameRef;
use pharos_server::{Context, Next, Outcome, Plugin};

/// Whether a label has a nonempty prefix and suffix around its first slash.
#[must_use]
pub fn is_label(label: &str) -> bool {
    label
        .find('/')
        .is_some_and(|index| index > 0 && index + 1 < label.len())
}

#[derive(Debug)]
pub struct Metadata {
    pub domains: Vec<Name>,
}

impl Metadata {
    #[cfg(feature = "plugin-kubernetes")]
    pub(crate) fn matches(&self, cx: &Context<'_>) -> bool {
        let Some(question) = cx.query.questions().next() else {
            return false;
        };
        let count = question.name.labels().count();
        self.domains.iter().any(|domain| {
            let n = domain.label_count();
            // RFC 4343 §3: DNS label comparisons ignore ASCII letter case.
            count >= n
                && question
                    .name
                    .labels()
                    .skip(count - n)
                    .zip(NameRef::parse(domain.as_wire(), 0).unwrap().labels())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
    }
}

pub(crate) fn parse(cursor: &mut Cursor<'_>, domains: &[&str]) -> Result<Metadata, Error> {
    cursor.next();
    let args = cursor.remaining_args();
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let domains = origins_from_args_or_server_block(&args, domains)
        .iter()
        .filter_map(|domain| domain.parse().ok())
        .collect();
    if cursor.next_block() || cursor.next() {
        return Err(cursor.arg_err());
    }
    Ok(Metadata { domains })
}

impl Plugin for Metadata {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
