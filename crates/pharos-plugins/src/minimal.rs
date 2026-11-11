//! Remove unnecessary sections from positive Responses.

use pharos_proto::{Message, NameRef, NameWirePart, ResponseType, typify_response};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Minimal;

fn references_counts(name: NameRef<'_>) -> bool {
    name.wire_parts().any(|part| match part {
        NameWirePart::Label { offset, len } => offset < 12 && offset + len > 8,
        NameWirePart::Root { offset } | NameWirePart::Pointer { offset, .. } => {
            (8..12).contains(&offset)
        }
    })
}

impl Plugin for Minimal {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let outcome = next.run(cx).await;
        if outcome != Outcome::Response {
            return outcome;
        }
        let Ok(message) = Message::parse(cx.response) else {
            return outcome;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs() as i64);
        if typify_response(Some(&message), now) != ResponseType::Positive {
            return outcome;
        }
        // RFC 1035 §4.1.4: changing header counts must not alter compressed names.
        // shortcut: retain unsafe encodings until Responses can be re-encoded without allocation.
        if message
            .questions()
            .any(|question| references_counts(question.name))
            || message.answers().any(|record| {
                references_counts(record.name)
                    || record.compressible_names().map_or(true, |names| {
                        names.into_iter().flatten().any(references_counts)
                    })
            })
        {
            return outcome;
        }
        // RFC 1035 §4.1.1: section counts describe the records in each Message section.
        let end = message
            .authorities()
            .next()
            .or_else(|| message.additionals().next())
            .map_or(cx.response.len(), |record| record.name.offset());
        cx.response.truncate(end);
        cx.response[8..12].fill(0);
        outcome
    }
}
