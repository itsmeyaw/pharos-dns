//! Modify DNS header flags in Queries and Responses.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug, Default)]
struct Rules {
    set: u16,
    clear: u16,
}

impl Rules {
    fn add(&mut self, flag: u16, set: bool) {
        if set {
            self.set |= flag;
            self.clear &= !flag;
        } else {
            self.clear |= flag;
            self.set &= !flag;
        }
    }

    fn apply(&self, flags: u16) -> u16 {
        (flags | self.set) & !self.clear
    }
}

#[derive(Debug, Default)]
pub struct Header {
    query: Rules,
    response: Rules,
}

impl Header {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        while cursor.next() {
            let mut header = Self::default();
            let _ = cursor.remaining_args();
            let mut any = false;
            while cursor.next_block() {
                let rules = if cursor.val().eq_ignore_ascii_case("query") {
                    &mut header.query
                } else if cursor.val().eq_ignore_ascii_case("response") {
                    &mut header.response
                } else {
                    return Err(cursor.error("invalid header selector"));
                };
                let args = cursor.remaining_args();
                if args.len() < 2 {
                    return Err(cursor.arg_err());
                }
                let set = if args[0].eq_ignore_ascii_case("set") {
                    true
                } else if args[0].eq_ignore_ascii_case("clear") {
                    false
                } else {
                    return Err(cursor.error("invalid header action"));
                };
                for flag in &args[1..] {
                    // RFC 1035 §4.1.1: AA, RD and RA occupy these header bits.
                    let bit = if flag.eq_ignore_ascii_case("aa") {
                        0x0400
                    } else if flag.eq_ignore_ascii_case("rd") {
                        0x0100
                    } else if flag.eq_ignore_ascii_case("ra") {
                        0x0080
                    } else {
                        return Err(cursor.error("unsupported header flag"));
                    };
                    rules.add(bit, set);
                    any = true;
                }
            }
            if any {
                return Ok(header);
            }
        }
        Err(cursor.arg_err())
    }
}

impl Plugin for Header {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let original_rd = cx.query.flags() & 0x0100;
        let query_flags = self.query.apply(cx.query.flags());
        // RFC 1035 §4.1.1: a rule cannot set AA in a Query.
        let query_flags = if self.query.set & 0x0400 != 0 {
            query_flags & !0x0400
        } else {
            query_flags
        };
        cx.query = cx.query.with_flags(query_flags);
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response && cx.response.len() >= 4 {
            let original_flags = u16::from_be_bytes([cx.response[2], cx.response[3]]);
            let flags = self.response.apply(original_flags);
            // RFC 1035 §4.1.1: a rule cannot add AA to a non-authoritative Response.
            let flags = if self.response.set & 0x0400 != 0 && original_flags & 0x0400 == 0 {
                flags & !0x0400
            } else {
                flags
            };
            // RFC 1035 §4.1.1: Response RD copies the received Query, not rewritten flags.
            let flags = (flags & !0x0100) | original_rd;
            cx.response[2..4].copy_from_slice(&flags.to_be_bytes());
        }
        outcome
    }
}
