//! Modify DNS header flags in Queries and Responses.

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
        cx.query = cx.query.with_flags(self.query.apply(cx.query.flags()));
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response && cx.response.len() >= 4 {
            let flags = u16::from_be_bytes([cx.response[2], cx.response[3]]);
            cx.response[2..4].copy_from_slice(&self.response.apply(flags).to_be_bytes());
        }
        outcome
    }
}
