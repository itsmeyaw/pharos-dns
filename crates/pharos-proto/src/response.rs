use crate::{Message, Opcode, Rcode, Rdata, Type};

/// CoreDNS's classification of a Response, using Pharos's DNS terminology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseType {
    Positive,
    NxDomain,
    ServerError,
    NoData,
    Referral,
    Meta,
    Update,
    OtherError,
}

/// A grouping of Response Types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseClass {
    Success,
    Denial,
    Error,
}

/// Groups a Response Type into its Response Class.
#[must_use]
pub const fn classify_response(response_type: ResponseType) -> ResponseClass {
    match response_type {
        ResponseType::Positive | ResponseType::Referral => ResponseClass::Success,
        ResponseType::NxDomain | ResponseType::NoData => ResponseClass::Denial,
        _ => ResponseClass::Error,
    }
}

// RFC 2308 §2: classify NXDOMAIN and NODATA as CoreDNS does.
/// Classifies a Response at a Unix timestamp in seconds.
#[must_use]
pub fn typify_response(message: Option<&Message<'_>>, now: i64) -> ResponseType {
    let Some(message) = message else {
        return ResponseType::OtherError;
    };
    if message.opcode() == Opcode::UPDATE {
        return ResponseType::Update;
    }
    if message.opcode() == Opcode::NOTIFY
        || message
            .questions()
            .next()
            .is_some_and(|q| matches!(q.qtype, Type::AXFR | Type::IXFR))
    {
        return ResponseType::Meta;
    }
    if message.opt().is_some_and(|opt| opt.dnssec_ok())
        && message
            .answers()
            .chain(message.authorities())
            .chain(message.additionals())
            .filter(|rr| rr.rtype == Type::RRSIG)
            .any(|rr| match rr.data() {
                Ok(Rdata::Rrsig {
                    expiration,
                    inception,
                    ..
                }) => !signature_valid(inception, expiration, now),
                _ => true,
            })
    {
        return ResponseType::OtherError;
    }
    let rcode = message.rcode();
    if message.answer_count() > 0 {
        if rcode == Rcode::NOERROR {
            return ResponseType::Positive;
        }
        if rcode == Rcode::NXDOMAIN {
            // RFC 6604 §3: a final CNAME-chain response may carry NXDOMAIN and CNAME answers.
            let mut has_cname = false;
            let mut is_cname_chain = true;
            for rr in message.answers() {
                has_cname |= rr.rtype == Type::CNAME;
                is_cname_chain &= matches!(rr.rtype, Type::CNAME | Type::RRSIG);
            }
            return if has_cname && is_cname_chain {
                ResponseType::NxDomain
            } else {
                ResponseType::OtherError
            };
        }
    }
    let mut soa = false;
    let mut ns = false;
    for rr in message.authorities() {
        soa |= rr.rtype == Type::SOA;
        ns |= rr.rtype == Type::NS;
    }
    if soa && rcode == Rcode::NOERROR {
        ResponseType::NoData
    } else if rcode == Rcode::NXDOMAIN {
        ResponseType::NxDomain
    } else if matches!(rcode, Rcode::SERVFAIL | Rcode::NOTIMP | Rcode::REFUSED) {
        // RFC 9520 §§2.2, 3.2: REFUSED is a cacheable resolution failure.
        ResponseType::ServerError
    } else if ns && rcode == Rcode::NOERROR {
        ResponseType::Referral
    } else if rcode == Rcode::NOERROR {
        ResponseType::Positive
    } else {
        ResponseType::OtherError
    }
}

// RFC 4034 §3.1.5 and RFC 1982 §3.2: compare RRSIG times with 32-bit serial arithmetic.
fn signature_valid(inception: u32, expiration: u32, now: i64) -> bool {
    // RFC 1982 §3.2: reduce Unix time to the 32-bit RRSIG serial space before comparison.
    let now = now as u32;
    let before_or_equal =
        |left: u32, right: u32| left == right || right.wrapping_sub(left) < (1_u32 << 31);
    before_or_equal(inception, now) && before_or_equal(now, expiration)
}
