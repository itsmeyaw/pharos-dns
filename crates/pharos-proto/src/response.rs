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
            return ResponseType::OtherError;
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
    } else if rcode == Rcode::SERVFAIL || rcode == Rcode::NOTIMP {
        ResponseType::ServerError
    } else if ns && rcode == Rcode::NOERROR {
        ResponseType::Referral
    } else if rcode == Rcode::NOERROR {
        ResponseType::Positive
    } else {
        ResponseType::OtherError
    }
}

fn signature_valid(inception: u32, expiration: u32, now: i64) -> bool {
    let expiration = i128::from(expiration);
    let inception = i128::from(inception);
    let now = i128::from(now);
    let adjust = |time: i128| time + ((time - now) / (1_i128 << 31)) * (1_i128 << 31);
    adjust(inception) <= now && now <= adjust(expiration)
}
