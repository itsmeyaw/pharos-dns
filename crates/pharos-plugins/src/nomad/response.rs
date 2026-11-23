//! The Response to a Nomad Query, built the way CoreDNS v1.15.0 plugin/nomad/nomad.go and helpers.go build it.

use std::net::{IpAddr, Ipv4Addr};

use pharos_proto::{Class, MessageBuilder, NameRef, Question, Section, Type};
use pharos_server::Error;

use super::registration::Registration;

/// What every Response of one Query shares.
pub(super) struct Reply<'a> {
    pub(super) id: u16,
    /// QR, AA, the Query's opcode, RD and CD; the RCODE bits are clear.
    pub(super) flags: u16,
    pub(super) max_size: usize,
    pub(super) question: Question<'a>,
    /// The lower-cased wire name of the Query: the owner of Additional records, the SRV target and the SOA owner.
    pub(super) owner: &'a [u8],
    pub(super) ttl: u32,
    /// The wire name `hostmaster.<zone>`.
    pub(super) mailbox: &'a [u8],
}

// RFC 2782 §2: the SRV priority and weight CoreDNS v1.15.0 plugin/nomad/helpers.go addSRVRecord hard-codes.
const PRIORITY: u16 = 10;
const WEIGHT: u16 = 10;

fn ipv4(address: IpAddr) -> Option<Ipv4Addr> {
    // Go net.IP.To4: an IPv4-mapped IPv6 address counts as IPv4.
    match address {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(address) => address.to_ipv4_mapped(),
    }
}

/// `registrations` is `None` when the lookup failed. Returns whether the Response is a success: a failed lookup and an NXDOMAIN answer are not.
pub(super) fn build(
    out: &mut Vec<u8>,
    reply: &Reply<'_>,
    registrations: Option<&[Registration]>,
) -> Result<bool, Error> {
    let qtype = reply.question.qtype;
    let (served, denied) = match registrations {
        // CoreDNS nomad.go handleServiceLookupError: NOERROR, authoritative, no records.
        None => (&[][..], false),
        Some(registrations) => {
            // CoreDNS nomad.go addServiceResponses: records are added until a registration fails, then the Response becomes NXDOMAIN; an unsupported QTYPE fails the first.
            let usable = if qtype == Type::A || qtype == Type::AAAA || qtype == Type::SRV {
                registrations
                    .iter()
                    .take_while(|registration| registration.address.is_some())
                    .count()
            } else {
                0
            };
            // CoreDNS nomad.go ServeDNS: no registrations at all is NXDOMAIN too.
            (
                &registrations[..usable],
                usable < registrations.len() || registrations.is_empty(),
            )
        }
    };
    let owner = NameRef::parse(reply.owner, 0).map_err(|_| Error::InvalidQuery)?;
    // RFC 1035 §4.1.1: RCODE 3 is a name error.
    let flags = reply.flags | if denied { 3 } else { 0 };
    let mut builder =
        MessageBuilder::new(out, reply.max_size, reply.id, flags).map_err(Error::Build)?;
    // RFC 1035 §4.1.2: the Response repeats the question.
    let question = reply.question;
    builder
        .question(question.name, question.qtype, question.qclass)
        .map_err(Error::Build)?;
    for registration in served {
        let Some(address) = registration.address else {
            continue;
        };
        let v4 = ipv4(address);
        if qtype == Type::A {
            // RFC 1035 §3.4.1: A RDATA is a 32-bit address.
            if let Some(address) = v4 {
                builder.record(
                    Section::Answer,
                    question.name,
                    qtype,
                    Class::IN,
                    reply.ttl,
                    &address.octets(),
                )
            } else {
                Ok(true)
            }
        } else if qtype == Type::AAAA {
            // RFC 3596 §2.2: AAAA RDATA is a 128-bit address.
            match (v4, address) {
                (None, IpAddr::V6(address)) => builder.record(
                    Section::Answer,
                    question.name,
                    qtype,
                    Class::IN,
                    reply.ttl,
                    &address.octets(),
                ),
                _ => Ok(true),
            }
        } else {
            // RFC 2782 §2: SRV RDATA is priority, weight, port and target; the target is not compressed.
            builder.record_with(
                Section::Answer,
                question.name,
                qtype,
                Class::IN,
                reply.ttl,
                |writer| {
                    writer.write_bytes(&PRIORITY.to_be_bytes())?;
                    writer.write_bytes(&WEIGHT.to_be_bytes())?;
                    writer.write_bytes(&registration.port.to_be_bytes())?;
                    writer.write_uncompressed_name(owner)
                },
            )
        }
        .map_err(Error::Build)?;
    }
    if denied {
        soa(&mut builder, reply, owner)?;
    }
    if qtype == Type::SRV {
        // RFC 2782 §3: the Additional section carries the address of each target.
        for registration in served {
            let Some(address) = registration.address else {
                continue;
            };
            match ipv4(address) {
                Some(address) => builder.record(
                    Section::Additional,
                    owner,
                    Type::A,
                    Class::IN,
                    reply.ttl,
                    &address.octets(),
                ),
                None => match address {
                    IpAddr::V6(address) => builder.record(
                        Section::Additional,
                        owner,
                        Type::AAAA,
                        Class::IN,
                        reply.ttl,
                        &address.octets(),
                    ),
                    IpAddr::V4(_) => Ok(true),
                },
            }
            .map_err(Error::Build)?;
        }
    }
    let _ = builder.finish();
    Ok(registrations.is_some() && !denied)
}

// CoreDNS v1.15.0 plugin/nomad/helpers.go createSOARecord, placed in the Answer section as CoreDNS does.
fn soa(
    builder: &mut MessageBuilder<'_>,
    reply: &Reply<'_>,
    owner: NameRef<'_>,
) -> Result<(), Error> {
    // RFC 1035 §2.3.4: a name is at most 255 octets; `ns1.` makes the owner four longer.
    let mut server = [0_u8; 260];
    let length = 4 + reply.owner.len();
    if length > 255 {
        return Err(Error::Internal);
    }
    server[..4].copy_from_slice(b"\x03ns1");
    server[4..length].copy_from_slice(reply.owner);
    let server = NameRef::parse(&server[..length], 0).map_err(|_| Error::Internal)?;
    let mailbox = NameRef::parse(reply.mailbox, 0).map_err(|_| Error::Internal)?;
    builder
        .record_with(
            Section::Answer,
            owner,
            Type::SOA,
            Class::IN,
            reply.ttl,
            |writer| {
                // RFC 1035 §3.3.13: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM.
                writer.write_name(server)?;
                writer.write_name(mailbox)?;
                for value in [0_u32, 3600, 600, 86400, 30] {
                    writer.write_bytes(&value.to_be_bytes())?;
                }
                Ok(())
            },
        )
        .map_err(Error::Build)?;
    Ok(())
}
