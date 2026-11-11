//! Compiled CoreDNS-style query log formats.

use std::{fmt::Write, net::SocketAddr, time::Duration};

use pharos_proto::{Message, NameRef, Opcode, Rcode, Rdata};
use pharos_server::{Context, Outcome, Protocol, response_limit};

/// CoreDNS's default query log format.
pub const COMMON_LOG_FORMAT: &str = "{remote}:{port} - {>id} \"{type} {class} {name} {proto} {size} {>do} {>bufsize}\" {rcode} {>rflags} {rsize} {duration}";
/// The common format with the numeric query opcode appended.
pub const COMBINED_LOG_FORMAT: &str = "{remote}:{port} - {>id} \"{type} {class} {name} {proto} {size} {>do} {>bufsize}\" {rcode} {>rflags} {rsize} {duration} \"{>opcode}\"";

#[derive(Clone, Debug)]
enum Part {
    Literal(String),
    Metadata(String),
    Type,
    Name,
    Class,
    Proto,
    Size,
    Remote,
    Port,
    Local,
    Id,
    Opcode,
    Do,
    Bufsize,
    Rcode,
    Rsize,
    Duration,
    Rflags,
}

/// A parsed format, reusable across requests and safe to share between threads.
#[derive(Clone, Debug)]
pub struct Format {
    parts: Vec<Part>,
}

impl Format {
    /// Expand the log shortcuts and compile known labels. Unknown labels stay literal.
    #[must_use]
    pub fn compile(format: &str) -> Self {
        let expanded = format
            .replace("{common}", COMMON_LOG_FORMAT)
            .replace("{combined}", COMBINED_LOG_FORMAT);
        let mut remaining = expanded.as_str();
        let mut parts = Vec::new();
        while let Some(end) = remaining.find('}') {
            let Some(start) = remaining[..end].rfind('{') else {
                parts.push(Part::Literal(remaining[..=end].to_owned()));
                remaining = &remaining[end + 1..];
                continue;
            };
            let label = &remaining[start..=end];
            let part = match label {
                "{type}" => Some(Part::Type),
                "{name}" => Some(Part::Name),
                "{class}" => Some(Part::Class),
                "{proto}" => Some(Part::Proto),
                "{size}" => Some(Part::Size),
                "{remote}" => Some(Part::Remote),
                "{port}" => Some(Part::Port),
                "{local}" => Some(Part::Local),
                "{>id}" => Some(Part::Id),
                "{>opcode}" => Some(Part::Opcode),
                "{>do}" => Some(Part::Do),
                "{>bufsize}" => Some(Part::Bufsize),
                "{rcode}" => Some(Part::Rcode),
                "{rsize}" => Some(Part::Rsize),
                "{duration}" => Some(Part::Duration),
                "{>rflags}" => Some(Part::Rflags),
                _ if label.starts_with("{/") => {
                    Some(Part::Metadata(label[2..label.len() - 1].to_owned()))
                }
                _ => None,
            };
            if let Some(part) = part {
                if start != 0 {
                    parts.push(Part::Literal(remaining[..start].to_owned()));
                }
                parts.push(part);
            } else {
                parts.push(Part::Literal(remaining[..=end].to_owned()));
            }
            remaining = &remaining[end + 1..];
        }
        if !remaining.is_empty() {
            parts.push(Part::Literal(remaining.to_owned()));
        }
        Self { parts }
    }

    /// Append a formatted entry to `output`, without clearing it.
    ///
    /// Formatting allocates only if `output` needs to grow. Deferred server
    /// errors are represented as the response the listener will synthesize.
    /// `{local}` uses the Listener address in the context.
    pub fn format(
        &self,
        output: &mut String,
        cx: &Context<'_, '_>,
        outcome: Outcome,
        elapsed: Duration,
    ) {
        let response = self
            .parts
            .iter()
            .any(|part| matches!(part, Part::Rcode | Part::Rsize | Part::Rflags))
            .then(|| response(cx, outcome));
        for part in &self.parts {
            match part {
                Part::Literal(value) => output.push_str(value),
                Part::Metadata(key) => output.push_str(cx.metadata.get(key).unwrap_or("-")),
                Part::Type => {
                    if let Some(question) = cx.query.questions().next() {
                        let _ = write!(output, "{}", question.qtype);
                    }
                }
                Part::Class => {
                    if let Some(question) = cx.query.questions().next() {
                        let _ = write!(output, "{}", question.qclass);
                    }
                }
                Part::Name => {
                    if let Some(question) = cx.query.questions().next() {
                        let start = output.len();
                        let _ = write!(output, "{}", question.name);
                        output[start..].make_ascii_lowercase();
                    } else {
                        output.push('.');
                    }
                }
                Part::Proto => output.push_str(match cx.protocol {
                    Protocol::Udp => "udp",
                    Protocol::Tcp => "tcp",
                }),
                Part::Size => {
                    let _ = write!(output, "{}", message_len(cx.query));
                }
                Part::Remote => match cx.client {
                    SocketAddr::V4(addr) => {
                        let _ = write!(output, "{}", addr.ip());
                    }
                    SocketAddr::V6(addr) => {
                        let _ = write!(output, "[{}", addr.ip());
                        if addr.scope_id() != 0 {
                            let _ = write!(output, "%{}", addr.scope_id());
                        }
                        output.push(']');
                    }
                },
                Part::Port => {
                    let _ = write!(output, "{}", cx.client.port());
                }
                // shortcut: wildcard addresses lack a destination IP, until Listener tracking is added.
                Part::Local => match cx.local {
                    SocketAddr::V4(addr) => {
                        let _ = write!(output, "{}", addr.ip());
                    }
                    SocketAddr::V6(addr) => {
                        let _ = write!(output, "[{}", addr.ip());
                        if addr.scope_id() != 0 {
                            let _ = write!(output, "%{}", addr.scope_id());
                        }
                        output.push(']');
                    }
                },
                Part::Id => {
                    let _ = write!(output, "{}", cx.query.id());
                }
                Part::Opcode => {
                    let _ = write!(output, "{}", cx.query.opcode().0);
                }
                Part::Do => {
                    let _ = write!(
                        output,
                        "{}",
                        cx.query.opt().is_some_and(|opt| opt.dnssec_ok())
                    );
                }
                Part::Bufsize => {
                    let _ = write!(output, "{}", response_limit(cx.query, cx.protocol));
                }
                Part::Rcode => {
                    if let Some(code) = response.and_then(|r| r.code) {
                        let _ = write!(output, "{code}");
                    } else {
                        output.push('-');
                    }
                }
                Part::Rsize => {
                    let _ = write!(output, "{}", response.map_or(0, |r| r.size));
                }
                Part::Duration => {
                    let _ = write!(output, "{}s", elapsed.as_secs_f64());
                }
                Part::Rflags => {
                    if let Some(flags) = response.and_then(|r| r.flags) {
                        append_flags(output, flags);
                    } else {
                        output.push('-');
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Response {
    code: Option<Rcode>,
    flags: Option<u16>,
    size: usize,
}

fn response(cx: &Context<'_, '_>, outcome: Outcome) -> Response {
    let deferred = match outcome {
        Outcome::Error(_) => Some(Rcode::SERVFAIL),
        Outcome::Unanswered(code)
            if matches!(
                code,
                Rcode::SERVFAIL | Rcode::REFUSED | Rcode::FORMERR | Rcode::NOTIMP
            ) =>
        {
            Some(code)
        }
        _ => None,
    };
    if let Some(code) = deferred {
        let flags = 0x8000
            | (cx.query.flags() & 0x7800)
            | if cx.query.opcode() == Opcode::QUERY {
                cx.query.flags() & 0x0110
            } else {
                0
            };
        let size = 12
            + cx.query
                .questions()
                .next()
                .map_or(0, |q| name_len(q.name) + 4)
            + usize::from(cx.query.opt().is_some()) * 11;
        return Response {
            code: Some(code),
            flags: Some(flags),
            size,
        };
    }
    if outcome == Outcome::Response {
        return match Message::parse(cx.response) {
            Ok(message) => Response {
                code: Some(message.rcode()),
                flags: Some(message.flags()),
                size: message_len(message),
            },
            Err(_) => Response {
                code: None,
                flags: None,
                size: cx.response.len(),
            },
        };
    }
    Response {
        code: None,
        flags: None,
        size: 0,
    }
}

fn append_flags(output: &mut String, flags: u16) {
    let mut separator = "";
    for (mask, label) in [
        (0x8000, "qr"),
        (0x0400, "aa"),
        (0x0200, "tc"),
        (0x0100, "rd"),
        (0x0080, "ra"),
        (0x0040, "z"),
        (0x0020, "ad"),
        (0x0010, "cd"),
    ] {
        if flags & mask != 0 {
            output.push_str(separator);
            output.push_str(label);
            separator = ",";
        }
    }
}

fn name_len(name: NameRef<'_>) -> usize {
    1 + name.labels().map(|label| label.len() + 1).sum::<usize>()
}

fn message_len(message: Message<'_>) -> usize {
    let questions = message
        .questions()
        .map(|q| name_len(q.name) + 4)
        .sum::<usize>();
    let records = message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .map(|record| {
            let mut size = record.rdata.len();
            let mut expand = |name: NameRef<'_>| {
                size = size - name.wire_len() + name_len(name);
            };
            match record.data() {
                Ok(Rdata::Ns(name) | Rdata::Cname(name) | Rdata::Ptr(name)) => expand(name),
                Ok(Rdata::Mx { exchange, .. }) => expand(exchange),
                Ok(Rdata::Soa { mname, rname, .. }) => {
                    expand(mname);
                    expand(rname);
                }
                Ok(
                    Rdata::Srv { target, .. }
                    | Rdata::Svcb { target, .. }
                    | Rdata::Https { target, .. },
                ) => expand(target),
                Ok(Rdata::Naptr { replacement, .. }) => expand(replacement),
                Ok(Rdata::Rrsig { signer, .. }) => expand(signer),
                Ok(Rdata::Nsec { next, .. }) => expand(next),
                Ok(Rdata::Tsig { algorithm, .. }) => expand(algorithm),
                // shortcut: unsupported or malformed name-bearing RDATA stays encoded; extend pharos-proto to decode it.
                _ => {}
            }
            name_len(record.name) + 10 + size
        })
        .sum::<usize>();
    12 + questions + records
}
