//! NSID Directive.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error as CorefileError};
use pharos_proto::{EdnsOption, Message, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Nsid {
    data: Vec<u8>,
}

impl Nsid {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, CorefileError> {
        let mut data = nix::unistd::gethostname()
            .ok()
            .map(|value| value.into_encoded_bytes())
            .unwrap_or_else(|| b"localhost".to_vec());
        if cursor.next() {
            let args = cursor.remaining_args();
            if !args.is_empty() {
                data = args.join(" ").into_bytes();
            }
        }
        if cursor.next() {
            return Err(cursor.error("nsid can only be used once"));
        }
        Ok(Self { data })
    }
}

impl Plugin for Nsid {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        // RFC 5001 §2.2: return NSID only when the Query contains the NSID option.
        let requested = cx.query.opt().is_some_and(|opt| {
            opt.options()
                .iter()
                .any(|option| matches!(option, EdnsOption::Nsid(_)))
        });
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response
            && let Err(error) = update_nsid(cx, requested.then_some(self.data.as_slice()))
        {
            return Outcome::Error(error);
        }
        outcome
    }
}

fn update_nsid(cx: &mut Context<'_, '_>, data: Option<&[u8]>) -> Result<(), Error> {
    let message = Message::parse(cx.response).map_err(|_| Error::InvalidQuery)?;
    // RFC 5001 §2.2: an NSID from Next must not reach a client that did not request it.
    if data.is_none()
        && !message.opt().is_some_and(|opt| {
            opt.options()
                .iter()
                .any(|option| matches!(option, EdnsOption::Nsid(_)))
        })
    {
        return Ok(());
    }
    let record = message
        .additionals()
        .enumerate()
        .find(|(_, record)| record.rtype == Type::OPT);
    let mut options = [0u8; 65535];
    let mut len = 0;
    let mut found = false;
    if let Some((_, record)) = record {
        let mut remaining = record.rdata;
        while !remaining.is_empty() {
            let code = u16::from_be_bytes([remaining[0], remaining[1]]);
            let size = usize::from(u16::from_be_bytes([remaining[2], remaining[3]])) + 4;
            let option = &remaining[..size];
            if code == 3 {
                if let Some(data) = data {
                    append_option(&mut options, &mut len, data)?;
                }
                found = true;
            } else {
                let end = len
                    .checked_add(size)
                    .filter(|end| *end <= options.len())
                    .ok_or(Error::ResponseBufferTooSmall)?;
                options[len..end].copy_from_slice(option);
                len = end;
            }
            remaining = &remaining[size..];
        }
    }
    if !found && let Some(data) = data {
        append_option(&mut options, &mut len, data)?;
    }
    // RFC 6891 §6.1.2: OPT RDLENGTH is the combined length of its options.
    let len_wire = u16::try_from(len).map_err(|_| Error::ResponseBufferTooSmall)?;
    let (start, old_end) = record.map_or((cx.response.len(), cx.response.len()), |(_, rr)| {
        (rr.rdata_offset, rr.rdata_offset + rr.rdata.len())
    });
    // RFC 1035 §4.2.2: The two-byte TCP length prefix caps a message at 65535 octets.
    let new_len = start
        .checked_add(len + if record.is_none() { 11 } else { 0 })
        .filter(|n| *n <= 65535 && *n <= cx.response.capacity())
        .ok_or(Error::ResponseBufferTooSmall)?;
    if record.is_none() {
        let count = message
            .additional_count()
            .checked_add(1)
            .ok_or(Error::ResponseBufferTooSmall)?;
        let size = cx
            .query
            .opt()
            .ok_or(Error::InvalidQuery)?
            .udp_payload_size();
        // RFC 6891 §6.1.2: Encode OPT owner, type, class, and option data in wire fields.
        cx.response.extend_from_slice(&[0, 0, 41]);
        cx.response.extend_from_slice(&size.to_be_bytes());
        // RFC 6891 §6.1.3: Set EDNS extended RCODE and version fields to zero.
        cx.response.extend_from_slice(&0x8000_u32.to_be_bytes());
        cx.response.extend_from_slice(&len_wire.to_be_bytes());
        cx.response.extend_from_slice(&options[..len]);
        cx.response[10..12].copy_from_slice(&count.to_be_bytes());
    } else {
        let (index, _) = record.ok_or(Error::InvalidQuery)?;
        if old_end < cx.response.len() {
            // shortcut: records after OPT are dropped; re-encode the Message to retain them.
            // RFC 1035 §4.1.4: removing later records avoids invalidating compression pointers.
            // RFC 1035 §4.1.1: Set TC when truncating the response.
            cx.response[2] |= 0x02;
            cx.response[10..12].copy_from_slice(&((index + 1) as u16).to_be_bytes());
        }
        if new_len > cx.response.len() {
            cx.response.resize(new_len, 0);
        }
        cx.response.truncate(new_len);
        cx.response[start - 2..start].copy_from_slice(&len_wire.to_be_bytes());
        cx.response[start..start + len].copy_from_slice(&options[..len]);
    }
    Ok(())
}

fn append_option(options: &mut [u8], len: &mut usize, data: &[u8]) -> Result<(), Error> {
    let end = len
        .checked_add(4)
        .and_then(|n| n.checked_add(data.len()))
        .filter(|end| *end <= options.len())
        .ok_or(Error::ResponseBufferTooSmall)?;
    let size = u16::try_from(data.len()).map_err(|_| Error::ResponseBufferTooSmall)?;
    // RFC 5001 §2.3: NSID is EDNS option code 3 with an opaque byte payload.
    options[*len..*len + 2].copy_from_slice(&3_u16.to_be_bytes());
    options[*len + 2..*len + 4].copy_from_slice(&size.to_be_bytes());
    // RFC 5001 §2.4: Copy NSID payload bytes without assuming null termination.
    options[*len + 4..end].copy_from_slice(data);
    *len = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_proto::Name;
    use pharos_server::{Metadata, Protocol, Transport};

    struct Return(Outcome);

    impl Next for Return {
        async fn run(self, _cx: &mut Context<'_, '_>) -> Outcome {
            self.0
        }
    }

    #[tokio::test]
    async fn strips_unsolicited_nsid_and_preserves_other_options() {
        let query = [
            0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut response = Vec::with_capacity(512);
        response.extend_from_slice(&[
            0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 10, 0, 3, 0, 1,
            1, 0, 12, 0, 1, 9,
        ]);
        let domain: Name = ".".parse().unwrap();
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:53".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let plugin = Nsid {
            data: b"NSID".to_vec(),
        };
        assert_eq!(
            plugin.serve(&mut cx, Return(Outcome::Response)).await,
            Outcome::Response
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(
            message.opt().unwrap().options().iter().collect::<Vec<_>>(),
            [EdnsOption::Padding(&[9])]
        );
    }

    #[tokio::test]
    async fn preserves_nonresponse_outcomes() {
        let query = [
            0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
        ];
        let domain: Name = ".".parse().unwrap();
        let plugin = Nsid {
            data: b"NSID".to_vec(),
        };
        for outcome in [
            Outcome::Drop,
            Outcome::Unanswered(pharos_proto::Rcode::REFUSED),
            Outcome::Error(Error::NoNextPlugin),
            Outcome::Stream(pharos_server::Stream::new(|_| Ok(false))),
        ] {
            let mut response = Vec::with_capacity(512);
            let mut slots = [];
            let mut cx = Context {
                query: Message::parse(&query).unwrap(),
                client: "127.0.0.1:53".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: Transport::Dns,
                protocol: Protocol::Udp,
                domain: &domain,
                metadata: Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            assert_eq!(
                plugin.serve(&mut cx, Return(outcome.clone())).await,
                outcome
            );
            assert!(response.is_empty());
        }
    }

    #[test]
    fn replaces_all_existing_nsid_options_and_preserves_others() {
        let query = [
            0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
        ];
        let mut response = Vec::with_capacity(512);
        response.extend_from_slice(&[
            0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 15, 0, 3, 0, 1,
            1, 0, 12, 0, 1, 9, 0, 3, 0, 1, 2,
        ]);
        let domain: Name = ".".parse().unwrap();
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:53".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        update_nsid(&mut cx, Some(b"NSID")).unwrap();
        let message = Message::parse(&response).unwrap();
        assert_eq!(
            message.opt().unwrap().options().iter().collect::<Vec<_>>(),
            [
                EdnsOption::Nsid(b"NSID"),
                EdnsOption::Padding(&[9]),
                EdnsOption::Nsid(b"NSID")
            ]
        );
    }

    #[test]
    fn rejects_oversized_identifier_without_mutating_response() {
        let query = [
            0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
        ];
        let mut response = Vec::with_capacity(65535);
        response.extend_from_slice(&[0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let original = response.clone();
        let domain: Name = ".".parse().unwrap();
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:53".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            update_nsid(&mut cx, Some(&vec![b'x'; 65535])),
            Err(Error::ResponseBufferTooSmall)
        );
        assert_eq!(response, original);
    }

    #[test]
    fn truncates_records_after_opt_before_replacing_nsid() {
        let query = [
            0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
        ];
        let mut response = Vec::with_capacity(512);
        response.extend_from_slice(&[
            0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0,
            1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1,
        ]);
        let domain: Name = ".".parse().unwrap();
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:53".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        update_nsid(&mut cx, Some(b"NSID")).unwrap();
        let message = Message::parse(&response).unwrap();
        assert!(message.tc());
        assert_eq!(message.additional_count(), 1);
        assert_eq!(
            message.opt().unwrap().options().iter().next(),
            Some(EdnsOption::Nsid(b"NSID"))
        );
    }
}
