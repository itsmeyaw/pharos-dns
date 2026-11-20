//! DNS-01 challenge state (RFC 8555 §8.4) and the Plugin that answers `_acme-challenge` TXT Queries from it.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use pharos_proto::{Class, MessageBuilder, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Protocol};

/// The TXT values to publish, by owner name, each with the number of challenges that need it.
#[derive(Debug, Default)]
pub struct Solver {
    records: RwLock<HashMap<String, BTreeMap<String, usize>>>,
    // Lets the Query path skip the lock while no challenge is pending.
    active: AtomicUsize,
}

// RFC 8555 §8.4: the validation TXT record is at "_acme-challenge" below the identifier.
const LABEL: &[u8] = b"_acme-challenge";

impl Solver {
    /// Publish `value` at `name`; presenting a value twice needs two clean-ups.
    // CoreDNS v1.15.0 plugin/tls/acme.go acmeDNS01Solver.Present.
    pub fn present(&self, name: &str, value: &str) {
        let mut records = self.records.write().unwrap_or_else(|e| e.into_inner());
        *records
            .entry(normalize(name))
            .or_default()
            .entry(value.to_owned())
            .or_default() += 1;
        self.active.store(records.len(), Ordering::Release);
    }

    /// Withdraw one presentation of `value` at `name`.
    // CoreDNS v1.15.0 plugin/tls/acme.go acmeDNS01Solver.CleanUp.
    pub fn clean_up(&self, name: &str, value: &str) {
        let name = normalize(name);
        let mut records = self.records.write().unwrap_or_else(|e| e.into_inner());
        if let Some(values) = records.get_mut(&name) {
            match values.get_mut(value) {
                Some(count) if *count > 1 => *count -= 1,
                _ => {
                    values.remove(value);
                }
            }
            if values.is_empty() {
                records.remove(&name);
            }
        }
        self.active.store(records.len(), Ordering::Release);
    }

    /// The values published at `name`, sorted.
    fn values(&self, name: &str) -> Vec<String> {
        self.records
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .map(|values| values.keys().cloned().collect())
            .unwrap_or_default()
    }
}

// RFC 4343 §3: names compare without regard to ASCII case; RFC 1034 §3.1: the root label ends the name.
fn normalize(name: &str) -> String {
    let mut name = name.to_ascii_lowercase();
    if !name.ends_with('.') {
        name.push('.');
    }
    name
}

impl Solver {
    /// Answer a TXT Query for a published challenge name, or defer to Next.
    // CoreDNS v1.15.0 plugin/tls/acme.go acmeChallengeHandler.ServeDNS.
    pub(in crate::tls) async fn serve<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
    ) -> Outcome {
        if self.active.load(Ordering::Acquire) == 0 {
            return next.run(cx).await;
        }
        let mut questions = cx.query.questions();
        let (Some(question), None) = (questions.next(), questions.next()) else {
            return next.run(cx).await;
        };
        if question.qtype != Type::TXT
            || question.qclass != Class::IN
            || !question
                .name
                .labels()
                .next()
                .is_some_and(|label| label.eq_ignore_ascii_case(LABEL))
        {
            return next.run(cx).await;
        }
        let values = self.values(&question.name.to_name().canonical());
        if values.is_empty() {
            return next.run(cx).await;
        }
        let (id, flags, protocol, max) = (
            cx.query.id(),
            cx.query.flags(),
            cx.protocol,
            cx.max_response_size,
        );
        match respond(
            cx.response,
            (id, flags),
            (protocol, max),
            &question,
            &values,
        ) {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }
}

fn respond(
    response: &mut Vec<u8>,
    (id, query_flags): (u16, u16),
    (protocol, max_response_size): (Protocol, usize),
    question: &pharos_proto::Question<'_>,
    values: &[String],
) -> Result<(), Error> {
    let max = max_response_size.max(512);
    if response.capacity() < max {
        if protocol == Protocol::Tcp {
            response.reserve(max.saturating_sub(response.len()));
        } else {
            return Err(Error::ResponseBufferTooSmall);
        }
    }
    // RFC 1035 §4.1.1: QR is set and the opcode and RD are copied; RFC 1034 §4.3.2: AA marks the answer authoritative.
    let mut flags = 0x8400 | (query_flags & 0x7800);
    if query_flags & 0x7800 == 0 {
        flags |= query_flags & 0x0110;
    }
    let mut builder = MessageBuilder::new(response, max, id, flags).map_err(Error::Build)?;
    builder
        .question(question.name, question.qtype, question.qclass)
        .map_err(Error::Build)?;
    for value in values {
        // RFC 1035 §3.3.14: TXT RDATA is one or more length-prefixed character-strings of at most 255 octets.
        let len = u8::try_from(value.len())
            .map_err(|_| Error::Build(pharos_proto::BuildError::InvalidRdata))?;
        let mut rdata = Vec::with_capacity(1 + value.len());
        rdata.push(len);
        rdata.extend_from_slice(value.as_bytes());
        // CoreDNS v1.15.0 plugin/tls/acme.go: the challenge RR has TTL 0 so resolvers do not cache it.
        if !builder
            .record(
                Section::Answer,
                question.name,
                Type::TXT,
                Class::IN,
                0,
                &rdata,
            )
            .map_err(Error::Build)?
        {
            break;
        }
    }
    let _ = builder.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
    use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

    use super::Solver;
    use crate::tls::Tls;

    struct NextRefused;
    impl Next for NextRefused {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Unanswered(Rcode::NXDOMAIN)
        }
    }

    async fn query(tls: &Tls, name: &str, qtype: Type, class: Class) -> (Outcome, Vec<u8>) {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 7, 0x0100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, class)
            .unwrap();
        let _ = builder.finish();
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(65535);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = tls.serve(&mut cx, NextRefused).await;
        (outcome, response)
    }

    fn texts(wire: &[u8]) -> Vec<Vec<u8>> {
        Message::parse(wire)
            .unwrap()
            .answers()
            .map(|record| match record.data().unwrap() {
                Rdata::Txt(txt) => txt[1..].to_vec(),
                other => panic!("{other:?}"),
            })
            .collect()
    }

    // CoreDNS v1.15.0 plugin/tls/acme_test.go TestACMEDNS01ChallengeHandler.
    #[tokio::test]
    async fn challenge_is_answered_until_every_presentation_is_cleaned_up() {
        let solver = Arc::new(Solver::default());
        solver.present("_acme-challenge.dns.example.", "digest");
        solver.present("_acme-challenge.dns.example.", "digest");
        let tls = Tls::challenge_only(Arc::clone(&solver));

        let (outcome, wire) =
            query(&tls, "_ACME-CHALLENGE.DNS.EXAMPLE.", Type::TXT, Class::IN).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(texts(&wire), [b"digest".to_vec()]);
        let message = Message::parse(&wire).unwrap();
        assert!(message.aa() && message.qr());

        solver.clean_up("_acme-challenge.dns.example.", "digest");
        let (outcome, _) = query(&tls, "_acme-challenge.dns.example.", Type::TXT, Class::IN).await;
        assert_eq!(outcome, Outcome::Response, "one presentation is left");

        solver.clean_up("_acme-challenge.dns.example.", "digest");
        let (outcome, _) = query(&tls, "_acme-challenge.dns.example.", Type::TXT, Class::IN).await;
        assert_eq!(outcome, Outcome::Unanswered(Rcode::NXDOMAIN));
    }

    #[tokio::test]
    async fn distinct_values_are_answered_sorted() {
        let solver = Arc::new(Solver::default());
        solver.present("_acme-challenge.dns.example", "b");
        solver.present("_acme-challenge.dns.example", "a");
        let tls = Tls::challenge_only(solver);
        let (_, wire) = query(&tls, "_acme-challenge.dns.example.", Type::TXT, Class::IN).await;
        assert_eq!(texts(&wire), [b"a".to_vec(), b"b".to_vec()]);
    }

    // CoreDNS v1.15.0 plugin/tls/acme.go ServeDNS: only one TXT IN Question for a published name is answered.
    #[tokio::test]
    async fn other_queries_go_to_the_next_plugin() {
        let solver = Arc::new(Solver::default());
        solver.present("_acme-challenge.dns.example.", "digest");
        let tls = Tls::challenge_only(solver);
        for (name, qtype, class) in [
            ("_acme-challenge.dns.example.", Type::A, Class::IN),
            ("_acme-challenge.dns.example.", Type::TXT, Class::CH),
            ("_acme-challenge.other.example.", Type::TXT, Class::IN),
            ("dns.example.", Type::TXT, Class::IN),
        ] {
            let (outcome, _) = query(&tls, name, qtype, class).await;
            assert_eq!(
                outcome,
                Outcome::Unanswered(Rcode::NXDOMAIN),
                "{name} {qtype:?}"
            );
        }
    }

    #[tokio::test]
    async fn with_no_pending_challenge_the_plugin_is_transparent() {
        let solver = Arc::new(Solver::default());
        let tls = Tls::challenge_only(solver);
        let (outcome, _) = query(&tls, "_acme-challenge.dns.example.", Type::TXT, Class::IN).await;
        assert_eq!(outcome, Outcome::Unanswered(Rcode::NXDOMAIN));
    }
}
