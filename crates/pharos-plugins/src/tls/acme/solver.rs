//! DNS-01 challenge state (RFC 8555 §8.4) and the Plugin that answers `_acme-challenge` TXT Queries from it.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Protocol};

/// One challenge name: the number of presentations of each value, and the sorted values to answer with.
#[derive(Debug, Default)]
struct Published {
    counts: BTreeMap<String, usize>,
    answer: Arc<[Box<str>]>,
}

/// The TXT values to publish, by lowercase wire-format owner name, each with the number of challenges that need it.
#[derive(Debug, Default)]
pub struct Solver {
    records: RwLock<HashMap<Box<[u8]>, Published>>,
    // Lets the Query path skip the lock while no challenge is pending.
    active: AtomicUsize,
}

// RFC 8555 §8.4: the validation TXT record is at "_acme-challenge" below the identifier.
const LABEL: &[u8] = b"_acme-challenge";

impl Solver {
    /// Publish `value` at `name`; presenting a value twice needs two clean-ups.
    // CoreDNS v1.15.0 plugin/tls/acme.go acmeDNS01Solver.Present.
    pub fn present(&self, name: &str, value: &str) {
        // A name that is not a valid domain name can never match a Query.
        let Some(key) = key(name) else { return };
        let mut records = self.records.write().unwrap_or_else(|e| e.into_inner());
        let published = records.entry(key).or_default();
        *published.counts.entry(value.to_owned()).or_default() += 1;
        published.share();
        self.active.store(records.len(), Ordering::Release);
    }

    /// Withdraw one presentation of `value` at `name`.
    // CoreDNS v1.15.0 plugin/tls/acme.go acmeDNS01Solver.CleanUp.
    pub fn clean_up(&self, name: &str, value: &str) {
        let Some(key) = key(name) else { return };
        let mut records = self.records.write().unwrap_or_else(|e| e.into_inner());
        if let Some(published) = records.get_mut(&key) {
            match published.counts.get_mut(value) {
                Some(count) if *count > 1 => *count -= 1,
                _ => {
                    published.counts.remove(value);
                }
            }
            if published.counts.is_empty() {
                records.remove(&key);
            } else {
                published.share();
            }
        }
        self.active.store(records.len(), Ordering::Release);
    }

    /// The values published at `name`, sorted.
    #[cfg(test)]
    pub(super) fn values(&self, name: &str) -> Vec<String> {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        key(name)
            .and_then(|key| records.get(&key))
            .map(|published| {
                published
                    .answer
                    .iter()
                    .map(|value| value.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The values published at the wire-format `name`, shared without copying.
    fn answer(&self, name: &NameRef<'_>) -> Option<Arc<[Box<str>]>> {
        // RFC 1035 §3.1: a name is at most 255 octets in wire format.
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in name.labels() {
            // RFC 4343 §3: names compare without regard to ASCII case.
            let end = len + 1 + label.len();
            *wire.get_mut(len)? = label.len() as u8;
            wire.get_mut(len + 1..end)?
                .iter_mut()
                .zip(label)
                .for_each(|(out, byte)| *out = byte.to_ascii_lowercase());
            len = end;
        }
        // RFC 1035 §3.1: the root label ends the name.
        *wire.get_mut(len)? = 0;
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        records
            .get(&wire[..=len])
            .map(|published| Arc::clone(&published.answer))
    }
}

impl Published {
    /// Rebuild the answer shared with Queries; only present and clean-up pay for it.
    fn share(&mut self) {
        self.answer = self
            .counts
            .keys()
            .map(|value| value.as_str().into())
            .collect();
    }
}

// RFC 4343 §3: names compare without regard to ASCII case; RFC 1034 §3.1: the root label ends the name.
fn key(name: &str) -> Option<Box<[u8]>> {
    let mut name = name.to_owned();
    if !name.ends_with('.') {
        name.push('.');
    }
    let name: Name = name.parse().ok()?;
    Some(name.as_wire().to_ascii_lowercase().into())
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
        let Some(values) = self.answer(&question.name) else {
            return next.run(cx).await;
        };
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
    values: &[Box<str>],
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
        let mut rdata = [0u8; 256];
        rdata[0] = len;
        rdata[1..=value.len()].copy_from_slice(value.as_bytes());
        // CoreDNS v1.15.0 plugin/tls/acme.go: the challenge RR has TTL 0 so resolvers do not cache it.
        if !builder
            .record(
                Section::Answer,
                question.name,
                Type::TXT,
                Class::IN,
                0,
                &rdata[..=value.len()],
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
pub(super) mod tests {
    use std::{
        alloc::System,
        future::Future,
        sync::Arc,
        task::{Context as TaskContext, Poll, Waker},
    };

    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
    use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

    use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

    use super::Solver;
    use crate::tls::Tls;

    /// Run `wire` through the Plugin as a UDP Query would be.
    pub(in crate::tls) async fn answer(tls: &Tls, wire: &[u8]) -> (Outcome, Vec<u8>) {
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(65535);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
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
        answer(tls, &wire).await
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

    #[global_allocator]
    static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

    // CODING_STANDARDS.md: no heap allocation per Query; the challenge Solver is the only unit-level
    // allocation test because no public API presents a challenge.
    #[test]
    fn challenge_answers_do_not_allocate_per_query() {
        const NAME: &str = "tls::acme::solver::tests::challenge_answers_do_not_allocate_per_query";
        if std::env::var_os("PHAROS_ALLOCATION_CHILD").is_none() {
            // The global allocator counts every thread, so measure in a process that runs only this test.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env("PHAROS_ALLOCATION_CHILD", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
            return;
        }
        let solver = Arc::new(Solver::default());
        solver.present("_acme-challenge.dns.example.", "one");
        solver.present("_acme-challenge.dns.example.", "two");
        let tls = Tls::challenge_only(solver);
        let name: Name = "_ACME-challenge.dns.example.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 7, 0x0100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::TXT,
                Class::IN,
            )
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
        let region = Region::new(GLOBAL);
        let future = tls.serve(&mut cx, NextRefused);
        let mut future = std::pin::pin!(future);
        let result = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(result, Poll::Ready(Outcome::Response));
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }
}
