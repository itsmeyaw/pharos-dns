//! Proxy Queries to upstream resolvers over gRPC.

mod client;
pub(crate) mod setup;

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use pharos_proto::{Message, Name, NameRef, Rcode};
use pharos_server::{Context, Next, Outcome, Plugin, metrics::GrpcMetrics};
use tokio::time::{Instant, timeout_at};

use client::{Client, Pool, Reply};

/// CoreDNS v1.15.0 plugin/grpc/setup.go `max`: the most Upstreams one Directive takes.
pub(crate) const MAX_UPSTREAMS: usize = 15;

/// CoreDNS v1.15.0 plugin/grpc/grpc.go `defaultTimeout`: one deadline covers every Upstream tried.
const TIMEOUT: Duration = Duration::from_secs(5);

/// How the Upstreams of one Directive are ordered for a Query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Policy {
    Random,
    RoundRobin,
    Sequential,
}

impl Policy {
    /// The order to try the `count` Upstreams in, written to the front of `buffer`.
    fn order<'a>(
        self,
        count: usize,
        robin: &AtomicU32,
        buffer: &'a mut [usize; MAX_UPSTREAMS],
    ) -> &'a [usize] {
        let order = &mut buffer[..count];
        for (index, slot) in order.iter_mut().enumerate() {
            *slot = index;
        }
        match self {
            // CoreDNS v1.15.0 plugin/grpc/policy.go sequential.List: configuration order.
            Self::Sequential => {}
            // CoreDNS v1.15.0 plugin/grpc/policy.go roundRobin.List: the next Upstream first, then the rest in order.
            Self::RoundRobin => {
                let first = robin.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as usize % count;
                order[..=first].rotate_right(1);
            }
            // CoreDNS v1.15.0 plugin/grpc/policy.go random.List: a random permutation.
            Self::Random => {
                // shortcut: a byte modulo `i + 1` is biased by under 4%, which load spreading tolerates; draw wider if that matters.
                let mut bytes = [0_u8; MAX_UPSTREAMS];
                if getrandom::getrandom(&mut bytes).is_err() {
                    return order;
                }
                for i in (1..count).rev() {
                    order.swap(i, usize::from(bytes[i]) % (i + 1));
                }
            }
        }
        order
    }
}

struct Upstream {
    /// The `to` label of its metrics.
    to: String,
    client: Client,
    metrics: Option<GrpcMetrics>,
}

/// One `grpc` Directive.
pub struct Grpc {
    from: Name,
    ignored: Vec<Name>,
    upstreams: Vec<Upstream>,
    policy: Policy,
    robin: AtomicU32,
    fallthrough: Vec<Name>,
    pool: Pool,
}

impl std::fmt::Debug for Grpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grpc")
            .field("from", &self.from)
            .field("upstreams", &self.upstreams.len())
            .finish()
    }
}

impl Grpc {
    pub(crate) fn set_metrics(&mut self, registry: &pharos_server::metrics::Registry) {
        for upstream in &mut self.upstreams {
            upstream.metrics = Some(registry.grpc(&upstream.to));
        }
    }

    pub(crate) fn stop(&self) {
        for upstream in &self.upstreams {
            upstream.client.stop();
        }
    }

    fn falls_through(&self, name: NameRef<'_>) -> bool {
        self.fallthrough
            .iter()
            .any(|zone| crate::name_within(name, zone))
    }

    /// CoreDNS v1.15.0 plugin/grpc/grpc.go `match`: inside `from` and not under an `except` name.
    fn matches(&self, name: NameRef<'_>) -> bool {
        crate::name_within(name, &self.from)
            && (name == self.from
                || !self
                    .ignored
                    .iter()
                    .any(|ignored| crate::name_within(name, ignored)))
    }
}

/// RFC 1035 §4.1.1: the Response to `query` carrying only `rcode`, as miekg/dns `SetRcode` builds it.
fn write_rcode(query: &Message<'_>, response: &mut Vec<u8>, rcode: Rcode) {
    // RFC 1035 §4.1.1: QR marks a Response; OPCODE is copied, and RD and CD are copied for a QUERY.
    let flags = 0x8000
        | (query.flags() & 0x7800)
        | if query.opcode() == pharos_proto::Opcode::QUERY {
            query.flags() & 0x0110
        } else {
            0
        }
        | (rcode.0 & 15);
    response.clear();
    let mut builder =
        pharos_proto::MessageBuilder::new(response, usize::from(u16::MAX), query.id(), flags)
            .expect("valid maximum");
    // RFC 1035 §4.1.1: a Response repeats the Question it answers.
    if let Some(question) = query.questions().next() {
        let _ = builder.question(question.name, question.qtype, question.qclass);
    }
    let _ = builder.finish();
}

impl Plugin for Grpc {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let root = [0];
        let question = cx.query.questions().next();
        let name = question.map_or_else(
            || NameRef::parse(&root, 0).expect("root"),
            |question| question.name,
        );
        if !self.matches(name) {
            return next.run(cx).await;
        }
        let fall = self.falls_through(name);
        let asked = question.map(|question| (question.name, question.qtype, question.qclass));
        // RFC 1035 §4.1.1: Return FORMERR when the query cannot be interpreted.
        let original = cx.query.as_wire();
        if cx.query.flags() != u16::from_be_bytes([original[2], original[3]])
            && !cx.query.can_change_flags_in_wire()
        {
            return Outcome::Unanswered(Rcode::FORMERR);
        }
        // CoreDNS v1.15.0 plugin/grpc/proxy.go query: the Upstream gets the Query as modified by earlier Plugins.
        let mut request = self.pool.take();
        let buffer = request.buffer();
        if cx.query.wire_changed() {
            if cx.query.copy_wire_checked(buffer).is_err() {
                return Outcome::Unanswered(Rcode::FORMERR);
            }
        } else {
            buffer.extend_from_slice(original);
        }
        let message = request.wire();
        let deadline = Instant::now() + TIMEOUT;
        let mut buffer = [0; MAX_UPSTREAMS];
        let order = self
            .policy
            .order(self.upstreams.len(), &self.robin, &mut buffer);
        for &index in order {
            // CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: no new attempt after the deadline.
            if Instant::now() >= deadline {
                break;
            }
            let upstream = &self.upstreams[index];
            let start = Instant::now();
            let reply = timeout_at(
                deadline,
                upstream.client.call(&message, deadline, cx.response),
            )
            .await;
            match reply {
                Ok(Ok(Reply::Message)) => {}
                // CoreDNS v1.15.0 plugin/grpc/proxy.go query: NotFound is an empty NXDOMAIN reply, not counted in metrics.
                Ok(Ok(Reply::NotFound)) => write_rcode(&cx.query, cx.response, Rcode::NXDOMAIN),
                // CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: an error moves on to the next Upstream.
                _ => {
                    cx.response.clear();
                    continue;
                }
            }
            let Ok(response) = Message::parse(cx.response.as_slice()) else {
                cx.response.clear();
                continue;
            };
            if matches!(reply, Ok(Ok(Reply::Message)))
                && let Some(metrics) = &upstream.metrics
            {
                metrics.observe(response.rcode().0, start.elapsed().as_secs_f64());
            }
            // CoreDNS v1.15.0 request.go `Match`: one Question equal to the Query's, in a Response.
            let matched = response.qr()
                && response.question_count() == 1
                && response.questions().next().zip(asked).is_some_and(
                    |(got, (name, qtype, qclass))| {
                        got.name == name && got.qtype == qtype && got.qclass == qclass
                    },
                );
            if !matched {
                // CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: a mismatched reply is FORMERR.
                return Outcome::Unanswered(Rcode::FORMERR);
            }
            if response.rcode() == Rcode::NXDOMAIN && fall {
                // CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: `fallthrough` hands NXDOMAIN to the next Plugin.
                let mut saved = self.pool.take();
                saved.buffer().extend_from_slice(cx.response);
                cx.response.clear();
                let outcome = next.run(cx).await;
                if !matches!(outcome, Outcome::Error(pharos_server::Error::NoNextPlugin)) {
                    return outcome;
                }
                // With no next Plugin the NXDOMAIN reply is the answer.
                cx.response.clear();
                cx.response.extend_from_slice(saved.contents());
            }
            // RFC 4035 §4.6: AD from an Upstream over a channel Pharos cannot vouch for is not trusted.
            cx.response[3] &= !0x20;
            // RFC 8945 §5.5: Listener clears AD if it re-signs this forwarded Response.
            cx.metadata.mark_forwarded_response();
            return Outcome::Response;
        }
        // CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: every Upstream failed; `fallthrough` tries the next Plugin.
        if fall {
            let outcome = next.run(cx).await;
            if !matches!(outcome, Outcome::Error(pharos_server::Error::NoNextPlugin)) {
                return outcome;
            }
        }
        // RFC 1034 §5.2.3: Temporary resolution failures return SERVFAIL.
        Outcome::Unanswered(Rcode::SERVFAIL)
    }
}
