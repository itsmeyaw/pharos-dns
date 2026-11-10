//! Detect forwarding loops during startup.

use pharos_proto::{Name, Type};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug)]
pub struct Loop {
    pub domain: String,
    qname: String,
    probe: Option<Name>,
    seen: AtomicUsize,
    disabled: AtomicBool,
}

impl Loop {
    pub fn new(domain: &str) -> Self {
        let random = || {
            let mut bytes = [0; 8];
            if getrandom::getrandom(&mut bytes).is_err() {
                return std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
            }
            u64::from_ne_bytes(bytes) & ((1 << 62) - 1)
        };
        let qname = format!(
            "{}.{}.{}",
            random(),
            random(),
            domain.trim_start_matches('.')
        );
        Self {
            domain: domain.into(),
            probe: qname.parse().ok(),
            qname,
            seen: AtomicUsize::new(0),
            disabled: AtomicBool::new(false),
        }
    }
}

impl Plugin for Loop {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        if !self.disabled.load(Ordering::Relaxed)
            && let Some(question) = cx.query.questions().next()
            && question.qtype == Type::HINFO
            && self
                .probe
                .as_ref()
                .is_some_and(|name| question.name == *name)
        {
            self.seen.fetch_add(1, Ordering::Relaxed);
        }
        next.run(cx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
    use pharos_server::{Metadata, Protocol, Transport};
    use std::sync::atomic::Ordering;

    struct Pass;
    impl Next for Pass {
        async fn run(self, _: &mut Context<'_>) -> Outcome {
            Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
        }
    }

    async fn query(plugin: &Loop, name: &str, kind: Type) -> Outcome {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::new();
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1000".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        plugin.serve(&mut cx, Pass).await
    }

    // Derived from CoreDNS v1.15.0 plugin/loop/loop_test.go.
    #[tokio::test]
    async fn counts_only_enabled_matching_hinfo_queries() {
        let plugin = Loop::new("example.org.");
        let name = plugin.qname.to_string();
        for (query_name, kind) in [
            ("outside.example.", Type::HINFO),
            (name.as_str(), Type::A),
            ("other.example.org.", Type::HINFO),
        ] {
            assert_eq!(
                query(&plugin, query_name, kind).await,
                Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
            );
        }
        assert_eq!(plugin.seen.load(Ordering::Relaxed), 0);
        for count in 1..=2 {
            assert_eq!(
                query(&plugin, &name, Type::HINFO).await,
                Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
            );
            assert_eq!(plugin.seen.load(Ordering::Relaxed), count);
        }
        plugin.disabled.store(true, Ordering::Relaxed);
        assert_eq!(
            query(&plugin, &name, Type::HINFO).await,
            Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
        );
        assert_eq!(plugin.seen.load(Ordering::Relaxed), 2);
    }
}
