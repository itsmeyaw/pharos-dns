//! Detect forwarding loops during startup.

pub(crate) mod setup;

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Lifecycle, Next, Outcome, Phase, Plugin};
use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout_at},
};

#[derive(Debug)]
pub struct Loop {
    pub domain: String,
    state: Arc<State>,
}

#[derive(Debug)]
struct State {
    domain: String,
    qname: String,
    probe: Option<Name>,
    seen: AtomicUsize,
    disabled: AtomicBool,
    complete: AtomicBool,
    resume: AtomicBool,
    address: Mutex<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
    cancel: watch::Sender<bool>,
}

impl Loop {
    pub(crate) fn parallel_query(&self, query: &Message<'_>) -> Option<watch::Receiver<bool>> {
        self.is_probe(query).then(|| self.state.cancel.subscribe())
    }
    pub(crate) fn is_probe(&self, query: &Message<'_>) -> bool {
        !self.state.disabled.load(Ordering::Acquire)
            && query.questions().next().is_some_and(|question| {
                question.qtype == Type::HINFO
                    && self
                        .state
                        .probe
                        .as_ref()
                        .is_some_and(|name| question.name == *name)
            })
    }
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
            state: Arc::new(State {
                domain: domain.into(),
                probe: qname.parse().ok(),
                qname,
                seen: AtomicUsize::new(0),
                disabled: AtomicBool::new(false),
                complete: AtomicBool::new(false),
                resume: AtomicBool::new(false),
                address: Mutex::new(SocketAddr::from(([127, 0, 0, 1], 0))),
                task: Mutex::new(None),
                cancel: watch::channel(false).0,
            }),
        }
    }

    pub(crate) fn register(&self, lifecycle: &mut Lifecycle, mut address: SocketAddr) {
        if address.ip().is_unspecified() {
            address.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        *self.state.address.lock().unwrap() = address;
        let state = Arc::clone(&self.state);
        lifecycle.register_sync(Phase::Started, move || {
            state.start();
            Ok(())
        });
        let state = Arc::clone(&self.state);
        lifecycle.register_sync(Phase::RestartFailed, move || {
            if state.resume.swap(false, Ordering::AcqRel) {
                state.start();
            }
            Ok(())
        });
        for phase in [Phase::Restart, Phase::Shutdown] {
            let state = Arc::clone(&self.state);
            lifecycle.register_sync(phase, move || {
                state.stop();
                Ok(())
            });
        }
    }
}

impl State {
    fn start(self: &Arc<Self>) {
        self.cancel.send_replace(false);
        self.disabled.store(false, Ordering::Release);
        self.seen.store(0, Ordering::Relaxed);
        let state = Arc::clone(self);
        *self.task.lock().unwrap() = Some(tokio::spawn(async move {
            state.probe().await;
        }));
    }

    fn stop(&self) {
        self.cancel.send_replace(true);
        let active = !self.disabled.swap(true, Ordering::AcqRel);
        if let Some(task) = self.task.lock().unwrap().take() {
            self.resume.store(
                active && !self.complete.load(Ordering::Acquire),
                Ordering::Release,
            );
            task.abort();
        }
    }

    async fn probe(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let address = *self.address.lock().unwrap();
        while Instant::now() < deadline {
            if timeout_at(deadline, self.exchange(address))
                .await
                .is_ok_and(|result| result.is_ok())
            {
                break;
            }
            self.seen.store(0, Ordering::Relaxed);
            tokio::time::sleep_until((Instant::now() + Duration::from_secs(1)).min(deadline)).await;
        }
        self.complete.store(true, Ordering::Release);
        self.disabled.store(true, Ordering::Release);
    }

    async fn exchange(&self, address: SocketAddr) -> io::Result<()> {
        let name = self
            .probe
            .as_ref()
            .ok_or_else(|| io::Error::other("invalid probe name"))?;
        let mut id = [0; 2];
        getrandom::getrandom(&mut id).map_err(|_| io::Error::other("random ID unavailable"))?;
        let id = u16::from_ne_bytes(id);
        let mut wire = Vec::new();
        let mut builder =
            MessageBuilder::new(&mut wire, 512, id, 0x0100).map_err(io::Error::other)?;
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).map_err(io::Error::other)?,
                Type::HINFO,
                Class::IN,
            )
            .map_err(io::Error::other)?;
        let _ = builder.finish();
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(address).await?;
        socket.send(&wire).await?;
        let mut response = [0; 65535];
        let len =
            tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response)).await??;
        let message = Message::parse(&response[..len]).map_err(io::Error::other)?;
        // RFC 1035 §4.1.1: the response ID matches the query ID.
        if message.id() != id {
            return Err(io::Error::other("probe response ID mismatch"));
        }
        Ok(())
    }
}

impl Plugin for Loop {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let state = &self.state;
        if self.is_probe(&cx.query) && state.seen.fetch_add(1, Ordering::Relaxed) >= 2 {
            let address = *state.address.lock().unwrap();
            pharos_server::logging::log(
                "FATAL",
                "loop",
                &format!(
                    "Loop ({} -> {}) detected for zone {:?}, see https://coredns.io/plugins/loop#troubleshooting. Query: \"HINFO {}\"",
                    cx.client, address, state.domain, state.qname
                ),
            );
            let _ = io::stdout().flush();
            // CoreDNS log.Fatalf exits immediately, skipping all shutdown hooks.
            std::process::exit(1);
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
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
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
        let name = plugin.state.qname.to_string();
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
        assert_eq!(plugin.state.seen.load(Ordering::Relaxed), 0);
        for count in 1..=2 {
            assert_eq!(
                query(&plugin, &name, Type::HINFO).await,
                Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
            );
            assert_eq!(plugin.state.seen.load(Ordering::Relaxed), count);
        }
        plugin.state.disabled.store(true, Ordering::Relaxed);
        assert_eq!(
            query(&plugin, &name, Type::HINFO).await,
            Outcome::Unanswered(pharos_proto::Rcode::NOERROR)
        );
        assert_eq!(plugin.state.seen.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn startup_probe_stops_on_restart_and_disables_after_success() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plugin = Loop::new(".");
        let mut lifecycle = Lifecycle::default();
        plugin.register(&mut lifecycle, socket.local_addr().unwrap());
        lifecycle.run(Phase::Started).await.unwrap();
        let mut wire = [0; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        let query = Message::parse(&wire[..len]).unwrap();
        assert_eq!(query.questions().next().unwrap().qtype, Type::HINFO);
        assert_eq!(
            query.questions().next().unwrap().name.to_string(),
            plugin.state.qname
        );
        lifecycle.run(Phase::Restart).await.unwrap();
        assert!(plugin.state.disabled.load(Ordering::Acquire));
        lifecycle.run(Phase::RestartFailed).await.unwrap();
        let (len, peer) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], peer).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !plugin.state.disabled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(plugin.state.disabled.load(Ordering::Acquire));
        assert!(plugin.state.complete.load(Ordering::Acquire));
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }

    #[tokio::test]
    async fn failed_reload_does_not_repeat_a_successful_probe() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plugin = Loop::new(".");
        let mut lifecycle = Lifecycle::default();
        plugin.register(&mut lifecycle, socket.local_addr().unwrap());
        lifecycle.run(Phase::Started).await.unwrap();
        let mut wire = [0; 512];
        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], peer).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !plugin.state.complete.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        lifecycle.run(Phase::Restart).await.unwrap();
        lifecycle.run(Phase::RestartFailed).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut wire))
                .await
                .is_err()
        );
        assert!(plugin.state.disabled.load(Ordering::Acquire));
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }
}
