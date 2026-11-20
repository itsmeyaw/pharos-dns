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
        let mut response = vec![0; 65535];
        while Instant::now() < deadline {
            if timeout_at(deadline, self.exchange(address, &mut response))
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

    async fn exchange(&self, address: SocketAddr, response: &mut [u8]) -> io::Result<()> {
        let name = self
            .probe
            .as_ref()
            .ok_or_else(|| io::Error::other("invalid probe name"))?;
        let mut id = [0; 2];
        // RFC 5452 §9.2: Outgoing queries use unpredictable IDs.
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
        let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(response)).await??;
        let message = Message::parse(&response[..len]).map_err(io::Error::other)?;
        // RFC 1035 §4.1.1: the response ID matches the query ID.
        if message.id() != id {
            return Err(io::Error::other("probe response ID mismatch"));
        }
        // RFC 5452 §9.1: Match the response's complete Question to the probe.
        let expected_name = NameRef::parse(name.as_wire(), 0).map_err(io::Error::other)?;
        let Some(question) = message.questions().next() else {
            return Err(io::Error::other("probe response Question missing"));
        };
        if message.question_count() != 1
            || question.name != expected_name
            || question.qtype != Type::HINFO
            || question.qclass != Class::IN
        {
            return Err(io::Error::other("probe response Question mismatch"));
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
mod tests;
