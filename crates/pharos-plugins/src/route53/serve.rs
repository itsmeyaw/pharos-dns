use super::{
    Config,
    zones::{Group, initialize, names, update_zones},
};
use crate::zone::{Zone, contains};
use pharos_proto::{Class, Name, Rcode};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::task::JoinHandle;

/// One `route53` Directive line; each has its own client, hosted zones and fallthrough list.
#[derive(Debug)]
pub(super) struct Stanza {
    config: Config,
    pub(super) groups: Arc<[Group]>,
    fallthrough: Vec<Name>,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// The `route53` Plugin: its stanzas, tried in Corefile order.
#[derive(Debug)]
pub struct Route53 {
    pub(super) stanzas: Vec<Arc<Stanza>>,
}

/// A Next that only records that the Zone passed the Query on, so Route53 stays in charge of what happens next.
struct Declined<'a>(&'a AtomicBool);

impl Next for Declined<'_> {
    fn run(self, _cx: &mut Context<'_, '_>) -> impl Future<Output = Outcome> + Send {
        self.0.store(true, Ordering::Relaxed);
        std::future::ready(Outcome::Unanswered(Rcode::SERVFAIL))
    }
}

// CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: the file.Result of a hosted zone Lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    Answer,
    NoData,
    NameError,
    EmptySuccess,
    Delegation,
    ServerFailure,
}

// CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: a hosted zone result from the Response `Zone::lookup` built in `response`.
fn classify(
    zone: &Zone,
    response: &[u8],
    name: &[u8],
    qclass: Class,
    check_empty: bool,
) -> Verdict {
    let [
        _,
        _,
        flags_high,
        flags_low,
        _,
        _,
        answers_high,
        answers_low,
        ..,
    ] = *response
    else {
        return Verdict::ServerFailure;
    };
    // RFC 1035 §4.1.1: the header holds the AA flag, the RCODE and the ANCOUNT.
    let flags = u16::from_be_bytes([flags_high, flags_low]);
    if u16::from_be_bytes([answers_high, answers_low]) > 0 {
        return Verdict::Answer;
    }
    match flags & 0x000f {
        3 => Verdict::NameError,
        2 => Verdict::ServerFailure,
        // RFC 2181 §6.1: a referral at a Zone Cut is not authoritative; QCLASS * never is, so it cannot tell.
        0 if flags & 0x0400 == 0 && qclass != Class::ANY => Verdict::Delegation,
        // RFC 8020 §2: an empty non-terminal is NOERROR with no answer; CoreDNS reports it as Success, not NoData.
        0 if check_empty && zone.exists(name) && !zone.exact(name) => Verdict::EmptySuccess,
        _ => Verdict::NoData,
    }
}

impl Stanza {
    // CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: None hands the Query to the next stanza or Plugin.
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Option<Outcome> {
        let question = cx.query.questions().next()?;
        let qclass = question.qclass;
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        let name = &wire[..len + 1];
        // CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: plugin.Zones.Matches takes the longest ZONE, the first on a tie.
        let mut group: Option<&Group> = None;
        for candidate in self.groups.iter() {
            if contains(name, &candidate.apex)
                && group.is_none_or(|best| candidate.apex.label_count() > best.apex.label_count())
            {
                group = Some(candidate);
            }
        }
        let group = group?;
        let fall = self.fallthrough.iter().any(|apex| contains(name, apex));
        let last = group.hosted.len() - 1;
        let mut verdict = Verdict::ServerFailure;
        // CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: hosted zones are tried in order; a Zone snapshot is swapped atomically, so no lock is held during a lookup.
        for (index, hosted) in group.hosted.iter().enumerate() {
            let snapshot = hosted.current.load();
            verdict = match snapshot.as_ref() {
                // CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: a zone without data is a ServerFailure result.
                None => Verdict::ServerFailure,
                Some(zone) => {
                    let declined = AtomicBool::new(false);
                    let outcome = zone.lookup(cx, Declined(&declined), &[]).await;
                    if declined.load(Ordering::Relaxed) {
                        return None;
                    }
                    match outcome {
                        Outcome::Response => {
                            classify(zone, cx.response, name, qclass, index != last || fall)
                        }
                        Outcome::Unanswered(rcode) if rcode == Rcode::SERVFAIL => {
                            Verdict::ServerFailure
                        }
                        other => return Some(other),
                    }
                }
            };
            // CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: take a non-empty Answer or NODATA, else try the next hosted zone.
            if matches!(verdict, Verdict::Answer | Verdict::NoData) {
                break;
            }
        }
        if matches!(verdict, Verdict::Answer | Verdict::NoData) {
            return Some(Outcome::Response);
        }
        // CoreDNS v1.15.0 plugin/route53/route53.go ServeDNS: len(Answer) == 0 && result != NoData && Fall.Through(qname).
        if fall {
            cx.response.clear();
            return None;
        }
        Some(if verdict == Verdict::ServerFailure {
            Outcome::Unanswered(Rcode::SERVFAIL)
        } else {
            Outcome::Response
        })
    }

    // CoreDNS v1.15.0 plugin/route53/route53.go Run: the refresh loop sleeps for the refresh interval after each update.
    async fn refresh_loop(self: Arc<Self>) {
        let mut api = None;
        loop {
            tokio::time::sleep(self.config.refresh).await;
            let client = match &api {
                Some(client) => Arc::clone(client),
                None => match super::aws::connect(&self.config).await {
                    Ok(client) => {
                        let client = Arc::new(client);
                        api = Some(Arc::clone(&client));
                        client
                    }
                    Err(error) => {
                        pharos_server::logging::log(
                            "ERROR",
                            "route53",
                            &format!(
                                "Failed to create route53 client for {}: {error}",
                                names(&self.groups)
                            ),
                        );
                        continue;
                    }
                },
            };
            // CoreDNS v1.15.0 plugin/route53/route53.go Run: a failed update keeps serving the last good data.
            if let Err(error) = update_zones(&client, &self.groups).await {
                pharos_server::logging::log(
                    "ERROR",
                    "route53",
                    &format!("Failed to update zones {}: {error}", names(&self.groups)),
                );
            }
        }
    }
}

impl Plugin for Route53 {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        // CoreDNS v1.15.0 plugin/route53/setup.go setup: each Directive line is its own handler, chained in order.
        for stanza in &self.stanzas {
            if let Some(outcome) = stanza.serve(cx).await {
                return outcome;
            }
        }
        next.run(cx).await
    }
}

// Setup is synchronous and may already run inside a Tokio runtime, so the initial load gets its own thread and runtime.
fn block_on<T: Send>(future: impl Future<Output = Result<T, String>> + Send) -> Result<T, String> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .spawn_scoped(scope, || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("cannot create AWS runtime: {error}"))?
                    .block_on(future)
            })
            .map_err(|error| format!("cannot start route53 loader: {error}"))?
            .join()
            .map_err(|_| "route53 loader panicked".to_owned())?
    })
}

impl Stanza {
    pub(super) fn new(config: Config) -> Result<Self, String> {
        let groups = config
            .zones
            .iter()
            .map(|(dns, ids)| Group::new(dns, ids))
            .collect::<Result<Vec<_>, _>>()?;
        let fallthrough = config
            .fallthrough
            .domains
            .iter()
            .map(|domain| {
                domain
                    .parse()
                    .map_err(|error| format!("invalid fallthrough zone {domain:?}: {error}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            config,
            groups: groups.into(),
            fallthrough,
            task: Mutex::new(None),
        })
    }

    // CoreDNS v1.15.0 plugin/route53/setup.go setup: create the client, verify the hosted zones, then load them before serving.
    fn start(config: Config) -> Result<Self, String> {
        let stanza = Self::new(config)?;
        let groups = Arc::clone(&stanza.groups);
        let config = stanza.config.clone();
        block_on(async move {
            let client = super::aws::connect(&config)
                .await
                .map_err(|error| format!("failed to create route53 client: {error}"))?;
            initialize(&Arc::new(client), &groups).await
        })?;
        Ok(stanza)
    }
}

impl Route53 {
    /// Creates every stanza, loading its hosted zones synchronously; any failure fails setup like CoreDNS.
    pub(super) fn start(configs: Vec<Config>) -> Result<Self, String> {
        let stanzas = configs
            .into_iter()
            .map(|config| Stanza::start(config).map(Arc::new))
            .collect::<Result<_, _>>()?;
        Ok(Self { stanzas })
    }

    pub(super) fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let stanzas = self.stanzas.clone();
        let start = move || {
            let stanzas = stanzas.clone();
            async move {
                for stanza in stanzas {
                    // Spawned here, in the server runtime, so the SDK client's connections live as long as the loop.
                    let task = tokio::spawn(Arc::clone(&stanza).refresh_loop());
                    if let Some(old) = stanza.task.lock().unwrap().replace(task) {
                        old.abort();
                    }
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let stanzas = self.stanzas.clone();
        let stop = move || {
            let tasks = stanzas
                .iter()
                .filter_map(|stanza| stanza.task.lock().unwrap().take())
                .collect::<Vec<_>>();
            async move {
                for task in tasks {
                    task.abort();
                    let _ = task.await;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
}
