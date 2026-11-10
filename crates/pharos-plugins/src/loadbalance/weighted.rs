use std::{
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use pharos_proto::{Name, NameRef, Record, Type};
use pharos_server::{Lifecycle, Phase};

#[derive(Debug)]
pub(super) struct Entry {
    name: Option<Name>,
    address: IpAddr,
    value: u8,
}

#[derive(Debug, Default)]
struct State {
    entries: arc_swap::ArcSwap<Vec<Entry>>,
    last_content: Mutex<Option<Vec<u8>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug)]
pub(super) struct Weights {
    path: PathBuf,
    reload: Duration,
    state: Arc<State>,
}

impl Weights {
    pub(super) fn new(path: PathBuf, reload: Duration) -> Self {
        Self {
            path,
            reload,
            state: Arc::new(State::default()),
        }
    }

    pub(super) fn load(&self) -> Arc<Vec<Entry>> {
        self.state.entries.load_full()
    }

    pub(super) fn register_hooks(&self, lifecycle: &mut Lifecycle) {
        let state = Arc::clone(&self.state);
        let path = self.path.clone();
        let reload = self.reload;
        let start = move || {
            let state = Arc::clone(&state);
            let path = path.clone();
            async move {
                state.read(&path, !reload.is_zero())?;
                if !reload.is_zero() {
                    let task_state = Arc::clone(&state);
                    let task = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(reload).await;
                            if let Err(error) = task_state.read(&path, false) {
                                pharos_server::logging::log(
                                    "ERROR",
                                    "loadbalance",
                                    &error.to_string(),
                                );
                            }
                        }
                    });
                    if let Some(old) = state.task.lock().unwrap().replace(task) {
                        old.abort();
                    }
                }
                Ok(())
            }
        };
        lifecycle.register(Phase::Startup, start.clone());
        lifecycle.register(Phase::RestartFailed, start);
        let state = Arc::clone(&self.state);
        let stop = move || {
            let task = state.task.lock().unwrap().take();
            async move {
                if let Some(task) = task {
                    task.abort();
                    let _ = task.await;
                }
                Ok(())
            }
        };
        lifecycle.register(Phase::Restart, stop.clone());
        lifecycle.register(Phase::Shutdown, stop);
    }
}

impl State {
    fn read(&self, path: &PathBuf, ignore_open_error: bool) -> io::Result<()> {
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if ignore_open_error => {
                pharos_server::logging::log(
                    "WARN",
                    "loadbalance",
                    &format!("weight file open error: {error}"),
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut last = self.last_content.lock().unwrap();
        if last.as_ref() == Some(&bytes) {
            return Ok(());
        }
        *last = Some(bytes.clone());
        let entries = parse(&bytes)?;
        self.entries.store(Arc::new(entries));
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> io::Result<Vec<Entry>> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    let mut domain: Option<Option<Name>> = None;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.len() >= 65536 {
            return Err(io::Error::other("weight line too long"));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            [name] => {
                if name.parse::<IpAddr>().is_ok() {
                    return Err(io::Error::other("wrong domain name"));
                }
                let fqdn = if name.ends_with('.') {
                    (*name).to_owned()
                } else {
                    format!("{name}.")
                };
                domain = Some(fqdn.parse().ok());
            }
            [address, weight] => {
                let address = address
                    .parse::<IpAddr>()
                    .map_err(io::Error::other)?
                    .to_canonical();
                let value = weight.parse::<u8>().map_err(io::Error::other)?;
                if value == 0 {
                    return Err(io::Error::other("zero weight"));
                }
                let name = domain
                    .as_ref()
                    .ok_or_else(|| io::Error::other("missing domain name"))?
                    .clone();
                entries.push(Entry {
                    name,
                    address,
                    value,
                });
            }
            _ => return Err(io::Error::other("invalid weight line")),
        }
    }
    Ok(entries)
}

pub(super) fn weight(entries: &[Entry], rr: &Record<'_>) -> u8 {
    let address = match (rr.rtype, rr.rdata) {
        (Type::A, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (Type::AAAA, bytes) if bytes.len() == 16 => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())).to_canonical()
        }
        _ => return 1,
    };
    entries
        .iter()
        .find_map(|entry| {
            let name = entry.name.as_ref()?;
            let configured = NameRef::parse(name.as_wire(), 0).ok()?;
            (entry.address == address && rr.name.labels().eq(configured.labels()))
                .then_some(entry.value)
        })
        .unwrap_or(1)
}
