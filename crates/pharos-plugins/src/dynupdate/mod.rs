#[cfg(any(test, feature = "plugin-dynupdate"))]
mod bbolt;
#[cfg(any(test, feature = "plugin-dynupdate"))]
pub(crate) mod setup;
#[cfg(any(feature = "plugin-dynupdate", all(test, feature = "plugin-file")))]
mod store;
#[cfg(all(feature = "plugin-dynupdate", feature = "plugin-transfer"))]
mod transfer;
#[cfg(any(feature = "plugin-dynupdate", all(test, feature = "plugin-file")))]
mod update;
#[cfg(any(feature = "plugin-dynupdate", all(test, feature = "plugin-file")))]
mod wire;

#[cfg(feature = "plugin-dynupdate")]
use arc_swap::ArcSwapOption;
#[cfg(feature = "plugin-dynupdate")]
use pharos_proto::{
    Class, Message, MessageBuilder, NameRef, Opcode, Rcode, Section, Type, zone::ZoneRecord,
};
#[cfg(feature = "plugin-dynupdate")]
use pharos_server::{Context, Next, Outcome, Plugin};
#[cfg(feature = "plugin-dynupdate")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "plugin-dynupdate")]
pub struct DynUpdate {
    config: Arc<setup::Config>,
    current: ArcSwapOption<store::Shared>,
    initialize: Mutex<()>,
    #[cfg(feature = "plugin-transfer")]
    notifier: crate::zone::ZoneNotifier,
    #[cfg(feature = "plugin-transfer")]
    notify_state: Arc<Mutex<NotifyState>>,
}

#[cfg(all(feature = "plugin-dynupdate", feature = "plugin-transfer"))]
#[derive(Default)]
struct NotifyState {
    pending: bool,
    running: bool,
    closed: bool,
}

#[cfg(feature = "plugin-dynupdate")]
struct ZoneTerminal;

#[cfg(feature = "plugin-dynupdate")]
impl Next for ZoneTerminal {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
}

#[cfg(feature = "plugin-dynupdate")]
impl std::fmt::Debug for DynUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynUpdate")
            .field("origin", &self.config.origin)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "plugin-dynupdate")]
impl DynUpdate {
    #[cfg(feature = "plugin-cache")]
    pub(crate) fn origin(&self) -> &pharos_proto::Name {
        &self.config.origin
    }

    fn new(config: setup::Config, zone: Arc<crate::zone::Zone>) -> Self {
        let initial = config
            .database
            .is_none()
            .then(|| Arc::new(store::Shared::memory(zone)));
        Self {
            config: Arc::new(config),
            current: ArcSwapOption::from(initial),
            initialize: Mutex::new(()),
            #[cfg(feature = "plugin-transfer")]
            notifier: crate::zone::ZoneNotifier::default(),
            #[cfg(feature = "plugin-transfer")]
            notify_state: Arc::new(Mutex::new(NotifyState::default())),
        }
    }

    fn snapshot(&self) -> std::io::Result<Arc<store::Shared>> {
        if let Some(shared) = self.current.load_full() {
            return Ok(shared);
        }
        let _guard = self
            .initialize
            .lock()
            .map_err(|_| std::io::Error::other("dynamic store initialization lock poisoned"))?;
        if let Some(shared) = self.current.load_full() {
            return Ok(shared);
        }
        let shared = store::acquire(&self.config)?;
        self.current.store(Some(Arc::clone(&shared)));
        Ok(shared)
    }

    async fn update(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let mut questions = cx.query.questions();
        let Some(question) = questions.next() else {
            return reply(cx, Rcode::FORMERR);
        };
        if questions.next().is_some() || question.qtype != Type::SOA || question.qclass != Class::IN
        {
            return reply(cx, Rcode::FORMERR);
        }
        if question.name != self.config.origin {
            return reply(cx, Rcode::NOTAUTH);
        }
        let Some(key) = cx.metadata.validated_tsig().map(|name| name.to_name()) else {
            return reply(cx, Rcode::REFUSED);
        };
        if !self.config.configured_key(&key) {
            return reply(cx, Rcode::REFUSED);
        }
        if usize::from(cx.query.answer_count()) + usize::from(cx.query.authority_count())
            > self.config.max_update_records
        {
            return reply(cx, Rcode::REFUSED);
        }
        let prereqs = cx
            .query
            .answers()
            .map(|record| expand_record(record, cx.query.as_wire()))
            .collect::<Result<Vec<_>, _>>();
        let updates = cx
            .query
            .authorities()
            .map(|record| expand_record(record, cx.query.as_wire()))
            .collect::<Result<Vec<_>, _>>();
        let (Ok(prereqs), Ok(updates)) = (prereqs, updates) else {
            return reply(cx, Rcode::FORMERR);
        };
        let Ok(shared) = self.snapshot() else {
            return reply(cx, Rcode::SERVFAIL);
        };
        let config = Arc::clone(&self.config);
        let result =
            tokio::task::spawn_blocking(move || shared.transact(&config, &key, &prereqs, &updates))
                .await;
        let code = match result {
            Ok(Ok((code, changed))) => {
                #[cfg(feature = "plugin-transfer")]
                if changed {
                    self.notify();
                }
                #[cfg(not(feature = "plugin-transfer"))]
                let _ = changed;
                code
            }
            _ => Rcode::SERVFAIL,
        };
        reply(cx, code)
    }

    #[cfg(feature = "plugin-transfer")]
    fn notify(&self) {
        if self.notifier.get().is_none() {
            return;
        }
        let Ok(mut state) = self.notify_state.lock() else {
            return;
        };
        if state.closed {
            return;
        }
        state.pending = true;
        if state.running {
            return;
        }
        state.running = true;
        drop(state);
        let state = Arc::clone(&self.notify_state);
        let notifier = self.notifier.clone();
        let origin = self.config.origin.clone();
        // RFC 1996 §3.1: a successful Zone change triggers a best-effort NOTIFY.
        tokio::spawn(async move {
            loop {
                {
                    let Ok(mut guard) = state.lock() else {
                        return;
                    };
                    if guard.closed || !guard.pending {
                        guard.running = false;
                        return;
                    }
                    guard.pending = false;
                }
                if let Some(transfer) = notifier.get()
                    && let Err(error) = transfer.notify(&origin).await
                {
                    pharos_server::logging::log(
                        "WARN",
                        "dynupdate",
                        &format!("NOTIFY {origin}: {error}"),
                    );
                }
            }
        });
    }

    #[cfg(feature = "plugin-transfer")]
    fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let state = Arc::clone(&self.notify_state);
        let stop = move || {
            if let Ok(mut state) = state.lock() {
                state.closed = true;
            }
            async { Ok(()) }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
        let state = Arc::clone(&self.notify_state);
        lifecycle.register(pharos_server::Phase::RestartFailed, move || {
            if let Ok(mut state) = state.lock() {
                state.closed = false;
            }
            async { Ok(()) }
        });
    }
}

#[cfg(feature = "plugin-dynupdate")]
fn expand_record(record: pharos_proto::Record<'_>, message: &[u8]) -> Result<ZoneRecord, ()> {
    // RFC 2136 §3.4: UPDATE records are expanded before becoming Zone data.
    let rdata = if record.rdata.is_empty() {
        Vec::new()
    } else if let Some(data) = crate::zone::update::legacy_name_rdata(
        record.rtype,
        message,
        record.rdata_offset,
        record.rdata.len(),
        false,
    )? {
        data
    } else {
        let data = record.data().map_err(|_| ())?;
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 65535, 0, 0).map_err(|_| ())?;
        let written = builder
            .record_with(
                Section::Answer,
                record.name,
                record.rtype,
                record.class,
                record.ttl,
                |writer| {
                    writer.disable_compression();
                    data.write(writer)
                },
            )
            .map_err(|_| ())?;
        if !written {
            return Err(());
        }
        let _ = builder.finish();
        let message = Message::parse(&wire).map_err(|_| ())?;
        message.answers().next().ok_or(())?.rdata.to_vec()
    };
    Ok(ZoneRecord {
        owner: record.name.to_name(),
        rtype: record.rtype,
        class: record.class,
        ttl: record.ttl,
        rdata,
    })
}

#[cfg(feature = "plugin-dynupdate")]
fn reply(cx: &mut Context<'_, '_>, code: Rcode) -> Outcome {
    // RFC 2136 §3.8: the response preserves the UPDATE question and reports the transaction status.
    let flags = 0x8400 | (cx.query.flags() & 0x7800) | code.0;
    let Ok(mut builder) = MessageBuilder::new(
        cx.response,
        cx.max_response_size.max(512),
        cx.query.id(),
        flags,
    ) else {
        return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
    };
    if let Some(question) = cx.query.questions().next()
        && builder
            .question(question.name, question.qtype, question.qclass)
            .is_err()
    {
        return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
    }
    let _ = builder.finish();
    Outcome::Response
}

#[cfg(feature = "plugin-dynupdate")]
impl Plugin for DynUpdate {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        if cx.query.opcode() == Opcode::UPDATE {
            return self.update(cx).await;
        }
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let apex = match NameRef::parse(self.config.origin.as_wire(), 0) {
            Ok(apex) => apex,
            Err(_) => return Outcome::Unanswered(Rcode::SERVFAIL),
        };
        let count = question.name.labels().count();
        let labels = apex.labels().count();
        // RFC 1034 §3.1: authoritative Zone matching follows label suffixes.
        if count < labels
            || !question
                .name
                .labels()
                .skip(count - labels)
                .zip(apex.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return next.run(cx).await;
        }
        let Ok(shared) = self.snapshot() else {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        };
        let zone = shared.current.load_full();
        // The Query is already known to be in this Zone and has no Fallthrough.
        zone.lookup(cx, ZoneTerminal, &[]).await
    }
}

#[cfg(all(test, feature = "plugin-dynupdate"))]
mod tests {
    use super::*;

    #[test]
    fn expands_compressed_legacy_name_fields() {
        let apex: pharos_proto::Name = "example.org.".parse().unwrap();
        let name = NameRef::parse(apex.as_wire(), 0).unwrap();
        let pointer = [0xc0, 0x0c];
        let mut cases = Vec::new();
        for kind in [
            Type::MD,
            Type::MF,
            Type::MB,
            Type::MG,
            Type::MR,
            Type::NSAP_PTR,
        ] {
            cases.push((kind, pointer.to_vec(), apex.as_wire().to_vec()));
        }
        for kind in [Type::MINFO, Type::RP] {
            cases.push((kind, pointer.repeat(2), apex.as_wire().repeat(2)));
        }
        for kind in [Type::AFSDB, Type::RT, Type::KX, Type::LP] {
            cases.push((
                kind,
                [vec![0, 1], pointer.to_vec()].concat(),
                [vec![0, 1], apex.as_wire().to_vec()].concat(),
            ));
        }
        cases.push((
            Type::PX,
            [vec![0, 1], pointer.repeat(2)].concat(),
            [vec![0, 1], apex.as_wire().repeat(2)].concat(),
        ));
        cases.push((
            Type::IPSECKEY,
            [vec![0, 3, 1], pointer.to_vec(), vec![42]].concat(),
            [vec![0, 3, 1], apex.as_wire().to_vec(), vec![42]].concat(),
        ));
        cases.push((
            Type::HIP,
            [vec![0, 1, 0, 0], pointer.to_vec()].concat(),
            [vec![0, 1, 0, 0], apex.as_wire().to_vec()].concat(),
        ));
        cases.push((
            Type::AMTRELAY,
            [vec![0, 3], pointer.to_vec()].concat(),
            [vec![0, 3], apex.as_wire().to_vec()].concat(),
        ));
        for (kind, rdata, expected) in cases {
            let mut wire = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x2800).unwrap();
            builder.question(name, Type::SOA, Class::IN).unwrap();
            builder
                .record(Section::Authority, name, kind, Class::IN, 60, &rdata)
                .unwrap();
            let _ = builder.finish();
            let message = Message::parse(&wire).unwrap();
            let rr = message.authorities().next().unwrap();
            assert_eq!(expand_record(rr, &wire).unwrap().rdata, expected, "{kind}");
        }
    }
}
