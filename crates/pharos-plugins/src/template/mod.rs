//! Dynamic DNS Responses from compiled templates.

pub(crate) mod setup;

use crate::{
    expression::{self, Value},
    gotemplate,
};
use pharos_corefile::Fallthrough;
use pharos_proto::{
    Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type,
    zone::{ZoneParser, ZoneRecord},
};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol};
use regex_automata::{
    nfa::thompson::{
        Builder, NFA, State,
        pikevm::{Cache, PikeVM},
    },
    util::{captures::Captures, primitives::PatternID},
};
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::{self, Write},
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};

const EXPRESSION_SCRATCH: usize = 65_535;

pub struct Template {
    rules: Vec<Rule>,
    metrics: Vec<Vec<RuleMetrics>>,
}

impl fmt::Debug for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Template")
            .field("rules", &self.rules.len())
            .finish()
    }
}

struct Rule {
    class: Class,
    qtype: Type,
    zones: Vec<String>,
    regex: Vec<Matcher>,
    records: Vec<TemplateRecord>,
    variables: Vec<Variable>,
    expressions: Vec<expression::Expression>,
    rcode: Rcode,
    ederror: Option<(u16, String)>,
    fallthrough: Fallthrough,
    workspace: Option<WorkspacePool>,
}
struct RuleMetrics {
    address: SocketAddr,
    zone: String,
    server: String,
    registry: pharos_server::metrics::Registry,
    bindings: arc_swap::ArcSwap<Vec<Arc<MetricBinding>>>,
    binding_lock: Mutex<()>,
}
struct MetricBinding {
    view: String,
    class: String,
    qtype: String,
    matched: pharos_server::metrics::TemplateMetrics,
    failures: Arc<[pharos_server::metrics::TemplateFailureMetrics]>,
}
struct Variable {
    name: String,
    expression: expression::Expression,
}
struct TemplateRecord {
    section: Section,
    source: String,
    compiled: gotemplate::Template,
}

struct Matcher {
    source: String,
    vm: PikeVM,
    names: Vec<Option<String>>,
    numbers: Vec<String>,
    warmer: PikeVM,
}
struct MatcherState {
    cache: Cache,
    captures: Captures,
}
struct RuleWorkspace {
    matchers: Vec<MatcherState>,
    scratch: Vec<u8>,
    variables: Vec<(&'static str, Value<'static>)>,
    matches: Vec<&'static str>,
    groups: Vec<(&'static str, &'static str)>,
}

struct WorkspacePool {
    identity: Arc<()>,
    matchers: Vec<(PikeVM, PikeVM)>,
    variable_count: usize,
    group_count: usize,
}

thread_local! {
    static WORKSPACES: RefCell<HashMap<usize, (Weak<()>, RuleWorkspace)>> = RefCell::new(HashMap::new());
}

impl WorkspacePool {
    fn with<T>(&self, f: impl FnOnce(&mut RuleWorkspace) -> T) -> T {
        let key = Arc::as_ptr(&self.identity) as usize;
        WORKSPACES.with(|workspaces| {
            let mut workspaces = workspaces.borrow_mut();
            if !workspaces.contains_key(&key) {
                workspaces.retain(|_, (owner, _)| owner.strong_count() != 0);
            }
            let (_, workspace) = workspaces.entry(key).or_insert_with(|| {
                let matchers = self
                    .matchers
                    .iter()
                    .map(|(vm, warmer)| {
                        let mut cache = warmer.create_cache();
                        let _ = warmer.is_match(&mut cache, "");
                        cache.reset(vm);
                        let mut captures = vm.create_captures();
                        vm.captures(&mut cache, "www.example.", &mut captures);
                        MatcherState { cache, captures }
                    })
                    .collect();
                let workspace = RuleWorkspace {
                    matchers,
                    scratch: vec![0; EXPRESSION_SCRATCH],
                    variables: vec![("", Value::Nil); self.variable_count],
                    matches: vec![""; self.group_count],
                    groups: vec![("", ""); self.group_count.saturating_mul(2)],
                };
                (Arc::downgrade(&self.identity), workspace)
            });
            f(workspace)
        })
    }
}

impl Matcher {
    fn new(pattern: &str) -> Result<Self, String> {
        let vm = PikeVM::new(pattern).map_err(|e| e.to_string())?;
        let names = vm
            .get_nfa()
            .group_info()
            .pattern_names(PatternID::ZERO)
            .map(|s| s.map(str::to_owned))
            .collect();
        let numbers = (0..vm.get_nfa().group_info().group_len(PatternID::ZERO))
            .map(|index| index.to_string())
            .collect();
        let bound = 1 + vm
            .get_nfa()
            .states()
            .iter()
            .map(|state| match state {
                State::Union { alternates } => alternates.len().saturating_sub(1),
                State::BinaryUnion { .. } => 1,
                State::Capture { .. } => 1,
                _ => 0,
            })
            .sum::<usize>();
        let mut builder = Builder::new();
        builder.start_pattern().map_err(|e| e.to_string())?;
        let fail = builder.add_fail().map_err(|e| e.to_string())?;
        let end = builder.add_match().map_err(|e| e.to_string())?;
        let mut alternatives = vec![fail; bound];
        alternatives.push(end);
        let start = builder.add_union(alternatives).map_err(|e| e.to_string())?;
        builder.finish_pattern(start).map_err(|e| e.to_string())?;
        let nfa: NFA = builder.build(start, start).map_err(|e| e.to_string())?;
        let warmer = PikeVM::new_from_nfa(nfa).map_err(|e| e.to_string())?;
        Ok(Self {
            source: pattern.to_owned(),
            vm,
            names,
            numbers,
            warmer,
        })
    }
}

impl Rule {
    fn initialize_workspace(&mut self) {
        let variable_count = self.variables.len();
        let group_count = self
            .regex
            .iter()
            .map(|m| m.numbers.len())
            .max()
            .unwrap_or(0);
        let matchers: Vec<_> = self
            .regex
            .iter()
            .map(|m| (m.vm.clone(), m.warmer.clone()))
            .collect();
        let workspace = WorkspacePool {
            identity: Arc::new(()),
            matchers,
            variable_count,
            group_count,
        };
        workspace.with(|_| ());
        self.workspace = Some(workspace);
    }
}

struct Text {
    bytes: [u8; 1024],
    len: usize,
}
impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 1024],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}
impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

struct Hit<'a> {
    rule: &'a Rule,
    records: Vec<(Section, ZoneRecord)>,
}
enum MatchResult<'a> {
    Next,
    Failed,
    RecordError,
    Hit(Hit<'a>),
}
enum EvaluationError {
    Expression,
    Record,
}

fn in_zone(name: &str, zone: &str) -> bool {
    // RFC 4343 §3: DNS names match case-insensitively at label boundaries.
    if zone == "." {
        return true;
    }
    let Some(prefix) = name.len().checked_sub(zone.len()) else {
        return false;
    };
    if !name.as_bytes()[prefix..].eq_ignore_ascii_case(zone.as_bytes()) {
        return false;
    }
    if prefix == 0 {
        return true;
    }
    let bytes = name.as_bytes();
    bytes[prefix - 1] == b'.'
        && bytes[..prefix - 1]
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'\\')
            .count()
            % 2
            == 0
}

impl Template {
    fn new(rules: Vec<Rule>) -> Self {
        let metrics = (0..rules.len()).map(|_| Vec::new()).collect();
        Self { rules, metrics }
    }
    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
        views: &[String],
    ) {
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            for (rule, rule_metrics) in self.rules.iter().zip(&mut self.metrics) {
                for zone in &rule.zones {
                    let metrics = RuleMetrics {
                        address,
                        zone: zone.clone(),
                        server: server.clone(),
                        registry: registry.clone(),
                        bindings: arc_swap::ArcSwap::from_pointee(Vec::new()),
                        binding_lock: Mutex::new(()),
                    };
                    if rule.class != Class::ANY && rule.qtype != Type::ANY {
                        for view in views.iter().map(String::as_str).chain([""]) {
                            metrics.binding(
                                view,
                                &rule.class.to_string(),
                                &rule.qtype.to_string(),
                                &rule.records,
                            );
                        }
                    }
                    rule_metrics.push(metrics);
                }
            }
        }
    }

    fn select<'a>(&'a self, cx: &Context<'_, '_>) -> MatchResult<'a> {
        let Some(question) = cx.query.questions().next() else {
            return MatchResult::Next;
        };
        let mut name = Text::new();
        if write!(&mut name, "{}", question.name).is_err() {
            return MatchResult::Failed;
        }
        name.bytes[..name.len].make_ascii_lowercase();
        let name = name.as_str();
        for (rule, rule_metrics) in self.rules.iter().zip(&self.metrics) {
            let Some(zone) = rule
                .zones
                .iter()
                .filter(|z| in_zone(name, z))
                .max_by_key(|z| z.len())
            else {
                continue;
            };
            if rule.class != Class::ANY
                && question.qclass != Class::ANY
                && rule.class != question.qclass
            {
                continue;
            }
            if rule.qtype != Type::ANY
                && question.qtype != Type::ANY
                && rule.qtype != question.qtype
            {
                continue;
            }
            let Some(pool) = &rule.workspace else {
                return MatchResult::Failed;
            };
            let result = pool.with(|workspace| {
                let mut matched = false;
                let RuleWorkspace {
                    matchers,
                    scratch,
                    variables,
                    matches: match_slots,
                    groups: group_slots,
                } = workspace;
                for (matcher, state) in rule.regex.iter().zip(matchers) {
                    let MatcherState { cache, captures } = state;
                    matcher.vm.captures(cache, name, captures);
                    if !captures.is_match() {
                        continue;
                    }
                    matched = true;
                    let mut matches = std::mem::take(match_slots);
                    let mut groups = std::mem::take(group_slots);
                    let mut group_count = 0;
                    for (i, slot) in matches.iter_mut().enumerate().take(captures.group_len()) {
                        *slot = captures
                            .get_group(i)
                            .and_then(|s| name.get(s.start..s.end))
                            .unwrap_or("");
                        groups[group_count] = (&matcher.numbers[i], *slot);
                        group_count += 1;
                        if let Some(Some(group)) = matcher.names.get(i) {
                            groups[group_count] = (group, *slot);
                            group_count += 1;
                        }
                    }
                    let mut class = Text::new();
                    let mut qtype = Text::new();
                    let mut remote = Text::new();
                    let qc = if question.qclass == Class::ANY {
                        rule.class
                    } else {
                        question.qclass
                    };
                    let qt = if question.qtype == Type::ANY {
                        rule.qtype
                    } else {
                        question.qtype
                    };
                    if qc == Class::ANY {
                        let _ = write!(class, "ANY");
                    } else {
                        let _ = write!(class, "{qc}");
                    }
                    let _ = write!(qtype, "{qt}");
                    if qc != Class::ANY && Class::from_mnemonic(class.as_str()).is_none() {
                        class.len = 0;
                    }
                    if Type::from_mnemonic(qtype.as_str()).is_none() {
                        qtype.len = 0;
                    }
                    let _ = write!(remote, "{}", cx.client.ip());
                    let mut data = gotemplate::Data::new(name, &cx.metadata);
                    data.zone = zone;
                    data.class = class.as_str();
                    data.qtype = qtype.as_str();
                    data.remote = remote.as_str();
                    data.regex = &matcher.source;
                    data.matches = &matches[..captures.group_len()];
                    data.groups = &groups[..group_count];
                    data.message = Some(&cx.query);
                    let metrics = rule_metrics.iter().find(|m| {
                        m.zone == *zone
                            && (m.address == cx.local
                                || m.address.ip().is_unspecified()
                                    && m.address.port() == cx.local.port())
                    });
                    let result = evaluate(rule, cx, &data, scratch, variables, metrics);
                    // Replace borrowed entries before returning storage to the worker.
                    *match_slots = matches.into_iter().map(|_| "").collect();
                    *group_slots = groups.into_iter().map(|_| ("", "")).collect();
                    return match result {
                        Ok(Some(records)) => MatchResult::Hit(Hit { rule, records }),
                        Ok(None) if rule.fallthrough.through(name) => break,
                        Ok(None) | Err(EvaluationError::Expression) => MatchResult::Failed,
                        Err(EvaluationError::Record) => MatchResult::RecordError,
                    };
                }
                if !matched && !rule.fallthrough.through(name) {
                    MatchResult::Failed
                } else {
                    MatchResult::Next
                }
            });
            if !matches!(result, MatchResult::Next) {
                return result;
            }
        }
        MatchResult::Next
    }
}

impl RuleMetrics {
    fn binding(
        &self,
        view: &str,
        class: &str,
        qtype: &str,
        records: &[TemplateRecord],
    ) -> Arc<MetricBinding> {
        let bindings = self.bindings.load();
        if let Some(binding) = bindings.iter().find(|binding| {
            binding.view == view && binding.class == class && binding.qtype == qtype
        }) {
            return Arc::clone(binding);
        }
        drop(bindings);
        let _guard = self
            .binding_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bindings = self.bindings.load();
        if let Some(binding) = bindings.iter().find(|binding| {
            binding.view == view && binding.class == class && binding.qtype == qtype
        }) {
            return Arc::clone(binding);
        }
        let matched = self
            .registry
            .template(&self.server, &self.zone, view, class, qtype);
        let failures = records
            .iter()
            .map(|record| {
                let section = match record.section {
                    Section::Answer => "answer",
                    Section::Authority => "authority",
                    Section::Additional => "additional",
                };
                matched.failure(section, &record.source)
            })
            .collect();
        let binding = Arc::new(MetricBinding {
            view: view.to_owned(),
            class: class.to_owned(),
            qtype: qtype.to_owned(),
            matched,
            failures,
        });
        let mut updated = (**bindings).clone();
        updated.push(Arc::clone(&binding));
        self.bindings.store(Arc::new(updated));
        binding
    }
}

fn evaluate<'a>(
    rule: &'a Rule,
    cx: &'a Context<'_, '_>,
    data: &'a gotemplate::Data<'a, '_>,
    scratch: &mut [u8],
    storage: &mut Vec<(&'static str, Value<'static>)>,
    metrics: Option<&RuleMetrics>,
) -> Result<Option<Vec<(Section, ZoneRecord)>>, EvaluationError> {
    let mut query = expression::Query::new(&cx.query, cx.client, cx.local, cx.protocol);
    query.groups = data.groups;
    query.matches = data.matches;
    let mut variables = std::mem::take(storage);
    let result = evaluate_slots(rule, cx, data, scratch, &query, &mut variables, metrics);
    // Replace borrowed entries before returning storage to the worker.
    *storage = variables.into_iter().map(|_| ("", Value::Nil)).collect();
    result
}

fn evaluate_slots<'a>(
    rule: &'a Rule,
    cx: &'a Context<'_, '_>,
    data: &'a gotemplate::Data<'a, '_>,
    mut scratch: &'a mut [u8],
    query: &'a expression::Query<'a>,
    variables: &mut [(&'a str, Value<'a>)],
    metrics: Option<&RuleMetrics>,
) -> Result<Option<Vec<(Section, ZoneRecord)>>, EvaluationError> {
    for (index, variable) in rule.variables.iter().enumerate() {
        let scoped = expression::ScopedQuery::new(query, &variables[..index]);
        let (value, rest) = variable
            .expression
            .evaluate_scoped_split(&scoped, &cx.metadata, scratch)
            .map_err(|_| EvaluationError::Expression)?;
        variables[index] = (&variable.name, value);
        scratch = rest;
    }
    let scoped = expression::ScopedQuery::new(query, variables);
    for expr in &rule.expressions {
        let (value, rest) = expr
            .evaluate_scoped_split(&scoped, &cx.metadata, scratch)
            .map_err(|_| EvaluationError::Expression)?;
        if value != Value::Bool(true) {
            return Ok(None);
        }
        scratch = rest;
    }
    // shortcut: new metric label combinations allocate on matched Queries; prebind when wildcard labels can be resolved at setup.
    let binding = metrics.map(|metrics| {
        metrics.binding(
            cx.metadata.metric_view(),
            data.class,
            data.qtype,
            &rule.records,
        )
    });
    if let Some(binding) = &binding {
        binding.matched.matched();
    }
    if rule.rcode == Rcode::SERVFAIL {
        return Ok(Some(Vec::new()));
    }
    let mut data = gotemplate::Data {
        name: data.name,
        zone: data.zone,
        class: data.class,
        qtype: data.qtype,
        remote: data.remote,
        regex: data.regex,
        matches: data.matches,
        groups: data.groups,
        variables,
        message: data.message,
        metadata: data.metadata,
    };
    // Rendered records are created only after every expression matches.
    data.variables = variables;
    // shortcut: rendered strings and record vectors allocate per matched Query; reuse buffers with #91.
    let mut records = Vec::new();
    for section in [Section::Answer, Section::Additional, Section::Authority] {
        for (index, record) in rule
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.section == section)
        {
            let mut output = String::new();
            record
                .compiled
                .render_with_scratch(&data, &mut output, scratch)
                .map_err(|_| {
                    if let Some(binding) = &binding {
                        binding.failures[index].render_failure();
                    }
                    EvaluationError::Record
                })?;
            // RFC 1035 §5: rendered records use zone-file presentation format.
            // shortcut: zone-text parse allocates per matched Query; see #91.
            let origin: Name = ".".parse().map_err(|_| EvaluationError::Record)?;
            let mut parser = ZoneParser::new(output.as_bytes(), origin, "template");
            parser.set_default_ttl(3600);
            let rr = parser.next().and_then(Result::ok).ok_or_else(|| {
                if let Some(binding) = &binding {
                    binding.failures[index].rr_failure();
                }
                EvaluationError::Record
            })?;
            records.push((record.section, rr));
        }
    }
    Ok(Some(records))
}

impl Plugin for Template {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let hit = match self.select(cx) {
            MatchResult::Next => return next.run(cx).await,
            MatchResult::Failed => return Outcome::Unanswered(Rcode::SERVFAIL),
            MatchResult::RecordError => {
                return Outcome::Error(Error::Build(pharos_proto::BuildError::InvalidRdata));
            }
            MatchResult::Hit(hit) => hit,
        };
        if hit.rule.rcode == Rcode::SERVFAIL {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        }
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return Outcome::Error(Error::InvalidQuery);
        };
        if hit.rule.rcode.0 > 15 && hit.rule.ederror.is_none() {
            return Outcome::Drop;
        }
        let mut lookups = Vec::new();
        for (index, (section, rr)) in hit.records.iter().enumerate() {
            if *section == Section::Answer
                && rr.rtype == Type::CNAME
                && matches!(question.qtype, Type::A | Type::AAAA)
                && let Ok(target) = NameRef::parse(&rr.rdata, 0)
            {
                // RFC 1034 §3.6.2: a CNAME answer restarts the lookup at its target.
                // shortcut: Self Lookup allocates; remove when #86 makes it allocation-free.
                if let Ok(response) = cx.self_lookup(&target.to_name(), question.qtype).await {
                    lookups.push((index, response));
                }
            }
        }
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == Protocol::Tcp {
                cx.response.reserve(max.saturating_sub(cx.response.len()));
            } else {
                return Outcome::Error(Error::ResponseBufferTooSmall);
            }
        }
        let result = (|| -> Result<(), Error> {
            // RFC 1035 §4.1.1: copy the Query ID, opcode and recursion-desired flag into the Response.
            let truncated = lookups
                .last()
                .and_then(|(_, wire)| Message::parse(wire).ok())
                .is_some_and(|message| message.tc());
            let flags = 0x8400
                | (query.flags() & 0x7800)
                | if query.opcode() == pharos_proto::Opcode::QUERY {
                    query.flags() & 0x0110
                } else {
                    0
                }
                | (hit.rule.rcode.0 & 0xf)
                | if truncated { 0x0200 } else { 0 };
            let mut builder =
                MessageBuilder::new(cx.response, max, query.id(), flags).map_err(Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
            for section in [Section::Answer, Section::Authority, Section::Additional] {
                for (index, (_, rr)) in hit
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(_, (s, _))| *s == section)
                {
                    let owner =
                        NameRef::parse(rr.owner.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
                    builder
                        .record(section, owner, rr.rtype, rr.class, rr.ttl, &rr.rdata)
                        .map_err(Error::Build)?;
                    for (_, wire) in lookups
                        .iter()
                        .filter(|(lookup_index, _)| *lookup_index == index)
                    {
                        if let Ok(response) = Message::parse(wire) {
                            for rr in response.answers() {
                                let data = rr.data().map_err(|_| Error::InvalidQuery)?;
                                builder
                                    .record_with(
                                        section,
                                        rr.name,
                                        rr.rtype,
                                        rr.class,
                                        rr.ttl,
                                        |w| data.write(w),
                                    )
                                    .map_err(Error::Build)?;
                            }
                        }
                    }
                }
            }
            if let Some((code, reason)) = &hit.rule.ederror {
                let option_len = u16::try_from(reason.len().saturating_add(2))
                    .map_err(|_| Error::ResponseBufferTooSmall)?;
                let mut ede = Vec::with_capacity(6 + reason.len());
                ede.extend_from_slice(&15u16.to_be_bytes());
                ede.extend_from_slice(&option_len.to_be_bytes());
                ede.extend_from_slice(&code.to_be_bytes());
                ede.extend_from_slice(reason.as_bytes());
                // RFC 8914 §4: Extended DNS Errors are carried as EDNS option 15.
                let root = NameRef::parse(&[0], 0).map_err(|_| Error::InvalidQuery)?;
                // RFC 6891 §6.1.3: the OPT TTL carries the upper eight RCODE bits.
                builder
                    .record(
                        Section::Additional,
                        root,
                        Type::OPT,
                        Class(4096),
                        (u32::from(hit.rule.rcode.0 >> 4) << 24) | 0x8000,
                        &ede,
                    )
                    .map_err(Error::Build)?;
            }
            let _ = builder.finish();
            Ok(())
        })();
        match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configure(
        text: &str,
    ) -> Result<Vec<pharos_corefile::BlockContext<crate::Chain>>, pharos_corefile::Error> {
        let blocks = pharos_corefile::parse("Corefile", text)?;
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives())
    }
    #[test]
    fn setup_checks_rcodes() {
        for (rcode, valid) in [
            ("NOTIMP", true),
            ("NOTIMPL", true),
            ("BADSIG", true),
            ("BADVERS", false),
        ] {
            assert_eq!(
                configure(&format!(". {{\n template IN A {{\n rcode {rcode}\n }}\n}}")).is_ok(),
                valid
            );
        }
    }
    #[test]
    fn zone_matching_respects_escaped_dots() {
        assert!(!in_zone(r"foo\.example.", "example."));
        assert!(in_zone(r"foo\\.example.", "example."));
    }
    #[test]
    fn many_function_variables_fit_a_small_worker_stack() {
        let variables = (0..400)
            .map(|i| {
                if i == 0 {
                    "var v0 name\n".to_owned()
                } else {
                    format!("var v{i} v{}\n", i - 1)
                }
            })
            .collect::<String>();
        let text = format!(
            ".:53 {{\n template IN A {{\n {variables} answer \"{{{{ .Name }}}} 60 IN TXT \\\"{{{{ call .Var.v399 }}}}\\\"\"\n }}\n}}"
        );
        let configured = configure(&text).unwrap();
        let template = configured[0].config.template.as_ref().unwrap();
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn_scoped(scope, || {
                    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
                    let root: Name = ".".parse().unwrap();
                    let mut response = Vec::with_capacity(512);
                    let mut slots = [];
                    let context = Context {
                        query: Message::parse(wire).unwrap(),
                        client: "127.0.0.1:1234".parse().unwrap(),
                        local: "127.0.0.1:53".parse().unwrap(),
                        transport: pharos_server::Transport::Dns,
                        protocol: Protocol::Udp,
                        domain: &root,
                        metadata: pharos_server::Metadata::new(&mut slots),
                        response: &mut response,
                        max_response_size: 512,
                    };
                    let MatchResult::Hit(hit) = template.select(&context) else {
                        panic!("template did not match")
                    };
                    assert_eq!(hit.records[0].1.rdata, b"\x02x.");
                })
                .unwrap()
                .join()
                .unwrap();
        });
    }
    #[test]
    fn workspace_is_stable_and_distinct_on_each_worker() {
        let configured = configure(". {\n template IN A\n}").unwrap();
        let workspace = configured[0].config.template.as_ref().unwrap().rules[0]
            .workspace
            .as_ref()
            .unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let one = scope.spawn(|| {
                workspace.with(|state| {
                    let address = std::ptr::from_ref(state) as usize;
                    barrier.wait();
                    address
                })
            });
            let two = scope.spawn(|| {
                workspace.with(|state| {
                    let address = std::ptr::from_ref(state) as usize;
                    barrier.wait();
                    address
                })
            });
            assert_ne!(one.join().unwrap(), two.join().unwrap());
        });
        let first = workspace.with(|state| std::ptr::from_ref(state) as usize);
        let second = workspace.with(|state| std::ptr::from_ref(state) as usize);
        assert_eq!(first, second);
    }
    #[test]
    fn readme_rule_workspace_payload_sizes() {
        fn payload(workspace: &RuleWorkspace) -> usize {
            use std::mem::size_of;
            size_of::<RuleWorkspace>()
                + workspace.scratch.capacity()
                + workspace.matchers.capacity() * size_of::<MatcherState>()
                + workspace.variables.capacity() * size_of::<(&str, Value<'_>)>()
                + workspace.matches.capacity() * size_of::<&str>()
                + workspace.groups.capacity() * size_of::<(&str, &str)>()
                + workspace
                    .matchers
                    .iter()
                    .map(|state| {
                        state.cache.memory_usage() + std::mem::size_of_val(state.captures.slots())
                    })
                    .sum::<usize>()
        }
        for (name, options) in [
            ("nxdomain", "rcode NXDOMAIN"),
            (
                "address",
                "match (^|[.])ip-(?P<a>[0-9]*)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$",
            ),
            (
                "reverse",
                "match ^(?P<d>[0-9]*)[.](?P<c>[0-9]*)[.](?P<b>[0-9]*)[.](?P<a>[0-9]*)[.]in-addr[.]arpa[.]$",
            ),
            (
                "hex",
                "match ^ip0a(?P<b>[a-f0-9]{2})(?P<c>[a-f0-9]{2})(?P<d>[a-f0-9]{2})[.]example[.]$",
            ),
            (
                "lan",
                "match ^(?P<ip>[0-9]{1,3}(-[0-9]{1,3}){3})[.](?P<id>[a-z2-7]{26})[.]example[.]com[.]$\nvar ip replace(group('ip'), '-', '.')",
            ),
            (
                "patterns",
                "match ^ip-(?P<a>10)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]dc[.]example[.]$\nmatch ^(?P<a>[0-9]*)[.](?P<b>[0-9]*)[.](?P<c>[0-9]*)[.](?P<d>[0-9]*)[.]ext[.]example[.]$",
            ),
        ] {
            let configured =
                configure(&format!(". {{\n template IN A {{\n {options}\n }}\n}}")).unwrap();
            let rule = &configured[0].config.template.as_ref().unwrap().rules[0];
            let bytes = rule
                .workspace
                .as_ref()
                .unwrap()
                .with(|workspace| payload(workspace));
            eprintln!("{name}: {bytes} bytes");
            assert!(bytes < 1_048_576);
        }
    }
    #[test]
    fn wildcard_metric_bindings_handle_concurrent_first_use() {
        let registry = pharos_server::metrics::Registry::default();
        let metrics = RuleMetrics {
            address: "127.0.0.1:53".parse().unwrap(),
            zone: ".".into(),
            server: "dns://127.0.0.1:53".into(),
            registry: registry.clone(),
            bindings: arc_swap::ArcSwap::from_pointee(Vec::new()),
            binding_lock: Mutex::new(()),
        };
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for i in 0..8 {
                let metrics = &metrics;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let qtype = if i % 2 == 0 { "A" } else { "AAAA" };
                    for _ in 0..20 {
                        metrics.binding("", "IN", qtype, &[]).matched.matched();
                    }
                });
            }
        });
        let mut output = String::new();
        registry.encode(&mut output);
        let lines: Vec<_> = output
            .lines()
            .filter(|line| line.starts_with("pharos_template_matches_total{"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.ends_with(" 80")), "{output}");
        metrics.binding("internal", "IN", "A", &[]);
        let _guard = metrics.binding_lock.lock().unwrap();
        assert_eq!(metrics.binding("", "IN", "A", &[]).class, "IN");
        assert_eq!(metrics.binding("internal", "IN", "A", &[]).view, "internal");
    }
    #[tokio::test]
    async fn wildcard_metrics_use_actual_question_labels() {
        let mut config = configure(". {\n template ANY ANY {\n rcode NXDOMAIN\n }\n}").unwrap();
        let registry = pharos_server::metrics::Registry::default();
        let local = "127.0.0.1:53".parse().unwrap();
        config[0].config.template.as_mut().unwrap().set_metrics(
            &registry,
            &[pharos_server::ListenerKey {
                transport: pharos_server::Transport::Dns,
                address: local,
            }],
            &[],
        );
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x10\0\x03";
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "192.0.2.1:1234".parse().unwrap(),
            local,
            transport: pharos_server::Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: pharos_server::Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(config[0].config.serve(&mut cx).await, Outcome::Response);
        let mut metrics = String::new();
        registry.encode(&mut metrics);
        let line = metrics
            .lines()
            .find(|line| line.starts_with("pharos_template_matches_total{"))
            .unwrap();
        assert!(
            line.contains("class=\"CH\"") && line.contains("type=\"TXT\""),
            "{line}"
        );
    }
    #[tokio::test]
    async fn record_errors_are_observable_but_expression_errors_are_unanswered() {
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
        let domain: Name = ".".parse().unwrap();
        for (option, expected) in [
            (
                "answer \"invalid record\"",
                Outcome::Error(Error::Build(pharos_proto::BuildError::InvalidRdata)),
            ),
            (
                "answer \"{{ .Missing }}\"",
                Outcome::Error(Error::Build(pharos_proto::BuildError::InvalidRdata)),
            ),
            (
                "expr incidr('notanip', '10.0.0.0/8')",
                Outcome::Unanswered(Rcode::SERVFAIL),
            ),
        ] {
            let config =
                configure(&format!(". {{\n template IN A {{\n {option}\n }}\n}}")).unwrap();
            let mut response = Vec::with_capacity(512);
            let mut slots = [];
            let mut cx = Context {
                query: Message::parse(wire).unwrap(),
                client: "192.0.2.1:1234".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: pharos_server::Transport::Dns,
                protocol: Protocol::Udp,
                domain: &domain,
                metadata: pharos_server::Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            assert_eq!(config[0].config.serve(&mut cx).await, expected);
        }
    }
    #[tokio::test]
    async fn extended_rcode_requires_opt_and_encodes_high_bits() {
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
        let domain: Name = ".".parse().unwrap();
        for (option, expected) in [("", Outcome::Drop), ("ederror 21", Outcome::Response)] {
            let config = configure(&format!(
                ". {{\n template IN A {{\n rcode BADKEY\n {option}\n }}\n}}"
            ))
            .unwrap();
            let mut response = Vec::with_capacity(512);
            let mut slots = [];
            let mut cx = Context {
                query: Message::parse(wire).unwrap(),
                client: "192.0.2.1:1234".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: pharos_server::Transport::Dns,
                protocol: Protocol::Udp,
                domain: &domain,
                metadata: pharos_server::Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            assert_eq!(config[0].config.serve(&mut cx).await, expected);
            if expected == Outcome::Response {
                assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::BADKEY);
            }
        }
    }
}
