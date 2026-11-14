use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use pharos_proto::{Message, Name, NameRef, Opcode, Type};

use crate::{
    Chain, ListenerKey, Protocol,
    metrics::{BlockMetrics, DynamicBlockMetrics, PluginMetrics, Registry},
};

/// A View filter receives the Query and client information without allocating.
pub type ViewFilter = fn(&Message<'_>, SocketAddr, Protocol) -> bool;

/// A Domain's Plugin Chain and its ordered View filters.
pub struct ServerBlock<C> {
    domain: Name,
    chain: Option<C>,
    filters: Vec<ViewFilter>,
    metrics: Option<BlockMetrics>,
    dynamic_metrics: Option<Arc<DynamicBlockMetrics>>,
    plugin_metrics: Vec<(&'static str, PluginMetrics)>,
    plugin_names: Vec<&'static str>,
    inherited_metrics: Vec<InheritedMetrics>,
}

struct InheritedMetrics {
    view: String,
    block: BlockMetrics,
    dynamic: Option<Arc<DynamicBlockMetrics>>,
    plugins: Vec<(&'static str, PluginMetrics)>,
}

impl<C> ServerBlock<C> {
    pub fn domain(&self) -> &Name {
        &self.domain
    }
    pub fn chain(&self) -> Option<&C> {
        self.chain.as_ref()
    }
    pub(crate) fn matches_filters(
        &self,
        query: &Message<'_>,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> bool {
        self.filters
            .iter()
            .all(|filter| filter(query, peer, protocol))
    }
    pub(crate) fn metrics(&self, view: &str) -> Option<&BlockMetrics> {
        self.inherited_metrics
            .iter()
            .find(|metrics| metrics.view == view)
            .map(|metrics| &metrics.block)
            .or(self.metrics.as_ref())
    }
    pub(crate) fn plugin_metrics(&self, name: &str, view: &str) -> Option<&PluginMetrics> {
        self.inherited_metrics
            .iter()
            .find(|metrics| metrics.view == view)
            .map_or(&self.plugin_metrics, |metrics| &metrics.plugins)
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, metrics)| metrics)
    }
    pub(crate) fn dynamic_metrics(&self, view: &str) -> Option<&DynamicBlockMetrics> {
        let default = self.dynamic_metrics.as_deref()?;
        self.inherited_metrics
            .iter()
            .find(|metrics| metrics.view == view)
            .map_or(Some(default), |metrics| metrics.dynamic.as_deref())
    }
    pub(crate) fn plugin_name(&self, name: &str) -> Option<&'static str> {
        self.plugin_names
            .iter()
            .copied()
            .find(|candidate| *candidate == name)
    }
}

/// Server Blocks grouped by their Listener and ordered by Domain specificity.
pub struct Router<C> {
    listeners: HashMap<ListenerKey, Vec<ServerBlock<C>>>,
    metric_contexts: HashMap<ListenerKey, MetricContext<C>>,
}

struct MetricContext<C> {
    registry: Registry,
    server: String,
    prepare: fn(&mut [ServerBlock<C>], &Registry, &str),
    has_view: fn(&ServerBlock<C>) -> bool,
    views: Arc<AtomicBool>,
}

impl<C> Default for Router<C> {
    fn default() -> Self {
        Self {
            listeners: HashMap::new(),
            metric_contexts: HashMap::new(),
        }
    }
}

impl<C> Router<C> {
    pub fn add(
        &mut self,
        key: ListenerKey,
        domain: Name,
        chain: Option<C>,
        filters: Vec<ViewFilter>,
    ) {
        let block = ServerBlock {
            domain,
            chain,
            filters,
            metrics: None,
            dynamic_metrics: None,
            plugin_metrics: Vec::new(),
            plugin_names: Vec::new(),
            inherited_metrics: Vec::new(),
        };
        let blocks = self.listeners.entry(key).or_default();
        blocks.push(block);
        blocks.sort_by_key(|block| std::cmp::Reverse(block.domain.label_count()));
        if let Some(context) = self.metric_contexts.get_mut(&key) {
            if blocks.iter().any(context.has_view) {
                context.views.store(true, Ordering::Relaxed);
            }
            (context.prepare)(blocks, &context.registry, &context.server);
        }
    }

    /// Select a Server Block, or return None when the Query must be refused.
    pub fn route(
        &self,
        key: &ListenerKey,
        query: Message<'_>,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Option<&ServerBlock<C>> {
        self.route_with::<false>(key, query, |block| {
            block.matches_filters(&query, peer, protocol)
        })
    }

    pub(crate) fn route_with<'a, const VIEW: bool>(
        &'a self,
        key: &ListenerKey,
        query: Message<'_>,
        mut matches: impl FnMut(&'a ServerBlock<C>) -> bool,
    ) -> Option<&'a ServerBlock<C>> {
        let question = query.questions().next()?;
        let blocks = self.listeners.get(key)?;
        // RFC 4035 §3.1.4.1: Answer DS queries at a zone cut from the parent zone's side.
        let ds = query.opcode() == Opcode::QUERY && question.qtype == Type::DS;
        let labels = question.name.labels().count();
        if VIEW && labels == 0 {
            let mut selected = None;
            for block in blocks
                .iter()
                .filter(|block| block.domain.label_count() == 0)
            {
                block.chain.as_ref()?;
                if matches(block) {
                    if !ds {
                        return Some(block);
                    }
                    selected = Some(block);
                }
            }
            return selected;
        }
        let mut selected = None;
        // RFC 1034 §4.3.2: Select the nearest ancestor zone for QNAME.
        for block in blocks
            .iter()
            .filter(|block| block.domain.label_count() != 0)
        {
            let count = block.domain.label_count();
            if count > labels {
                continue;
            }
            let domain = NameRef::parse(block.domain.as_wire(), 0).expect("validated Domain");
            // RFC 4343 §3: DNS lookup compares ASCII letters case-insensitively.
            if !question
                .name
                .labels()
                .skip(labels - count)
                .zip(domain.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                continue;
            }
            block.chain.as_ref()?;
            if matches(block) {
                if !ds {
                    return Some(block);
                }
                selected = Some(block);
            }
        }
        if selected.is_some() {
            return selected;
        }
        blocks
            .iter()
            .filter(|block| block.domain.label_count() == 0 && block.chain.is_some())
            .find(|block| matches(block))
    }
}

impl<C: Chain> Router<C> {
    pub(crate) fn accepts_update(&self, key: &ListenerKey) -> bool {
        self.listeners.get(key).is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| block.chain.as_ref().is_some_and(Chain::accepts_update))
        })
    }

    pub(crate) fn shed_enabled(&self, key: &ListenerKey) -> bool {
        self.listeners.get(key).is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| block.chain.as_ref().is_some_and(Chain::shed_enabled))
        })
    }
    pub(crate) fn metrics_enabled(&self, key: &ListenerKey) -> bool {
        self.listeners.get(key).is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| block.chain.as_ref().is_some_and(Chain::metrics_enabled))
        })
    }
    pub(crate) fn prepare_metrics(
        &mut self,
        key: &ListenerKey,
        registry: &Registry,
        server: &str,
    ) -> Arc<AtomicBool> {
        let views = Arc::new(AtomicBool::new(self.listeners.get(key).is_some_and(
            |blocks| {
                blocks
                    .iter()
                    .any(|block| block.chain.as_ref().is_some_and(Chain::has_view))
            },
        )));
        self.metric_contexts.insert(
            *key,
            MetricContext {
                registry: registry.clone(),
                server: server.to_owned(),
                prepare: prepare_blocks::<C>,
                has_view: |block| block.chain.as_ref().is_some_and(Chain::has_view),
                views: Arc::clone(&views),
            },
        );
        if let Some(blocks) = self.listeners.get_mut(key) {
            prepare_blocks(blocks, registry, server);
        }
        views
    }
}

fn prepare_blocks<C: Chain>(blocks: &mut [ServerBlock<C>], registry: &Registry, server: &str) {
    let has_views = blocks
        .iter()
        .any(|block| block.chain.as_ref().is_some_and(Chain::has_view));
    for index in 0..blocks.len() {
        let (previous, rest) = blocks.split_at_mut(index);
        let block = &mut rest[0];
        prepare_block(block, registry, server);
        block.inherited_metrics.clear();
        if !has_views
            || block.metrics.is_none()
            || block
                .chain
                .as_ref()
                .is_none_or(|chain| !chain.view_name().is_empty())
        {
            continue;
        }
        let parent = NameRef::parse(block.domain.as_wire(), 0).expect("validated Domain");
        let parent_labels = block.domain.label_count();
        for candidate in previous {
            let Some(chain) = &candidate.chain else {
                continue;
            };
            let name = chain.view_name();
            let count = candidate.domain.label_count();
            if name.is_empty() || (parent_labels == 0 && count != 0) || count < parent_labels {
                continue;
            }
            let child = NameRef::parse(candidate.domain.as_wire(), 0).expect("validated Domain");
            // RFC 4343 §3: DNS lookup compares ASCII letters case-insensitively.
            if !child
                .labels()
                .skip(count - parent_labels)
                .zip(parent.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
                || block
                    .inherited_metrics
                    .iter()
                    .any(|metrics| metrics.view == name)
            {
                continue;
            }
            // CoreDNS core/dnsserver/server.go: DS retains the last matching nonempty ViewName.
            let metrics = registry.block(server, &block.domain.to_string(), name);
            let plugins = block
                .plugin_names
                .iter()
                .map(|&plugin| (plugin, metrics.plugin(plugin)))
                .collect();
            block.inherited_metrics.push(InheritedMetrics {
                view: name.to_owned(),
                block: metrics,
                dynamic: block
                    .chain
                    .as_ref()
                    .and_then(|chain| chain.dynamic_metric_zones())
                    .map(|zones| {
                        zones.bind(registry, server, name, &block.domain, &block.plugin_names)
                    }),
                plugins,
            });
        }
    }
}

fn prepare_block<C: Chain>(block: &mut ServerBlock<C>, registry: &Registry, server: &str) {
    block.plugin_metrics.clear();
    block.plugin_names.clear();
    if let Some(chain) = &block.chain {
        if chain.stacktrace() {
            crate::panic::prepare_stacktrace();
        }
        let metrics = chain
            .metrics_enabled()
            .then(|| registry.block(server, &block.domain.to_string(), chain.view_name()));
        chain.visit_enabled(&mut |name| {
            block.plugin_names.push(name);
            if let Some(metrics) = &metrics {
                metrics.plugin_enabled(name);
                block.plugin_metrics.push((name, metrics.plugin(name)));
            }
        });
        block.dynamic_metrics = metrics
            .as_ref()
            .and_then(|_| chain.dynamic_metric_zones())
            .map(|zones| {
                zones.bind(
                    registry,
                    server,
                    chain.view_name(),
                    &block.domain,
                    &block.plugin_names,
                )
            });
        block.metrics = metrics;
    }
}
