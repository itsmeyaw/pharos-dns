use std::{collections::HashMap, net::SocketAddr};

use pharos_proto::{Message, Name, NameRef, Opcode, Type};

use crate::{
    Chain, ListenerKey, Protocol,
    metrics::{BlockMetrics, PluginMetrics, Registry},
};

/// A View filter receives the Query and client information without allocating.
pub type ViewFilter = fn(&Message<'_>, SocketAddr, Protocol) -> bool;

/// A Domain's Plugin Chain and its ordered View filters.
pub struct ServerBlock<C> {
    domain: Name,
    chain: Option<C>,
    filters: Vec<ViewFilter>,
    metrics: Option<BlockMetrics>,
    plugin_metrics: Vec<(&'static str, PluginMetrics)>,
    plugin_names: Vec<&'static str>,
}

impl<C> ServerBlock<C> {
    pub fn domain(&self) -> &Name {
        &self.domain
    }
    pub fn chain(&self) -> Option<&C> {
        self.chain.as_ref()
    }
    pub(crate) fn metrics(&self) -> Option<&BlockMetrics> {
        self.metrics.as_ref()
    }
    pub(crate) fn plugin_metrics(&self, name: &str) -> Option<&PluginMetrics> {
        self.plugin_metrics
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, metrics)| metrics)
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
    prepare: fn(&mut ServerBlock<C>, &Registry, &str),
    has_view: fn(&ServerBlock<C>) -> bool,
    views: bool,
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
        let mut block = ServerBlock {
            domain,
            chain,
            filters,
            metrics: None,
            plugin_metrics: Vec::new(),
            plugin_names: Vec::new(),
        };
        if let Some(context) = self.metric_contexts.get_mut(&key) {
            (context.prepare)(&mut block, &context.registry, &context.server);
            context.views |= (context.has_view)(&block);
        }
        let blocks = self.listeners.entry(key).or_default();
        blocks.push(block);
        blocks.sort_by_key(|block| std::cmp::Reverse(block.domain.label_count()));
    }

    /// Select a Server Block, or return None when the Query must be refused.
    pub fn route(
        &self,
        key: &ListenerKey,
        query: Message<'_>,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Option<&ServerBlock<C>> {
        self.route_with(key, query, peer, protocol, |_| true)
    }

    pub(crate) fn route_with(
        &self,
        key: &ListenerKey,
        query: Message<'_>,
        peer: SocketAddr,
        protocol: Protocol,
        mut matches: impl FnMut(&ServerBlock<C>) -> bool,
    ) -> Option<&ServerBlock<C>> {
        let question = query.questions().next()?;
        let blocks = self.listeners.get(key)?;
        let ds = query.opcode() == Opcode::QUERY && question.qtype == Type::DS;
        let labels = question.name.labels().count();
        let mut selected = None;
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
            if block
                .filters
                .iter()
                .all(|filter| filter(&query, peer, protocol))
                && matches(block)
            {
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
            .find(|block| {
                block
                    .filters
                    .iter()
                    .all(|filter| filter(&query, peer, protocol))
                    && matches(block)
            })
    }
}

impl<C: Chain> Router<C> {
    pub(crate) fn has_views(&self, key: &ListenerKey) -> bool {
        self.metric_contexts.get(key).is_some_and(|context| context.views)
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
    pub(crate) fn prepare_metrics(&mut self, key: &ListenerKey, registry: &Registry, server: &str) {
        self.metric_contexts.insert(
            *key,
            MetricContext {
                registry: registry.clone(),
                server: server.to_owned(),
                prepare: prepare_block::<C>,
                has_view: |block| block.chain.as_ref().is_some_and(|chain| !chain.view_name().is_empty()),
                views: self.listeners.get(key).is_some_and(|blocks| blocks.iter().any(|block| block.chain.as_ref().is_some_and(|chain| !chain.view_name().is_empty()))),
            },
        );
        if let Some(blocks) = self.listeners.get_mut(key) {
            for block in blocks {
                prepare_block(block, registry, server);
            }
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
        block.metrics = metrics;
    }
}
