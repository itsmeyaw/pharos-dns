use std::{collections::HashMap, net::SocketAddr};

use pharos_proto::{Message, Name, NameRef, Opcode, Type};

use crate::{ListenerKey, Protocol};

/// A View filter receives the Query and client information without allocating.
pub type ViewFilter = fn(&Message<'_>, SocketAddr, Protocol) -> bool;

/// A Domain's Plugin Chain and its ordered View filters.
pub struct ServerBlock<C> {
    domain: Name,
    chain: Option<C>,
    filters: Vec<ViewFilter>,
}

impl<C> ServerBlock<C> {
    pub fn domain(&self) -> &Name {
        &self.domain
    }
    pub fn chain(&self) -> Option<&C> {
        self.chain.as_ref()
    }
}

/// Server Blocks grouped by their Listener and ordered by Domain specificity.
pub struct Router<C> {
    listeners: HashMap<ListenerKey, Vec<ServerBlock<C>>>,
}

impl<C> Default for Router<C> {
    fn default() -> Self {
        Self {
            listeners: HashMap::new(),
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
        let blocks = self.listeners.entry(key).or_default();
        blocks.push(ServerBlock {
            domain,
            chain,
            filters,
        });
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
            if !question
                .name
                .labels()
                .skip(labels - count)
                .zip(domain.labels())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                continue;
            }
            if block.chain.is_none() {
                return None;
            }
            if block
                .filters
                .iter()
                .all(|filter| filter(&query, peer, protocol))
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
            })
    }
}
