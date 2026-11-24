//! Record lookup over the etcd view.
//!
//! Ported from CoreDNS v1.15.0 plugin/backend_lookup.go and the `Services` and `Records` of
//! plugin/etcd/etcd.go. The lookups return records; `Etcd::serve` writes the Response.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use pharos_proto::{BuildError, Class, Message, MessageBuilder, Name, Section, Type};
use pharos_server::Context;

use super::{
    Etcd,
    msg::{self, HostType, Service},
    scratch,
    view::{CachedRecords, Error as ViewError, Record},
};

/// CoreDNS v1.15.0 plugin/backend_lookup.go `maxCnameChainLength`.
const MAX_CNAME_CHAIN_LENGTH: usize = 10;

/// The octets `apex.dns` adds to the wire form of the zone name.
const APEX_WIRE_LEN: usize = 9;

/// Why a lookup found nothing to answer with.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Failure {
    /// CoreDNS v1.15.0 plugin/etcd/etcd.go `errKeyNotFound`: NXDOMAIN, or the next Plugin.
    NameError,
    /// Anything else: SERVFAIL.
    Other,
}

type Found<T> = Result<T, Failure>;

/// A record to write, kept apart from the wire so names can be chased before the Response is built.
#[derive(Debug)]
pub(super) struct Rr {
    pub name: Name,
    pub ttl: u32,
    pub data: Data,
}

#[derive(Debug)]
pub(super) enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    /// RDATA: the character-strings.
    Txt(Vec<u8>),
    Ptr(Name),
    Ns(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    /// The `index`th answer of a Response to a Self Lookup.
    Foreign {
        wire: Arc<Vec<u8>>,
        index: usize,
        rtype: Type,
        class: Class,
    },
}

impl Rr {
    fn new(name: &Name, ttl: u32, data: Data) -> Self {
        Self {
            name: name.clone(),
            ttl,
            data,
        }
    }

    fn is_cname(&self) -> bool {
        matches!(
            self.data,
            Data::Cname(_)
                | Data::Foreign {
                    rtype: Type::CNAME,
                    ..
                }
        )
    }

    /// Add the record to `section`; `false` when the Response is full.
    pub(super) fn write(
        &self,
        builder: &mut MessageBuilder<'_>,
        section: Section,
    ) -> Result<bool, BuildError> {
        let owner = self.name.as_name_ref();
        let (ttl, class) = (self.ttl, Class::IN);
        match &self.data {
            // RFC 1035 §3.4.1 and RFC 3596 §2.2: address records hold the address in network order.
            Data::A(ip) => builder.record(section, owner, Type::A, class, ttl, &ip.octets()),
            Data::Aaaa(ip) => builder.record(section, owner, Type::AAAA, class, ttl, &ip.octets()),
            // RFC 1035 §3.3.14: TXT RDATA is one or more character-strings.
            Data::Txt(text) => builder.record(section, owner, Type::TXT, class, ttl, text),
            // RFC 1035 §3.3.1, §3.3.11 and §3.3.12: the RDATA is a domain name.
            Data::Cname(name) => {
                builder.record_with(section, owner, Type::CNAME, class, ttl, |w| {
                    w.write_name(name.as_name_ref())
                })
            }
            Data::Ptr(name) => builder.record_with(section, owner, Type::PTR, class, ttl, |w| {
                w.write_name(name.as_name_ref())
            }),
            Data::Ns(name) => builder.record_with(section, owner, Type::NS, class, ttl, |w| {
                w.write_name(name.as_name_ref())
            }),
            // RFC 1035 §3.3.9: MX RDATA is the preference and the exchange.
            Data::Mx {
                preference,
                exchange,
            } => builder.record_with(section, owner, Type::MX, class, ttl, |w| {
                w.write_bytes(&preference.to_be_bytes())?;
                w.write_name(exchange.as_name_ref())
            }),
            // RFC 2782 §The format of the SRV RR: the target is not compressed.
            Data::Srv {
                priority,
                weight,
                port,
                target,
            } => builder.record_with(section, owner, Type::SRV, class, ttl, |w| {
                w.write_bytes(&priority.to_be_bytes())?;
                w.write_bytes(&weight.to_be_bytes())?;
                w.write_bytes(&port.to_be_bytes())?;
                w.write_uncompressed_name(target.as_name_ref())
            }),
            Data::Foreign {
                wire,
                index,
                rtype,
                class,
            } => {
                let Ok(message) = Message::parse(wire) else {
                    return Ok(true);
                };
                let Some(Ok(data)) = message.answers().nth(*index).map(|record| record.data())
                else {
                    return Ok(true);
                };
                builder.record_with(section, owner, *rtype, *class, ttl, |w| data.write(w))
            }
        }
    }
}

/// What the Query asks about: CoreDNS `request.Request`'s `QName`, `Name` and `QType`.
#[derive(Clone, Debug)]
pub(super) struct Query {
    /// The name as asked, in the case asked.
    pub owner: Name,
    /// The name lowercased: the key into etcd.
    pub key: String,
    pub qtype: Type,
}

impl Query {
    pub(super) fn new(owner: Name, qtype: Type) -> Self {
        Self {
            key: owner.canonical(),
            owner,
            qtype,
        }
    }
}

/// The Records of a lookup that found some.
#[derive(Debug, Default)]
pub(super) struct Answer {
    pub records: Vec<Rr>,
    pub extra: Vec<Rr>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    A,
    Aaaa,
    Txt,
}

/// The answers of a Self Lookup.
struct Foreign {
    answers: Vec<Rr>,
    truncated: bool,
}

/// The services at one name that a lookup works with, borrowed from the view.
///
/// CoreDNS v1.15.0 plugin/etcd/etcd.go `Services`: what etcd holds at the name, of one group.
pub(super) struct Services {
    found: Arc<CachedRecords>,
    qtype: Type,
    /// The key path of a name with a wildcard, which the keys found must match.
    // shortcut: a wildcard name allocates its path on each Query; wildcard Queries are rare, borrow it from a pooled buffer if they get hot.
    wildcard: Option<Box<str>>,
    /// The group the services are cut to; allocated only for services that have a group.
    group: Option<Box<str>>,
}

impl Services {
    fn new(found: Arc<CachedRecords>, qtype: Type, wildcard: Option<Box<str>>) -> Found<Self> {
        let mut services = Self {
            found,
            qtype,
            wildcard,
            group: None,
        };
        // CoreDNS v1.15.0 plugin/etcd/etcd.go `loopNodes`: a value that is not a service fails the lookup.
        if services.found.records.iter().any(|record| {
            matches!(record, Record::Invalid { .. }) && services.key_matches(record.key())
        }) {
            return Err(Failure::Other);
        }
        // CoreDNS v1.15.0 plugin/etcd/msg/service.go `Group`: keep one group of the services.
        services.group = msg::chosen_group(services.matching()).map(Box::from);
        Ok(services)
    }

    /// CoreDNS v1.15.0 plugin/etcd/etcd.go `loopNodes`: a wildcard name keeps the keys it matches.
    fn key_matches(&self, key: &str) -> bool {
        self.wildcard
            .as_deref()
            .is_none_or(|full| wildcard_matches(key, full))
    }

    /// The services before the group is chosen.
    fn matching(&self) -> impl Iterator<Item = &Service> + Clone {
        self.found.records.iter().filter_map(|record| match record {
            Record::Service(service)
                if self.key_matches(&service.key) && should_include(service, self.qtype) =>
            {
                Some(service)
            }
            _ => None,
        })
    }

    /// The services of the lookup, in key order.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Service> + Clone {
        let group = self.group.as_deref();
        self.matching()
            .filter(move |s| group.is_none_or(|g| s.group.is_empty() || s.group == g))
    }
}

/// One lookup of the `etcd` Plugin in `zone`.
pub(super) struct Lookup<'a, 'q, 'c> {
    pub etcd: &'a Etcd,
    pub cx: &'a Context<'q, 'c>,
    pub zone: &'a Name,
    /// `zone` lowercased.
    pub zone_key: &'a str,
}

impl Lookup<'_, '_, '_> {
    /// CoreDNS v1.15.0 plugin/etcd/handler.go `ServeDNS`: the etcd read that starts the lookup for the
    /// type asked at `key`, the name lowercased. `None` when the lookup starts without one.
    pub(super) async fn first(&self, key: &str, qtype: Type) -> Found<Option<Services>> {
        match qtype {
            Type::SOA => Ok(None),
            // CoreDNS v1.15.0 plugin/etcd/handler.go: NS is answered at the zone apex only.
            Type::NS if key == self.zone_key => Ok(None),
            Type::TXT | Type::MX | Type::SRV => self.services_at(key, qtype, false).await.map(Some),
            Type::CNAME | Type::PTR => self.services_at(key, qtype, true).await.map(Some),
            // CoreDNS v1.15.0 plugin/etcd/handler.go: a fake A lookup tells NODATA from NXDOMAIN.
            _ => self.apex_services(key, qtype).await.map(Some),
        }
    }

    /// CoreDNS v1.15.0 plugin/etcd/handler.go `ServeDNS`: the lookup for the type asked, given what
    /// [`Self::first`] read.
    pub(super) async fn answer(&self, q: &Query, first: Option<Services>) -> Found<Answer> {
        let mut answer = Answer::default();
        let Some(services) = first else {
            // Only NS at the zone apex starts without services; SOA is written without a lookup.
            if q.qtype == Type::NS {
                (answer.records, answer.extra) = self.ns(q).await?;
            }
            return Ok(answer);
        };
        match q.qtype {
            Type::A | Type::AAAA | Type::TXT => {
                let kind = match q.qtype {
                    Type::A => Kind::A,
                    Type::AAAA => Kind::Aaaa,
                    _ => Kind::Txt,
                };
                (answer.records, answer.truncated) =
                    self.address(kind, q, &[], Some(services)).await?;
            }
            Type::CNAME => answer.records = self.cname(q, &services),
            Type::PTR => answer.records = self.ptr(q, &services),
            Type::MX => (answer.records, answer.extra) = self.mx(q, &services).await,
            Type::SRV => (answer.records, answer.extra) = self.srv(q, &services).await,
            _ => {
                self.address(Kind::A, q, &[], Some(services)).await?;
            }
        }
        Ok(answer)
    }

    /// CoreDNS v1.15.0 plugin/etcd/etcd.go `Services`: what etcd holds at the name, of one group.
    async fn services_at(&self, key: &str, qtype: Type, exact: bool) -> Found<Services> {
        let prefix = &self.etcd.config.path_prefix;
        let mut path = scratch::lease();
        let star = msg::path_with_wildcard_into(&mut path, key, prefix);
        // CoreDNS v1.15.0 plugin/etcd/etcd.go `Records`: a read error is NXDOMAIN only when no key is found.
        let found = match self.etcd.view.get(&path, !exact).await {
            Ok(found) => found,
            Err(ViewError::KeyNotFound) => return Err(Failure::NameError),
            Err(ViewError::Client(_)) => return Err(Failure::Other),
        };
        let wildcard = star.then(|| msg::path(key, prefix).into_boxed_str());
        Services::new(found, qtype, wildcard)
    }

    /// A Query for `prefix` under the zone, like the fake names of CoreDNS `NS`.
    fn under_zone(&self, q: &Query, prefix: &str) -> Found<Query> {
        let owner = Name::parse(prefix, self.zone).map_err(|_| Failure::Other)?;
        Ok(Query::new(owner, q.qtype))
    }

    /// CoreDNS v1.15.0 plugin/backend_lookup.go `checkForApex`.
    async fn apex_services(&self, key: &str, qtype: Type) -> Found<Services> {
        if key != self.zone_key {
            return self.services_at(key, qtype, false).await;
        }
        // RFC 1035 §2.3.4: a name is at most 255 octets, so the zone must leave room for `apex.dns`.
        if self.zone.as_wire().len() + APEX_WIRE_LEN > 255 {
            return Err(Failure::Other);
        }
        // The zone name itself is answered from the special `apex.dns` entry.
        let mut apex = scratch::lease();
        apex.push_str("apex.dns.");
        if self.zone_key != "." {
            apex.push_str(self.zone_key);
        }
        match self.services_at(&apex, qtype, false).await {
            // Without `no_apex_fallback` the entries under the zone name serve when `apex.dns` is absent.
            Err(Failure::NameError) if !self.etcd.config.no_apex_fallback => {
                self.services_at(key, qtype, false).await
            }
            other => other,
        }
    }

    /// The A, AAAA or TXT records at `q`, with the CNAMEs chased to them, and whether one is truncated.
    ///
    /// CoreDNS v1.15.0 plugin/backend_lookup.go `A`, `AAAA` and `TXT`, which differ in what they keep.
    /// `previous` holds the targets of the CNAMEs followed so far; `preloaded` the services at `q`
    /// when they were read already.
    async fn address(
        &self,
        kind: Kind,
        q: &Query,
        previous: &[Name],
        preloaded: Option<Services>,
    ) -> Found<(Vec<Rr>, bool)> {
        let services = match preloaded {
            Some(services) => services,
            None if kind == Kind::Txt => self.services_at(&q.key, q.qtype, false).await?,
            None => self.apex_services(&q.key, q.qtype).await?,
        };
        let (mut records, mut truncated) = (Vec::new(), false);
        let mut dup = HashSet::new();
        for service in services.iter() {
            match (service.host_type(), kind) {
                (HostType::Cname, _) => {
                    let Some(target) = fqdn_name(&service.host) else {
                        continue;
                    };
                    // CoreDNS v1.15.0 plugin/backend_lookup.go: a CNAME to the name itself or below it is a direct loop.
                    if target.is_subdomain_of(&q.owner) {
                        continue;
                    }
                    // CoreDNS v1.15.0 plugin/backend_lookup.go: a chain is at most `maxCnameChainLength` long and never repeats.
                    if previous.len() > MAX_CNAME_CHAIN_LENGTH || previous.contains(&target) {
                        continue;
                    }
                    let cname = Rr::new(&q.owner, service.ttl, Data::Cname(target.clone()));
                    if target.is_subdomain_of(self.zone) {
                        // CoreDNS v1.15.0 plugin/backend_lookup.go: a target in the zone is looked up here.
                        let next = Query::new(target.clone(), q.qtype);
                        let chain = [previous, std::slice::from_ref(&target)].concat();
                        if let Ok((found, tc)) =
                            Box::pin(self.address(kind, &next, &chain, None)).await
                        {
                            truncated |= tc;
                            if !found.is_empty() {
                                records.push(cname);
                                records.extend(found);
                            }
                        }
                        continue;
                    }
                    // CoreDNS v1.15.0 plugin/backend_lookup.go: a target elsewhere is looked up through the Server.
                    let Some(found) = self.foreign(&target, q.qtype).await else {
                        continue;
                    };
                    // CoreDNS v1.15.0 plugin/backend_lookup.go `TXT`: only `A` and `AAAA` carry TC over.
                    truncated |= found.truncated && kind != Kind::Txt;
                    records.push(cname);
                    records.extend(found.answers);
                }
                // CoreDNS v1.15.0 plugin/backend_lookup.go: one record per distinct host.
                (HostType::A(ip), Kind::A) if dup.insert(service.host.as_str()) => {
                    records.push(Rr::new(&q.owner, service.ttl, Data::A(ip)));
                }
                (HostType::Aaaa(ip), Kind::Aaaa) if dup.insert(service.host.as_str()) => {
                    records.push(Rr::new(&q.owner, service.ttl, Data::Aaaa(ip)));
                }
                // CoreDNS v1.15.0 plugin/backend_lookup.go `TXT`: one record per distinct text.
                (HostType::Txt, Kind::Txt) if dup.insert(service.text.as_str()) => {
                    records.push(Rr::new(
                        &q.owner,
                        service.ttl,
                        Data::Txt(txt_rdata(&service.text)),
                    ));
                }
                _ => {}
            }
        }
        Ok((records, truncated))
    }

    /// CoreDNS v1.15.0 plugin/backend_lookup.go `CNAME`.
    fn cname(&self, q: &Query, services: &Services) -> Vec<Rr> {
        // Only the first service answers, and only when its host is a name.
        services
            .iter()
            .next()
            .filter(|service| service.host.parse::<IpAddr>().is_err())
            .and_then(|service| {
                let target = fqdn_name(&service.host)?;
                Some(Rr::new(&q.owner, service.ttl, Data::Cname(target)))
            })
            .into_iter()
            .collect()
    }

    /// CoreDNS v1.15.0 plugin/backend_lookup.go `PTR`: services whose host is a name.
    fn ptr(&self, q: &Query, services: &Services) -> Vec<Rr> {
        let mut dup = HashSet::new();
        let mut records = Vec::new();
        for service in services.iter() {
            if service.host.parse::<IpAddr>().is_err()
                && dup.insert(service.host.as_str())
                && let Some(target) = fqdn_name(&service.host)
            {
                records.push(Rr::new(&q.owner, service.ttl, Data::Ptr(target)));
            }
        }
        records
    }

    /// CoreDNS v1.15.0 plugin/backend_lookup.go `NS`: the nameservers live at `ns.dns.ZONE`.
    async fn ns(&self, q: &Query) -> Found<(Vec<Rr>, Vec<Rr>)> {
        let fake = self.under_zone(q, "ns.dns")?;
        let services = self.services_at(&fake.key, q.qtype, false).await?;
        let (mut records, mut extra) = (Vec::new(), Vec::new());
        let mut seen = HashSet::new();
        for service in services.iter() {
            let host_type = service.host_type();
            match host_type {
                // CoreDNS v1.15.0 plugin/backend_lookup.go `NS`: a nameserver is an address, not a name.
                HostType::Cname => return Err(Failure::Other),
                HostType::A(_) | HostType::Aaaa(_) => {
                    let Some(ns) = target_name(&msg::domain(&service.key), service.target_strip)
                    else {
                        continue;
                    };
                    extra.extend(address_rr(&ns, service.ttl, host_type));
                    if seen.insert(ns.clone()) {
                        records.push(Rr::new(&q.owner, service.ttl, Data::Ns(ns)));
                    }
                }
                HostType::Txt => {}
            }
        }
        Ok((records, extra))
    }

    /// CoreDNS v1.15.0 plugin/backend_lookup.go `MX`.
    async fn mx(&self, q: &Query, services: &Services) -> (Vec<Rr>, Vec<Rr>) {
        let (mut records, mut extra) = (Vec::new(), Vec::new());
        let mut dup = HashSet::new();
        let mut looked_up = HashSet::new();
        for service in services.iter() {
            if !service.mail {
                continue;
            }
            let host_type = service.host_type();
            match host_type {
                HostType::Cname => {
                    let Some(exchange) = target_name(&service.host, service.target_strip) else {
                        continue;
                    };
                    records.push(mx_rr(q, service, exchange.clone()));
                    if looked_up.insert(exchange.clone()) {
                        extra.extend(self.addresses(&exchange).await);
                    }
                }
                HostType::A(_) | HostType::Aaaa(_) => {
                    let domain = msg::domain(&service.key);
                    let Some(exchange) = target_name(&domain, service.target_strip) else {
                        continue;
                    };
                    let Some(owner) = fqdn_name(&domain) else {
                        continue;
                    };
                    if dup.insert((exchange.clone(), service.priority as u16, String::new())) {
                        records.push(mx_rr(q, service, exchange));
                    }
                    // CoreDNS v1.15.0 plugin/backend_lookup.go `MX`: the address is named by the key, without the strip.
                    if dup.insert((owner.clone(), 0, service.host.clone())) {
                        extra.extend(address_rr(&owner, service.ttl, host_type));
                    }
                }
                HostType::Txt => {}
            }
        }
        (records, extra)
    }

    /// CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`.
    async fn srv(&self, q: &Query, services: &Services) -> (Vec<Rr>, Vec<Rr>) {
        // Two passes: the weight of a service is its share of the weights at its priority.
        let mut totals: HashMap<i64, i64> = HashMap::new();
        for service in services.iter() {
            let total = totals.entry(service.priority).or_default();
            *total = total.wrapping_add(srv_weight(service));
        }
        let (mut records, mut extra) = (Vec::new(), Vec::new());
        let mut dup = HashSet::new();
        let mut looked_up = HashSet::new();
        for service in services.iter() {
            // CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: port -1 marks a service without a port.
            if service.port == -1 {
                continue;
            }
            let weight = srv_share(service, totals[&service.priority]);
            let host_type = service.host_type();
            match host_type {
                HostType::Cname => {
                    let Some(target) = target_name(&service.host, service.target_strip) else {
                        continue;
                    };
                    records.push(srv_rr(q, service, weight, target.clone()));
                    if looked_up.insert(target.clone()) {
                        extra.extend(self.addresses(&target).await);
                    }
                }
                HostType::A(_) | HostType::Aaaa(_) => {
                    let Some(target) =
                        target_name(&msg::domain(&service.key), service.target_strip)
                    else {
                        continue;
                    };
                    let port = service.port as u16;
                    if dup.insert((target.clone(), port, String::new())) {
                        records.push(srv_rr(q, service, weight, target.clone()));
                    }
                    if dup.insert((target.clone(), 0, service.host.clone())) {
                        extra.extend(address_rr(&target, service.ttl, host_type));
                    }
                }
                HostType::Txt => {}
            }
        }
        (records, extra)
    }

    /// The addresses of the target of an SRV or MX record, for the Additional section.
    async fn addresses(&self, target: &Name) -> Vec<Rr> {
        // CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: a target elsewhere is looked up through the Server.
        if !target.is_subdomain_of(self.zone) {
            let mut found = Vec::new();
            if let Some(a) = self.foreign(target, Type::A).await {
                found.extend(a.answers);
            }
            // CNAMEs of the AAAA answer are taken to be among those of the A answer.
            if let Some(aaaa) = self.foreign(target, Type::AAAA).await {
                found.extend(aaaa.answers.into_iter().filter(|rr| !rr.is_cname()));
            }
            return found;
        }
        // CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: a target in the zone has A records here.
        let query = Query::new(target.clone(), Type::A);
        match self.address(Kind::A, &query, &[], None).await {
            Ok((found, _)) => found,
            Err(_) => Vec::new(),
        }
    }

    /// CoreDNS v1.15.0 plugin/etcd/etcd.go `Lookup`: ask the Server for `name`.
    async fn foreign(&self, name: &Name, qtype: Type) -> Option<Foreign> {
        // Rr values outlive the Lookup, so take the buffer out of the pool.
        let wire = Arc::new(self.cx.self_lookup(name, qtype).await.ok()?.into_vec());
        let message = Message::parse(&wire).ok()?;
        let answers = message
            .answers()
            .enumerate()
            .map(|(index, record)| Rr {
                name: record.name.to_name(),
                ttl: record.ttl,
                data: Data::Foreign {
                    wire: Arc::clone(&wire),
                    index,
                    rtype: record.rtype,
                    class: record.class,
                },
            })
            .collect();
        Some(Foreign {
            answers,
            truncated: message.tc(),
        })
    }
}

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `loopNodes`: `*` and `any` in the name match any element of the key.
fn wildcard_matches(key: &str, name_path: &str) -> bool {
    let mut key = key.split('/');
    name_path.split('/').all(|part| {
        key.next()
            .is_some_and(|element| matches!(part, "*" | "any") || element == part)
    })
}

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `shouldInclude`: only a TXT lookup takes a service without a host.
fn should_include(service: &Service, qtype: Type) -> bool {
    (qtype == Type::TXT && !service.text.is_empty()) || !service.host.is_empty()
}

/// miekg/dns `Fqdn`, as a name; `None` when the text is not a valid name.
fn fqdn_name(host: &str) -> Option<Name> {
    fqdn(host).parse().ok()
}

fn fqdn(host: &str) -> Cow<'_, str> {
    if msg::is_fqdn(host) {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("{host}."))
    }
}

/// CoreDNS v1.15.0 plugin/etcd/msg/service.go `NewSRV`: the host, with `targetstrip` labels cut off.
fn target_name(host: &str, target_strip: i64) -> Option<Name> {
    let host = fqdn(host);
    // CoreDNS v1.15.0 plugin/etcd/msg/service.go `NewSRV`: strip only when `targetstrip` is positive.
    let host = if target_strip > 0 {
        msg::target_strip(&host, target_strip)
    } else {
        &host
    };
    host.parse().ok()
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: a service that sets no weight counts for 100.
pub(super) fn srv_weight(service: &Service) -> i64 {
    if service.weight == 0 {
        100
    } else {
        service.weight
    }
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: the weight of a service among those of its
/// priority, which weigh `total` together; RFC 2782 wants a lone target at 0, CoreDNS keeps it at least 1.
pub(super) fn srv_share(service: &Service, total: i64) -> u16 {
    let share = 100.0 / total as f64;
    let share = if service.weight == 0 {
        share * 100.0
    } else {
        share * service.weight as f64
    };
    (share.floor() as u16).max(1)
}

/// RFC 1035 §3.3.14: the text in character-strings of at most 255 octets.
fn txt_rdata(text: &str) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(text.len() + text.len() / 255 + 1);
    for chunk in msg::split255(text.as_bytes()) {
        rdata.push(chunk.len() as u8);
        rdata.extend_from_slice(chunk);
    }
    rdata
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `newAddress`.
fn address_rr(name: &Name, ttl: u32, host_type: HostType) -> Option<Rr> {
    match host_type {
        HostType::A(ip) => Some(Rr::new(name, ttl, Data::A(ip))),
        HostType::Aaaa(ip) => Some(Rr::new(name, ttl, Data::Aaaa(ip))),
        HostType::Cname | HostType::Txt => None,
    }
}

/// CoreDNS v1.15.0 plugin/etcd/msg/service.go `NewSRV`.
fn srv_rr(q: &Query, service: &Service, weight: u16, target: Name) -> Rr {
    Rr::new(
        &q.owner,
        service.ttl,
        Data::Srv {
            // Go converts the integers to `uint16` by truncating them.
            priority: service.priority as u16,
            weight,
            port: service.port as u16,
            target,
        },
    )
}

/// CoreDNS v1.15.0 plugin/etcd/msg/service.go `NewMX`: the priority is the preference.
fn mx_rr(q: &Query, service: &Service, exchange: Name) -> Rr {
    Rr::new(
        &q.owner,
        service.ttl,
        Data::Mx {
            preference: service.priority as u16,
            exchange,
        },
    )
}
