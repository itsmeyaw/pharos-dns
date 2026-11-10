# Pharos

Pharos is a Rust rewrite of CoreDNS: a DNS name server whose behaviour is assembled from Plugins configured in a Corefile. DNS terms follow the DNS RFCs (RFC 9499 first); everything else follows CoreDNS.

## Configuration

**Corefile**:
The configuration file that declares every Server Block Pharos runs.
_Avoid_: Caddyfile, config file

**Server Block**:
A stanza in the Corefile made of one or more Server Block Keys followed by the Directives that apply to them.
_Avoid_: Site, block, serverblock, configuration block, server

**Server Block Key**:
One head token of a Server Block, naming a Transport, a Domain and a port the block answers for.
_Avoid_: Address, host, zone

**Transport**:
The wire protocol a Server Block Key listens with: `dns` (DNS over UDP and TCP), `tls`, `quic`, `grpc`, `https` or `https3`.
_Avoid_: Scheme, protocol

**Listener**:
One Transport, address and port that Pharos accepts Queries on, serving one or more Server Blocks.
_Avoid_: Server (in the RFCs that means the whole name server), socket

**Directive**:
A keyword inside a Server Block that enables and configures one Plugin.
_Avoid_: Option, command

**Plugin Order**:
The fixed, build-time order in which Plugins run, independent of the order Directives appear in the Corefile.
_Avoid_: Directive order, priority

## Plugins

**Plugin**:
A self-contained unit of DNS behaviour enabled by one Directive. Some Plugins only configure Pharos and never join the Plugin Chain.
_Avoid_: Handler, middleware, module

**Plugin Chain**:
The ordered Plugins a Query passes through after being routed to a Server Block.
_Avoid_: Plugin stack, pipeline

**Next**:
The Plugin that follows the current one in the Plugin Chain.

**Fallthrough**:
A Plugin passing a Query it would otherwise answer on to Next, for some or all of the Domains it serves.
_Avoid_: Pass-through

**Backend**:
A Plugin that produces Responses from its own data or from an Upstream, rather than altering Queries and Responses that pass through it.
_Avoid_: Data source, provider

**Metadata**:
Named, per-Query facts that one Plugin publishes for others to read, labelled `plugin/name`.

## Messages

**Message**:
The single format of all DNS communication; each Message is either a Query or a Response (RFC 1035).
_Avoid_: Packet

**Query**:
A Message asking for records matching a QNAME, QTYPE and QCLASS.
_Avoid_: Request, question (the Question is one section of a Query)

**Response**:
A Message answering a Query.
_Avoid_: Reply, answer (the Answer is one section of a Response)

**Positive Response**:
A Response whose Answer section holds the requested RRset, or a CNAME chain leading to it.
_Avoid_: NoError (an RCODE that NODATA and Referral Responses also carry), answer

**NXDOMAIN**:
A Response saying the domain name in the Query does not exist (RFC 2308 synonym of RFC 1035's "Name Error").
_Avoid_: NameError, not found

**NODATA**:
A Response saying the name exists for the class but has no records of the queried type: RCODE NOERROR with no relevant answers.
_Avoid_: NXRRSET, empty answer

**Referral**:
A Response pointing the client at the name servers of a Zone it should ask instead, usually a child Zone below a Zone Cut.
_Avoid_: Delegation, delegation response

**Negative Response**:
A Response saying an RRset does not exist, or whose RCODE says the name server cannot answer (RFC 2308).

**Response Type**:
The classification of a Response: Positive, NXDOMAIN, NODATA, Referral, ServerError, Meta (NOTIFY or Zone Transfer), Update or OtherError.

**Response Class**:
A coarser grouping of Response Types: Success (Positive, Referral), Denial (NXDOMAIN, NODATA) or Error (everything else).

**View**:
A configuration that gives different Responses depending on attributes of the Query, such as its source address. In Pharos it is a filter that decides whether a Query is routed to a Server Block.
_Avoid_: Split DNS (that is the effect, not the mechanism)

## Namespace and authoritative data

**Domain**:
The part of the domain name space at or below a given domain name (RFC 1034). Server Block Keys and Plugins are scoped to Domains, whether or not Pharos is authoritative for them.
_Avoid_: Zone (unless Pharos holds its authoritative data), suffix

**Zone**:
A unit of authoritative information: the namespace from an Apex down to its Zone Cuts (RFC 1034).
_Avoid_: Domain

**Apex**:
The top name of a Zone, which owns the Zone's SOA and authoritative NS RRset.
_Avoid_: Origin, zone name, top node

**Origin**:
The domain name that relative names in a zone file are resolved against (`$ORIGIN`).
_Avoid_: Apex

**Zone Cut**:
The boundary between a parent Zone and the child Zone below it.

**Delegation**:
Creating a child Zone beneath a Zone by adding an NS RRset for the child's Apex in the parent. The word also names the child Zone created this way.
_Avoid_: Referral (that is the Response)

**Primary Server**:
An authoritative server configured as the source of Zone Transfers for one or more Secondary Servers (RFC 1996).
_Avoid_: Master, master server

**Secondary Server**:
An authoritative server that uses Zone Transfer to retrieve a Zone (RFC 1996).
_Avoid_: Slave, slave server

**Zone Transfer**:
A client requesting a copy of a Zone and an authoritative server sending it, either in full (AXFR) or as the changes since a serial (IXFR).
_Avoid_: Sync, replication

**NOTIFY**:
A Message from a Primary Server telling Secondary Servers that a Zone has changed (RFC 1996).

## Forwarding

**Forwarding**:
Sending a Query with the RD bit set to another name server to resolve it (RFC 9499).
_Avoid_: Proxying, relaying

**Upstream**:
A remote name server that Pharos sends Queries to when Forwarding.
_Avoid_: Forwarder (ambiguous in RFC 2308), proxy

**Self Lookup**:
Pharos sending a new Query through its own Plugin Chain on behalf of a Plugin, for example to follow a CNAME.
_Avoid_: Upstream, recursion

## Operations

**Health**:
Whether the Pharos process is alive.
_Avoid_: Liveness, readiness

**Readiness**:
Whether every Plugin that reports readiness is ready to serve.
_Avoid_: Health

**Lameduck**:
A period after shutdown is requested during which Pharos keeps serving and still reports Health.
_Avoid_: Drain, grace period

**Reload**:
Replacing the running configuration with a changed Corefile without restarting the process.
_Avoid_: Restart, hot reload
