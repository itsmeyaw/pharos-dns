//! FORWARDER_QUERY and FORWARDER_RESPONSE for the Server Block's `dnstap` taps.
//!
//! Follows CoreDNS v1.15.0 `plugin/forward/dnstap.go` `toDnstap`: the messages are from this
//! server's side of the exchange toward the Upstream.

use std::{net::SocketAddr, time::SystemTime};

use pharos_server::Context;

use crate::{
    dnstap::{
        Tap,
        msg::{Message, MessageType, SocketProtocol},
    },
    proxy::{Exchange, Options, Transport},
};

// CoreDNS v1.15.0 plugin/forward/dnstap.go: the address is a TCPAddr for "tcp" and a UDPAddr otherwise.
fn socket_protocol(transport: Transport) -> SocketProtocol {
    match transport {
        Transport::Udp | Transport::Quic => SocketProtocol::Udp,
        Transport::Tcp | Transport::Tls | Transport::Https => SocketProtocol::Tcp,
    }
}

// CoreDNS v1.15.0 plugin/pkg/proxy/connect.go lookupDNS: `force_tcp` beats `prefer_udp`, which beats the client's transport.
fn requested(options: Options, client: Transport) -> Transport {
    if options.force_tcp {
        Transport::Tcp
    } else if options.prefer_udp {
        Transport::Udp
    } else {
        client
    }
}

/// Taps one exchange with `upstream`: always the Query, and the Response when `exchange` carries one in `reply`.
///
/// A failed exchange has no socket to report, so its transport is the one asked for and it has no query address.
// CoreDNS v1.15.0 plugin/forward/dnstap.go toDnstap: the Response is tapped only when the reply is not nil.
pub(super) fn exchanged(
    taps: &[Tap],
    cx: &Context<'_, '_>,
    start: SystemTime,
    upstream: SocketAddr,
    exchange: Option<&Exchange>,
    reply: &[u8],
    (options, client): (Options, Transport),
) {
    let protocol =
        socket_protocol(exchange.map_or_else(|| requested(options, client), |e| e.transport));
    let local = exchange.map(|exchange| exchange.local_addr);
    let response_time = exchange.map(|_| SystemTime::now());
    for tap in taps {
        let mut query = Message::new(MessageType::ForwarderQuery);
        query.set_query_time(start);
        if let Some(local) = local {
            query.set_query_address(local, protocol);
        }
        query.set_response_address(upstream, protocol);
        if tap.include_raw() {
            query.set_query_message(cx.query.as_wire());
        }
        tap.send_with(&query, cx);

        if let (Some(exchange), Some(response_time)) = (exchange, response_time) {
            let mut response = Message::new(MessageType::ForwarderResponse);
            if tap.include_raw() {
                response.set_response_message(&reply[..exchange.len]);
            }
            response.set_query_time(start);
            response.set_query_address(exchange.local_addr, protocol);
            response.set_response_address(upstream, protocol);
            response.set_response_time(response_time);
            tap.send_with(&response, cx);
        }
    }
}
