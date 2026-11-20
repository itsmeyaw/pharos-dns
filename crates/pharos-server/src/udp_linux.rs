use std::{
    cell::RefCell,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::Arc,
};

use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg, sendmmsg};
use tokio::{io::Interest, net::UdpSocket, sync::watch, task::JoinHandle};

use crate::Handler;

const BATCH: usize = 16;
// RFC 5625 §4.4.3: Receive up to 65,535 octets, exceeding the 4,096-octet requirement.
const MAX_MESSAGE: usize = 65535;

thread_local! {
    static RECEIVE: RefCell<MultiHeaders<SockaddrStorage>> = RefCell::new(MultiHeaders::preallocate(BATCH, None));
    static SEND: RefCell<MultiHeaders<SockaddrStorage>> = RefCell::new(MultiHeaders::preallocate(1, None));
}

fn receive(
    socket: &UdpSocket,
    buffers: &mut [Vec<u8>; BATCH],
    peers: &mut [Option<(usize, SocketAddr)>; BATCH],
) -> io::Result<usize> {
    RECEIVE.with_borrow_mut(|headers| {
        let mut slices = buffers.each_mut().map(|buffer| [IoSliceMut::new(buffer)]);
        let messages = recvmmsg(
            socket.as_raw_fd(),
            headers,
            &mut slices,
            MsgFlags::MSG_DONTWAIT,
            None,
        )
        .map_err(io::Error::from)?;
        let mut count = 0;
        for message in messages {
            let address = message.address.and_then(|address| {
                address
                    .as_sockaddr_in()
                    .map(|v| SocketAddr::from(*v))
                    .or_else(|| address.as_sockaddr_in6().map(|v| SocketAddr::from(*v)))
            });
            // POSIX.1-2024 recvmsg: MSG_TRUNC indicates discarded message data.
            peers[count] = if message.flags.contains(MsgFlags::MSG_TRUNC) {
                None
            } else {
                address.map(|address| (message.bytes, address))
            };
            count += 1;
        }
        Ok(count)
    })
}

// RFC 2181 §4.2: Send UDP replies to the source port of the query.
pub(crate) fn send(socket: &UdpSocket, response: &[u8], peer: SocketAddr) -> io::Result<()> {
    let slices = [[IoSlice::new(response)]];
    let peers = [Some(SockaddrStorage::from(peer))];
    SEND.with_borrow_mut(|headers| {
        // One message avoids iterating nix's uninitialized send-address results.
        sendmmsg(
            socket.as_raw_fd(),
            headers,
            &slices,
            peers,
            [],
            MsgFlags::MSG_DONTWAIT,
        )
        .map_err(io::Error::from)?;
        Ok(())
    })
}

// RFC 1035 §4.2.1: Serve standard DNS queries over UDP.
pub(crate) fn spawn<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let socket = Arc::new(socket);
        // Zeroed on the first readable event, not at startup: 64 workers' buffers took ~30 ms to fault in.
        let mut buffers: Option<[Vec<u8>; BATCH]> = None;
        let mut peers = [None; BATCH];
        let mut slot = None;
        let mut pending = tokio::task::JoinSet::new();
        let mut free = Vec::new();
        let mut scratch = None;
        let mut proxy = crate::proxyproto::UdpState::default();
        'read: loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                result = pending.join_next(), if !pending.is_empty() => { crate::udp::recycle(result, &mut free); continue; },
                ready = socket.readable() => match ready {
                    Ok(()) => {}
                    Err(error) => {
                        crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                        tokio::select! {
                            _ = shutdown.changed() => break 'read,
                            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                        }
                        continue;
                    }
                },
            }
            let buffers =
                buffers.get_or_insert_with(|| std::array::from_fn(|_| vec![0; MAX_MESSAGE]));
            let count = match socket
                .try_io(Interest::READABLE, || receive(&socket, buffers, &mut peers))
            {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                    tokio::select! {
                        _ = shutdown.changed() => break 'read,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                    }
                    continue;
                }
            };
            for index in 0..count {
                if let Some((length, peer)) = peers[index] {
                    let Some((start, client)) =
                        crate::udp::proxied(&*handler, &mut proxy, &buffers[index][..length], peer)
                    else {
                        continue;
                    };
                    if let Some(cancelled) =
                        handler.parallel_query(&buffers[index][start..length], client)
                    {
                        crate::udp::spawn_parallel(
                            Arc::clone(&socket),
                            Arc::clone(&handler),
                            &buffers[index][start..length],
                            peer,
                            shutdown.clone(),
                            cancelled,
                            None,
                        );
                        continue;
                    }
                    // recvmmsg(2): inspect already-received probes before waiting for capacity.
                    if pending.len() >= crate::udp::MAX_IN_FLIGHT {
                        for (later, buffer) in peers[index + 1..count]
                            .iter_mut()
                            .zip(&buffers[index + 1..count])
                        {
                            if let Some((size, address)) = *later
                                && let Some(cancelled) = handler
                                    .parallel_query(&buffer[..size], crate::canonical_peer(address))
                            {
                                crate::udp::spawn_parallel(
                                    Arc::clone(&socket),
                                    Arc::clone(&handler),
                                    &buffer[..size],
                                    address,
                                    shutdown.clone(),
                                    cancelled,
                                    None,
                                );
                                *later = None;
                            }
                        }
                    }
                    if !crate::udp::capacity(
                        &mut pending,
                        &mut free,
                        &mut shutdown,
                        &socket,
                        &handler,
                        None,
                        &mut scratch,
                    )
                    .await
                    {
                        break 'read;
                    }
                    crate::udp::take_slot(&mut slot, &mut free, &handler, &socket, None);
                    slot.as_mut().unwrap().prepare(
                        &buffers[index][start..length],
                        (peer, client),
                        &proxy.tlv,
                        None,
                    );
                    crate::udp::dispatch(
                        &mut slot,
                        &mut pending,
                        &mut free,
                        &handler,
                        &socket,
                        None,
                    )
                    .await;
                }
            }
        }
        // Tokio JoinSet::abort_all: release pending sockets before the Listener is replaced.
        crate::udp::shutdown_pending(&mut pending).await;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
