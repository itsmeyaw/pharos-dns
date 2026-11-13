use std::{
    cell::RefCell,
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::Arc,
};

use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage, recvmmsg, sendmmsg};
use tokio::{io::Interest, net::UdpSocket, sync::watch, task::JoinHandle};

use crate::{Action, Handler, Protocol};

const BATCH: usize = 16;
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

fn send(socket: &UdpSocket, response: &[u8], peer: SocketAddr) -> io::Result<()> {
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
        let mut response = Vec::with_capacity(MAX_MESSAGE);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => return Ok(()),
                ready = socket.readable() => match ready {
                    Ok(()) => {}
                    Err(error) => {
                        crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                        tokio::select! {
                            _ = shutdown.changed() => return Ok(()),
                            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                        }
                        continue;
                    }
                },
            }
            let buffers = buffers.get_or_insert_with(|| std::array::from_fn(|_| vec![0; MAX_MESSAGE]));
            let count = match socket.try_io(Interest::READABLE, || receive(&socket, buffers, &mut peers)) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                    tokio::select! {
                        _ = shutdown.changed() => return Ok(()),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                    }
                    continue;
                }
            };
            for index in 0..count {
                if let Some((length, peer)) = peers[index] {
                    let client = crate::canonical_peer(peer);
                    if let Some(cancelled) =
                        handler.parallel_query(&buffers[index][..length], client)
                    {
                        crate::udp::spawn_parallel(
                            Arc::clone(&socket),
                            Arc::clone(&handler),
                            &buffers[index][..length],
                            peer,
                            shutdown.clone(),
                            cancelled,
                            None,
                        );
                        continue;
                    }
                    response.clear();
                    if H::handle_shared(
                        &handler,
                        &buffers[index][..length],
                        client,
                        Protocol::Udp,
                        &mut response,
                    )
                    .await
                        == Action::Respond
                        && let Err(error) = socket
                            .async_io(Interest::WRITABLE, || send(&socket, &response, peer))
                            .await
                    {
                        crate::logging::log(
                            "ERROR",
                            "server",
                            &format!("UDP Response to {peer} failed: {error}"),
                        );
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct Echo;

    impl Handler for Echo {
        async fn handle(&self, query: &[u8], _: SocketAddr, _: Protocol, response: &mut Vec<u8>) -> Action {
            response.extend_from_slice(query);
            Action::Respond
        }
    }

    #[tokio::test]
    async fn answers_first_datagram_after_idle_start() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let _worker = spawn(server, Arc::new(Echo), receiver);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", address).await.unwrap();
        let mut buffer = [0; 16];
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"ping");
        drop(shutdown);
    }
}
