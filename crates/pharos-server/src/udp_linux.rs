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
        let mut buffers = std::array::from_fn(|_| vec![0; MAX_MESSAGE]);
        let mut peers = [None; BATCH];
        let mut response = Vec::with_capacity(MAX_MESSAGE);
        loop {
            let count = tokio::select! {
                biased;
                _ = shutdown.changed() => return Ok(()),
                received = socket.async_io(Interest::READABLE, || receive(&socket, &mut buffers, &mut peers)) => match received {
                    Ok(count) => count,
                    Err(error) => {
                        eprintln!("UDP receive failed: {error}");
                        tokio::select! {
                            _ = shutdown.changed() => return Ok(()),
                            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                        }
                        continue;
                    }
                },
            };
            for index in 0..count {
                if let Some((length, peer)) = peers[index] {
                    response.clear();
                    if handler
                        .handle(
                            &buffers[index][..length],
                            peer,
                            Protocol::Udp,
                            &mut response,
                        )
                        .await
                        == Action::Respond
                        && let Err(error) = socket
                            .async_io(Interest::WRITABLE, || send(&socket, &response, peer))
                            .await
                    {
                        eprintln!("UDP Response to {peer} failed: {error}");
                    }
                }
            }
        }
    })
}
