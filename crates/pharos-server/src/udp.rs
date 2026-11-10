use std::{
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};

use crate::{Action, Handler, Protocol};

pub(crate) fn bind(address: SocketAddr) -> io::Result<StdUdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(SocketProtocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

pub(crate) fn spawn<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut query = vec![0; 65535];
        let mut response = Vec::with_capacity(65535);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => return Ok(()),
                received = socket.recv_from(&mut query) => {
                    let (length, peer) = received?;
                    response.clear();
                    if handler.handle(&query[..length], peer, Protocol::Udp, &mut response) == Action::Respond {
                        socket.send_to(&response, peer).await?;
                    }
                }
            }
        }
    })
}
