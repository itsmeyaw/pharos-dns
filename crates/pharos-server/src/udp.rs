use std::{
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
#[cfg(not(target_os = "linux"))]
use std::sync::Arc;
#[cfg(not(target_os = "linux"))]
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};

#[cfg(not(target_os = "linux"))]
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

#[cfg(not(target_os = "linux"))]
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
                    let (length, peer) = match received {
                        Ok(message) => message,
                        Err(error) => {
                            eprintln!("UDP receive failed: {error}");
                            tokio::select! {
                                _ = shutdown.changed() => return Ok(()),
                                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                            }
                            continue;
                        }
                    };
                    response.clear();
                    if handler.handle(&query[..length], peer, Protocol::Udp, &mut response).await == Action::Respond
                        && let Err(error) = socket.send_to(&response, peer).await {
                        eprintln!("UDP Response to {peer} failed: {error}");
                    }
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
pub(crate) use crate::udp_linux::spawn;
