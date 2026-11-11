use std::{
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::sync::Arc;
#[cfg(not(target_os = "linux"))]
use tokio::task::JoinHandle;
use tokio::{net::UdpSocket, sync::watch};

use crate::{Action, Handler, Protocol};

// A forwarding-loop probe must not hold the receive worker while it returns to us.
pub(crate) fn spawn_parallel<H: Handler>(
    socket: Arc<UdpSocket>,
    handler: Arc<H>,
    query: &[u8],
    peer: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
    mut cancelled: watch::Receiver<bool>,
) {
    let query = query.to_vec();
    tokio::spawn(async move {
        if *cancelled.borrow() {
            return;
        }
        let mut response = Vec::with_capacity(65535);
        tokio::select! {
            _ = shutdown.changed() => {},
            _ = cancelled.changed() => {},
            action = handler.handle(&query, peer, Protocol::Udp, &mut response) => {
                if action == Action::Respond && let Err(error) = socket.send_to(&response, peer).await {
                    crate::logging::log("ERROR", "server", &format!("UDP Response to {peer} failed: {error}"));
                }
            }
        }
    });
}

pub(crate) fn bind(address: SocketAddr) -> io::Result<StdUdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(SocketProtocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
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
        let socket = Arc::new(socket);
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
                            crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                            tokio::select! {
                                _ = shutdown.changed() => return Ok(()),
                                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                            }
                            continue;
                        }
                    };
                    if let Some(cancelled) = handler.parallel_query(&query[..length], peer) {
                        spawn_parallel(Arc::clone(&socket), Arc::clone(&handler), &query[..length], peer, shutdown.clone(), cancelled);
                        continue;
                    }
                    response.clear();
                    if H::handle_shared(&handler, &query[..length], peer, Protocol::Udp, &mut response).await == Action::Respond
                        && let Err(error) = socket.send_to(&response, peer).await {
                        crate::logging::log("ERROR", "server", &format!("UDP Response to {peer} failed: {error}"));
                    }
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
pub(crate) use crate::udp_linux::spawn;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Blocking {
        started: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }
    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl Handler for Blocking {
        async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
            let _guard = Guard(Arc::clone(&self.dropped));
            self.started.store(true, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn parallel_query_is_cancelled_when_configuration_restarts() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let (shutdown, receiver) = watch::channel(false);
        let (restart, cancelled) = watch::channel(false);
        spawn_parallel(
            socket,
            Arc::new(Blocking {
                started: Arc::clone(&started),
                dropped: Arc::clone(&dropped),
            }),
            &[0],
            "127.0.0.1:1234".parse().unwrap(),
            receiver,
            cancelled,
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        restart.send_replace(true);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(shutdown);
    }
}
