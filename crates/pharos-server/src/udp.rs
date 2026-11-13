use std::{
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::sync::Arc;
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
    stack: Option<Arc<crate::shed::ShedStack>>,
) {
    let query = query.to_vec();
    tokio::spawn(async move {
        if *cancelled.borrow() {
            return;
        }
        let mut response = if let Some(stack) = &stack {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = cancelled.changed() => return,
                data = stack.checkout_wait() => data,
            }
        } else {
            Vec::with_capacity(65535)
        };
        tokio::select! {
            _ = shutdown.changed() => {},
            _ = cancelled.changed() => {},
            action = handler.handle(&query, crate::canonical_peer(peer), Protocol::Udp, &mut response) => {
                if action == Action::Respond {
                    if let Some(stack) = &stack {
                        stack.push(response, peer);
                        return;
                    } else if let Err(error) = socket.send_to(&response, peer).await {
                        crate::logging::log("ERROR", "server", &format!("UDP Response to {peer} failed: {error}"));
                    }
                }
            }
        }
        if let Some(stack) = stack {
            stack.release(response);
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
        socket.set_only_v6(!address.ip().is_unspecified())?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

// Growing the descriptor table waits for an RCU grace period once threads exist (~25 ms here).
#[cfg(target_os = "linux")]
pub fn reserve_descriptors(count: i32) -> io::Result<()> {
    let null = std::fs::File::open("/dev/null")?;
    let fd = nix::fcntl::fcntl(&null, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(count)).map_err(io::Error::from)?;
    nix::unistd::close(fd).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
pub fn reserve_descriptors(_count: i32) -> io::Result<()> {
    Ok(())
}

pub(crate) fn spawn<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    if let Some(metrics) = handler.shed_metrics() {
        return spawn_shed(socket, handler, shutdown, metrics);
    }
    #[cfg(target_os = "linux")]
    {
        crate::udp_linux::spawn(socket, handler, shutdown)
    }
    #[cfg(not(target_os = "linux"))]
    {
        spawn_plain(socket, handler, shutdown)
    }
}

fn spawn_shed<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    metrics: crate::metrics::ShedMetrics,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let socket = Arc::new(socket);
        let stack = crate::shed::ShedStack::for_socket(metrics);
        let mut writer = AbortOnDrop(tokio::spawn(Arc::clone(&stack).writer(Arc::clone(&socket))));
        let mut query = vec![0; 65535];
        loop {
            let received = tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                received = socket.recv_from(&mut query) => received,
            };
            let (length, peer) = match received {
                Ok(message) => message,
                Err(error) => {
                    crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                    tokio::select! { _ = shutdown.changed() => break, _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {} }
                    continue;
                }
            };
            let client = crate::canonical_peer(peer);
            if should_shed(&stack, &*handler, &query[..length], client) {
                continue;
            }
            if let Some(cancelled) = handler.parallel_query(&query[..length], client) {
                spawn_parallel(
                    Arc::clone(&socket),
                    Arc::clone(&handler),
                    &query[..length],
                    peer,
                    shutdown.clone(),
                    cancelled,
                    Some(Arc::clone(&stack)),
                );
                continue;
            }
            let mut response = tokio::select! {
                _ = shutdown.changed() => break,
                data = stack.checkout_wait() => data,
            };
            if H::handle_shared(
                &handler,
                &query[..length],
                client,
                Protocol::Udp,
                &mut response,
            )
            .await
                == Action::Respond
            {
                stack.push(response, peer);
            } else {
                stack.release(response);
            }
        }
        stack.close();
        (&mut writer.0).await.map_err(io::Error::other)?;
        Ok(())
    })
}

struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn should_shed<H: Handler>(
    stack: &crate::shed::ShedStack,
    handler: &H,
    query: &[u8],
    peer: SocketAddr,
) -> bool {
    if stack.full() && handler.shed_query(query, peer) {
        stack.query_drop();
        true
    } else {
        false
    }
}

#[cfg(not(target_os = "linux"))]
fn spawn_plain<H: Handler>(
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
                    let client = crate::canonical_peer(peer);
                    if let Some(cancelled) = handler.parallel_query(&query[..length], client) {
                        spawn_parallel(Arc::clone(&socket), Arc::clone(&handler), &query[..length], peer, shutdown.clone(), cancelled, None);
                        continue;
                    }
                    response.clear();
                    if H::handle_shared(&handler, &query[..length], client, Protocol::Udp, &mut response).await == Action::Respond
                        && let Err(error) = socket.send_to(&response, peer).await {
                        crate::logging::log("ERROR", "server", &format!("UDP Response to {peer} failed: {error}"));
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Blocking {
        started: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    struct Shedding(bool);
    impl Handler for Shedding {
        fn shed_query(&self, _: &[u8], _: SocketAddr) -> bool {
            self.0
        }
        async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
            Action::Drop
        }
    }

    #[test]
    fn full_stack_only_drops_queries_from_shed_blocks() {
        let registry = crate::metrics::Registry::default();
        let stack = crate::shed::ShedStack::new(1, registry.shed("dns://:53"));
        let peer = "127.0.0.1:53".parse().unwrap();
        assert!(!should_shed(&stack, &Shedding(true), &[], peer));
        stack.push(stack.checkout().unwrap(), peer);
        assert!(!should_shed(&stack, &Shedding(false), &[], peer));
        assert!(should_shed(&stack, &Shedding(true), &[], peer));
        let mut text = String::new();
        registry.encode(&mut text);
        assert!(
            text.contains("reason=\"query\",server=\"dns://:53\"} 1"),
            "{text}"
        );
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
            None,
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
