use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, tcp::OwnedReadHalf},
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::{Action, Handler, Protocol};

// CoreDNS has no default connection limit; cap ours to bound resource use.
const MAX_CONNECTIONS: usize = 1024;
const MAX_IN_FLIGHT_PER_CONNECTION: usize = 16;
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn spawn<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let (stop, connections_stop) = watch::channel(false);
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    match accepted {
                        Ok((stream, peer)) => {
                            connections.spawn(serve(
                                stream, crate::canonical_peer(peer), Arc::clone(&handler),
                                connections_stop.clone(),
                            ));
                        }
                        Err(error) => {
                            crate::logging::log("ERROR", "server", &format!("TCP accept failed: {error}"));
                            tokio::select! {
                                _ = shutdown.changed() => break Ok(()),
                                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                            }
                        }
                    }
                }
            }
        };
        stop.send_replace(true);
        drop(listener);
        while connections.join_next().await.is_some() {}
        result
    })
}

async fn read_frame(reader: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    let mut length = [0; 2];
    timeout(IDLE_TIMEOUT, reader.read_exact(&mut length[..1]))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    timeout(READ_TIMEOUT, async {
        reader.read_exact(&mut length[1..]).await?;
        let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
        reader.read_exact(&mut query).await?;
        Ok(query)
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

async fn serve<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(Some(writer)));
    let (failed, mut write_failed) = watch::channel(false);
    let mut queries: JoinSet<Vec<u8>> = JoinSet::new();
    let mut responses = Vec::with_capacity(MAX_IN_FLIGHT_PER_CONNECTION);

    'read: loop {
        while let Some(result) = queries.try_join_next() {
            if let Ok(response) = result {
                responses.push(response);
            }
        }
        if *shutdown.borrow() || *write_failed.borrow() {
            break;
        }
        while queries.len() >= MAX_IN_FLIGHT_PER_CONNECTION {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break 'read,
                _ = write_failed.changed() => break 'read,
                result = queries.join_next() => {
                    if let Some(Ok(response)) = result {
                        responses.push(response);
                    }
                },
            }
        }
        let query = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = write_failed.changed() => break,
            query = read_frame(&mut reader) => match query {
                Ok(query) => query,
                Err(_) => break,
            },
        };

        while let Some(result) = queries.try_join_next() {
            if let Ok(response) = result {
                responses.push(response);
            }
        }

        // A complete frame is accepted work and must finish even during shutdown.
        let handler = Arc::clone(&handler);
        let writer = Arc::clone(&writer);
        let failed = failed.clone();
        let mut response = responses.pop().unwrap_or_default();
        response.clear();
        queries.spawn(async move {
            if H::handle_shared(&handler, &query, peer, Protocol::Tcp, &mut response).await
                == Action::Respond
                && let Ok(length) = u16::try_from(response.len())
            {
                let mut writer = writer.lock().await;
                if let Some(stream) = writer.as_mut() {
                    let result = timeout(WRITE_TIMEOUT, async {
                        stream.write_all(&length.to_be_bytes()).await?;
                        stream.write_all(&response).await
                    })
                    .await;
                    if !matches!(result, Ok(Ok(()))) {
                        *writer = None;
                        let _ = failed.send(true);
                    }
                }
            }
            response
        });
    }
    while queries.join_next().await.is_some() {}
}
