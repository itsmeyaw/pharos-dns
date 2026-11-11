use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, tcp::OwnedReadHalf},
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::{Action, Handler, Protocol, TcpOptions};

// CoreDNS has no default connection limit; cap ours to bound resource use.
const MAX_CONNECTIONS: usize = 1024;
const MAX_IN_FLIGHT_PER_CONNECTION: usize = 16;

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
                                connections_stop.clone(), handler.tcp_options(),
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
    // RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
    let mut length = [0; 2];
    reader.read_exact(&mut length).await?;
    let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
    reader.read_exact(&mut query).await?;
    Ok(query)
}

async fn serve<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    options: TcpOptions,
) {
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(Some(writer)));
    let (failed, mut write_failed) = watch::channel(false);
    let mut queries: JoinSet<Vec<u8>> = JoinSet::new();
    let mut responses = Vec::with_capacity(MAX_IN_FLIGHT_PER_CONNECTION);
    let mut count = 0usize;

    'read: loop {
        while let Some(result) = queries.try_join_next() {
            if let Ok(response) = result {
                responses.push(response);
            }
        }
        if *shutdown.borrow() || *write_failed.borrow() {
            break;
        }
        if options.max_queries.is_some_and(|max| count >= max) {
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
        let query = {
            let frame = read_frame(&mut reader);
            tokio::pin!(frame);
            loop {
                let result = if queries.is_empty() {
                    let duration = if count == 0 {
                        options.read
                    } else {
                        options.idle
                    };
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break 'read,
                        _ = write_failed.changed() => break 'read,
                        result = timeout(duration, &mut frame) => match result {
                            Ok(result) => result,
                            Err(_) => break 'read,
                        },
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break 'read,
                        _ = write_failed.changed() => break 'read,
                        result = &mut frame => result,
                        result = queries.join_next() => {
                            if let Some(Ok(response)) = result { responses.push(response); }
                            continue;
                        },
                    }
                };
                match result {
                    Ok(query) => break query,
                    Err(_) => break 'read,
                }
            }
        };
        count += 1;

        while let Some(result) = queries.try_join_next() {
            if let Ok(response) = result {
                responses.push(response);
            }
        }

        // A complete frame is accepted work and must finish even during shutdown.
        // RFC 7766 §6.2.1.1: servers should process pipelined TCP queries concurrently.
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
                // RFC 7766 §5: TCP responses use the same connection as the query.
                let mut writer = writer.lock().await;
                if let Some(stream) = writer.as_mut() {
                    let result = timeout(options.write, async {
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
