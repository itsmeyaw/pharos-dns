use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, tcp::OwnedReadHalf},
    sync::{Mutex, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};

use crate::{Action, Handler, Protocol, TcpOptions};

// CoreDNS has no default connection limit; cap ours to bound resource use.
// RFC 7766 §10: Bound concurrent connections and idle sessions to mitigate denial of service.
const MAX_CONNECTIONS: usize = 1024;
const MAX_IN_FLIGHT_PER_CONNECTION: usize = 16;

// RFC 1034 §2.4: Name servers concurrently process resolver queries.
pub(crate) fn spawn<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let mut connections = JoinSet::new();
        // One stop channel per connection: a shared watch's Notify mutex is locked on every poll by every connection.
        let mut stops: Vec<watch::Sender<bool>> = Vec::new();
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            // RFC 1035 §4.2.2: Accept multiple TCP connections without blocking other work.
            tokio::select! {
                biased;
                _ = shutdown.changed() => break Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    match accepted {
                        Ok((stream, peer)) => {
                            stops.retain(|stop| !stop.is_closed());
                            let (stop, stopped) = watch::channel(false);
                            stops.push(stop.clone());
                            // RFC 1996 §3.5: Keep serving DNS during TCP NOTIFY transactions.
                            connections.spawn(serve(
                                stream, crate::canonical_peer(peer), Arc::clone(&handler),
                                (stop, stopped), handler.tcp_options(),
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
        for stop in &stops {
            stop.send_replace(true);
        }
        drop(listener);
        while connections.join_next().await.is_some() {}
        result
    })
}

/// Writes one length-prefixed DNS Message. `wire` must not exceed 65,535 octets.
pub async fn write_tcp_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    wire: &[u8],
) -> io::Result<()> {
    // RFC 7766 §8: pass the two-octet length and the Message to TCP in one write.
    let length = (wire.len() as u16).to_be_bytes();
    let mut written = 0;
    while written < length.len() + wire.len() {
        let buffers = [
            IoSlice::new(&length[written.min(length.len())..]),
            IoSlice::new(&wire[written.saturating_sub(length.len())..]),
        ];
        let n = stream.write_vectored(&buffers).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        written += n;
    }
    Ok(())
}

async fn read_frame(reader: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    // RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
    let mut length = [0; 2];
    reader.read_exact(&mut length).await?;
    let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
    // RFC 7766 §8: Do not close when one read lacks the complete DNS Message.
    reader.read_exact(&mut query).await?;
    Ok(query)
}

async fn serve<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<H>,
    (stop, mut stopped): (watch::Sender<bool>, watch::Receiver<bool>),
    options: TcpOptions,
) {
    // RFC 7766 §7: send each Response as soon as it is available.
    // RFC 9293 §3.7.4: Nagle would hold it until the previous segment is ACKed.
    let _ = stream.set_nodelay(true);
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(Some(writer)));
    let mut queries: JoinSet<Vec<u8>> = JoinSet::new();
    let mut responses = Vec::with_capacity(MAX_IN_FLIGHT_PER_CONNECTION);
    let mut count = 0usize;
    // One long-lived timer, re-armed only when it fires early: a timer per frame locks the time driver per Query.
    let idle = tokio::time::sleep(options.read);
    tokio::pin!(idle);

    // RFC 7766 §6.2.1: Serve multiple queries on one TCP connection.
    'read: loop {
        while let Some(result) = queries.try_join_next() {
            if let Ok(response) = result {
                responses.push(response);
            }
        }
        if *stopped.borrow() {
            break;
        }
        // RFC 7766 §6.2.3: a server may close a connection at any time and clients must cope.
        // RFC 7766 §6.2.4: A server may close a connection after its query limit.
        if options.max_queries.is_some_and(|max| count >= max) {
            break;
        }
        while queries.len() >= MAX_IN_FLIGHT_PER_CONNECTION {
            tokio::select! {
                biased;
                _ = stopped.changed() => break 'read,
                result = queries.join_next() => {
                    if let Some(Ok(response)) = result {
                        responses.push(response);
                    }
                },
            }
        }
        // RFC 7766 §6.2.3: servers close idle connections after a timeout; idle starts once no Query is in flight.
        // RFC 7828 §3: Idle time resets when session activity resumes.
        let query = {
            let frame = read_frame(&mut reader);
            tokio::pin!(frame);
            let mut deadline = None;
            loop {
                let result = if queries.is_empty() {
                    let duration = if count == 0 {
                        options.read
                    } else {
                        options.idle
                    };
                    let until = *deadline.get_or_insert_with(|| Instant::now() + duration);
                    if idle.deadline() > until {
                        idle.as_mut().reset(until);
                    }
                    tokio::select! {
                        biased;
                        _ = stopped.changed() => break 'read,
                        result = &mut frame => result,
                        _ = &mut idle => {
                            if Instant::now() >= until {
                                break 'read;
                            }
                            idle.as_mut().reset(until);
                            continue;
                        },
                    }
                } else {
                    deadline = None;
                    tokio::select! {
                        biased;
                        _ = stopped.changed() => break 'read,
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
        // RFC 7766 §7: Prepare responses in parallel and send them as soon as available.
        let handler = Arc::clone(&handler);
        let writer = Arc::clone(&writer);
        let stop = stop.clone();
        let mut response = responses.pop().unwrap_or_default();
        response.clear();
        let mut task = Box::pin(async move {
            let action =
                H::handle_shared(&handler, &query, peer, Protocol::Tcp, &mut response).await;
            let mut transfer = match action {
                Action::Drop => return response,
                Action::Respond => None,
                Action::Stream(transfer) => Some(transfer),
            };
            let signing = transfer.as_ref().and_then(|stream| stream.signing.clone());
            let mut signer = match signing.as_ref() {
                Some(signing) => match pharos_proto::TsigRecord::parse(&query) {
                    Ok(record) => Some(pharos_proto::TsigStream::new(&signing.key, record.mac)),
                    Err(_) => {
                        *writer.lock().await = None;
                        let _ = stop.send(true);
                        return response;
                    }
                },
                None => None,
            };
            loop {
                // RFC 5936 §4.1.2: a connection can serve concurrent Transfer sessions.
                // RFC 9103 §6.2: AXFR sessions may run concurrently on one TCP connection.
                let mut writer = writer.lock().await;
                if writer.is_none() {
                    break;
                }
                if let Some(transfer) = transfer.as_mut() {
                    response.clear();
                    match transfer.next(&mut response) {
                        Ok(true) => {}
                        // RFC 5936 §4.1.2: Completed AXFR leaves the connection open for reuse.
                        Ok(false) => break,
                        Err(failure) => {
                            // RFC 5936 §2.3: closing the connection terminates the client's AXFR session.
                            crate::logging::log(
                                "ERROR",
                                "server",
                                &format!("Zone Transfer producer failed: {failure:?}"),
                            );
                            *writer = None;
                            let _ = stop.send(true);
                            break;
                        }
                    }
                }
                if let (Some(signer), Some(signing)) = (signer.as_mut(), signing.as_ref()) {
                    // RFC 8945 §5.3.1: sign every stream Message with the preceding MAC.
                    // RFC 5936 §2.2.5: Include TSIG under transaction-security rules.
                    let signing_failed =
                        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                            Ok(now) => signer
                                .sign(&mut response, now.as_secs(), signing.fudge)
                                .is_err(),
                            Err(_) => true,
                        };
                    if signing_failed {
                        crate::logging::log("ERROR", "server", "Zone Transfer TSIG signing failed");
                        *writer = None;
                        let _ = stop.send(true);
                        break;
                    }
                }
                // RFC 5936 §2: TCP framing limits each AXFR Message to 65535 octets.
                if u16::try_from(response.len()).is_err() {
                    if transfer.is_some() {
                        // RFC 1035 §4.2.2: TCP Message lengths must fit in two octets.
                        crate::logging::log(
                            "ERROR",
                            "server",
                            "Zone Transfer Message exceeds 65535 octets",
                        );
                        *writer = None;
                        let _ = stop.send(true);
                    }
                    break;
                }
                // RFC 5936 §2.2: every Transfer Message is separately framed on the connection.
                // RFC 2136 §3.8: Send the TCP response on the requestor's open connection.
                // RFC 2181 §4.2: Send each TCP reply on the Query's connection.
                if let Some(stream) = writer.as_mut() {
                    // RFC 7766 §5: Send responses on the same TCP connection as queries.
                    let result = timeout(options.write, write_tcp_frame(stream, &response)).await;
                    if !matches!(result, Ok(Ok(()))) {
                        *writer = None;
                        let _ = stop.send(true);
                        break;
                    }
                } else {
                    break;
                }
                if transfer.is_none() {
                    break;
                }
            }
            response
        });
        // Like CoreDNS and Hickory, answer a ready Query inline; spawn only one that waits.
        // A panic loses only this Query, as it would in a spawned task.
        let poll = std::future::poll_fn(|cx| {
            Poll::Ready(catch_unwind(AssertUnwindSafe(|| task.as_mut().poll(cx))))
        });
        match poll.await {
            Ok(Poll::Ready(response)) => responses.push(response),
            Ok(Poll::Pending) => {
                queries.spawn(task);
            }
            Err(_) => {}
        }
    }
    // RFC 1035 §4.2.2: Finish outstanding responses before closing a TCP connection.
    while queries.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_frame_vectored_write_handles_partial_and_zero_writes() {
        use std::{
            pin::Pin,
            task::{Context, Poll},
        };
        struct Writer {
            bytes: Vec<u8>,
            limit: usize,
            calls: usize,
            first_segments: usize,
        }
        impl AsyncWrite for Writer {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                panic!("expected vectored write")
            }
            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buffers: &[IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                if self.calls == 0 {
                    self.first_segments = buffers.iter().filter(|b| !b.is_empty()).count();
                }
                self.calls += 1;
                let mut left = self.limit;
                let mut written = 0;
                for buffer in buffers {
                    let count = left.min(buffer.len());
                    self.bytes.extend_from_slice(&buffer[..count]);
                    written += count;
                    left -= count;
                }
                Poll::Ready(Ok(written))
            }
            fn is_write_vectored(&self) -> bool {
                true
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        for limit in [1, 3, 100] {
            let mut writer = Writer {
                bytes: Vec::new(),
                limit,
                calls: 0,
                first_segments: 0,
            };
            write_tcp_frame(&mut writer, b"hello").await.unwrap();
            assert_eq!(writer.bytes, b"\0\x05hello");
            assert_eq!(writer.first_segments, 2);
            if limit == 100 {
                assert_eq!(writer.calls, 1);
            }
        }
        let mut writer = Writer {
            bytes: Vec::new(),
            limit: 0,
            calls: 0,
            first_segments: 0,
        };
        assert_eq!(
            write_tcp_frame(&mut writer, b"hello")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
    }
}
