//! Frame Streams encoder over `AsyncRead + AsyncWrite`, as golang-framestream's bidirectional `Encoder`.
//!
//! Wire format: <https://farsightsec.github.io/fstrm/> (`fstrm/control.h`). A data frame is a
//! 32-bit big-endian length and the payload. A zero length is the escape for a control frame:
//! a 32-bit control length, a 32-bit control type, then `CONTENT_TYPE` fields (type 1,
//! 32-bit length, bytes).

use std::{future::Future, io, time::Duration};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};

#[cfg(test)]
mod tests;

/// CoreDNS v1.15.0 plugin/dnstap/encoder.go `newEncoder`: the content type of every dnstap stream.
pub const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// CoreDNS v1.15.0 plugin/dnstap/io.go `tcpTimeout`: golang-framestream applies it to each write
/// and each read of the handshake and of `Close` on a `net.Conn`; the dial itself has the same limit.
pub const TCP_TIMEOUT: Duration = Duration::from_secs(4);

// Pharos choice: golang-framestream uses Go's 4 KiB `bufio.Writer`; a larger buffer batches more frames per syscall.
const WRITE_BUFFER: usize = 16 * 1024;

// fstrm control.h FSTRM_CONTROL_FRAME_LENGTH_MAX: the largest control frame payload.
const CONTROL_MAX: usize = 512;

// fstrm control.h FSTRM_CONTROL_FIELD_CONTENT_TYPE.
const FIELD_CONTENT_TYPE: u32 = 1;

/// fstrm control.h `fstrm_control_type`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlType {
    Accept = 1,
    Start = 2,
    Stop = 3,
    Ready = 4,
    Finish = 5,
}

/// A decoded control frame. `kind` stays a raw number: an unknown type is the caller's to reject.
#[derive(Debug, Eq, PartialEq)]
pub struct Control {
    pub kind: u32,
    pub content_types: Vec<Vec<u8>>,
}

// fstrm control.h: escape `00 00 00 00`, control frame length, control type, then fields.
fn put_control(buf: &mut Vec<u8>, kind: ControlType, content_types: &[&[u8]]) {
    let length: usize = 4 + content_types.iter().map(|ct| 8 + ct.len()).sum::<usize>();
    buf.extend_from_slice(&0_u32.to_be_bytes());
    buf.extend_from_slice(&(length as u32).to_be_bytes());
    buf.extend_from_slice(&(kind as u32).to_be_bytes());
    for ct in content_types {
        buf.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
        buf.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        buf.extend_from_slice(ct);
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Reads one control frame, escape included. golang-framestream Control.go `DecodeEscape` and `Decode`.
pub async fn read_control<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Control> {
    if reader.read_u32().await? != 0 {
        return Err(invalid("expected a control frame"));
    }
    // golang-framestream Control.go Decode: the length is at least the control type and at most 512.
    let length = reader.read_u32().await? as usize;
    if !(4..=CONTROL_MAX).contains(&length) {
        return Err(invalid("control frame length out of range"));
    }
    let mut storage = [0; CONTROL_MAX];
    let payload = &mut storage[..length];
    reader.read_exact(payload).await?;
    let kind = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut rest = &payload[4..];
    let mut content_types = Vec::new();
    while !rest.is_empty() {
        let [t0, t1, t2, t3, l0, l1, l2, l3, tail @ ..] = rest else {
            return Err(invalid("truncated control frame field"));
        };
        let field = u32::from_be_bytes([*t0, *t1, *t2, *t3]);
        let size = u32::from_be_bytes([*l0, *l1, *l2, *l3]) as usize;
        if field != FIELD_CONTENT_TYPE || size > tail.len() {
            return Err(invalid("invalid control frame field"));
        }
        content_types.push(tail[..size].to_vec());
        rest = &tail[size..];
    }
    Ok(Control {
        kind,
        content_types,
    })
}

// golang-framestream timeout.go: each Write and Read on the connection gets its own deadline.
async fn within<T>(
    limit: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(limit, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "frame streams timeout"))?
}

async fn write_control<S: AsyncWrite + Unpin>(
    stream: &mut S,
    limit: Duration,
    kind: ControlType,
    content_types: &[&[u8]],
) -> io::Result<()> {
    let mut frame =
        Vec::with_capacity(16 + content_types.iter().map(|ct| 8 + ct.len()).sum::<usize>());
    put_control(&mut frame, kind, content_types);
    // golang-framestream ControlFrame.EncodeFlush: control frames are flushed at once.
    within(limit, async {
        stream.write_all(&frame).await?;
        stream.flush().await
    })
    .await
}

fn expect_kind(control: &Control, kind: ControlType) -> io::Result<()> {
    // golang-framestream Control.go DecodeTypeEscape: any other control type is ErrDecode.
    if control.kind == kind as u32 {
        Ok(())
    } else {
        Err(invalid("unexpected control frame type"))
    }
}

/// A Frame Streams sender that has completed the bidirectional handshake.
#[derive(Debug)]
pub struct Encoder<S> {
    stream: BufWriter<S>,
    timeout: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Encoder<S> {
    /// READY with `content_type`, read ACCEPT, send START. Each step is bounded by `timeout`.
    pub async fn connect(stream: S, content_type: &[u8], timeout: Duration) -> io::Result<Self> {
        let mut stream = BufWriter::with_capacity(WRITE_BUFFER, stream);
        // golang-framestream Writer.go NewWriter: READY lists the content types we can send.
        write_control(&mut stream, timeout, ControlType::Ready, &[content_type]).await?;
        let accept = within(timeout, read_control(&mut stream)).await?;
        expect_kind(&accept, ControlType::Accept)?;
        // golang-framestream Control.go ChooseContentType: no types in ACCEPT means START carries none;
        // otherwise ours must be listed.
        let ours = [content_type];
        let chosen: &[&[u8]] = if accept.content_types.is_empty() {
            &[]
        } else if accept.content_types.iter().any(|ct| ct == content_type) {
            &ours
        } else {
            return Err(invalid("content type mismatch"));
        };
        write_control(&mut stream, timeout, ControlType::Start, chosen).await?;
        Ok(Self { stream, timeout })
    }

    /// Buffers one data frame; it reaches the peer on `flush` or when the buffer fills.
    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        // Frame Streams: a zero length is the control escape, so a data frame is never empty.
        let length = u32::try_from(payload.len())
            .ok()
            .filter(|&length| length != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "data frame size"))?;
        let stream = &mut self.stream;
        within(self.timeout, async {
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(payload).await
        })
        .await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        within(self.timeout, self.stream.flush()).await
    }

    /// STOP, then wait for FINISH. golang-framestream Writer.go `Close` for a bidirectional stream.
    pub async fn close(mut self) -> io::Result<()> {
        write_control(&mut self.stream, self.timeout, ControlType::Stop, &[]).await?;
        let finish = within(self.timeout, read_control(&mut self.stream)).await?;
        expect_kind(&finish, ControlType::Finish)
    }
}
