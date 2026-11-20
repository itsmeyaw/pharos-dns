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
        limit: 100,
        calls: 0,
        first_segments: 0,
    };
    let oversized = vec![0; usize::from(u16::MAX) + 1];
    assert_eq!(
        write_tcp_frame(&mut writer, &oversized)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(writer.calls, 0);

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
