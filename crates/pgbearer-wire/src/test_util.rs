//! Test-only readers and writers that exercise partial I/O.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Delivers `data` in chunks whose sizes cycle through `sizes`, optionally
/// returning `Pending` (after waking itself) before every chunk.
#[derive(Debug)]
pub(crate) struct ChunkedReader {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    next: usize,
    pend: bool,
    pended: bool,
}

impl ChunkedReader {
    /// Chunks cycle through `sizes` (0 is treated as 1).
    pub(crate) fn new(data: impl Into<Vec<u8>>, sizes: Vec<usize>) -> Self {
        let sizes = if sizes.is_empty() { vec![1] } else { sizes };
        ChunkedReader {
            data: data.into(),
            pos: 0,
            sizes,
            next: 0,
            pend: false,
            pended: false,
        }
    }

    /// One byte per read.
    pub(crate) fn bytewise(data: impl Into<Vec<u8>>) -> Self {
        Self::new(data, vec![1])
    }

    /// Return `Pending` before every chunk.
    pub(crate) fn pending(mut self) -> Self {
        self.pend = true;
        self
    }

    /// Bytes handed out so far.
    pub(crate) fn consumed(&self) -> usize {
        self.pos
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pend && !this.pended {
            this.pended = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.pended = false;
        let size = this.sizes[this.next % this.sizes.len()].max(1);
        this.next += 1;
        let n = size.min(buf.remaining()).min(this.data.len() - this.pos);
        buf.put_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// Byte `i` of the test pattern.
pub(crate) fn pattern_byte(i: u64) -> u8 {
    (i % 251) as u8
}

/// Produces `len` bytes of the test pattern without holding them in memory.
#[derive(Debug)]
pub(crate) struct PatternReader {
    pos: u64,
    len: u64,
}

impl PatternReader {
    pub(crate) fn new(len: u64) -> Self {
        PatternReader { pos: 0, len }
    }
}

impl AsyncRead for PatternReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Odd chunk size so chunk and message boundaries do not line up.
        let n = (buf.remaining() as u64).min(this.len - this.pos).min(7919) as usize;
        let start = this.pos;
        for (i, b) in buf.initialize_unfilled_to(n).iter_mut().enumerate() {
            *b = pattern_byte(start + i as u64);
        }
        buf.advance(n);
        this.pos += n as u64;
        Poll::Ready(Ok(()))
    }
}

/// Produces `len` copies of one byte quickly (for multi-gigabyte bodies).
#[derive(Debug)]
pub(crate) struct FillReader {
    left: u64,
    byte: u8,
}

impl FillReader {
    pub(crate) fn new(byte: u8, len: u64) -> Self {
        FillReader { left: len, byte }
    }
}

impl AsyncRead for FillReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = (buf.remaining() as u64).min(this.left) as usize;
        buf.initialize_unfilled_to(n).fill(this.byte);
        buf.advance(n);
        this.left -= n as u64;
        Poll::Ready(Ok(()))
    }
}

/// Checks that it receives the test pattern; records the largest write.
#[derive(Debug, Default)]
pub(crate) struct PatternChecker {
    pub(crate) received: u64,
    pub(crate) largest_write: usize,
    pub(crate) mismatch: Option<u64>,
}

impl AsyncWrite for PatternChecker {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Accept at most 1000 bytes per call to exercise partial writes.
        let n = buf.len().min(1000);
        for &b in &buf[..n] {
            if this.mismatch.is_none() && b != pattern_byte(this.received) {
                this.mismatch = Some(this.received);
            }
            this.received += 1;
        }
        this.largest_write = this.largest_write.max(buf.len());
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A reader that hands out its data, then fails with an I/O error.
#[derive(Debug)]
pub(crate) struct FailingReader {
    data: Vec<u8>,
    pos: usize,
}

impl FailingReader {
    pub(crate) fn new(data: impl Into<Vec<u8>>) -> Self {
        FailingReader {
            data: data.into(),
            pos: 0,
        }
    }
}

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos >= this.data.len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection reset by test",
            )));
        }
        let n = buf.remaining().min(this.data.len() - this.pos);
        buf.put_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

/// Run a future to completion on a fresh current-thread runtime (for proptest).
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(f)
}
