//! Framing of regular (tagged) protocol messages.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::WireError;

/// Default limit for message bodies that are read whole for inspection.
/// Bodies that are relayed are streamed and have no such limit.
pub const DEFAULT_INSPECT_LIMIT: usize = 16 * 1024 * 1024;

/// Default capacity of the [`FrameReader`] read buffer.
pub const DEFAULT_BUFFER_CAPACITY: usize = 64 * 1024;

/// Smallest read buffer capacity [`FrameReader::with_capacity`] accepts; it
/// must at least hold a header.
pub const MIN_BUFFER_CAPACITY: usize = 16;

/// Largest body length a header can declare (`i32::MAX` minus the 4 bytes of
/// the length field itself).
pub const MAX_BODY_LEN: usize = i32::MAX as usize - 4;

/// Size of a tagged message header (tag byte and `i32` length).
pub const HEADER_LEN: usize = 5;

/// Header of a tagged message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Message type byte.
    pub tag: u8,
    /// Body length in bytes (the length field minus 4).
    pub body_len: usize,
}

impl Header {
    /// Encode the 5-byte header (`tag`, then `body_len + 4` as big-endian i32).
    pub fn encode(&self) -> [u8; 5] {
        let len = (self.body_len as u32 + 4).to_be_bytes();
        [self.tag, len[0], len[1], len[2], len[3]]
    }
}

/// A complete message held in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message type byte.
    pub tag: u8,
    /// Message body (without tag and length).
    pub body: Bytes,
}

impl Message {
    /// Create a message.
    pub fn new(tag: u8, body: impl Into<Bytes>) -> Self {
        Message {
            tag,
            body: body.into(),
        }
    }

    /// The header for this message.
    pub fn header(&self) -> Header {
        Header {
            tag: self.tag,
            body_len: self.body.len(),
        }
    }

    /// Append the encoded message (header and body) to `buf`.
    pub fn encode_into(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.header().encode());
        buf.extend_from_slice(&self.body);
    }
}

/// Buffered reader of tagged messages.
///
/// Typical relay loop:
///
/// ```ignore
/// while let Some(h) = reader.next_header().await? {
///     if needs_inspection(h.tag) {
///         let body = reader.read_body(&h, DEFAULT_INSPECT_LIMIT).await?;
///         // inspect, then write h.encode() and body
///     } else {
///         writer.write_all(&h.encode()).await?;
///         reader.copy_body(&h, &mut writer).await?;
///     }
///     if reader.buffered() == 0 { writer.flush().await?; }
/// }
/// ```
///
/// Contract:
/// * After [`next_header`](Self::next_header) returns a header, the caller must
///   consume exactly that body with [`read_body`](Self::read_body),
///   [`copy_body`](Self::copy_body) or [`skip_body`](Self::skip_body) before
///   calling `next_header` again.
/// * Lengths below 4 or above `i32::MAX` are [`WireError::InvalidLength`].
/// * EOF exactly at a message boundary yields `Ok(None)`; EOF anywhere else is
///   [`WireError::UnexpectedEof`].
/// * The reader never buffers more than its internal read buffer capacity
///   (64 KiB by default), regardless of message size.
///
/// Cancel safety: [`next_header`](Self::next_header) is cancel safe (a
/// partially received header stays buffered and is picked up by the next
/// call), so it can be used as a `tokio::select!` branch. The body methods
/// are not: if one of them is cancelled, part of the body may have been
/// consumed, and the reader then reports a protocol error on further use.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    buf: BytesMut,
    /// Upper bound on the bytes held in `buf` by reads into it.
    capacity: usize,
    /// Body bytes of the current message not yet consumed; `None` when the
    /// reader is at a message boundary.
    pending_body: Option<usize>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wrap a reader.
    pub fn new(inner: R) -> Self {
        Self::with_buffer(inner, BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY))
    }

    /// Wrap a reader, starting with bytes already read from it.
    pub fn with_buffer(inner: R, buf: BytesMut) -> Self {
        FrameReader {
            inner,
            buf,
            capacity: DEFAULT_BUFFER_CAPACITY,
            pending_body: None,
        }
    }

    /// Wrap a reader with a read buffer of `capacity` bytes (at least
    /// [`MIN_BUFFER_CAPACITY`]). Larger buffers mean fewer reads and writes
    /// for large messages; smaller ones mean less memory per connection.
    pub fn with_capacity(inner: R, capacity: usize) -> Self {
        let capacity = capacity.max(MIN_BUFFER_CAPACITY);
        FrameReader {
            inner,
            buf: BytesMut::with_capacity(capacity),
            capacity,
            pending_body: None,
        }
    }

    /// Number of bytes currently buffered (not yet consumed). When this is
    /// zero, a relay should flush its writer before waiting for more input.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Read the next header. `Ok(None)` on clean EOF at a message boundary.
    ///
    /// Fails with [`WireError::Protocol`] if the body of the previous message
    /// has not been consumed.
    pub async fn next_header(&mut self) -> Result<Option<Header>, WireError> {
        if let Some(left) = self.pending_body {
            return Err(WireError::protocol(format!(
                "frame reader: {left} body bytes of the previous message were not consumed"
            )));
        }
        while self.buf.len() < HEADER_LEN {
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(WireError::UnexpectedEof)
                };
            }
        }
        let tag = self.buf[0];
        let len = i32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]);
        let body_len = usize::try_from(len)
            .ok()
            .and_then(|l| l.checked_sub(4))
            .ok_or(WireError::InvalidLength {
                len: i64::from(len),
                limit: MAX_BODY_LEN + 4,
            })?;
        self.buf.advance(HEADER_LEN);
        self.pending_body = (body_len > 0).then_some(body_len);
        Ok(Some(Header { tag, body_len }))
    }

    /// Read the whole body of the message whose header was just returned.
    /// Fails with [`WireError::InvalidLength`] if `header.body_len > limit`.
    ///
    /// The limit is checked before anything is allocated, and bodies larger
    /// than the read buffer are allocated as their bytes arrive, so a peer
    /// cannot make the reader allocate more than it actually sends. After a
    /// limit error the body is still pending and can be discarded with
    /// [`skip_body`](Self::skip_body). The returned bytes never share memory
    /// with the reader's buffer, so keeping them does not pin that buffer.
    pub async fn read_body(&mut self, header: &Header, limit: usize) -> Result<Bytes, WireError> {
        self.check_pending(header)?;
        let n = header.body_len;
        if n > limit {
            return Err(WireError::InvalidLength {
                len: i64::try_from(n).unwrap_or(i64::MAX),
                limit,
            });
        }
        if n <= self.capacity {
            while self.buf.len() < n {
                if self.fill().await? == 0 {
                    return Err(WireError::UnexpectedEof);
                }
            }
            let body = Bytes::copy_from_slice(&self.buf[..n]);
            self.buf.advance(n);
            self.pending_body = None;
            return Ok(body);
        }

        // Larger than the read buffer: take what is buffered, then read the
        // rest straight into the body, never past its end.
        let buffered = self.buf.len().min(n);
        let mut body = BytesMut::with_capacity(self.capacity.max(buffered));
        body.extend_from_slice(&self.buf[..buffered]);
        self.buf.advance(buffered);
        while body.len() < n {
            // Keep the pending count exact at every await point, so that a
            // failed or cancelled call cannot be retried as if nothing had
            // been consumed.
            self.pending_body = Some(n - body.len());
            let want = (n - body.len()).min(self.capacity);
            body.reserve(want);
            if self.inner.read_buf(&mut (&mut body).limit(want)).await? == 0 {
                return Err(WireError::UnexpectedEof);
            }
        }
        self.pending_body = None;
        Ok(body.freeze())
    }

    /// Stream the body to `writer` without buffering it whole. Returns the
    /// number of bytes copied (always `header.body_len` on success). Does not flush.
    ///
    /// Buffered bytes are written first; the rest is read in chunks of at
    /// most the buffer capacity and written as it arrives.
    pub async fn copy_body<W: AsyncWrite + Unpin>(
        &mut self,
        header: &Header,
        writer: &mut W,
    ) -> Result<u64, WireError> {
        self.check_pending(header)?;
        let mut remaining = header.body_len;
        while remaining > 0 {
            // Exact at every await point (see `read_body`).
            self.pending_body = Some(remaining);
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(WireError::UnexpectedEof);
            }
            let n = remaining.min(self.buf.len());
            writer.write_all(&self.buf[..n]).await?;
            self.buf.advance(n);
            remaining -= n;
        }
        self.pending_body = None;
        Ok(header.body_len as u64)
    }

    /// Discard the body.
    ///
    /// Never allocates more than the read buffer, whatever the body size.
    pub async fn skip_body(&mut self, header: &Header) -> Result<(), WireError> {
        self.check_pending(header)?;
        let mut remaining = header.body_len;
        while remaining > 0 {
            self.pending_body = Some(remaining);
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(WireError::UnexpectedEof);
            }
            let n = remaining.min(self.buf.len());
            self.buf.advance(n);
            remaining -= n;
        }
        self.pending_body = None;
        Ok(())
    }

    /// Read a whole message (header and body). `Ok(None)` on clean EOF.
    pub async fn read_message(&mut self, limit: usize) -> Result<Option<Message>, WireError> {
        match self.next_header().await? {
            None => Ok(None),
            Some(h) => {
                let body = self.read_body(&h, limit).await?;
                Ok(Some(Message { tag: h.tag, body }))
            }
        }
    }

    /// Mutable access to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Return the underlying reader and any buffered, unconsumed bytes.
    pub fn into_parts(self) -> (R, BytesMut) {
        (self.inner, self.buf)
    }

    /// Check that `header` describes the body that is due next.
    fn check_pending(&self, header: &Header) -> Result<(), WireError> {
        match self.pending_body {
            Some(left) if left == header.body_len => Ok(()),
            None if header.body_len == 0 => Ok(()),
            Some(left) => Err(WireError::protocol(format!(
                "frame reader: header declares a {}-byte body but {left} body bytes are pending",
                header.body_len
            ))),
            None => Err(WireError::protocol(
                "frame reader: no message body is pending (call next_header first)",
            )),
        }
    }

    /// Read more input into the buffer, up to its capacity. Returns the number
    /// of bytes read; 0 means EOF.
    async fn fill(&mut self) -> Result<usize, WireError> {
        let room = self.capacity.saturating_sub(self.buf.len());
        if room == 0 {
            // Unreachable by construction: callers only fill a buffer that
            // holds less than they need, and they never need more than the
            // capacity.
            return Err(WireError::protocol("frame reader: read buffer is full"));
        }
        // Reclaims the space of consumed bytes when possible.
        self.buf.reserve(room);
        let read = self
            .inner
            .read_buf(&mut (&mut self.buf).limit(room))
            .await?;
        Ok(read)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use crate::test_util::{
        ChunkedReader, FailingReader, FillReader, PatternChecker, PatternReader, block_on,
    };
    use proptest::prelude::*;
    use tokio::io::AsyncWriteExt;

    fn encode_all(msgs: &[Message]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        for m in msgs {
            m.encode_into(&mut buf);
        }
        buf.to_vec()
    }

    fn sample() -> Vec<Message> {
        vec![
            Message::new(b'Q', &b"SELECT 1\0"[..]),
            Message::new(b'S', Bytes::new()),
            Message::new(b'd', vec![7u8; 300]),
            Message::new(b'X', Bytes::new()),
        ]
    }

    async fn read_all<R: AsyncRead + Unpin>(
        reader: &mut FrameReader<R>,
    ) -> Result<Vec<Message>, WireError> {
        let mut out = Vec::new();
        while let Some(m) = reader.read_message(DEFAULT_INSPECT_LIMIT).await? {
            out.push(m);
        }
        Ok(out)
    }

    fn raw_header(tag: u8, len: i32) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend_from_slice(&len.to_be_bytes());
        v
    }

    #[test]
    fn header_and_message_encoding() {
        let h = Header {
            tag: b'Q',
            body_len: 9,
        };
        assert_eq!(h.encode(), [b'Q', 0, 0, 0, 13]);
        let m = Message::new(b'Q', &b"SELECT 1\0"[..]);
        assert_eq!(m.header(), h);
        let mut buf = BytesMut::new();
        m.encode_into(&mut buf);
        assert_eq!(&buf[..], b"Q\0\0\0\x0dSELECT 1\0");
    }

    #[tokio::test]
    async fn reads_messages_from_one_slice() {
        let msgs = sample();
        let bytes = encode_all(&msgs);
        let mut r = FrameReader::new(&bytes[..]);
        assert_eq!(read_all(&mut r).await.unwrap(), msgs);
        assert_eq!(r.buffered(), 0);
        // EOF is sticky.
        assert!(r.next_header().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn reads_messages_split_into_single_bytes() {
        let msgs = sample();
        let bytes = encode_all(&msgs);
        let mut r = FrameReader::new(ChunkedReader::bytewise(bytes).pending());
        assert_eq!(read_all(&mut r).await.unwrap(), msgs);
    }

    #[tokio::test]
    async fn empty_stream_is_clean_eof() {
        let mut r = FrameReader::new(&b""[..]);
        assert!(r.next_header().await.unwrap().is_none());
        assert!(r.read_message(10).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eof_inside_a_header_or_body() {
        let bytes = encode_all(&[Message::new(b'Q', &b"SELECT 1\0"[..])]);
        for cut in 1..bytes.len() {
            let mut r = FrameReader::new(ChunkedReader::bytewise(bytes[..cut].to_vec()));
            assert!(
                matches!(r.read_message(100).await, Err(WireError::UnexpectedEof)),
                "read_body, cut at {cut}"
            );
            if cut >= HEADER_LEN {
                let mut r = FrameReader::new(&bytes[..cut]);
                let h = r.next_header().await.unwrap().unwrap();
                assert!(matches!(
                    r.skip_body(&h).await,
                    Err(WireError::UnexpectedEof)
                ));
                let mut r = FrameReader::new(&bytes[..cut]);
                let h = r.next_header().await.unwrap().unwrap();
                let mut sink = Vec::new();
                assert!(matches!(
                    r.copy_body(&h, &mut sink).await,
                    Err(WireError::UnexpectedEof)
                ));
                // Further use is refused: the stream is no longer framed.
                assert!(matches!(r.next_header().await, Err(WireError::Protocol(_))));
            }
        }
    }

    #[tokio::test]
    async fn invalid_lengths() {
        for len in [i32::MIN, -1, 0, 1, 3] {
            let mut bytes = raw_header(b'Q', len);
            bytes.extend_from_slice(&[0; 8]);
            let mut r = FrameReader::new(&bytes[..]);
            match r.next_header().await {
                Err(WireError::InvalidLength { len: got, limit }) => {
                    assert_eq!(got, i64::from(len));
                    assert_eq!(limit, i32::MAX as usize);
                }
                other => panic!("length {len}: expected InvalidLength, got {other:?}"),
            }
        }
        // Length 4 is an empty body; i32::MAX is the largest body.
        let empty = raw_header(b'S', 4);
        let mut r = FrameReader::new(&empty[..]);
        assert_eq!(
            r.next_header().await.unwrap(),
            Some(Header {
                tag: b'S',
                body_len: 0
            })
        );
        let largest = raw_header(b'd', i32::MAX);
        let mut r = FrameReader::new(&largest[..]);
        let h = r.next_header().await.unwrap().unwrap();
        assert_eq!(h.body_len, MAX_BODY_LEN);
        assert_eq!(h.encode(), [b'd', 0x7f, 0xff, 0xff, 0xff]);
    }

    #[tokio::test]
    async fn read_body_limit_is_checked_before_reading() {
        let mut bytes = raw_header(b'p', i32::MAX);
        bytes.extend_from_slice(b"only a few bytes");
        let mut r = FrameReader::new(&bytes[..]);
        let h = r.next_header().await.unwrap().unwrap();
        match r.read_body(&h, 16 * 1024).await {
            Err(WireError::InvalidLength { len, limit }) => {
                assert_eq!(len, MAX_BODY_LEN as i64);
                assert_eq!(limit, 16 * 1024);
            }
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn over_limit_body_can_be_skipped() {
        let msgs = [
            Message::new(b'p', vec![1u8; 100]),
            Message::new(b'Q', &b"x\0"[..]),
        ];
        let bytes = encode_all(&msgs);
        let mut r = FrameReader::new(&bytes[..]);
        let h = r.next_header().await.unwrap().unwrap();
        assert!(matches!(
            r.read_body(&h, 99).await,
            Err(WireError::InvalidLength {
                len: 100,
                limit: 99
            })
        ));
        r.skip_body(&h).await.unwrap();
        assert_eq!(r.read_message(99).await.unwrap(), Some(msgs[1].clone()));
        // A body exactly at the limit is fine.
        let mut r = FrameReader::new(&bytes[..]);
        assert_eq!(r.read_message(100).await.unwrap(), Some(msgs[0].clone()));
    }

    #[tokio::test]
    async fn contract_misuse_is_reported() {
        let bytes = encode_all(&sample());
        let mut r = FrameReader::new(&bytes[..]);
        let h = r.next_header().await.unwrap().unwrap();
        // Calling next_header again without consuming the body.
        assert!(matches!(r.next_header().await, Err(WireError::Protocol(_))));
        // A header that does not match the pending body.
        let wrong = Header {
            tag: h.tag,
            body_len: h.body_len + 1,
        };
        assert!(matches!(
            r.read_body(&wrong, 1000).await,
            Err(WireError::Protocol(_))
        ));
        // The correct header still works.
        assert_eq!(&r.read_body(&h, 1000).await.unwrap()[..], b"SELECT 1\0");
        // Consuming twice.
        assert!(matches!(r.skip_body(&h).await, Err(WireError::Protocol(_))));
        // Empty bodies need not be consumed explicitly.
        let sync = r.next_header().await.unwrap().unwrap();
        assert_eq!(sync.body_len, 0);
        let copy = r.next_header().await.unwrap().unwrap();
        assert_eq!(copy.tag, b'd');
        // ... but consuming them is fine too.
        r.skip_body(&copy).await.unwrap();
        let term = r.next_header().await.unwrap().unwrap();
        assert!(r.read_body(&term, 0).await.unwrap().is_empty());
        assert!(r.next_header().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn copy_body_streams_large_bodies_through_a_small_buffer() {
        const BODY: u64 = 5 * 1024 * 1024 + 17;
        const CAP: usize = 1024;
        let header = raw_header(b'd', (BODY + 4) as i32);
        let trailer = encode_all(&[Message::new(b'c', Bytes::new())]);
        let input = AsyncReadExt::chain(
            AsyncReadExt::chain(&header[..], PatternReader::new(BODY)),
            &trailer[..],
        );
        let mut r = FrameReader::with_capacity(input, CAP);
        let h = r.next_header().await.unwrap().unwrap();
        assert_eq!(h.body_len as u64, BODY);
        let mut out = PatternChecker::default();
        assert_eq!(r.copy_body(&h, &mut out).await.unwrap(), BODY);
        assert_eq!(out.received, BODY);
        assert_eq!(out.mismatch, None);
        assert!(
            out.largest_write <= CAP,
            "largest write {}",
            out.largest_write
        );
        assert!(r.buffered() <= CAP);
        assert!(
            r.buf.capacity() <= 2 * CAP,
            "buffer grew to {}",
            r.buf.capacity()
        );
        assert_eq!(
            r.read_message(0).await.unwrap(),
            Some(Message::new(b'c', Bytes::new()))
        );
        assert!(r.read_message(0).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn copy_body_with_buffered_bytes_and_following_messages() {
        let msgs = [
            Message::new(b'D', (0..200u8).collect::<Vec<_>>()),
            Message::new(b'C', &b"SELECT 1\0"[..]),
            Message::new(b'Z', &b"I"[..]),
        ];
        let bytes = encode_all(&msgs);
        let mut r = FrameReader::with_capacity(ChunkedReader::new(bytes, vec![3, 50, 1, 7]), 32);
        let mut relayed = Vec::new();
        while let Some(h) = r.next_header().await.unwrap() {
            relayed.write_all(&h.encode()).await.unwrap();
            let n = r.copy_body(&h, &mut relayed).await.unwrap();
            assert_eq!(n, h.body_len as u64);
        }
        assert_eq!(relayed, encode_all(&msgs));
    }

    #[tokio::test]
    async fn read_body_larger_than_the_buffer() {
        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let msgs = [Message::new(b'Q', body), Message::new(b'S', Bytes::new())];
        let bytes = encode_all(&msgs);
        let mut r = FrameReader::with_capacity(ChunkedReader::new(bytes, vec![4096, 1, 999]), 64);
        assert_eq!(read_all(&mut r).await.unwrap(), msgs);
    }

    #[tokio::test]
    async fn skip_body_of_a_large_body() {
        const BODY: u64 = 3 * 1024 * 1024;
        let header = raw_header(b'd', (BODY + 4) as i32);
        let trailer = encode_all(&[Message::new(b'Z', &b"T"[..])]);
        let input = AsyncReadExt::chain(
            AsyncReadExt::chain(&header[..], PatternReader::new(BODY)),
            &trailer[..],
        );
        let mut r = FrameReader::with_capacity(input, 100);
        let h = r.next_header().await.unwrap().unwrap();
        r.skip_body(&h).await.unwrap();
        assert!(r.buf.capacity() <= 200);
        assert_eq!(
            r.read_message(10).await.unwrap(),
            Some(Message::new(b'Z', &b"T"[..]))
        );
    }

    #[tokio::test]
    async fn largest_possible_body_streams_and_skips() {
        // A body of i32::MAX - 4 bytes (just under 2 GiB) through the default buffer.
        let header = raw_header(b'd', i32::MAX);
        let trailer = encode_all(&[Message::new(b'c', Bytes::new())]);
        let input = AsyncReadExt::chain(
            AsyncReadExt::chain(&header[..], FillReader::new(0x5a, MAX_BODY_LEN as u64)),
            &trailer[..],
        );
        let mut r = FrameReader::new(input);
        let h = r.next_header().await.unwrap().unwrap();
        let mut sink = tokio::io::sink();
        assert_eq!(
            r.copy_body(&h, &mut sink).await.unwrap(),
            MAX_BODY_LEN as u64
        );
        assert!(r.buffered() <= DEFAULT_BUFFER_CAPACITY);
        assert_eq!(r.next_header().await.unwrap().unwrap().tag, b'c');

        let input = AsyncReadExt::chain(
            AsyncReadExt::chain(&header[..], FillReader::new(0, MAX_BODY_LEN as u64)),
            &trailer[..],
        );
        let mut r = FrameReader::new(input);
        let h = r.next_header().await.unwrap().unwrap();
        r.skip_body(&h).await.unwrap();
        assert_eq!(r.next_header().await.unwrap().unwrap().tag, b'c');
    }

    #[tokio::test]
    async fn io_errors_are_reported() {
        let mut bytes = raw_header(b'd', 1004);
        bytes.extend_from_slice(&[0; 10]);
        let mut r = FrameReader::new(FailingReader::new(bytes.clone()));
        let h = r.next_header().await.unwrap().unwrap();
        assert!(matches!(r.skip_body(&h).await, Err(WireError::Io(_))));

        let mut r = FrameReader::with_capacity(FailingReader::new(bytes), 16);
        let h = r.next_header().await.unwrap().unwrap();
        assert!(matches!(r.read_body(&h, 2000).await, Err(WireError::Io(_))));
        assert!(matches!(r.next_header().await, Err(WireError::Protocol(_))));

        let mut r = FrameReader::new(FailingReader::new(vec![b'Q', 0]));
        assert!(matches!(r.next_header().await, Err(WireError::Io(_))));
    }

    #[tokio::test]
    async fn partially_consumed_body_cannot_be_retried() {
        // copy_body fails after the buffered part was written.
        let mut bytes = raw_header(b'd', 4 + 100);
        bytes.extend_from_slice(&[1; 40]);
        let mut r = FrameReader::with_capacity(FailingReader::new(bytes.clone()), 16);
        let h = r.next_header().await.unwrap().unwrap();
        let mut out = Vec::new();
        assert!(matches!(
            r.copy_body(&h, &mut out).await,
            Err(WireError::Io(_))
        ));
        assert!(!out.is_empty());
        assert!(matches!(
            r.copy_body(&h, &mut out).await,
            Err(WireError::Protocol(_))
        ));
        assert!(matches!(r.skip_body(&h).await, Err(WireError::Protocol(_))));

        // skip_body likewise.
        let mut r = FrameReader::with_capacity(FailingReader::new(bytes.clone()), 16);
        let h = r.next_header().await.unwrap().unwrap();
        assert!(matches!(r.skip_body(&h).await, Err(WireError::Io(_))));
        assert!(matches!(
            r.read_body(&h, 1000).await,
            Err(WireError::Protocol(_))
        ));

        // A cancelled large read_body.
        let (mut client, server) = tokio::io::duplex(1024);
        let mut r = FrameReader::with_capacity(server, 16);
        client.write_all(&raw_header(b'p', 4 + 100)).await.unwrap();
        client.write_all(&[2; 30]).await.unwrap();
        let h = r.next_header().await.unwrap().unwrap();
        tokio::select! {
            biased;
            res = r.read_body(&h, 1000) => panic!("body cannot be complete yet: {res:?}"),
            () = tokio::task::yield_now() => {}
        }
        assert!(matches!(
            r.read_body(&h, 1000).await,
            Err(WireError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn with_buffer_and_into_parts() {
        let bytes = encode_all(&sample());
        let (first, rest) = bytes.split_at(7);
        let mut r = FrameReader::with_buffer(rest, BytesMut::from(first));
        assert_eq!(r.buffered(), 7);
        assert_eq!(read_all(&mut r).await.unwrap(), sample());

        let mut r = FrameReader::new(&bytes[..]);
        let h = r.next_header().await.unwrap().unwrap();
        r.skip_body(&h).await.unwrap();
        let (inner, buffered) = r.into_parts();
        let mut leftover = buffered.to_vec();
        leftover.extend_from_slice(inner);
        assert_eq!(leftover, encode_all(&sample()[1..]));
    }

    #[tokio::test]
    async fn next_header_is_cancel_safe() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut r = FrameReader::new(server);
        client.write_all(&[b'Q', 0, 0]).await.unwrap();
        // Poll next_header until it has consumed the partial header, then drop it.
        tokio::select! {
            biased;
            res = r.next_header() => panic!("header cannot be complete yet: {res:?}"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(r.buffered(), 3);
        client.write_all(&[0, 6, b'h', b'i']).await.unwrap();
        let h = r.next_header().await.unwrap().unwrap();
        assert_eq!(
            h,
            Header {
                tag: b'Q',
                body_len: 2
            }
        );
        assert_eq!(&r.read_body(&h, 10).await.unwrap()[..], b"hi");
        drop(client);
        assert!(r.next_header().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn returned_bodies_do_not_alias_the_buffer() {
        let bytes = encode_all(&sample());
        let mut r = FrameReader::new(&bytes[..]);
        let first = r.read_message(100).await.unwrap().unwrap();
        assert_eq!(first, sample()[0]);
        // The body owns its memory: holding it does not pin the read buffer.
        assert!(first.body.is_unique());
        assert_eq!(r.next_header().await.unwrap().unwrap().body_len, 0);
        let h = r.next_header().await.unwrap().unwrap();
        let copy_data = r.read_body(&h, 1000).await.unwrap();
        assert_eq!(copy_data.len(), 300);
        assert!(copy_data.is_unique());
    }

    fn message_strategy() -> impl Strategy<Value = Message> {
        (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..300))
            .prop_map(|(tag, body)| Message::new(tag, body))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn random_chunking_preserves_messages(
            msgs in proptest::collection::vec(message_strategy(), 0..12),
            sizes in proptest::collection::vec(1usize..40, 1..8),
            cap in 16usize..128,
            mode in 0u8..3,
        ) {
            let bytes = encode_all(&msgs);
            let reader = ChunkedReader::new(bytes, sizes);
            let mut r = FrameReader::with_capacity(reader, cap);
            let got = block_on(async {
                let mut out = Vec::new();
                while let Some(h) = r.next_header().await? {
                    let body = match mode {
                        0 => r.read_body(&h, usize::MAX).await?,
                        1 => {
                            let mut v = Vec::new();
                            r.copy_body(&h, &mut v).await?;
                            Bytes::from(v)
                        }
                        _ => {
                            r.skip_body(&h).await?;
                            Bytes::new()
                        }
                    };
                    prop_assert!(r.buffered() <= cap);
                    out.push(Message::new(h.tag, body));
                }
                Ok::<_, TestCaseError>(out)
            });
            let got = match got {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            prop_assert_eq!(got.len(), msgs.len());
            for (g, m) in got.iter().zip(&msgs) {
                prop_assert_eq!(g.tag, m.tag);
                if mode != 2 {
                    prop_assert_eq!(&g.body, &m.body);
                }
            }
        }

        #[test]
        fn random_bytes_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..200),
            sizes in proptest::collection::vec(1usize..20, 1..4),
        ) {
            let mut r = FrameReader::with_capacity(ChunkedReader::new(bytes, sizes), 16);
            block_on(async {
                for _ in 0..50 {
                    match r.next_header().await {
                        Ok(Some(h)) => {
                            if r.read_body(&h, 64).await.is_err() && r.skip_body(&h).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    }
}
