//! Framing of regular (tagged) protocol messages.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::WireError;

/// Default limit for message bodies that are read whole for inspection.
/// Bodies that are relayed are streamed and have no such limit.
pub const DEFAULT_INSPECT_LIMIT: usize = 16 * 1024 * 1024;

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
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wrap a reader.
    pub fn new(inner: R) -> Self {
        Self::with_buffer(inner, BytesMut::with_capacity(64 * 1024))
    }

    /// Wrap a reader, starting with bytes already read from it.
    pub fn with_buffer(inner: R, buf: BytesMut) -> Self {
        FrameReader { inner, buf }
    }

    /// Number of bytes currently buffered (not yet consumed). When this is
    /// zero, a relay should flush its writer before waiting for more input.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Read the next header. `Ok(None)` on clean EOF at a message boundary.
    pub async fn next_header(&mut self) -> Result<Option<Header>, WireError> {
        todo!("pgbearer-wire: FrameReader::next_header")
    }

    /// Read the whole body of the message whose header was just returned.
    /// Fails with [`WireError::InvalidLength`] if `header.body_len > limit`.
    pub async fn read_body(&mut self, header: &Header, limit: usize) -> Result<Bytes, WireError> {
        let _ = (header, limit);
        todo!("pgbearer-wire: FrameReader::read_body")
    }

    /// Stream the body to `writer` without buffering it whole. Returns the
    /// number of bytes copied (always `header.body_len` on success). Does not flush.
    pub async fn copy_body<W: AsyncWrite + Unpin>(
        &mut self,
        header: &Header,
        writer: &mut W,
    ) -> Result<u64, WireError> {
        let _ = (header, writer);
        todo!("pgbearer-wire: FrameReader::copy_body")
    }

    /// Discard the body.
    pub async fn skip_body(&mut self, header: &Header) -> Result<(), WireError> {
        let _ = header;
        todo!("pgbearer-wire: FrameReader::skip_body")
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
}
