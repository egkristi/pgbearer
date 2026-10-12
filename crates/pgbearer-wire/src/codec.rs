//! Shared low-level helpers: a bounds-checked cursor for decoding message
//! bodies, and writers for C strings and length-prefixed messages.
//!
//! Every read through [`Cursor`] is bounds checked and returns
//! [`WireError::Protocol`] instead of panicking, so decoders built on it are
//! safe to run on untrusted input.

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::WireError;

/// A forward-only, bounds-checked reader over a message body.
#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    /// Message name used in error messages, for example `"ParameterStatus"`.
    ctx: &'static str,
}

impl<'a> Cursor<'a> {
    /// Start reading `buf`; `ctx` names the message in error messages.
    pub(crate) fn new(buf: &'a [u8], ctx: &'static str) -> Self {
        Cursor { buf, ctx }
    }

    /// Number of bytes not yet consumed.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// A protocol error mentioning the message name.
    pub(crate) fn error(&self, what: impl std::fmt::Display) -> WireError {
        WireError::Protocol(format!("{}: {what}", self.ctx))
    }

    fn truncated(&self, needed: usize) -> WireError {
        self.error(format_args!(
            "message truncated (needed {needed} more bytes, {} left)",
            self.buf.len()
        ))
    }

    /// Consume exactly `n` bytes.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        match self.buf.split_at_checked(n) {
            Some((head, tail)) => {
                self.buf = tail;
                Ok(head)
            }
            None => Err(self.truncated(n)),
        }
    }

    /// Consume a fixed-size array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// Consume everything that is left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }

    /// Consume one byte.
    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    /// Consume a big-endian `u16`.
    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Consume a big-endian `i32`.
    pub(crate) fn i32(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    /// Consume a big-endian `u32`.
    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Consume a NUL-terminated byte string; the NUL is consumed but not returned.
    pub(crate) fn cstr_bytes(&mut self) -> Result<&'a [u8], WireError> {
        match self.buf.iter().position(|&b| b == 0) {
            Some(nul) => {
                let s = &self.buf[..nul];
                self.buf = &self.buf[nul + 1..];
                Ok(s)
            }
            None => Err(self.error("string is missing its NUL terminator")),
        }
    }

    /// Consume a NUL-terminated string that must be valid UTF-8.
    pub(crate) fn cstr(&mut self) -> Result<&'a str, WireError> {
        let raw = self.cstr_bytes()?;
        std::str::from_utf8(raw).map_err(|_| self.error("string is not valid UTF-8"))
    }

    /// Consume a NUL-terminated string, replacing invalid UTF-8 sequences.
    pub(crate) fn cstr_lossy(&mut self) -> Result<String, WireError> {
        Ok(String::from_utf8_lossy(self.cstr_bytes()?).into_owned())
    }

    /// Fail unless every byte has been consumed.
    pub(crate) fn finish(&self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(self.error(format_args!(
                "{} bytes of unexpected trailing data",
                self.buf.len()
            )))
        }
    }
}

/// Append `s` as a C string. A C string cannot contain NUL, so anything from
/// the first NUL byte onward is dropped (exactly what a C receiver would
/// read); this keeps the encoded message well formed whatever `s` contains.
pub(crate) fn put_cstr(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    buf.put_slice(&bytes[..end]);
    buf.put_u8(0);
}

/// Write `tag` and a placeholder length; returns the position of the length
/// field for [`finish_message`].
pub(crate) fn begin_message(buf: &mut BytesMut, tag: u8) -> usize {
    buf.put_u8(tag);
    begin_length(buf)
}

/// Write a placeholder `i32` length; returns its position for [`finish_message`].
pub(crate) fn begin_length(buf: &mut BytesMut) -> usize {
    let pos = buf.len();
    buf.put_i32(0);
    pos
}

/// Patch the length field at `len_pos` with the number of bytes written since
/// it (the length counts itself). Lengths that do not fit an `i32` (bodies
/// of 2 GiB or more, which no caller produces) saturate at `i32::MAX`.
pub(crate) fn finish_message(buf: &mut BytesMut, len_pos: usize) {
    let len = buf.len().saturating_sub(len_pos);
    let len = i32::try_from(len).unwrap_or(i32::MAX);
    if let Some(field) = buf.get_mut(len_pos..len_pos + 4) {
        field.copy_from_slice(&len.to_be_bytes());
    }
}

/// `read_exact`, mapping EOF to [`WireError::UnexpectedEof`]. Reads exactly
/// `buf.len()` bytes and nothing more.
pub(crate) async fn read_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), WireError> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(WireError::UnexpectedEof),
        Err(e) => Err(WireError::Io(e)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;

    #[test]
    fn cursor_reads_and_bounds_checks() {
        let data = [0u8, 1, 0, 0, 0, 2, b'h', b'i', 0, 0xff];
        let mut c = Cursor::new(&data, "Test");
        assert_eq!(c.u16().unwrap(), 1);
        assert_eq!(c.i32().unwrap(), 2);
        assert_eq!(c.cstr().unwrap(), "hi");
        assert_eq!(c.remaining(), 1);
        assert!(c.finish().is_err());
        assert!(c.i32().is_err(), "short read must fail");
        assert_eq!(c.u8().unwrap(), 0xff);
        assert_eq!(c.remaining(), 0);
        assert!(c.u8().is_err());
        c.finish().unwrap();
    }

    #[test]
    fn cursor_errors_name_the_message() {
        let mut c = Cursor::new(b"abc", "Query");
        let err = c.cstr().unwrap_err().to_string();
        assert!(err.contains("Query"), "{err}");
        assert!(err.contains("NUL"), "{err}");
        let mut c = Cursor::new(b"\xff\0", "Query");
        assert!(c.cstr().unwrap_err().to_string().contains("UTF-8"));
        let mut c = Cursor::new(b"\xff\0", "Query");
        assert_eq!(c.cstr_lossy().unwrap(), "\u{fffd}");
    }

    #[test]
    fn put_cstr_truncates_at_nul() {
        let mut buf = BytesMut::new();
        put_cstr(&mut buf, "ab\0cd");
        put_cstr(&mut buf, "");
        assert_eq!(&buf[..], b"ab\0\0");
    }

    #[test]
    fn message_length_is_patched() {
        let mut buf = BytesMut::from(&b"xx"[..]);
        let pos = begin_message(&mut buf, b'Q');
        buf.put_slice(b"abc");
        finish_message(&mut buf, pos);
        assert_eq!(&buf[..], b"xxQ\0\0\0\x07abc");
    }
}
