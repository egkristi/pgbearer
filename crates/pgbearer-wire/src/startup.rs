//! Startup-phase packets (no type byte).
//!
//! Layout: `i32 length (including itself) | i32 code | payload`.

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncRead;

use crate::WireError;
use crate::codec::{Cursor, begin_length, finish_message, put_cstr, read_exact};

/// `SSLRequest` code.
pub const SSL_REQUEST_CODE: i32 = 80_877_103;
/// `GSSENCRequest` code.
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;
/// `CancelRequest` code.
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;
/// Default maximum startup packet length (same as PostgreSQL's `MAX_STARTUP_PACKET_LENGTH`).
pub const DEFAULT_MAX_STARTUP_PACKET_LEN: usize = 10_000;
/// Minimum and maximum cancel secret key length (protocol 3.2 allows 4..=256).
pub const CANCEL_KEY_LEN_RANGE: std::ops::RangeInclusive<usize> = 4..=256;

/// A protocol version `major.minor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    /// Major version (3).
    pub major: u16,
    /// Minor version (0 or 2).
    pub minor: u16,
}

impl ProtocolVersion {
    /// Protocol 3.0.
    pub const V3_0: ProtocolVersion = ProtocolVersion { major: 3, minor: 0 };
    /// Protocol 3.2 (PostgreSQL 18).
    pub const V3_2: ProtocolVersion = ProtocolVersion { major: 3, minor: 2 };
    /// Newest version pgbearer speaks.
    pub const LATEST: ProtocolVersion = Self::V3_2;

    /// Decode from the 32-bit code (`major << 16 | minor`).
    pub fn from_code(code: i32) -> Self {
        ProtocolVersion {
            major: ((code as u32) >> 16) as u16,
            minor: (code as u32 & 0xffff) as u16,
        }
    }

    /// Encode as the 32-bit code.
    pub fn code(self) -> i32 {
        ((u32::from(self.major) << 16) | u32::from(self.minor)) as i32
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A `StartupMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupMessage {
    /// Requested protocol version (may be newer than pgbearer supports).
    pub version: ProtocolVersion,
    /// Parameters in the order sent. Names starting with `_pq_.` are protocol
    /// extension options.
    pub params: Vec<(String, String)>,
}

impl StartupMessage {
    /// First value of parameter `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The `user` parameter.
    pub fn user(&self) -> Option<&str> {
        self.get("user")
    }

    /// The `database` parameter, defaulting to `user` as PostgreSQL does.
    pub fn database(&self) -> Option<&str> {
        self.get("database").or_else(|| self.user())
    }

    /// Protocol extension options (`_pq_.*`).
    pub fn protocol_options(&self) -> impl Iterator<Item = &str> {
        self.params
            .iter()
            .filter(|(k, _)| k.starts_with("_pq_."))
            .map(|(k, _)| k.as_str())
    }

    /// The first parameter name that appears more than once, if any.
    ///
    /// [`get`](Self::get) returns the *first* value of a repeated parameter,
    /// while PostgreSQL itself uses the *last* one. Callers that make
    /// decisions on parameters such as `user`, `database` or `options` can
    /// reject duplicates with this to remove the ambiguity.
    pub fn duplicate_param(&self) -> Option<&str> {
        let mut seen = std::collections::HashSet::with_capacity(self.params.len());
        self.params
            .iter()
            .map(|(name, _)| name.as_str())
            .find(|name| !seen.insert(*name))
    }
}

/// A `CancelRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    /// Process id from `BackendKeyData`.
    pub process_id: u32,
    /// Secret key from `BackendKeyData` (4 bytes with protocol 3.0, up to 256 with 3.2).
    pub secret_key: Bytes,
}

/// A startup-phase packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPacket {
    /// `StartupMessage`.
    Startup(StartupMessage),
    /// `SSLRequest`.
    SslRequest,
    /// `GSSENCRequest`.
    GssEncRequest,
    /// `CancelRequest`.
    Cancel(CancelRequest),
}

/// Read exactly one startup-phase packet, consuming no bytes beyond it.
///
/// Rules:
/// * `length` must be at least 8 and at most `max_len`, else [`WireError::InvalidLength`].
/// * `StartupMessage`: major version must be 3, else [`WireError::Protocol`]. The
///   payload is a sequence of NUL-terminated `name\0value\0` pairs ending with an
///   extra `\0`. Names and values must be valid UTF-8; empty names (other than the
///   terminator) are a protocol error. A missing terminator is a protocol error.
/// * `CancelRequest`: `i32 pid` then the secret key: the rest of the packet,
///   whose length must be within [`CANCEL_KEY_LEN_RANGE`].
/// * `SSLRequest` / `GSSENCRequest`: length must be exactly 8, else
///   [`WireError::Protocol`].
/// * EOF before the first byte returns [`WireError::UnexpectedEof`], as does
///   EOF anywhere inside the packet.
///
/// Validation happens as early as possible: a bad length, code or cancel key
/// length is reported before the rest of the packet is read, and the payload
/// buffer grows with the bytes actually received rather than being allocated
/// up front from the declared length. Minor protocol versions are not
/// checked (3.1, 3.3, … are returned as is): the caller answers versions it
/// does not support with `NegotiateProtocolVersion`. Duplicate parameter
/// names are accepted; see [`StartupMessage::duplicate_param`].
pub async fn read_startup_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> Result<StartupPacket, WireError> {
    let len = i32::from_be_bytes(read_array(reader).await?);
    let len_usize = usize::try_from(len)
        .ok()
        .filter(|l| (MIN_PACKET_LEN..=max_len).contains(l))
        .ok_or(WireError::InvalidLength {
            len: i64::from(len),
            limit: max_len,
        })?;
    let code = i32::from_be_bytes(read_array(reader).await?);
    // Bytes after the length and code fields.
    let payload_len = len_usize - MIN_PACKET_LEN;

    match code {
        SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => {
            let name = if code == SSL_REQUEST_CODE {
                "SSLRequest"
            } else {
                "GSSENCRequest"
            };
            if payload_len != 0 {
                return Err(WireError::protocol(format!(
                    "{name} must be exactly {MIN_PACKET_LEN} bytes long, got {len}"
                )));
            }
            Ok(if code == SSL_REQUEST_CODE {
                StartupPacket::SslRequest
            } else {
                StartupPacket::GssEncRequest
            })
        }
        CANCEL_REQUEST_CODE => {
            // i32 process id, then the secret key.
            let key_len = payload_len.saturating_sub(4);
            if payload_len < 4 || !CANCEL_KEY_LEN_RANGE.contains(&key_len) {
                return Err(WireError::protocol(format!(
                    "CancelRequest secret key must be {} to {} bytes long, packet length is {len}",
                    CANCEL_KEY_LEN_RANGE.start(),
                    CANCEL_KEY_LEN_RANGE.end()
                )));
            }
            let process_id = u32::from_be_bytes(read_array(reader).await?);
            let secret_key = read_vec(reader, key_len).await?;
            Ok(StartupPacket::Cancel(CancelRequest {
                process_id,
                secret_key: Bytes::from(secret_key),
            }))
        }
        _ => {
            let version = ProtocolVersion::from_code(code);
            if version.major != ProtocolVersion::V3_0.major {
                return Err(WireError::protocol(format!(
                    "unsupported frontend protocol {version}: server supports {} to {}",
                    ProtocolVersion::V3_0,
                    ProtocolVersion::LATEST
                )));
            }
            let payload = read_vec(reader, payload_len).await?;
            let params = parse_params(&payload)?;
            Ok(StartupPacket::Startup(StartupMessage { version, params }))
        }
    }
}

/// Length of the smallest startup packet (length and code fields only).
const MIN_PACKET_LEN: usize = 8;

/// Payload bytes are read in chunks of this size, so memory use follows the
/// bytes actually received rather than the declared length.
const READ_CHUNK: usize = 4 * 1024;

/// `read_exact` into a fixed-size array, mapping EOF to [`WireError::UnexpectedEof`].
async fn read_array<R: AsyncRead + Unpin, const N: usize>(
    reader: &mut R,
) -> Result<[u8; N], WireError> {
    let mut out = [0u8; N];
    read_exact(reader, &mut out).await?;
    Ok(out)
}

/// Read exactly `n` bytes, growing the buffer as data arrives.
async fn read_vec<R: AsyncRead + Unpin>(reader: &mut R, n: usize) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(n.min(READ_CHUNK));
    while out.len() < n {
        let start = out.len();
        let end = n.min(start + READ_CHUNK);
        out.resize(end, 0);
        read_exact(reader, &mut out[start..end]).await?;
    }
    Ok(out)
}

/// Parse the `name\0value\0 ... \0` parameter list of a `StartupMessage`.
fn parse_params(payload: &[u8]) -> Result<Vec<(String, String)>, WireError> {
    let mut cur = Cursor::new(payload, "StartupMessage");
    let mut params = Vec::new();
    loop {
        let name = cur
            .cstr_bytes()
            .map_err(|_| cur.error("parameter list is missing its terminator"))?;
        if name.is_empty() {
            // The empty name is the list terminator and must be the last byte.
            cur.finish()?;
            return Ok(params);
        }
        let value = cur
            .cstr_bytes()
            .map_err(|_| cur.error("parameter name without a value"))?;
        let name = std::str::from_utf8(name)
            .map_err(|_| cur.error("parameter name is not valid UTF-8"))?;
        let value = std::str::from_utf8(value)
            .map_err(|_| cur.error("parameter value is not valid UTF-8"))?;
        params.push((name.to_owned(), value.to_owned()));
    }
}

/// Encode a `StartupMessage` (used for backend connections).
///
/// Fails with [`WireError::Protocol`] if a name is empty (an empty name is the
/// list terminator) or a name or value contains NUL, because a C string would
/// silently cut it short; and with [`WireError::InvalidLength`] if the packet
/// would exceed [`DEFAULT_MAX_STARTUP_PACKET_LEN`], PostgreSQL's own limit.
/// On error `buf` is left as it was.
pub fn encode_startup_message(
    buf: &mut BytesMut,
    version: ProtocolVersion,
    params: &[(&str, &str)],
) -> Result<(), WireError> {
    for (name, value) in params {
        if name.is_empty() {
            return Err(WireError::protocol("startup parameter name is empty"));
        }
        if name.contains('\0') || value.contains('\0') {
            return Err(WireError::protocol(format!(
                "startup parameter {:?} contains a NUL byte",
                name.replace('\0', "\\0")
            )));
        }
    }
    let start = buf.len();
    let len_pos = begin_length(buf);
    buf.put_i32(version.code());
    for (name, value) in params {
        put_cstr(buf, name);
        put_cstr(buf, value);
    }
    buf.put_u8(0);
    let len = buf.len() - start;
    if len > DEFAULT_MAX_STARTUP_PACKET_LEN {
        buf.truncate(start);
        return Err(WireError::InvalidLength {
            len: i64::try_from(len).unwrap_or(i64::MAX),
            limit: DEFAULT_MAX_STARTUP_PACKET_LEN,
        });
    }
    finish_message(buf, len_pos);
    Ok(())
}

/// Encode an `SSLRequest`.
pub fn encode_ssl_request(buf: &mut BytesMut) {
    buf.put_i32(8);
    buf.put_i32(SSL_REQUEST_CODE);
}

/// Encode a `CancelRequest`.
///
/// The packet length is `12 + secret_key.len()`. The key length is not
/// checked here; servers accept 4 bytes (protocol 3.0) or the length they
/// issued in `BackendKeyData` (protocol 3.2, at most 256 bytes).
pub fn encode_cancel_request(buf: &mut BytesMut, process_id: u32, secret_key: &[u8]) {
    let len_pos = begin_length(buf);
    buf.put_i32(CANCEL_REQUEST_CODE);
    buf.put_u32(process_id);
    buf.put_slice(secret_key);
    finish_message(buf, len_pos);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use crate::test_util::{ChunkedReader, block_on};
    use proptest::prelude::*;

    const MAX: usize = DEFAULT_MAX_STARTUP_PACKET_LEN;

    /// A raw packet: length prefix computed from `code` and `payload`.
    fn packet(code: i32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(8 + payload.len() as i32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn startup_bytes(version: ProtocolVersion, params: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        encode_startup_message(&mut buf, version, params).unwrap();
        buf.to_vec()
    }

    async fn read(bytes: &[u8]) -> Result<StartupPacket, WireError> {
        let mut r = bytes;
        read_startup_packet(&mut r, MAX).await
    }

    fn expect_startup(p: StartupPacket) -> StartupMessage {
        match p {
            StartupPacket::Startup(m) => m,
            other => panic!("expected StartupMessage, got {other:?}"),
        }
    }

    fn expect_cancel(p: StartupPacket) -> CancelRequest {
        match p {
            StartupPacket::Cancel(c) => c,
            other => panic!("expected CancelRequest, got {other:?}"),
        }
    }

    fn assert_protocol(r: Result<StartupPacket, WireError>, needle: &str) {
        match r {
            Err(WireError::Protocol(msg)) => {
                assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}")
            }
            other => panic!("expected protocol error mentioning {needle:?}, got {other:?}"),
        }
    }

    fn assert_invalid_length(r: Result<StartupPacket, WireError>, expected: i64) {
        match r {
            Err(WireError::InvalidLength { len, limit }) => {
                assert_eq!(len, expected);
                assert_eq!(limit, MAX);
            }
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    #[test]
    fn protocol_version_codes() {
        assert_eq!(ProtocolVersion::V3_0.code(), 196_608);
        assert_eq!(ProtocolVersion::V3_2.code(), 196_610);
        assert_eq!(ProtocolVersion::from_code(196_610), ProtocolVersion::V3_2);
        assert_eq!(ProtocolVersion::V3_2.to_string(), "3.2");
        assert!(ProtocolVersion::V3_0 < ProtocolVersion::V3_2);
        // Special request codes decode to major 1234.
        assert_eq!(ProtocolVersion::from_code(SSL_REQUEST_CODE).major, 1234);
    }

    #[tokio::test]
    async fn startup_3_0_round_trip() {
        let bytes = startup_bytes(
            ProtocolVersion::V3_0,
            &[
                ("user", "alice"),
                ("application_name", "psql"),
                ("options", ""),
            ],
        );
        assert_eq!(
            i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        let m = expect_startup(read(&bytes).await.unwrap());
        assert_eq!(m.version, ProtocolVersion::V3_0);
        assert_eq!(m.user(), Some("alice"));
        assert_eq!(m.database(), Some("alice"), "database defaults to user");
        assert_eq!(m.get("application_name"), Some("psql"));
        assert_eq!(m.get("options"), Some(""), "empty values are allowed");
        assert_eq!(m.get("missing"), None);
        assert_eq!(m.protocol_options().count(), 0);
        assert_eq!(m.duplicate_param(), None);
    }

    #[tokio::test]
    async fn startup_3_2_with_protocol_options() {
        let bytes = startup_bytes(
            ProtocolVersion::V3_2,
            &[
                ("user", "bob"),
                ("database", "orders"),
                ("_pq_.test_option", "on"),
                ("_pq_.other", "x"),
            ],
        );
        let m = expect_startup(read(&bytes).await.unwrap());
        assert_eq!(m.version, ProtocolVersion::V3_2);
        assert_eq!(m.database(), Some("orders"));
        assert_eq!(
            m.protocol_options().collect::<Vec<_>>(),
            vec!["_pq_.test_option", "_pq_.other"]
        );
        assert_eq!(m.params.len(), 4, "order and content preserved");
        assert_eq!(m.params[2], ("_pq_.test_option".into(), "on".into()));
    }

    #[tokio::test]
    async fn newer_minor_versions_are_returned_for_negotiation() {
        let bytes = packet(
            ProtocolVersion {
                major: 3,
                minor: 99,
            }
            .code(),
            b"user\0u\0\0",
        );
        let m = expect_startup(read(&bytes).await.unwrap());
        assert_eq!(
            m.version,
            ProtocolVersion {
                major: 3,
                minor: 99
            }
        );
    }

    #[tokio::test]
    async fn empty_parameter_list() {
        let m = expect_startup(read(&packet(196_608, b"\0")).await.unwrap());
        assert!(m.params.is_empty());
        assert_eq!(m.user(), None);
        assert_eq!(m.database(), None);
    }

    #[tokio::test]
    async fn duplicates_are_reported() {
        let bytes = packet(196_608, b"user\0a\0database\0d\0user\0b\0\0");
        let m = expect_startup(read(&bytes).await.unwrap());
        assert_eq!(m.user(), Some("a"), "get returns the first value");
        assert_eq!(m.duplicate_param(), Some("user"));
    }

    #[tokio::test]
    async fn reads_exactly_one_packet() {
        let mut bytes = startup_bytes(ProtocolVersion::V3_0, &[("user", "u")]);
        bytes.extend_from_slice(b"NEXT");
        let mut r = &bytes[..];
        read_startup_packet(&mut r, MAX).await.unwrap();
        assert_eq!(r, b"NEXT");

        // SSLRequest followed by a TLS ClientHello: the TLS bytes are untouched.
        let mut buf = BytesMut::new();
        encode_ssl_request(&mut buf);
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        let mut r = &buf[..];
        assert_eq!(
            read_startup_packet(&mut r, MAX).await.unwrap(),
            StartupPacket::SslRequest
        );
        assert_eq!(r, &[0x16, 0x03, 0x01]);

        let mut bytes = packet(CANCEL_REQUEST_CODE, &[0, 0, 0, 1, 9, 9, 9, 9]);
        bytes.push(b'Z');
        let mut r = &bytes[..];
        read_startup_packet(&mut r, MAX).await.unwrap();
        assert_eq!(r, b"Z");
    }

    #[tokio::test]
    async fn bytewise_and_pending_reader() {
        let bytes = startup_bytes(ProtocolVersion::V3_2, &[("user", "u"), ("database", "d")]);
        let mut extra = bytes.clone();
        extra.extend_from_slice(b"rest");
        let mut r = ChunkedReader::bytewise(extra).pending();
        let m = expect_startup(read_startup_packet(&mut r, MAX).await.unwrap());
        assert_eq!(m.database(), Some("d"));
        assert_eq!(r.consumed(), bytes.len(), "no over-read");
    }

    #[tokio::test]
    async fn ssl_and_gssenc_requests() {
        assert_eq!(
            read(&packet(SSL_REQUEST_CODE, b"")).await.unwrap(),
            StartupPacket::SslRequest
        );
        assert_eq!(
            read(&packet(GSSENC_REQUEST_CODE, b"")).await.unwrap(),
            StartupPacket::GssEncRequest
        );
        assert_protocol(
            read(&packet(SSL_REQUEST_CODE, b"\0\0\0\0")).await,
            "SSLRequest",
        );
        assert_protocol(
            read(&packet(GSSENC_REQUEST_CODE, b"x")).await,
            "GSSENCRequest",
        );
    }

    #[tokio::test]
    async fn cancel_requests() {
        for key_len in [4usize, 32, 256] {
            let key: Vec<u8> = (0..key_len).map(|i| i as u8).collect();
            let mut buf = BytesMut::new();
            encode_cancel_request(&mut buf, 0xdead_beef, &key);
            assert_eq!(buf.len(), 12 + key_len);
            assert_eq!(&buf[..4], &((12 + key_len) as i32).to_be_bytes());
            let c = expect_cancel(read(&buf).await.unwrap());
            assert_eq!(c.process_id, 0xdead_beef);
            assert_eq!(&c.secret_key[..], &key[..]);
        }
        // 3.0 cancel request is exactly 16 bytes.
        let mut buf = BytesMut::new();
        encode_cancel_request(&mut buf, 7, &[1, 2, 3, 4]);
        assert_eq!(
            &buf[..],
            &[0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 7, 1, 2, 3, 4]
        );
    }

    #[tokio::test]
    async fn cancel_key_length_limits() {
        for bad in [0usize, 1, 3, 257, 300] {
            let mut payload = vec![0, 0, 0, 1];
            payload.extend(std::iter::repeat_n(7u8, bad));
            assert_protocol(
                read(&packet(CANCEL_REQUEST_CODE, &payload)).await,
                "secret key",
            );
        }
        // Shorter than a process id.
        assert_protocol(
            read(&packet(CANCEL_REQUEST_CODE, &[0, 0])).await,
            "secret key",
        );
        assert_protocol(read(&packet(CANCEL_REQUEST_CODE, b"")).await, "secret key");
    }

    #[tokio::test]
    async fn length_boundaries() {
        for len in [i32::MIN, -1, 0, 4, 7] {
            let mut bytes = len.to_be_bytes().to_vec();
            bytes.extend_from_slice(&[0; 16]);
            assert_invalid_length(read(&bytes).await, i64::from(len));
        }
        // Exactly max_len is accepted; one more is rejected before reading it.
        let filler = "x".repeat(MAX - 8 - "a\0".len() - 2);
        let bytes = startup_bytes(ProtocolVersion::V3_0, &[("a", &filler)]);
        assert_eq!(bytes.len(), MAX);
        let m = expect_startup(read(&bytes).await.unwrap());
        assert_eq!(m.get("a").map(str::len), Some(filler.len()));

        // The encoder refuses oversize packets, so build this one by hand.
        let filler = "x".repeat(MAX - 8 - "a\0".len() - 1);
        let mut payload = b"a\0".to_vec();
        payload.extend_from_slice(filler.as_bytes());
        payload.extend_from_slice(b"\0\0");
        let bytes = packet(196_608, &payload);
        assert_eq!(bytes.len(), MAX + 1);
        assert_invalid_length(read(&bytes).await, (MAX + 1) as i64);

        // A huge declared length is rejected without waiting for the data.
        let mut r = &i32::MAX.to_be_bytes()[..];
        assert_invalid_length(read_startup_packet(&mut r, MAX).await, i64::from(i32::MAX));

        // The caller's limit applies.
        let bytes = startup_bytes(ProtocolVersion::V3_0, &[("user", "u")]);
        let mut r = &bytes[..];
        assert!(matches!(
            read_startup_packet(&mut r, bytes.len() - 1).await,
            Err(WireError::InvalidLength { .. })
        ));
        let mut r = &bytes[..];
        assert!(read_startup_packet(&mut r, bytes.len()).await.is_ok());
    }

    #[tokio::test]
    async fn eof_handling() {
        assert!(matches!(read(b"").await, Err(WireError::UnexpectedEof)));
        assert!(matches!(read(&[0, 0]).await, Err(WireError::UnexpectedEof)));
        assert!(matches!(
            read(&[0, 0, 0, 8, 4]).await,
            Err(WireError::UnexpectedEof)
        ));
        let bytes = startup_bytes(ProtocolVersion::V3_0, &[("user", "alice")]);
        for cut in 0..bytes.len() {
            assert!(
                matches!(read(&bytes[..cut]).await, Err(WireError::UnexpectedEof)),
                "cut at {cut}"
            );
        }
        let cancel = packet(CANCEL_REQUEST_CODE, &[0, 0, 0, 1, 2, 2, 2, 2]);
        assert!(matches!(
            read(&cancel[..cancel.len() - 1]).await,
            Err(WireError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn unsupported_versions() {
        for code in [
            ProtocolVersion { major: 2, minor: 0 }.code(),
            ProtocolVersion { major: 4, minor: 0 }.code(),
            ProtocolVersion {
                major: 1234,
                minor: 5681,
            }
            .code(),
            0,
            -1,
        ] {
            assert_protocol(read(&packet(code, b"user\0u\0\0")).await, "unsupported");
        }
    }

    #[tokio::test]
    async fn malformed_parameter_lists() {
        let v3 = 196_608;
        // No terminator at all.
        assert_protocol(read(&packet(v3, b"")).await, "terminator");
        assert_protocol(read(&packet(v3, b"user\0alice\0")).await, "terminator");
        assert_protocol(read(&packet(v3, b"user")).await, "terminator");
        // A name without a value.
        assert_protocol(read(&packet(v3, b"user\0")).await, "without a value");
        assert_protocol(read(&packet(v3, b"user\0alice")).await, "without a value");
        // Trailing garbage after the terminator (also covers an empty name in the middle).
        assert_protocol(read(&packet(v3, b"\0x")).await, "trailing");
        assert_protocol(read(&packet(v3, b"user\0a\0\0\0")).await, "trailing");
        assert_protocol(read(&packet(v3, b"\0user\0a\0\0")).await, "trailing");
        // Invalid UTF-8.
        assert_protocol(read(&packet(v3, b"us\xffer\0a\0\0")).await, "UTF-8");
        assert_protocol(read(&packet(v3, b"user\0\xc3\x28\0\0")).await, "UTF-8");
    }

    #[test]
    fn encode_startup_rejects_empty_names_nul_and_oversize() {
        let v = ProtocolVersion::V3_0;
        let mut buf = BytesMut::from(&b"keep"[..]);
        for params in [
            &[("", "ignored")][..],
            &[("user", "al\0ice")][..],
            &[("\0x", "y")][..],
            &[("pgbearer.sub", "a\0b")][..],
        ] {
            assert!(matches!(
                encode_startup_message(&mut buf, v, params),
                Err(WireError::Protocol(_))
            ));
            assert_eq!(&buf[..], b"keep");
        }
        let big = "x".repeat(DEFAULT_MAX_STARTUP_PACKET_LEN);
        assert!(matches!(
            encode_startup_message(&mut buf, v, &[("options", big.as_str())]),
            Err(WireError::InvalidLength { .. })
        ));
        assert_eq!(&buf[..], b"keep");
        // Exactly at the limit is fine: 4 (length) + 4 (code) + "a\0" + value + "\0" + "\0".
        let fits = "y".repeat(DEFAULT_MAX_STARTUP_PACKET_LEN - 4 - 4 - 2 - 1 - 1);
        let mut out = BytesMut::new();
        encode_startup_message(&mut out, v, &[("a", fits.as_str())]).unwrap();
        assert_eq!(out.len(), DEFAULT_MAX_STARTUP_PACKET_LEN);
        let m = expect_startup(block_on(read(&out)).unwrap());
        assert_eq!(m.get("a"), Some(fits.as_str()));
    }

    fn param_string() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>().prop_filter("no NUL", |c| *c != '\0'), 0..20)
            .prop_map(|v| v.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = block_on(read(&bytes));
        }

        #[test]
        fn random_payload_never_panics(
            code in prop_oneof![
                Just(196_608i32),
                Just(196_610),
                Just(CANCEL_REQUEST_CODE),
                Just(SSL_REQUEST_CODE),
                Just(GSSENC_REQUEST_CODE),
                any::<i32>(),
            ],
            payload in proptest::collection::vec(prop_oneof![Just(0u8), any::<u8>()], 0..300),
            chunk in 1usize..16,
        ) {
            let bytes = packet(code, &payload);
            let mut r = ChunkedReader::new(bytes.clone(), vec![chunk]);
            let result = block_on(read_startup_packet(&mut r, MAX));
            if result.is_ok() {
                prop_assert_eq!(r.consumed(), bytes.len());
            }
        }

        #[test]
        fn startup_round_trip(
            params in proptest::collection::vec(
                (param_string().prop_filter("non-empty", |s| !s.is_empty()), param_string()),
                0..8,
            ),
            minor in 0u16..4,
        ) {
            let version = ProtocolVersion { major: 3, minor };
            let refs: Vec<(&str, &str)> =
                params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let bytes = startup_bytes(version, &refs);
            let m = expect_startup(block_on(read(&bytes)).unwrap());
            prop_assert_eq!(m.version, version);
            prop_assert_eq!(m.params, params);
        }

        #[test]
        fn cancel_round_trip(pid in any::<u32>(), key in proptest::collection::vec(any::<u8>(), 4..=256)) {
            let mut buf = BytesMut::new();
            encode_cancel_request(&mut buf, pid, &key);
            let c = expect_cancel(block_on(read(&buf)).unwrap());
            prop_assert_eq!(c.process_id, pid);
            prop_assert_eq!(&c.secret_key[..], &key[..]);
        }
    }
}
