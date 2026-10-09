//! Startup-phase packets (no type byte).
//!
//! Layout: `i32 length (including itself) | i32 code | payload`.

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncRead;

use crate::WireError;

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
/// * `SSLRequest` / `GSSENCRequest`: length must be exactly 8.
/// * EOF before the first byte returns [`WireError::UnexpectedEof`].
pub async fn read_startup_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> Result<StartupPacket, WireError> {
    let _ = (reader, max_len);
    todo!("pgbearer-wire: read_startup_packet")
}

/// Encode a `StartupMessage` (used for backend connections).
pub fn encode_startup_message(
    buf: &mut BytesMut,
    version: ProtocolVersion,
    params: &[(&str, &str)],
) {
    let _ = (buf, version, params);
    todo!("pgbearer-wire: encode_startup_message")
}

/// Encode an `SSLRequest`.
pub fn encode_ssl_request(buf: &mut BytesMut) {
    buf.put_i32(8);
    buf.put_i32(SSL_REQUEST_CODE);
}

/// Encode a `CancelRequest`.
pub fn encode_cancel_request(buf: &mut BytesMut, process_id: u32, secret_key: &[u8]) {
    let _ = (buf, process_id, secret_key);
    todo!("pgbearer-wire: encode_cancel_request")
}
