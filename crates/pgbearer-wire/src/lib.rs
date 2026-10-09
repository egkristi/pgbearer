//! PostgreSQL wire protocol codec for pgbearer.
//!
//! Design (see ARCHITECTURE.md §7):
//!
//! * **Startup phase** ([`startup`]): packets without a type byte —
//!   `StartupMessage` (protocol 3.0 and 3.2), `SSLRequest`, `GSSENCRequest`,
//!   `CancelRequest`. They are read with *exact* reads so nothing past the
//!   packet is consumed; this matters because a TLS handshake follows an
//!   `SSLRequest` on the same socket.
//! * **Regular messages** ([`frame`]): `u8 tag | i32 len | body`. The
//!   [`frame::FrameReader`] parses only the 5-byte header; bodies are either
//!   read whole (for the few messages pgbearer inspects, with a size limit) or
//!   streamed to a writer without being buffered whole.
//! * **Typed messages** ([`messages`]): decode/encode for the messages that
//!   pgbearer needs to inspect or generate. Everything else is relayed as
//!   opaque bytes.
//! * **PROXY protocol v2** ([`proxy_protocol`]): header parsing for load
//!   balancers that preserve the client address.
//!
//! This crate performs no policy decisions and no network I/O beyond reading
//! and writing the streams it is given.

pub mod frame;
pub mod messages;
pub mod proxy_protocol;
pub mod startup;

pub use frame::{FrameReader, Header, Message};
pub use startup::{CancelRequest, ProtocolVersion, StartupMessage, StartupPacket};

/// Errors from the codec.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// I/O error on the underlying stream.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The peer closed the connection in the middle of a message.
    #[error("unexpected end of stream")]
    UnexpectedEof,
    /// A length field was invalid (negative, too small, or above the limit).
    #[error("invalid message length {len} (limit {limit})")]
    InvalidLength {
        /// Length found.
        len: i64,
        /// Applicable limit.
        limit: usize,
    },
    /// The message content does not follow the protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
}

impl WireError {
    /// Shorthand for [`WireError::Protocol`].
    pub fn protocol(msg: impl Into<String>) -> Self {
        WireError::Protocol(msg.into())
    }
}

/// Message type bytes (tags).
pub mod tag {
    // Frontend (client -> server)
    /// `Bind`.
    pub const BIND: u8 = b'B';
    /// `Close`.
    pub const CLOSE: u8 = b'C';
    /// `CopyData` (both directions).
    pub const COPY_DATA: u8 = b'd';
    /// `CopyDone` (both directions).
    pub const COPY_DONE: u8 = b'c';
    /// `CopyFail`.
    pub const COPY_FAIL: u8 = b'f';
    /// `Describe`.
    pub const DESCRIBE: u8 = b'D';
    /// `Execute`.
    pub const EXECUTE: u8 = b'E';
    /// `Flush`.
    pub const FLUSH: u8 = b'H';
    /// `FunctionCall`.
    pub const FUNCTION_CALL: u8 = b'F';
    /// `Parse`.
    pub const PARSE: u8 = b'P';
    /// `PasswordMessage`, `SASLInitialResponse`, `SASLResponse`, `GSSResponse`.
    pub const PASSWORD: u8 = b'p';
    /// `Query`.
    pub const QUERY: u8 = b'Q';
    /// `Sync`.
    pub const SYNC: u8 = b'S';
    /// `Terminate`.
    pub const TERMINATE: u8 = b'X';

    // Backend (server -> client)
    /// `Authentication*`.
    pub const AUTHENTICATION: u8 = b'R';
    /// `BackendKeyData`.
    pub const BACKEND_KEY_DATA: u8 = b'K';
    /// `BindComplete`.
    pub const BIND_COMPLETE: u8 = b'2';
    /// `CloseComplete`.
    pub const CLOSE_COMPLETE: u8 = b'3';
    /// `CommandComplete`.
    pub const COMMAND_COMPLETE: u8 = b'C';
    /// `CopyInResponse`.
    pub const COPY_IN_RESPONSE: u8 = b'G';
    /// `CopyOutResponse`.
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    /// `CopyBothResponse`.
    pub const COPY_BOTH_RESPONSE: u8 = b'W';
    /// `DataRow`.
    pub const DATA_ROW: u8 = b'D';
    /// `EmptyQueryResponse`.
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    /// `ErrorResponse`.
    pub const ERROR_RESPONSE: u8 = b'E';
    /// `FunctionCallResponse`.
    pub const FUNCTION_CALL_RESPONSE: u8 = b'V';
    /// `NegotiateProtocolVersion`.
    pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
    /// `NoData`.
    pub const NO_DATA: u8 = b'n';
    /// `NoticeResponse`.
    pub const NOTICE_RESPONSE: u8 = b'N';
    /// `NotificationResponse`.
    pub const NOTIFICATION_RESPONSE: u8 = b'A';
    /// `ParameterDescription`.
    pub const PARAMETER_DESCRIPTION: u8 = b't';
    /// `ParameterStatus`.
    pub const PARAMETER_STATUS: u8 = b'S';
    /// `ParseComplete`.
    pub const PARSE_COMPLETE: u8 = b'1';
    /// `PortalSuspended`.
    pub const PORTAL_SUSPENDED: u8 = b's';
    /// `ReadyForQuery`.
    pub const READY_FOR_QUERY: u8 = b'Z';
    /// `RowDescription`.
    pub const ROW_DESCRIPTION: u8 = b'T';
}

/// Returns true if `first_byte` starts a TLS handshake record (direct TLS,
/// PostgreSQL 17+ `sslnegotiation=direct`).
pub fn is_tls_handshake_byte(first_byte: u8) -> bool {
    first_byte == 0x16
}
