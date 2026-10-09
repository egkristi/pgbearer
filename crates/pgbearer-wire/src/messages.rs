//! Typed decode/encode for the messages pgbearer inspects or generates.
//!
//! Decoders take a message *body* (without tag and length). Encoders append
//! a complete message (tag, length, body) to a `BytesMut`.

use bytes::{Bytes, BytesMut};
use pgbearer_core::ClientError;

use crate::WireError;

/// Transaction status from `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxStatus {
    /// `I`: idle, not in a transaction.
    Idle,
    /// `T`: in a transaction block.
    InTransaction,
    /// `E`: in a failed transaction block.
    Failed,
}

impl TxStatus {
    /// The status byte.
    pub fn as_byte(self) -> u8 {
        match self {
            TxStatus::Idle => b'I',
            TxStatus::InTransaction => b'T',
            TxStatus::Failed => b'E',
        }
    }

    /// Parse a status byte.
    pub fn from_byte(b: u8) -> Option<TxStatus> {
        match b {
            b'I' => Some(TxStatus::Idle),
            b'T' => Some(TxStatus::InTransaction),
            b'E' => Some(TxStatus::Failed),
            _ => None,
        }
    }
}

/// An `Authentication*` message from a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// `AuthenticationOk` (0).
    Ok,
    /// `AuthenticationCleartextPassword` (3).
    CleartextPassword,
    /// `AuthenticationMD5Password` (5) with salt.
    Md5Password {
        /// 4-byte salt.
        salt: [u8; 4],
    },
    /// `AuthenticationSASL` (10) with mechanism names.
    Sasl {
        /// Offered mechanisms.
        mechanisms: Vec<String>,
    },
    /// `AuthenticationSASLContinue` (11).
    SaslContinue {
        /// Server data.
        data: Bytes,
    },
    /// `AuthenticationSASLFinal` (12).
    SaslFinal {
        /// Server data.
        data: Bytes,
    },
    /// Any other method (GSS, SSPI, KerberosV5, …), by code.
    Other(i32),
}

/// Fields of an `ErrorResponse` or `NoticeResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorFields {
    /// `S`: localized severity.
    pub severity: Option<String>,
    /// `V`: non-localized severity (`ERROR`, `FATAL`, `PANIC`, …).
    pub severity_nonlocalized: Option<String>,
    /// `C`: SQLSTATE.
    pub code: Option<String>,
    /// `M`: message.
    pub message: Option<String>,
    /// `D`: detail.
    pub detail: Option<String>,
    /// `H`: hint.
    pub hint: Option<String>,
    /// All fields in order, including the above.
    pub fields: Vec<(u8, String)>,
}

impl ErrorFields {
    /// True for FATAL or PANIC (the server will close the connection).
    pub fn is_fatal(&self) -> bool {
        let s = self
            .severity_nonlocalized
            .as_deref()
            .or(self.severity.as_deref())
            .unwrap_or("");
        s == "FATAL" || s == "PANIC"
    }
}

/// A `Parse` message (only the parts pgbearer needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parse {
    /// Prepared statement name (empty = unnamed).
    pub statement: String,
    /// Query text.
    pub query: String,
    /// Parameter type OIDs.
    pub param_types: Vec<u32>,
}

/// A `Close` or `Describe` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `S` for statement, `P` for portal.
    pub kind: u8,
    /// Name.
    pub name: String,
}

/// Decoders for message bodies.
pub mod decode {
    use super::*;

    /// `Authentication*` (tag `R`).
    pub fn authentication(body: &[u8]) -> Result<Authentication, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::authentication")
    }

    /// `ErrorResponse` / `NoticeResponse` (tags `E`/`N`).
    pub fn error_fields(body: &[u8]) -> Result<ErrorFields, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::error_fields")
    }

    /// `ParameterStatus` (tag `S` from the server): `(name, value)`.
    pub fn parameter_status(body: &[u8]) -> Result<(String, String), WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::parameter_status")
    }

    /// `BackendKeyData` (tag `K`): `(process_id, secret_key)`; secret length 4..=256.
    pub fn backend_key_data(body: &[u8]) -> Result<(u32, Bytes), WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::backend_key_data")
    }

    /// `ReadyForQuery` (tag `Z`).
    pub fn ready_for_query(body: &[u8]) -> Result<TxStatus, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::ready_for_query")
    }

    /// `NegotiateProtocolVersion` (tag `v`): `(newest_minor, unrecognized_options)`.
    pub fn negotiate_protocol_version(body: &[u8]) -> Result<(u32, Vec<String>), WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::negotiate_protocol_version")
    }

    /// `PasswordMessage` (tag `p`, cleartext): the password bytes without the trailing NUL.
    /// The body must end with exactly one NUL and contain no other NUL.
    pub fn password_message(body: &[u8]) -> Result<Bytes, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::password_message")
    }

    /// `SASLInitialResponse` (tag `p`): `(mechanism, initial data or None if length is -1)`.
    pub fn sasl_initial_response(body: &[u8]) -> Result<(String, Option<Bytes>), WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::sasl_initial_response")
    }

    /// `SASLResponse` (tag `p`): the raw data (the whole body).
    pub fn sasl_response(body: &[u8]) -> Bytes {
        Bytes::copy_from_slice(body)
    }

    /// `Query` (tag `Q`): the SQL text.
    pub fn query(body: &[u8]) -> Result<String, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::query")
    }

    /// `Parse` (tag `P`).
    pub fn parse(body: &[u8]) -> Result<Parse, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::parse")
    }

    /// `Close` (tag `C` from the client) or `Describe` (tag `D` from the client).
    pub fn target(body: &[u8]) -> Result<Target, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::target")
    }

    /// `Bind` (tag `B`): `(portal, statement)`; the rest of the body is not decoded.
    pub fn bind_names(body: &[u8]) -> Result<(String, String), WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::bind_names")
    }

    /// `CommandComplete` (tag `C` from the server): the command tag.
    pub fn command_complete(body: &[u8]) -> Result<String, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::command_complete")
    }

    /// `DataRow` (tag `D` from the server): column values (`None` for NULL).
    pub fn data_row(body: &[u8]) -> Result<Vec<Option<Bytes>>, WireError> {
        let _ = body;
        todo!("pgbearer-wire: decode::data_row")
    }
}

/// Encoders (each appends one complete message).
pub mod encode {
    use super::*;

    /// `AuthenticationOk`.
    pub fn authentication_ok(buf: &mut BytesMut) {
        let _ = buf;
        todo!("pgbearer-wire: encode::authentication_ok")
    }

    /// `AuthenticationCleartextPassword`.
    pub fn authentication_cleartext_password(buf: &mut BytesMut) {
        let _ = buf;
        todo!("pgbearer-wire: encode::authentication_cleartext_password")
    }

    /// `AuthenticationSASL` with the given mechanisms.
    pub fn authentication_sasl(buf: &mut BytesMut, mechanisms: &[&str]) {
        let _ = (buf, mechanisms);
        todo!("pgbearer-wire: encode::authentication_sasl")
    }

    /// `AuthenticationSASLContinue`.
    pub fn authentication_sasl_continue(buf: &mut BytesMut, data: &[u8]) {
        let _ = (buf, data);
        todo!("pgbearer-wire: encode::authentication_sasl_continue")
    }

    /// `AuthenticationSASLFinal`.
    pub fn authentication_sasl_final(buf: &mut BytesMut, data: &[u8]) {
        let _ = (buf, data);
        todo!("pgbearer-wire: encode::authentication_sasl_final")
    }

    /// `ParameterStatus`.
    pub fn parameter_status(buf: &mut BytesMut, name: &str, value: &str) {
        let _ = (buf, name, value);
        todo!("pgbearer-wire: encode::parameter_status")
    }

    /// `BackendKeyData`.
    pub fn backend_key_data(buf: &mut BytesMut, process_id: u32, secret_key: &[u8]) {
        let _ = (buf, process_id, secret_key);
        todo!("pgbearer-wire: encode::backend_key_data")
    }

    /// `ReadyForQuery`.
    pub fn ready_for_query(buf: &mut BytesMut, status: TxStatus) {
        let _ = (buf, status);
        todo!("pgbearer-wire: encode::ready_for_query")
    }

    /// `ErrorResponse` from a [`ClientError`]: fields `S`, `V`, `C`, `M`, and `H` if set.
    /// The internal reason is never encoded.
    pub fn error_response(buf: &mut BytesMut, err: &ClientError) {
        let _ = (buf, err);
        todo!("pgbearer-wire: encode::error_response")
    }

    /// `NoticeResponse` with severity `NOTICE`/`WARNING` and the given code and message.
    pub fn notice_response(buf: &mut BytesMut, severity: &str, code: &str, message: &str) {
        let _ = (buf, severity, code, message);
        todo!("pgbearer-wire: encode::notice_response")
    }

    /// `NegotiateProtocolVersion`.
    pub fn negotiate_protocol_version(
        buf: &mut BytesMut,
        newest_minor: u32,
        unrecognized: &[&str],
    ) {
        let _ = (buf, newest_minor, unrecognized);
        todo!("pgbearer-wire: encode::negotiate_protocol_version")
    }

    /// `PasswordMessage` (cleartext or MD5 hash); appends the trailing NUL.
    pub fn password_message(buf: &mut BytesMut, password: &[u8]) {
        let _ = (buf, password);
        todo!("pgbearer-wire: encode::password_message")
    }

    /// `SASLInitialResponse`.
    pub fn sasl_initial_response(buf: &mut BytesMut, mechanism: &str, data: &[u8]) {
        let _ = (buf, mechanism, data);
        todo!("pgbearer-wire: encode::sasl_initial_response")
    }

    /// `SASLResponse`.
    pub fn sasl_response(buf: &mut BytesMut, data: &[u8]) {
        let _ = (buf, data);
        todo!("pgbearer-wire: encode::sasl_response")
    }

    /// `Query`.
    pub fn query(buf: &mut BytesMut, sql: &str) {
        let _ = (buf, sql);
        todo!("pgbearer-wire: encode::query")
    }

    /// `Terminate`.
    pub fn terminate(buf: &mut BytesMut) {
        let _ = buf;
        todo!("pgbearer-wire: encode::terminate")
    }

    /// `Sync`.
    pub fn sync(buf: &mut BytesMut) {
        let _ = buf;
        todo!("pgbearer-wire: encode::sync")
    }

    /// `Parse`.
    pub fn parse(buf: &mut BytesMut, statement: &str, query: &str, param_types: &[u32]) {
        let _ = (buf, statement, query, param_types);
        todo!("pgbearer-wire: encode::parse")
    }

    /// `Close` (statement `S` or portal `P`).
    pub fn close(buf: &mut BytesMut, kind: u8, name: &str) {
        let _ = (buf, kind, name);
        todo!("pgbearer-wire: encode::close")
    }
}
