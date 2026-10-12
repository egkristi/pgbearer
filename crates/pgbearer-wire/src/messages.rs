//! Typed decode/encode for the messages pgbearer inspects or generates.
//!
//! Decoders take a message *body* (without tag and length). Encoders append
//! a complete message (tag, length, body) to a `BytesMut`.
//!
//! Decoders are strict and safe on untrusted input: truncated bodies,
//! missing NUL terminators, trailing garbage and impossible counts are all
//! [`WireError::Protocol`], counts are checked against the bytes actually
//! present before anything is allocated, and nothing panics.
//!
//! Text is decoded as UTF-8 (PostgreSQL sends text in the client encoding,
//! which pgbearer expects to be `UTF8`). Frontend text that is not valid
//! UTF-8 is a protocol error; such messages can still be relayed as opaque
//! bytes. `ErrorResponse`/`NoticeResponse` fields are the exception: they are
//! decoded lossily, so that an error in another encoding can still be
//! classified (for example as FATAL).
//!
//! Encoders write strings as C strings: anything from an interior NUL onward
//! is dropped, so the output is always well formed.

use bytes::{BufMut, Bytes, BytesMut};
use pgbearer_core::ClientError;

use crate::WireError;
use crate::codec::{Cursor, begin_message, finish_message, put_cstr};

/// `Authentication*` request codes.
pub mod auth_code {
    /// `AuthenticationOk`.
    pub const OK: i32 = 0;
    /// `AuthenticationCleartextPassword`.
    pub const CLEARTEXT_PASSWORD: i32 = 3;
    /// `AuthenticationMD5Password`.
    pub const MD5_PASSWORD: i32 = 5;
    /// `AuthenticationSASL`.
    pub const SASL: i32 = 10;
    /// `AuthenticationSASLContinue`.
    pub const SASL_CONTINUE: i32 = 11;
    /// `AuthenticationSASLFinal`.
    pub const SASL_FINAL: i32 = 12;
}

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
    ///
    /// Codes 0, 3, 5, 10, 11 and 12 are decoded; any other code is returned as
    /// [`Authentication::Other`] without looking at the rest of the body.
    pub fn authentication(body: &[u8]) -> Result<Authentication, WireError> {
        let mut cur = Cursor::new(body, "Authentication");
        let code = cur.i32()?;
        let auth = match code {
            auth_code::OK => Authentication::Ok,
            auth_code::CLEARTEXT_PASSWORD => Authentication::CleartextPassword,
            auth_code::MD5_PASSWORD => Authentication::Md5Password { salt: cur.array()? },
            auth_code::SASL => {
                let mut mechanisms = Vec::new();
                loop {
                    let name = cur.cstr()?;
                    if name.is_empty() {
                        break;
                    }
                    mechanisms.push(name.to_owned());
                }
                Authentication::Sasl { mechanisms }
            }
            auth_code::SASL_CONTINUE => Authentication::SaslContinue {
                data: Bytes::copy_from_slice(cur.rest()),
            },
            auth_code::SASL_FINAL => Authentication::SaslFinal {
                data: Bytes::copy_from_slice(cur.rest()),
            },
            other => return Ok(Authentication::Other(other)),
        };
        cur.finish()?;
        Ok(auth)
    }

    /// `ErrorResponse` / `NoticeResponse` (tags `E`/`N`).
    ///
    /// Field values are decoded lossily (invalid UTF-8 is replaced). If a
    /// field type repeats, the typed accessors hold the last value, as libpq
    /// does; [`ErrorFields::fields`] keeps every field in order.
    pub fn error_fields(body: &[u8]) -> Result<ErrorFields, WireError> {
        let mut cur = Cursor::new(body, "ErrorResponse");
        let mut out = ErrorFields::default();
        loop {
            let kind = cur.u8()?;
            if kind == 0 {
                break;
            }
            let value = cur.cstr_lossy()?;
            let slot = match kind {
                b'S' => Some(&mut out.severity),
                b'V' => Some(&mut out.severity_nonlocalized),
                b'C' => Some(&mut out.code),
                b'M' => Some(&mut out.message),
                b'D' => Some(&mut out.detail),
                b'H' => Some(&mut out.hint),
                _ => None,
            };
            if let Some(slot) = slot {
                *slot = Some(value.clone());
            }
            out.fields.push((kind, value));
        }
        cur.finish()?;
        Ok(out)
    }

    /// `ParameterStatus` (tag `S` from the server): `(name, value)`.
    pub fn parameter_status(body: &[u8]) -> Result<(String, String), WireError> {
        let mut cur = Cursor::new(body, "ParameterStatus");
        let name = cur.cstr()?.to_owned();
        let value = cur.cstr()?.to_owned();
        cur.finish()?;
        Ok((name, value))
    }

    /// `BackendKeyData` (tag `K`): `(process_id, secret_key)`; secret length 4..=256.
    pub fn backend_key_data(body: &[u8]) -> Result<(u32, Bytes), WireError> {
        let mut cur = Cursor::new(body, "BackendKeyData");
        let process_id = cur.u32()?;
        let secret = cur.rest();
        if !crate::startup::CANCEL_KEY_LEN_RANGE.contains(&secret.len()) {
            return Err(cur.error(format_args!(
                "secret key must be {} to {} bytes long, got {}",
                crate::startup::CANCEL_KEY_LEN_RANGE.start(),
                crate::startup::CANCEL_KEY_LEN_RANGE.end(),
                secret.len()
            )));
        }
        Ok((process_id, Bytes::copy_from_slice(secret)))
    }

    /// `ReadyForQuery` (tag `Z`).
    pub fn ready_for_query(body: &[u8]) -> Result<TxStatus, WireError> {
        let mut cur = Cursor::new(body, "ReadyForQuery");
        let byte = cur.u8()?;
        cur.finish()?;
        TxStatus::from_byte(byte).ok_or_else(|| {
            cur.error(format_args!(
                "unknown transaction status {:?}",
                char::from(byte)
            ))
        })
    }

    /// `NegotiateProtocolVersion` (tag `v`): `(newest_minor, unrecognized_options)`.
    pub fn negotiate_protocol_version(body: &[u8]) -> Result<(u32, Vec<String>), WireError> {
        let mut cur = Cursor::new(body, "NegotiateProtocolVersion");
        let newest_minor = cur.i32()?;
        let newest_minor = u32::try_from(newest_minor)
            .map_err(|_| cur.error(format_args!("negative minor version {newest_minor}")))?;
        let count = cur.i32()?;
        // Each option needs at least its NUL terminator.
        let count = usize::try_from(count)
            .ok()
            .filter(|&c| c <= cur.remaining())
            .ok_or_else(|| {
                cur.error(format_args!(
                    "option count {count} does not fit the {} remaining bytes",
                    cur.remaining()
                ))
            })?;
        let mut options = Vec::with_capacity(count);
        for _ in 0..count {
            options.push(cur.cstr()?.to_owned());
        }
        cur.finish()?;
        Ok((newest_minor, options))
    }

    /// `PasswordMessage` (tag `p`, cleartext): the password bytes without the trailing NUL.
    /// The body must end with exactly one NUL and contain no other NUL.
    pub fn password_message(body: &[u8]) -> Result<Bytes, WireError> {
        let mut cur = Cursor::new(body, "PasswordMessage");
        let password = cur.cstr_bytes()?;
        cur.finish()?;
        Ok(Bytes::copy_from_slice(password))
    }

    /// `SASLInitialResponse` (tag `p`): `(mechanism, initial data or None if length is -1)`.
    pub fn sasl_initial_response(body: &[u8]) -> Result<(String, Option<Bytes>), WireError> {
        let mut cur = Cursor::new(body, "SASLInitialResponse");
        let mechanism = cur.cstr()?.to_owned();
        let len = cur.i32()?;
        let data = match len {
            -1 => None,
            len => {
                let len = usize::try_from(len)
                    .map_err(|_| cur.error(format_args!("invalid data length {len}")))?;
                Some(Bytes::copy_from_slice(cur.bytes(len)?))
            }
        };
        cur.finish()?;
        Ok((mechanism, data))
    }

    /// `SASLResponse` (tag `p`): the raw data (the whole body).
    pub fn sasl_response(body: &[u8]) -> Bytes {
        Bytes::copy_from_slice(body)
    }

    /// `Query` (tag `Q`): the SQL text.
    pub fn query(body: &[u8]) -> Result<String, WireError> {
        let mut cur = Cursor::new(body, "Query");
        let sql = cur.cstr()?.to_owned();
        cur.finish()?;
        Ok(sql)
    }

    /// `Parse` (tag `P`).
    ///
    /// The parameter count is read as an unsigned 16-bit integer, as
    /// PostgreSQL does (up to 65535 parameters).
    pub fn parse(body: &[u8]) -> Result<Parse, WireError> {
        let mut cur = Cursor::new(body, "Parse");
        let statement = cur.cstr()?.to_owned();
        let query = cur.cstr()?.to_owned();
        let count = usize::from(cur.u16()?);
        if count.saturating_mul(4) != cur.remaining() {
            return Err(cur.error(format_args!(
                "{count} parameter types need {} bytes, {} left",
                count.saturating_mul(4),
                cur.remaining()
            )));
        }
        let mut param_types = Vec::with_capacity(count);
        for _ in 0..count {
            param_types.push(cur.u32()?);
        }
        cur.finish()?;
        Ok(Parse {
            statement,
            query,
            param_types,
        })
    }

    /// `Close` (tag `C` from the client) or `Describe` (tag `D` from the client).
    pub fn target(body: &[u8]) -> Result<Target, WireError> {
        let mut cur = Cursor::new(body, "Close/Describe");
        let kind = cur.u8()?;
        if kind != b'S' && kind != b'P' {
            return Err(cur.error(format_args!(
                "target kind must be 'S' or 'P', got {:?}",
                char::from(kind)
            )));
        }
        let name = cur.cstr()?.to_owned();
        cur.finish()?;
        Ok(Target { kind, name })
    }

    /// `Bind` (tag `B`): `(portal, statement)`; the rest of the body is not decoded.
    pub fn bind_names(body: &[u8]) -> Result<(String, String), WireError> {
        let mut cur = Cursor::new(body, "Bind");
        let portal = cur.cstr()?.to_owned();
        let statement = cur.cstr()?.to_owned();
        Ok((portal, statement))
    }

    /// `CommandComplete` (tag `C` from the server): the command tag.
    pub fn command_complete(body: &[u8]) -> Result<String, WireError> {
        let mut cur = Cursor::new(body, "CommandComplete");
        let tag = cur.cstr()?.to_owned();
        cur.finish()?;
        Ok(tag)
    }

    /// `DataRow` (tag `D` from the server): column values (`None` for NULL).
    ///
    /// The column count is read as an unsigned 16-bit integer. The values
    /// share one copy of the body.
    pub fn data_row(body: &[u8]) -> Result<Vec<Option<Bytes>>, WireError> {
        let mut cur = Cursor::new(body, "DataRow");
        let count = usize::from(cur.u16()?);
        // Each column needs at least its 4-byte length.
        if count.saturating_mul(4) > cur.remaining() {
            return Err(cur.error(format_args!(
                "{count} columns do not fit the {} remaining bytes",
                cur.remaining()
            )));
        }
        let whole = Bytes::copy_from_slice(body);
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let len = cur.i32()?;
            if len == -1 {
                values.push(None);
                continue;
            }
            let len = usize::try_from(len)
                .map_err(|_| cur.error(format_args!("invalid column length {len}")))?;
            let start = body.len() - cur.remaining();
            cur.bytes(len)?;
            values.push(Some(whole.slice(start..start + len)));
        }
        cur.finish()?;
        Ok(values)
    }
}

/// Encoders (each appends one complete message).
pub mod encode {
    use super::*;

    /// Append an `Authentication*` message with `code` and `extra` bytes.
    fn authentication(buf: &mut BytesMut, code: i32, extra: &[u8]) {
        let pos = begin_message(buf, crate::tag::AUTHENTICATION);
        buf.put_i32(code);
        buf.put_slice(extra);
        finish_message(buf, pos);
    }

    /// Append a message whose body is `body`.
    fn raw(buf: &mut BytesMut, tag: u8, body: &[u8]) {
        let pos = begin_message(buf, tag);
        buf.put_slice(body);
        finish_message(buf, pos);
    }

    /// `AuthenticationOk`.
    pub fn authentication_ok(buf: &mut BytesMut) {
        authentication(buf, auth_code::OK, &[]);
    }

    /// `AuthenticationCleartextPassword`.
    pub fn authentication_cleartext_password(buf: &mut BytesMut) {
        authentication(buf, auth_code::CLEARTEXT_PASSWORD, &[]);
    }

    /// `AuthenticationMD5Password` with the given salt.
    pub fn authentication_md5_password(buf: &mut BytesMut, salt: [u8; 4]) {
        authentication(buf, auth_code::MD5_PASSWORD, &salt);
    }

    /// `AuthenticationSASL` with the given mechanisms. Empty names are
    /// skipped, because an empty name terminates the list.
    pub fn authentication_sasl(buf: &mut BytesMut, mechanisms: &[&str]) {
        let pos = begin_message(buf, crate::tag::AUTHENTICATION);
        buf.put_i32(auth_code::SASL);
        for mechanism in mechanisms {
            if !mechanism.is_empty() && !mechanism.starts_with('\0') {
                put_cstr(buf, mechanism);
            }
        }
        buf.put_u8(0);
        finish_message(buf, pos);
    }

    /// `AuthenticationSASLContinue`.
    pub fn authentication_sasl_continue(buf: &mut BytesMut, data: &[u8]) {
        authentication(buf, auth_code::SASL_CONTINUE, data);
    }

    /// `AuthenticationSASLFinal`.
    pub fn authentication_sasl_final(buf: &mut BytesMut, data: &[u8]) {
        authentication(buf, auth_code::SASL_FINAL, data);
    }

    /// `ParameterStatus`.
    pub fn parameter_status(buf: &mut BytesMut, name: &str, value: &str) {
        let pos = begin_message(buf, crate::tag::PARAMETER_STATUS);
        put_cstr(buf, name);
        put_cstr(buf, value);
        finish_message(buf, pos);
    }

    /// `BackendKeyData`. The key length is not checked (clients expect 4
    /// bytes with protocol 3.0 and at most 256 with 3.2).
    pub fn backend_key_data(buf: &mut BytesMut, process_id: u32, secret_key: &[u8]) {
        let pos = begin_message(buf, crate::tag::BACKEND_KEY_DATA);
        buf.put_u32(process_id);
        buf.put_slice(secret_key);
        finish_message(buf, pos);
    }

    /// `ReadyForQuery`.
    pub fn ready_for_query(buf: &mut BytesMut, status: TxStatus) {
        raw(buf, crate::tag::READY_FOR_QUERY, &[status.as_byte()]);
    }

    /// Append an `ErrorResponse`/`NoticeResponse` with fields `S`, `V`, `C`,
    /// `M` and, if given, `H`.
    fn error_or_notice(
        buf: &mut BytesMut,
        tag: u8,
        severity: &str,
        code: &str,
        message: &str,
        hint: Option<&str>,
    ) {
        let pos = begin_message(buf, tag);
        for (field, value) in [
            (b'S', Some(severity)),
            (b'V', Some(severity)),
            (b'C', Some(code)),
            (b'M', Some(message)),
            (b'H', hint),
        ] {
            if let Some(value) = value {
                buf.put_u8(field);
                put_cstr(buf, value);
            }
        }
        buf.put_u8(0);
        finish_message(buf, pos);
    }

    /// `ErrorResponse` from a [`ClientError`]: fields `S`, `V`, `C`, `M`, and `H` if set.
    /// The internal reason is never encoded.
    pub fn error_response(buf: &mut BytesMut, err: &ClientError) {
        error_or_notice(
            buf,
            crate::tag::ERROR_RESPONSE,
            err.severity.as_str(),
            err.code,
            &err.message,
            err.hint.as_deref(),
        );
    }

    /// `NoticeResponse` with severity `NOTICE`/`WARNING` and the given code and message.
    pub fn notice_response(buf: &mut BytesMut, severity: &str, code: &str, message: &str) {
        error_or_notice(
            buf,
            crate::tag::NOTICE_RESPONSE,
            severity,
            code,
            message,
            None,
        );
    }

    /// `NegotiateProtocolVersion`.
    pub fn negotiate_protocol_version(
        buf: &mut BytesMut,
        newest_minor: u32,
        unrecognized: &[&str],
    ) {
        let pos = begin_message(buf, crate::tag::NEGOTIATE_PROTOCOL_VERSION);
        buf.put_u32(newest_minor);
        buf.put_i32(i32::try_from(unrecognized.len()).unwrap_or(i32::MAX));
        for option in unrecognized {
            put_cstr(buf, option);
        }
        finish_message(buf, pos);
    }

    /// `PasswordMessage` (cleartext or MD5 hash); appends the trailing NUL.
    ///
    /// The password is written as is: one that contains a NUL byte produces
    /// a message that PostgreSQL rejects, rather than a silently shortened
    /// password.
    pub fn password_message(buf: &mut BytesMut, password: &[u8]) {
        let pos = begin_message(buf, crate::tag::PASSWORD);
        buf.put_slice(password);
        buf.put_u8(0);
        finish_message(buf, pos);
    }

    /// `SASLInitialResponse`.
    pub fn sasl_initial_response(buf: &mut BytesMut, mechanism: &str, data: &[u8]) {
        let pos = begin_message(buf, crate::tag::PASSWORD);
        put_cstr(buf, mechanism);
        buf.put_i32(i32::try_from(data.len()).unwrap_or(i32::MAX));
        buf.put_slice(data);
        finish_message(buf, pos);
    }

    /// `SASLResponse`.
    pub fn sasl_response(buf: &mut BytesMut, data: &[u8]) {
        raw(buf, crate::tag::PASSWORD, data);
    }

    /// `Query`.
    pub fn query(buf: &mut BytesMut, sql: &str) {
        let pos = begin_message(buf, crate::tag::QUERY);
        put_cstr(buf, sql);
        finish_message(buf, pos);
    }

    /// `Terminate`.
    pub fn terminate(buf: &mut BytesMut) {
        raw(buf, crate::tag::TERMINATE, &[]);
    }

    /// `Sync`.
    pub fn sync(buf: &mut BytesMut) {
        raw(buf, crate::tag::SYNC, &[]);
    }

    /// `Parse`.
    ///
    /// At most 65535 parameter types (the protocol limit) are encoded.
    pub fn parse(buf: &mut BytesMut, statement: &str, query: &str, param_types: &[u32]) {
        let pos = begin_message(buf, crate::tag::PARSE);
        put_cstr(buf, statement);
        put_cstr(buf, query);
        let count = u16::try_from(param_types.len()).unwrap_or(u16::MAX);
        buf.put_u16(count);
        for oid in &param_types[..usize::from(count)] {
            buf.put_u32(*oid);
        }
        finish_message(buf, pos);
    }

    /// `Close` (statement `S` or portal `P`). `kind` is written as given.
    pub fn close(buf: &mut BytesMut, kind: u8, name: &str) {
        let pos = begin_message(buf, crate::tag::CLOSE);
        buf.put_u8(kind);
        put_cstr(buf, name);
        finish_message(buf, pos);
    }

    /// `Describe` (statement `S` or portal `P`). `kind` is written as given.
    pub fn describe(buf: &mut BytesMut, kind: u8, name: &str) {
        let pos = begin_message(buf, crate::tag::DESCRIBE);
        buf.put_u8(kind);
        put_cstr(buf, name);
        finish_message(buf, pos);
    }

    /// `CommandComplete` with the given command tag.
    pub fn command_complete(buf: &mut BytesMut, tag: &str) {
        let pos = begin_message(buf, crate::tag::COMMAND_COMPLETE);
        put_cstr(buf, tag);
        finish_message(buf, pos);
    }

    /// `DataRow` (`None` encodes SQL NULL).
    ///
    /// At most 65535 columns (the protocol limit) are encoded.
    pub fn data_row(buf: &mut BytesMut, values: &[Option<&[u8]>]) {
        let pos = begin_message(buf, crate::tag::DATA_ROW);
        let count = u16::try_from(values.len()).unwrap_or(u16::MAX);
        buf.put_u16(count);
        for value in &values[..usize::from(count)] {
            match value {
                None => buf.put_i32(-1),
                Some(v) => {
                    buf.put_i32(i32::try_from(v.len()).unwrap_or(i32::MAX));
                    buf.put_slice(v);
                }
            }
        }
        finish_message(buf, pos);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use crate::tag;
    use pgbearer_core::Severity;
    use proptest::prelude::*;

    /// Split one encoded message into `(tag, body)`, checking the length field
    /// and that nothing follows it.
    fn split(buf: &BytesMut) -> (u8, Vec<u8>) {
        assert!(buf.len() >= 5, "message too short: {buf:?}");
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        assert_eq!(
            len + 1,
            buf.len(),
            "length field must cover the whole message"
        );
        (buf[0], buf[5..].to_vec())
    }

    fn encoded(f: impl FnOnce(&mut BytesMut)) -> (u8, Vec<u8>) {
        let mut buf = BytesMut::new();
        f(&mut buf);
        split(&buf)
    }

    fn is_protocol<T: std::fmt::Debug>(r: Result<T, WireError>) -> bool {
        matches!(r, Err(WireError::Protocol(_)))
    }

    #[test]
    fn tx_status_bytes() {
        for s in [TxStatus::Idle, TxStatus::InTransaction, TxStatus::Failed] {
            assert_eq!(TxStatus::from_byte(s.as_byte()), Some(s));
        }
        assert_eq!(TxStatus::from_byte(b'X'), None);
    }

    #[test]
    fn authentication_round_trips() {
        let (t, body) = encoded(encode::authentication_ok);
        assert_eq!((t, &body[..]), (tag::AUTHENTICATION, &[0u8, 0, 0, 0][..]));
        assert_eq!(decode::authentication(&body).unwrap(), Authentication::Ok);

        let (_, body) = encoded(encode::authentication_cleartext_password);
        assert_eq!(body, [0, 0, 0, 3]);
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::CleartextPassword
        );

        let (_, body) = encoded(|b| encode::authentication_md5_password(b, [1, 2, 3, 4]));
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::Md5Password { salt: [1, 2, 3, 4] }
        );

        let (_, body) =
            encoded(|b| encode::authentication_sasl(b, &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]));
        assert_eq!(body, b"\0\0\0\x0aSCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0");
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::Sasl {
                mechanisms: vec!["SCRAM-SHA-256-PLUS".into(), "SCRAM-SHA-256".into()]
            }
        );

        let (_, body) = encoded(|b| encode::authentication_sasl_continue(b, b"r=abc,s=xyz,i=4096"));
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::SaslContinue {
                data: Bytes::from_static(b"r=abc,s=xyz,i=4096")
            }
        );

        let (_, body) = encoded(|b| encode::authentication_sasl_final(b, b"v=sig"));
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::SaslFinal {
                data: Bytes::from_static(b"v=sig")
            }
        );
        let (_, body) = encoded(|b| encode::authentication_sasl_final(b, b""));
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::SaslFinal { data: Bytes::new() }
        );
    }

    #[test]
    fn authentication_other_codes() {
        assert_eq!(
            decode::authentication(&[0, 0, 0, 7]).unwrap(),
            Authentication::Other(7)
        );
        // GSSContinue carries data, which is not inspected.
        assert_eq!(
            decode::authentication(&[0, 0, 0, 8, 1, 2, 3]).unwrap(),
            Authentication::Other(8)
        );
        assert_eq!(
            decode::authentication(&(-5i32).to_be_bytes()).unwrap(),
            Authentication::Other(-5)
        );
    }

    #[test]
    fn authentication_malformed() {
        assert!(is_protocol(decode::authentication(b"")));
        assert!(is_protocol(decode::authentication(&[0, 0, 0])));
        assert!(
            is_protocol(decode::authentication(&[0, 0, 0, 0, 0])),
            "Ok with trailing data"
        );
        assert!(is_protocol(decode::authentication(&[0, 0, 0, 3, 1])));
        assert!(
            is_protocol(decode::authentication(&[0, 0, 0, 5, 1, 2, 3])),
            "short salt"
        );
        assert!(is_protocol(decode::authentication(&[
            0, 0, 0, 5, 1, 2, 3, 4, 5
        ])));
        assert!(
            is_protocol(decode::authentication(b"\0\0\0\x0a")),
            "no list terminator"
        );
        assert!(is_protocol(decode::authentication(
            b"\0\0\0\x0aSCRAM-SHA-256\0"
        )));
        assert!(
            is_protocol(decode::authentication(b"\0\0\0\x0aSCRAM\0\0x")),
            "trailing"
        );
        assert!(
            is_protocol(decode::authentication(b"\0\0\0\x0a\xff\0\0")),
            "UTF-8"
        );
        // An empty mechanism list is well formed (the caller decides).
        assert_eq!(
            decode::authentication(b"\0\0\0\x0a\0").unwrap(),
            Authentication::Sasl { mechanisms: vec![] }
        );
    }

    #[test]
    fn error_response_round_trip_never_leaks_internal_reason() {
        let err = ClientError::fatal("28000", "authentication failed")
            .with_hint("check your token")
            .with_internal_reason("SECRET: jwt signature mismatch for kid abc");
        let (t, body) = encoded(|b| encode::error_response(b, &err));
        assert_eq!(t, tag::ERROR_RESPONSE);
        assert!(
            !body.windows(6).any(|w| w == b"SECRET"),
            "internal reason must never be encoded"
        );
        assert_eq!(
            body,
            b"SFATAL\0VFATAL\0C28000\0Mauthentication failed\0Hcheck your token\0\0"
        );
        let f = decode::error_fields(&body).unwrap();
        assert_eq!(f.severity.as_deref(), Some("FATAL"));
        assert_eq!(f.severity_nonlocalized.as_deref(), Some("FATAL"));
        assert_eq!(f.code.as_deref(), Some("28000"));
        assert_eq!(f.message.as_deref(), Some("authentication failed"));
        assert_eq!(f.hint.as_deref(), Some("check your token"));
        assert_eq!(f.detail, None);
        assert_eq!(
            f.fields.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            b"SVCMH".to_vec()
        );
        assert!(f.is_fatal());
    }

    #[test]
    fn error_response_without_hint() {
        let mut err = ClientError::fatal("53300", "too many connections");
        err.severity = Severity::Error;
        let (_, body) = encoded(|b| encode::error_response(b, &err));
        assert_eq!(body, b"SERROR\0VERROR\0C53300\0Mtoo many connections\0\0");
        let f = decode::error_fields(&body).unwrap();
        assert_eq!(f.hint, None);
        assert!(!f.is_fatal());
    }

    #[test]
    fn notice_response_round_trip() {
        let (t, body) =
            encoded(|b| encode::notice_response(b, "WARNING", "01000", "token expires soon"));
        assert_eq!(t, tag::NOTICE_RESPONSE);
        let f = decode::error_fields(&body).unwrap();
        assert_eq!(f.severity.as_deref(), Some("WARNING"));
        assert_eq!(f.severity_nonlocalized.as_deref(), Some("WARNING"));
        assert_eq!(f.code.as_deref(), Some("01000"));
        assert_eq!(f.message.as_deref(), Some("token expires soon"));
        assert!(!f.is_fatal());
    }

    #[test]
    fn error_fields_from_a_real_server() {
        // Localized severity differs from the non-localized one; unknown
        // fields (P, F, L, R) are kept in order.
        let body =
            b"SFATAL_DE\0VPANIC\0C XX000\0Mboom\0Ddetail\0Hhint\0P12\0Fpostgres.c\0L42\0Rmain\0\0";
        let f = decode::error_fields(body).unwrap();
        assert_eq!(f.severity.as_deref(), Some("FATAL_DE"));
        assert_eq!(f.severity_nonlocalized.as_deref(), Some("PANIC"));
        assert!(f.is_fatal(), "V takes precedence over S");
        assert_eq!(f.detail.as_deref(), Some("detail"));
        assert_eq!(f.fields.len(), 10);
        assert_eq!(f.fields[6], (b'P', "12".to_string()));
        assert_eq!(f.fields[9], (b'R', "main".to_string()));

        // Pre-9.6 servers send only S.
        let f = decode::error_fields(b"SFATAL\0Mx\0\0").unwrap();
        assert!(f.is_fatal());
        // Empty field list.
        let f = decode::error_fields(b"\0").unwrap();
        assert_eq!(f, ErrorFields::default());
        assert!(!f.is_fatal());
        // Repeated field: the typed accessor holds the last value.
        let f = decode::error_fields(b"Ma\0Mb\0\0").unwrap();
        assert_eq!(f.message.as_deref(), Some("b"));
        assert_eq!(f.fields.len(), 2);
        // Invalid UTF-8 (another client_encoding) is decoded lossily.
        let f = decode::error_fields(b"VFATAL\0Mcaf\xe9\0\0").unwrap();
        assert_eq!(f.message.as_deref(), Some("caf\u{fffd}"));
        assert!(f.is_fatal());
    }

    #[test]
    fn error_fields_malformed() {
        assert!(is_protocol(decode::error_fields(b"")), "missing terminator");
        assert!(
            is_protocol(decode::error_fields(b"SERROR\0")),
            "missing terminator"
        );
        assert!(
            is_protocol(decode::error_fields(b"SERROR")),
            "unterminated string"
        );
        assert!(is_protocol(decode::error_fields(b"S")));
        assert!(is_protocol(decode::error_fields(b"\0\0")), "trailing data");
        assert!(
            is_protocol(decode::error_fields(b"Mx\0\0junk")),
            "trailing data"
        );
    }

    #[test]
    fn parameter_status_round_trip() {
        let (t, body) = encoded(|b| encode::parameter_status(b, "server_version", "18.0"));
        assert_eq!(t, tag::PARAMETER_STATUS);
        assert_eq!(
            decode::parameter_status(&body).unwrap(),
            ("server_version".into(), "18.0".into())
        );
        let (_, body) = encoded(|b| encode::parameter_status(b, "application_name", ""));
        assert_eq!(
            decode::parameter_status(&body).unwrap(),
            ("application_name".into(), String::new())
        );
        assert!(is_protocol(decode::parameter_status(b"a\0")));
        assert!(is_protocol(decode::parameter_status(b"a\0b")));
        assert!(is_protocol(decode::parameter_status(b"a\0b\0c")));
        assert!(is_protocol(decode::parameter_status(b"")));
        assert!(is_protocol(decode::parameter_status(b"a\0\xff\0")));
    }

    #[test]
    fn backend_key_data_round_trip() {
        for len in [4usize, 32, 256] {
            let key: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let (t, body) = encoded(|b| encode::backend_key_data(b, 0x8000_0001, &key));
            assert_eq!(t, tag::BACKEND_KEY_DATA);
            let (pid, secret) = decode::backend_key_data(&body).unwrap();
            assert_eq!(pid, 0x8000_0001);
            assert_eq!(&secret[..], &key[..]);
        }
        for len in [0usize, 3, 257] {
            let mut body = vec![0, 0, 0, 1];
            body.extend(std::iter::repeat_n(1u8, len));
            assert!(
                is_protocol(decode::backend_key_data(&body)),
                "key length {len}"
            );
        }
        assert!(is_protocol(decode::backend_key_data(&[0, 0, 1])));
    }

    #[test]
    fn ready_for_query_round_trip() {
        for s in [TxStatus::Idle, TxStatus::InTransaction, TxStatus::Failed] {
            let (t, body) = encoded(|b| encode::ready_for_query(b, s));
            assert_eq!(t, tag::READY_FOR_QUERY);
            assert_eq!(body, [s.as_byte()]);
            assert_eq!(decode::ready_for_query(&body).unwrap(), s);
        }
        assert!(is_protocol(decode::ready_for_query(b"")));
        assert!(is_protocol(decode::ready_for_query(b"X")));
        assert!(is_protocol(decode::ready_for_query(b"II")));
    }

    #[test]
    fn negotiate_protocol_version_round_trip() {
        let (t, body) =
            encoded(|b| encode::negotiate_protocol_version(b, 2, &["_pq_.foo", "_pq_.bar"]));
        assert_eq!(t, tag::NEGOTIATE_PROTOCOL_VERSION);
        assert_eq!(body, b"\0\0\0\x02\0\0\0\x02_pq_.foo\0_pq_.bar\0");
        assert_eq!(
            decode::negotiate_protocol_version(&body).unwrap(),
            (2, vec!["_pq_.foo".to_string(), "_pq_.bar".to_string()])
        );
        let (_, body) = encoded(|b| encode::negotiate_protocol_version(b, 0, &[]));
        assert_eq!(
            decode::negotiate_protocol_version(&body).unwrap(),
            (0, vec![])
        );
    }

    #[test]
    fn negotiate_protocol_version_malformed() {
        let body = |minor: i32, count: i32, rest: &[u8]| {
            let mut v = minor.to_be_bytes().to_vec();
            v.extend_from_slice(&count.to_be_bytes());
            v.extend_from_slice(rest);
            v
        };
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            -1, 0, b""
        ))));
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            2, -1, b""
        ))));
        // A huge count with a tiny body is rejected before allocating.
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            2,
            i32::MAX,
            b"a\0"
        ))));
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            2, 2, b"a\0"
        ))));
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            2, 2, b"a\0\0\0"
        ))));
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            2, 1, b"a"
        ))));
        assert!(is_protocol(decode::negotiate_protocol_version(&body(
            2, 0, b"x"
        ))));
        assert!(is_protocol(decode::negotiate_protocol_version(&[
            0, 0, 0, 2
        ])));
    }

    #[test]
    fn password_message_round_trip() {
        let token = b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig";
        let (t, body) = encoded(|b| encode::password_message(b, token));
        assert_eq!(t, tag::PASSWORD);
        assert_eq!(body.last(), Some(&0));
        assert_eq!(&decode::password_message(&body).unwrap()[..], token);
        // Empty password is well formed.
        assert!(decode::password_message(b"\0").unwrap().is_empty());
        // Non-UTF-8 bytes are returned as they are.
        assert_eq!(
            &decode::password_message(b"\xff\xfe\0").unwrap()[..],
            b"\xff\xfe"
        );
    }

    #[test]
    fn password_message_malformed() {
        assert!(is_protocol(decode::password_message(b"")));
        assert!(is_protocol(decode::password_message(b"secret")), "no NUL");
        assert!(
            is_protocol(decode::password_message(b"sec\0ret\0")),
            "interior NUL"
        );
        assert!(
            is_protocol(decode::password_message(b"secret\0\0")),
            "two NULs"
        );
        assert!(is_protocol(decode::password_message(b"\0\0")));
        // A password containing NUL is encoded as is and rejected by the decoder.
        let (_, body) = encoded(|b| encode::password_message(b, b"a\0b"));
        assert!(is_protocol(decode::password_message(&body)));
    }

    #[test]
    fn sasl_initial_response_round_trip() {
        let (t, body) =
            encoded(|b| encode::sasl_initial_response(b, "SCRAM-SHA-256", b"n,,n=,r=nonce"));
        assert_eq!(t, tag::PASSWORD);
        assert_eq!(
            decode::sasl_initial_response(&body).unwrap(),
            (
                "SCRAM-SHA-256".to_string(),
                Some(Bytes::from_static(b"n,,n=,r=nonce"))
            )
        );
        let (_, body) = encoded(|b| encode::sasl_initial_response(b, "OAUTHBEARER", b""));
        assert_eq!(
            decode::sasl_initial_response(&body).unwrap(),
            ("OAUTHBEARER".to_string(), Some(Bytes::new()))
        );
        // Length -1: no initial response.
        assert_eq!(
            decode::sasl_initial_response(b"OAUTHBEARER\0\xff\xff\xff\xff").unwrap(),
            ("OAUTHBEARER".to_string(), None)
        );
    }

    #[test]
    fn sasl_initial_response_malformed() {
        let m = |len: i32, data: &[u8]| {
            let mut v = b"SCRAM-SHA-256\0".to_vec();
            v.extend_from_slice(&len.to_be_bytes());
            v.extend_from_slice(data);
            v
        };
        assert!(is_protocol(decode::sasl_initial_response(&m(-2, b""))));
        assert!(is_protocol(decode::sasl_initial_response(&m(
            i32::MIN,
            b""
        ))));
        assert!(
            is_protocol(decode::sasl_initial_response(&m(5, b"abcd"))),
            "short data"
        );
        assert!(is_protocol(decode::sasl_initial_response(&m(
            i32::MAX,
            b"abcd"
        ))));
        assert!(
            is_protocol(decode::sasl_initial_response(&m(3, b"abcd"))),
            "trailing"
        );
        assert!(
            is_protocol(decode::sasl_initial_response(&m(-1, b"x"))),
            "trailing"
        );
        assert!(is_protocol(decode::sasl_initial_response(
            b"SCRAM-SHA-256\0\0\0"
        )));
        assert!(is_protocol(decode::sasl_initial_response(b"SCRAM-SHA-256")));
        assert!(is_protocol(decode::sasl_initial_response(b"")));
    }

    #[test]
    fn sasl_response_round_trip() {
        let (t, body) = encoded(|b| encode::sasl_response(b, b"c=biws,r=nonce,p=proof"));
        assert_eq!(t, tag::PASSWORD);
        assert_eq!(&decode::sasl_response(&body)[..], b"c=biws,r=nonce,p=proof");
        assert!(decode::sasl_response(b"").is_empty());
    }

    #[test]
    fn query_round_trip() {
        let (t, body) = encoded(|b| encode::query(b, "SELECT 'é' AS x"));
        assert_eq!(t, tag::QUERY);
        assert_eq!(decode::query(&body).unwrap(), "SELECT 'é' AS x");
        assert_eq!(decode::query(b"\0").unwrap(), "");
        assert!(is_protocol(decode::query(b"")));
        assert!(is_protocol(decode::query(b"SELECT 1")));
        assert!(is_protocol(decode::query(b"SELECT 1\0; DROP TABLE t\0")));
        assert!(is_protocol(decode::query(b"SELECT 1\0\0")));
        assert!(is_protocol(decode::query(b"SELECT '\xe9'\0")));
        // Interior NUL is truncated by the encoder, never smuggled.
        let (_, body) = encoded(|b| encode::query(b, "SELECT 1\0; DROP TABLE t"));
        assert_eq!(decode::query(&body).unwrap(), "SELECT 1");
    }

    #[test]
    fn parse_round_trip() {
        let (t, body) = encoded(|b| encode::parse(b, "s1", "SELECT $1::int, $2", &[23, 0]));
        assert_eq!(t, tag::PARSE);
        assert_eq!(
            decode::parse(&body).unwrap(),
            Parse {
                statement: "s1".into(),
                query: "SELECT $1::int, $2".into(),
                param_types: vec![23, 0],
            }
        );
        let (_, body) = encoded(|b| encode::parse(b, "", "SELECT 1", &[]));
        let p = decode::parse(&body).unwrap();
        assert_eq!(p.statement, "");
        assert!(p.param_types.is_empty());
        // More than i16::MAX parameters, as PostgreSQL allows.
        let many: Vec<u32> = (0..40_000).collect();
        let (_, body) = encoded(|b| encode::parse(b, "big", "q", &many));
        assert_eq!(decode::parse(&body).unwrap().param_types, many);
        // OIDs above i32::MAX survive.
        let (_, body) = encoded(|b| encode::parse(b, "", "q", &[u32::MAX]));
        assert_eq!(decode::parse(&body).unwrap().param_types, vec![u32::MAX]);
    }

    #[test]
    fn parse_malformed() {
        assert!(is_protocol(decode::parse(b"")));
        assert!(is_protocol(decode::parse(b"s\0")));
        assert!(is_protocol(decode::parse(b"s\0q\0")), "missing count");
        assert!(is_protocol(decode::parse(b"s\0q\0\0")), "short count");
        assert!(is_protocol(decode::parse(b"s\0q\0\0\x01")), "missing oid");
        assert!(
            is_protocol(decode::parse(b"s\0q\0\0\x01\0\0\0")),
            "short oid"
        );
        assert!(is_protocol(decode::parse(b"s\0q\0\0\x00\0")), "trailing");
        assert!(
            is_protocol(decode::parse(b"s\0q\0\0\x01\0\0\0\x17\0")),
            "trailing"
        );
        assert!(is_protocol(decode::parse(b"s\0q\0\xff\xff")), "huge count");
        assert!(is_protocol(decode::parse(b"\xff\0q\0\0\0")), "UTF-8");
    }

    #[test]
    fn close_and_describe_targets() {
        let (t, body) = encoded(|b| encode::close(b, b'S', "stmt_1"));
        assert_eq!(t, tag::CLOSE);
        assert_eq!(
            decode::target(&body).unwrap(),
            Target {
                kind: b'S',
                name: "stmt_1".into()
            }
        );
        let (t, body) = encoded(|b| encode::describe(b, b'P', ""));
        assert_eq!(t, tag::DESCRIBE);
        assert_eq!(
            decode::target(&body).unwrap(),
            Target {
                kind: b'P',
                name: String::new()
            }
        );
        assert!(is_protocol(decode::target(b"")));
        assert!(is_protocol(decode::target(b"S")));
        assert!(is_protocol(decode::target(b"Sname")));
        assert!(is_protocol(decode::target(b"Xname\0")), "unknown kind");
        assert!(
            is_protocol(decode::target(b"sname\0")),
            "kind is case sensitive"
        );
        assert!(is_protocol(decode::target(b"Sname\0x")), "trailing");
        // An unknown kind is encoded as given and rejected on decode.
        let (_, body) = encoded(|b| encode::close(b, b'Q', "x"));
        assert!(is_protocol(decode::target(&body)));
    }

    #[test]
    fn bind_names_ignore_the_rest() {
        // portal, statement, then formats/params/result formats.
        let mut body = b"portal_1\0stmt_1\0".to_vec();
        body.extend_from_slice(&[0, 1, 0, 1, 0, 1, 0, 0, 0, 2, b'4', b'2', 0, 0]);
        assert_eq!(
            decode::bind_names(&body).unwrap(),
            ("portal_1".into(), "stmt_1".into())
        );
        assert_eq!(
            decode::bind_names(b"\0\0").unwrap(),
            (String::new(), String::new())
        );
        assert!(is_protocol(decode::bind_names(b"")));
        assert!(is_protocol(decode::bind_names(b"p\0")));
        assert!(is_protocol(decode::bind_names(b"p\0s")));
        assert!(is_protocol(decode::bind_names(b"p\0\xff\0")));
    }

    #[test]
    fn command_complete_round_trip() {
        let (t, body) = encoded(|b| encode::command_complete(b, "INSERT 0 5"));
        assert_eq!(t, tag::COMMAND_COMPLETE);
        assert_eq!(decode::command_complete(&body).unwrap(), "INSERT 0 5");
        assert!(is_protocol(decode::command_complete(b"SELECT 1")));
        assert!(is_protocol(decode::command_complete(b"SELECT 1\0x")));
    }

    #[test]
    fn data_row_round_trip() {
        let values: [Option<&[u8]>; 4] = [Some(b"42"), None, Some(b""), Some(&[0, 255, 0])];
        let (t, body) = encoded(|b| encode::data_row(b, &values));
        assert_eq!(t, tag::DATA_ROW);
        let row = decode::data_row(&body).unwrap();
        assert_eq!(
            row,
            vec![
                Some(Bytes::from_static(b"42")),
                None,
                Some(Bytes::new()),
                Some(Bytes::from_static(&[0, 255, 0]))
            ]
        );
        let (_, body) = encoded(|b| encode::data_row(b, &[]));
        assert!(decode::data_row(&body).unwrap().is_empty());
    }

    #[test]
    fn data_row_malformed() {
        assert!(is_protocol(decode::data_row(b"")));
        assert!(is_protocol(decode::data_row(b"\0")));
        assert!(is_protocol(decode::data_row(b"\0\x01")), "missing column");
        assert!(
            is_protocol(decode::data_row(b"\0\x01\0\0\0\x05abc")),
            "short value"
        );
        assert!(
            is_protocol(decode::data_row(b"\0\x01\xff\xff\xff\xfe")),
            "length -2"
        );
        assert!(is_protocol(decode::data_row(b"\0\x01\x7f\xff\xff\xffabc")));
        assert!(
            is_protocol(decode::data_row(b"\0\x01\xff\xff\xff\xffx")),
            "trailing"
        );
        assert!(is_protocol(decode::data_row(b"\0\0x")), "trailing");
        // A huge column count with a tiny body is rejected before allocating.
        assert!(is_protocol(decode::data_row(b"\xff\xff\0\0\0\0")));
    }

    #[test]
    fn fixed_messages() {
        assert_eq!(encoded(encode::terminate), (tag::TERMINATE, vec![]));
        assert_eq!(encoded(encode::sync), (tag::SYNC, vec![]));
        let mut buf = BytesMut::new();
        encode::sync(&mut buf);
        encode::terminate(&mut buf);
        assert_eq!(&buf[..], b"S\0\0\0\x04X\0\0\0\x04");
    }

    #[test]
    fn encoders_append() {
        let mut buf = BytesMut::from(&b"prefix"[..]);
        encode::authentication_ok(&mut buf);
        encode::parameter_status(&mut buf, "a", "b");
        encode::ready_for_query(&mut buf, TxStatus::Idle);
        assert_eq!(
            &buf[..],
            b"prefixR\0\0\0\x08\0\0\0\0S\0\0\0\x08a\0b\0Z\0\0\0\x05I"
        );
    }

    #[test]
    fn sasl_encoder_skips_empty_names() {
        let (_, body) = encoded(|b| encode::authentication_sasl(b, &["", "SCRAM-SHA-256", "\0x"]));
        assert_eq!(
            decode::authentication(&body).unwrap(),
            Authentication::Sasl {
                mechanisms: vec!["SCRAM-SHA-256".into()]
            }
        );
    }

    fn text() -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<char>().prop_filter("no NUL", |c| *c != '\0'), 0..24)
            .prop_map(|v| v.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn random_bodies_never_panic(body in proptest::collection::vec(
            prop_oneof![Just(0u8), Just(0xffu8), any::<u8>()], 0..128)
        ) {
            let _ = decode::authentication(&body);
            let _ = decode::error_fields(&body);
            let _ = decode::parameter_status(&body);
            let _ = decode::backend_key_data(&body);
            let _ = decode::ready_for_query(&body);
            let _ = decode::negotiate_protocol_version(&body);
            let _ = decode::password_message(&body);
            let _ = decode::sasl_initial_response(&body);
            let _ = decode::sasl_response(&body);
            let _ = decode::query(&body);
            let _ = decode::parse(&body);
            let _ = decode::target(&body);
            let _ = decode::bind_names(&body);
            let _ = decode::command_complete(&body);
            let _ = decode::data_row(&body);
        }

        #[test]
        fn text_messages_round_trip(a in text(), b in text(), oids in proptest::collection::vec(any::<u32>(), 0..8)) {
            let (_, body) = encoded(|buf| encode::parameter_status(buf, &a, &b));
            prop_assert_eq!(decode::parameter_status(&body).unwrap(), (a.clone(), b.clone()));
            let (_, body) = encoded(|buf| encode::query(buf, &a));
            prop_assert_eq!(decode::query(&body).unwrap(), a.clone());
            let (_, body) = encoded(|buf| encode::parse(buf, &a, &b, &oids));
            let p = decode::parse(&body).unwrap();
            prop_assert_eq!((p.statement, p.query, p.param_types), (a.clone(), b.clone(), oids));
            let (_, body) = encoded(|buf| encode::notice_response(buf, "NOTICE", &a, &b));
            let f = decode::error_fields(&body).unwrap();
            prop_assert_eq!(f.code, Some(a.clone()));
            prop_assert_eq!(f.message, Some(b.clone()));
            let (_, body) = encoded(|buf| encode::close(buf, b'S', &a));
            prop_assert_eq!(decode::target(&body).unwrap().name, a);
        }

        #[test]
        fn binary_messages_round_trip(
            data in proptest::collection::vec(any::<u8>(), 0..64),
            cols in proptest::collection::vec(proptest::option::of(proptest::collection::vec(any::<u8>(), 0..16)), 0..8),
        ) {
            let (_, body) = encoded(|b| encode::authentication_sasl_continue(b, &data));
            prop_assert_eq!(
                decode::authentication(&body).unwrap(),
                Authentication::SaslContinue { data: Bytes::from(data.clone()) }
            );
            let (_, body) = encoded(|b| encode::sasl_initial_response(b, "SCRAM-SHA-256", &data));
            prop_assert_eq!(
                decode::sasl_initial_response(&body).unwrap().1,
                Some(Bytes::from(data.clone()))
            );
            let refs: Vec<Option<&[u8]>> = cols.iter().map(|c| c.as_deref()).collect();
            let (_, body) = encoded(|b| encode::data_row(b, &refs));
            let row = decode::data_row(&body).unwrap();
            let row: Vec<Option<Vec<u8>>> = row.into_iter().map(|v| v.map(|b| b.to_vec())).collect();
            prop_assert_eq!(row, cols);
        }
    }
}
