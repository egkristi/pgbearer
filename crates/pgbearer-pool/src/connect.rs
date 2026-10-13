//! Opening an authenticated backend connection, and the connection itself.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use pgbearer_config::{BackendConfig, KeepaliveConfig, ResolvedCredential};
use pgbearer_tls::{BackendTls, ClientCertPaths};
use pgbearer_wire::messages::{TxStatus, decode, encode};
use pgbearer_wire::startup::{encode_ssl_request, encode_startup_message};
use pgbearer_wire::{FrameReader, ProtocolVersion, WireError, tag};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::{BackendError, BackendStream};

/// Largest server message read during startup and authentication.
pub(crate) const STARTUP_MESSAGE_LIMIT: usize = 1024 * 1024;

/// Largest server message read by [`BackendConnection::simple_query`].
const QUERY_MESSAGE_LIMIT: usize = pgbearer_wire::frame::DEFAULT_INSPECT_LIMIT;

/// Upper bound on [`BackendConnection::terminate`].
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(1);

/// StartupMessage keys that [`ConnectParams::parameters`] may not contain:
/// the pool sets `user` and `database` itself, and `options`, `replication`
/// and protocol options (`_pq_.*`) would change what the login means.
const RESERVED_PARAMETERS: &[&str] = &["user", "database", "options", "replication"];

/// Result of [`BackendConnection::simple_query`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleQueryResult {
    /// Result sets: rows of text values (`None` = NULL), one entry per
    /// statement that returned rows.
    pub result_sets: Vec<Vec<Vec<Option<String>>>>,
    /// Command tags.
    pub command_tags: Vec<String>,
}

/// What to connect to.
#[derive(Debug, Clone, Copy)]
pub struct ConnectParams<'a> {
    /// Backend configuration.
    pub backend: &'a BackendConfig,
    /// TLS for this backend.
    pub tls: &'a BackendTls,
    /// Database.
    pub database: &'a str,
    /// Role to log in as.
    pub role: &'a str,
    /// Credential for the role.
    pub credential: &'a ResolvedCredential,
    /// StartupMessage parameters after `user` and `database`.
    pub parameters: &'a [(String, String)],
}

/// How the backend authenticated the login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendAuthMethod {
    /// `AuthenticationOk` without a password exchange: TLS client
    /// certificate (or `trust`).
    CertificateOrTrust,
    /// `SCRAM-SHA-256` without channel binding.
    ScramSha256,
    /// `SCRAM-SHA-256-PLUS` with `tls-server-end-point` channel binding.
    ScramSha256Plus,
    /// `AuthenticationMD5Password` (over TLS).
    Md5,
    /// `AuthenticationCleartextPassword` (over TLS).
    Cleartext,
}

impl BackendAuthMethod {
    /// A short name for logs and audit.
    pub fn as_str(self) -> &'static str {
        match self {
            BackendAuthMethod::CertificateOrTrust => "cert_or_trust",
            BackendAuthMethod::ScramSha256 => "scram-sha-256",
            BackendAuthMethod::ScramSha256Plus => "scram-sha-256-plus",
            BackendAuthMethod::Md5 => "md5",
            BackendAuthMethod::Cleartext => "password",
        }
    }
}

/// An authenticated backend connection.
///
/// The session relay uses `reader` and `writer` directly. The `writer` is
/// buffered; callers must flush.
pub struct BackendConnection {
    /// Framed reader for server messages.
    pub reader: FrameReader<ReadHalf<BackendStream>>,
    /// Buffered writer for client messages.
    pub writer: BufWriter<WriteHalf<BackendStream>>,
    /// Real backend process id (from `BackendKeyData`).
    pub process_id: u32,
    /// Server parameters (from `ParameterStatus`), in arrival order of first
    /// appearance; later values replace earlier ones.
    pub server_params: Vec<(String, String)>,
    /// Negotiated protocol version (always 3.0 towards backends today).
    pub protocol_version: ProtocolVersion,
    /// Last `ReadyForQuery` status.
    pub tx_status: TxStatus,
    /// Whether TLS is in use.
    pub tls: bool,
    /// Address the TCP connection is connected to.
    pub peer_addr: SocketAddr,
    /// Local address of the TCP connection (joins `pg_stat_activity.client_addr/port`).
    pub local_addr: SocketAddr,
    /// Real backend secret key; never exposed (only via [`crate::CancelTarget`]).
    pub(crate) secret_key: Bytes,
    /// How the login was authenticated.
    pub(crate) auth_method: BackendAuthMethod,
}

impl std::fmt::Debug for BackendConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendConnection")
            .field("process_id", &self.process_id)
            .field("protocol_version", &self.protocol_version)
            .field("tx_status", &self.tx_status)
            .field("tls", &self.tls)
            .field("peer_addr", &self.peer_addr)
            .field("local_addr", &self.local_addr)
            .field("auth_method", &self.auth_method)
            .finish_non_exhaustive()
    }
}

impl BackendConnection {
    /// Connect and authenticate (see the crate documentation).
    pub async fn connect(params: &ConnectParams<'_>) -> Result<BackendConnection, BackendError> {
        tokio::time::timeout(params.backend.pool.connect_timeout, connect(params))
            .await
            .unwrap_or(Err(BackendError::Timeout))
    }

    /// How the backend authenticated this login.
    pub fn auth_method(&self) -> BackendAuthMethod {
        self.auth_method
    }

    /// Run a simple query, consuming all responses up to `ReadyForQuery`.
    /// Updates `server_params` and `tx_status`. If the server returned an
    /// error, all responses are still consumed and `Err(Server)` is returned.
    /// `NoticeResponse` messages are ignored. Flushes the writer.
    ///
    /// Text values are decoded as UTF-8, lossily (the client's
    /// `client_encoding` applies). `NotificationResponse` messages are
    /// dropped; `COPY` is not supported ([`BackendError::Protocol`], and the
    /// connection must be closed). A query containing a NUL byte is refused
    /// before anything is sent.
    pub async fn simple_query(&mut self, sql: &str) -> Result<SimpleQueryResult, BackendError> {
        if sql.contains('\0') {
            return Err(BackendError::Protocol(
                "query text contains a NUL byte".into(),
            ));
        }
        let mut buf = BytesMut::new();
        encode::query(&mut buf, sql);
        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;

        let mut result = SimpleQueryResult::default();
        let mut rows: Option<Vec<Vec<Option<String>>>> = None;
        let mut error: Option<BackendError> = None;
        loop {
            let Some(msg) = self.reader.read_message(QUERY_MESSAGE_LIMIT).await? else {
                // A FATAL error is followed by EOF instead of ReadyForQuery.
                return Err(error.unwrap_or_else(|| {
                    BackendError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "server closed the connection during a query",
                    ))
                }));
            };
            match msg.tag {
                tag::ROW_DESCRIPTION => rows = Some(Vec::new()),
                tag::DATA_ROW => {
                    let values = decode::data_row(&msg.body)?;
                    let Some(rows) = rows.as_mut() else {
                        return Err(BackendError::Protocol(
                            "DataRow without RowDescription".into(),
                        ));
                    };
                    rows.push(
                        values
                            .into_iter()
                            .map(|v| v.map(|b| String::from_utf8_lossy(&b).into_owned()))
                            .collect(),
                    );
                }
                tag::COMMAND_COMPLETE => {
                    result
                        .command_tags
                        .push(decode::command_complete(&msg.body)?);
                    if let Some(rows) = rows.take() {
                        result.result_sets.push(rows);
                    }
                }
                tag::EMPTY_QUERY_RESPONSE | tag::NOTICE_RESPONSE | tag::NOTIFICATION_RESPONSE => {}
                tag::ERROR_RESPONSE => {
                    rows = None;
                    error = Some(BackendError::from_error_response(&msg.body));
                }
                tag::PARAMETER_STATUS => {
                    let (name, value) = decode::parameter_status(&msg.body)?;
                    self.note_parameter_status(name, value);
                }
                tag::READY_FOR_QUERY => {
                    self.tx_status = decode::ready_for_query(&msg.body)?;
                    break;
                }
                other => {
                    return Err(BackendError::Protocol(format!(
                        "unexpected message {} in response to a simple query",
                        describe_tag(other)
                    )));
                }
            }
        }
        match error {
            Some(e) => Err(e),
            None => Ok(result),
        }
    }

    /// Record a `ParameterStatus` seen by the relay.
    pub fn note_parameter_status(&mut self, name: String, value: String) {
        match self.server_params.iter_mut().find(|(n, _)| *n == name) {
            Some((_, v)) => *v = value,
            None => self.server_params.push((name, value)),
        }
    }

    /// Send `Terminate` and close (best effort, bounded by 1 s).
    pub async fn terminate(self) {
        let mut writer = self.writer;
        let _ = tokio::time::timeout(TERMINATE_TIMEOUT, async move {
            let mut buf = BytesMut::new();
            encode::terminate(&mut buf);
            writer.write_all(&buf).await?;
            writer.flush().await?;
            writer.shutdown().await
        })
        .await;
    }
}

/// Steps 1–5 of the crate documentation (without the overall timeout).
async fn connect(params: &ConnectParams<'_>) -> Result<BackendConnection, BackendError> {
    // Checks that need no network I/O first.
    let startup = encode_startup(params)?;
    let client_cert = match params.credential {
        ResolvedCredential::Cert {
            cert_file,
            key_file,
        } => Some(ClientCertPaths {
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
        }),
        ResolvedCredential::Password { .. } => None,
    };
    let tls = params
        .tls
        .connector(client_cert.as_ref())
        .map_err(|e| BackendError::Tls(e.to_string()))?;
    if client_cert.is_some() && tls.is_none() {
        return Err(BackendError::Auth(
            "a client certificate credential requires TLS to the backend".into(),
        ));
    }
    let (host, port) = params.backend.host_port().ok_or_else(|| {
        BackendError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("backend {:?} has no endpoint", params.backend.name),
        ))
    })?;

    // 1. TCP.
    let tcp = connect_tcp(&host, port, &params.backend.keepalive).await?;
    let peer_addr = tcp.peer_addr()?;
    let local_addr = tcp.local_addr()?;

    // 2. TLS.
    let use_tls = tls.is_some();
    let (stream, channel_binding): (BackendStream, Option<Vec<u8>>) = match tls {
        None => (Box::new(tcp), None),
        Some((connector, server_name)) => {
            let stream = negotiate_tls(tcp, &connector, server_name).await?;
            let channel_binding = pgbearer_tls::peer_tls_server_end_point(stream.get_ref().1);
            (Box::new(stream), channel_binding)
        }
    };
    let (read, write) = tokio::io::split(stream);
    let mut conn = BackendConnection {
        reader: FrameReader::new(read),
        writer: BufWriter::new(write),
        process_id: 0,
        server_params: Vec::new(),
        protocol_version: ProtocolVersion::V3_0,
        tx_status: TxStatus::Idle,
        tls: use_tls,
        peer_addr,
        local_addr,
        secret_key: Bytes::new(),
        auth_method: BackendAuthMethod::CertificateOrTrust,
    };

    // 3. StartupMessage.
    conn.writer.write_all(&startup).await?;
    conn.writer.flush().await?;

    // 4. Authentication.
    conn.auth_method = crate::auth::authenticate(&mut conn, params, channel_binding).await?;

    // 5. Parameters and key data until ReadyForQuery.
    finish_startup(&mut conn).await?;
    Ok(conn)
}

/// The StartupMessage for `params` (protocol 3.0).
pub(crate) fn encode_startup(params: &ConnectParams<'_>) -> Result<BytesMut, BackendError> {
    if let Some((name, _)) = params
        .parameters
        .iter()
        .find(|(name, _)| RESERVED_PARAMETERS.contains(&name.as_str()) || name.starts_with("_pq_."))
    {
        return Err(BackendError::Protocol(format!(
            "startup parameter {name:?} is reserved and cannot be forwarded"
        )));
    }
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(params.parameters.len() + 2);
    pairs.push(("user", params.role));
    pairs.push(("database", params.database));
    pairs.extend(
        params
            .parameters
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str())),
    );
    let mut buf = BytesMut::new();
    encode_startup_message(&mut buf, ProtocolVersion::V3_0, &pairs).map_err(|e| match e {
        WireError::InvalidLength { len, .. } => {
            BackendError::StartupTooLarge(usize::try_from(len).unwrap_or(usize::MAX))
        }
        other => BackendError::from(other),
    })?;
    Ok(buf)
}

/// Resolve `host` (DNS on every connect) and connect to the first address
/// that accepts, then set the socket options.
async fn connect_tcp(host: &str, port: u16, keepalive: &KeepaliveConfig) -> Result<TcpStream, BackendError> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let mut last_error = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                set_socket_options(&stream, keepalive)?;
                return Ok(stream);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(BackendError::Io(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{host}:{port} resolved to no addresses"),
        )
    })))
}

/// `TCP_NODELAY`, and when enabled `SO_KEEPALIVE` with idle/interval/count
/// and (Linux) `TCP_USER_TIMEOUT`.
pub(crate) fn set_socket_options(stream: &TcpStream, keepalive: &KeepaliveConfig) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    if !keepalive.enabled {
        return Ok(());
    }
    let socket = socket2::SockRef::from(stream);
    let params = socket2::TcpKeepalive::new()
        .with_time(keepalive.idle)
        .with_interval(keepalive.interval)
        .with_retries(keepalive.count);
    socket.set_tcp_keepalive(&params)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if !keepalive.user_timeout.is_zero() {
        socket.set_tcp_user_timeout(Some(keepalive.user_timeout))?;
    }
    Ok(())
}

/// Send `SSLRequest` on the raw socket and, on `'S'`, run the handshake.
///
/// Exactly one byte of the response is read. Any byte already readable
/// after the `'S'` was sent before the handshake (plaintext injected by the
/// server or by an attacker on the path, CVE-2021-23222 class) and fails the
/// connection; nothing is ever buffered across the handshake.
pub(crate) async fn negotiate_tls(
    mut tcp: TcpStream,
    connector: &TlsConnector,
    server_name: ServerName<'static>,
) -> Result<TlsStream<TcpStream>, BackendError> {
    let mut request = BytesMut::new();
    encode_ssl_request(&mut request);
    tcp.write_all(&request).await?;
    tcp.flush().await?;
    let mut response = [0u8; 1];
    tcp.read_exact(&mut response).await?;
    match response[0] {
        b'S' => {
            let mut extra = [0u8; 1];
            match tcp.try_read(&mut extra) {
                Ok(0) => {
                    return Err(BackendError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "server closed the connection after accepting TLS",
                    )));
                }
                Ok(_) => {
                    return Err(BackendError::Protocol(
                        "server sent unencrypted data after accepting TLS, before the handshake"
                            .into(),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(BackendError::Io(e)),
            }
            connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| BackendError::Tls(format!("handshake failed: {e}")))
        }
        b'N' => Err(BackendError::Tls("server does not support TLS".into())),
        other => Err(BackendError::Protocol(format!(
            "unexpected response {other:#04x} to SSLRequest"
        ))),
    }
}

/// Step 5: `ParameterStatus` and `BackendKeyData` until `ReadyForQuery`.
async fn finish_startup(conn: &mut BackendConnection) -> Result<(), BackendError> {
    let mut key = None;
    loop {
        let msg = read_startup_message(conn).await?;
        match msg.tag {
            tag::PARAMETER_STATUS => {
                let (name, value) = decode::parameter_status(&msg.body)?;
                conn.note_parameter_status(name, value);
            }
            tag::BACKEND_KEY_DATA => key = Some(decode::backend_key_data(&msg.body)?),
            tag::READY_FOR_QUERY => {
                conn.tx_status = decode::ready_for_query(&msg.body)?;
                break;
            }
            tag::NOTICE_RESPONSE => {}
            tag::ERROR_RESPONSE => return Err(BackendError::from_error_response(&msg.body)),
            other => {
                return Err(BackendError::Protocol(format!(
                    "unexpected message {} after authentication",
                    describe_tag(other)
                )));
            }
        }
    }
    let (process_id, secret_key) = key.ok_or_else(|| {
        BackendError::Protocol("server sent no BackendKeyData".into())
    })?;
    conn.process_id = process_id;
    conn.secret_key = secret_key;
    Ok(())
}

/// The next server message during startup; EOF is an error.
pub(crate) async fn read_startup_message(
    conn: &mut BackendConnection,
) -> Result<pgbearer_wire::Message, BackendError> {
    conn.reader
        .read_message(STARTUP_MESSAGE_LIMIT)
        .await?
        .ok_or_else(|| {
            BackendError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed the connection during startup",
            ))
        })
}

/// A message tag for error messages (`'Z'`, or hex for non-printable bytes).
pub(crate) fn describe_tag(tag: u8) -> String {
    if tag.is_ascii_graphic() {
        format!("'{}'", char::from(tag))
    } else {
        format!("{tag:#04x}")
    }
}
