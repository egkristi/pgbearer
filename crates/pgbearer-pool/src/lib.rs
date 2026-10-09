//! Backend connections and pooling (ARCHITECTURE.md §10).
//!
//! * [`BackendConnection::connect`] opens a connection to PostgreSQL **as the
//!   mapped role**: TCP (with `connect_timeout`), optional TLS via
//!   `SSLRequest` + [`pgbearer_tls::BackendTls`] (presenting the role's client
//!   certificate when the credential is `Cert`), `StartupMessage` (protocol
//!   3.0; `user`, `database`, `application_name=pgbearer`,
//!   `client_encoding=UTF8`), then authentication:
//!   - `AuthenticationOk` directly (certificate auth / trust),
//!   - SASL `SCRAM-SHA-256-PLUS` when offered and TLS is used (channel binding
//!     `tls-server-end-point`), else `SCRAM-SHA-256`
//!     (`postgres_protocol::authentication::sasl`),
//!   - `AuthenticationMD5Password` and `AuthenticationCleartextPassword`
//!     (cleartext only over TLS),
//!   - anything else → [`BackendError::Auth`].
//!
//!   Then collects `ParameterStatus` and `BackendKeyData` until `ReadyForQuery`.
//!   An `ErrorResponse` at any point → [`BackendError::Server`]. Passwords are
//!   read from the password file on every connect (rotation) and zeroized after use.
//! * **Role safety check**: on each *new* connection, unless
//!   `allow_privileged_role`, run
//!   `SELECT rolsuper, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user`
//!   and refuse ([`PoolError::PrivilegedRole`]) if any is true.
//! * [`PoolManager`] keeps one pool per `(backend, database, role)`:
//!   - `max_connections` per pool and `max_backend_connections` per backend
//!     (all pools of that backend) — both enforced with semaphores held by the
//!     [`PooledConnection`];
//!   - [`acquire`](PoolManager::acquire) waits (FIFO) up to `acquire_timeout`,
//!     then [`PoolError::Timeout`] (`53300`); it prefers an idle connection
//!     (LIFO), discarding ones past `max_lifetime` (±10 % jitter) or idle past
//!     `idle_timeout`, and health-checks connections idle longer than
//!     `health_check_idle` with an empty simple query;
//!   - [`release`](PoolManager::release) with `reusable = true` runs
//!     `reset_query` (session mode) only if the connection is idle (`I`),
//!     then returns it to the idle list; on any error, or `reusable = false`,
//!     or after [`invalidate_backend`](PoolManager::invalidate_backend), the
//!     connection is closed (`Terminate`);
//!   - a maintenance task closes idle connections past their timeouts.
//! * Metrics: `pgbearer_pool_connections`, `pgbearer_pool_acquire_duration_seconds`,
//!   `pgbearer_pool_acquire_timeouts_total`, `pgbearer_backend_connects_total`,
//!   `pgbearer_backend_connect_errors_total`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use pgbearer_config::{BackendConfig, ResolvedCredential};
use pgbearer_core::ClientError;
use pgbearer_telemetry::Metrics;
use pgbearer_tls::BackendTls;
use pgbearer_wire::messages::{ErrorFields, TxStatus};
use pgbearer_wire::{FrameReader, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, BufWriter, ReadHalf, WriteHalf};
use tokio_util::sync::CancellationToken;

/// A bidirectional byte stream (plain TCP or TLS).
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// A boxed backend stream.
pub type BackendStream = Box<dyn AsyncStream>;

/// Errors talking to a backend.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// TCP connect or I/O failure.
    #[error("backend i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS negotiation failed or the server refused TLS.
    #[error("backend tls error: {0}")]
    Tls(String),
    /// Authentication failed or used an unsupported method.
    #[error("backend authentication failed: {0}")]
    Auth(String),
    /// The server sent something unexpected.
    #[error("backend protocol error: {0}")]
    Protocol(String),
    /// The server sent an ErrorResponse.
    #[error("backend error {}: {}", .0.code.as_deref().unwrap_or("?"), .0.message.as_deref().unwrap_or("?"))]
    Server(ErrorFields),
    /// The operation timed out.
    #[error("backend operation timed out")]
    Timeout,
}

impl From<pgbearer_wire::WireError> for BackendError {
    fn from(e: pgbearer_wire::WireError) -> Self {
        match e {
            pgbearer_wire::WireError::Io(io) => BackendError::Io(io),
            other => BackendError::Protocol(other.to_string()),
        }
    }
}

/// Pool errors.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// No backend with this name.
    #[error("unknown backend {0:?}")]
    UnknownBackend(String),
    /// No credential configured for the role.
    #[error("no login credential for role {role:?} on backend {backend:?}")]
    NoCredential {
        /// Backend.
        backend: String,
        /// Role.
        role: String,
    },
    /// Waited `acquire_timeout` without getting a connection.
    #[error("timed out waiting for a backend connection to {0:?}")]
    Timeout(String),
    /// The role has privileged attributes and the grant does not allow them.
    #[error("role {role:?} is privileged ({attributes}); refusing to use it")]
    PrivilegedRole {
        /// Role.
        role: String,
        /// Which attributes (for example `superuser, bypassrls`).
        attributes: String,
    },
    /// The pool manager is shutting down.
    #[error("pool is closed")]
    Closed,
    /// Connecting to the backend failed.
    #[error(transparent)]
    Backend(#[from] BackendError),
}

impl PoolError {
    /// The error to send to the client (generic; no internals).
    ///
    /// * `Timeout` → `53300` "too many connections for this database role; try again later".
    /// * `Backend(Server(e))` with SQLSTATE class 28 (auth) or `PrivilegedRole`/`NoCredential`
    ///   → `28000` "backend login for the mapped role failed" (internal reason attached).
    /// * `Backend(Server(e))` with `57P03` (starting up / shutting down) → `57P03`.
    /// * Other backend errors → `08006` "database unavailable".
    /// * `UnknownBackend`, `Closed` → `57P03` "service unavailable".
    pub fn to_client_error(&self) -> ClientError {
        todo!("pgbearer-pool: PoolError::to_client_error")
    }

    /// Short metric/audit reason code.
    pub fn reason_code(&self) -> &'static str {
        match self {
            PoolError::UnknownBackend(_) => "unknown_backend",
            PoolError::NoCredential { .. } => "no_credential",
            PoolError::Timeout(_) => "timeout",
            PoolError::PrivilegedRole { .. } => "privileged_role",
            PoolError::Closed => "closed",
            PoolError::Backend(BackendError::Io(_)) => "connect",
            PoolError::Backend(BackendError::Tls(_)) => "tls",
            PoolError::Backend(BackendError::Auth(_)) => "auth",
            PoolError::Backend(BackendError::Protocol(_)) => "protocol",
            PoolError::Backend(BackendError::Server(_)) => "server_error",
            PoolError::Backend(BackendError::Timeout) => "connect_timeout",
        }
    }
}

/// Where and how to send a cancel request for a backend connection.
#[derive(Clone)]
pub struct CancelTarget {
    _private: (),
}

impl CancelTarget {
    /// Open a new connection to the backend (with TLS if the original used
    /// TLS) and send `CancelRequest` with the backend's real key. Times out
    /// after 5 s.
    pub async fn send(&self) -> Result<(), BackendError> {
        todo!("pgbearer-pool: CancelTarget::send")
    }
}

impl std::fmt::Debug for CancelTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CancelTarget { .. }")
    }
}

/// Result of [`BackendConnection::simple_query`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleQueryResult {
    /// Rows of text values (`None` = NULL), all statements concatenated.
    pub rows: Vec<Vec<Option<String>>>,
    /// Command tags.
    pub command_tags: Vec<String>,
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
    /// Real backend process id.
    pub process_id: u32,
    /// Real backend secret key.
    pub secret_key: Bytes,
    /// Current server parameters (from `ParameterStatus`), kept up to date by
    /// `simple_query` and by the relay (which must call [`note_parameter_status`](Self::note_parameter_status)).
    pub server_params: BTreeMap<String, String>,
    /// Negotiated protocol version.
    pub protocol_version: ProtocolVersion,
    /// Last `ReadyForQuery` status.
    pub tx_status: TxStatus,
    /// Whether TLS is in use.
    pub tls: bool,
    cancel: CancelTarget,
}

impl BackendConnection {
    /// Connect and authenticate as `role` on `database` (see crate docs).
    pub async fn connect(
        backend: &BackendConfig,
        tls: &BackendTls,
        database: &str,
        role: &str,
        credential: &ResolvedCredential,
    ) -> Result<BackendConnection, BackendError> {
        let _ = (backend, tls, database, role, credential);
        todo!("pgbearer-pool: BackendConnection::connect")
    }

    /// Run a simple query, consuming all responses up to `ReadyForQuery`.
    /// Updates `server_params` and `tx_status`. If the server returned an
    /// error, all responses are still consumed and `Err(Server)` is returned.
    /// `NoticeResponse` messages are ignored. Flushes the writer.
    pub async fn simple_query(&mut self, sql: &str) -> Result<SimpleQueryResult, BackendError> {
        let _ = sql;
        todo!("pgbearer-pool: BackendConnection::simple_query")
    }

    /// Record a `ParameterStatus` seen by the relay.
    pub fn note_parameter_status(&mut self, name: String, value: String) {
        self.server_params.insert(name, value);
    }

    /// Where to send cancel requests for this connection.
    pub fn cancel_target(&self) -> CancelTarget {
        self.cancel.clone()
    }

    /// Send `Terminate` and close (best effort).
    pub async fn terminate(mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.writer.write_all(&[b'X', 0, 0, 0, 4]).await;
        let _ = self.writer.flush().await;
        let _ = self.writer.shutdown().await;
    }
}

/// What a client needs from the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireRequest {
    /// Backend name.
    pub backend: String,
    /// Database.
    pub database: String,
    /// Role to log in as.
    pub role: String,
    /// Allow privileged roles (break-glass grants).
    pub allow_privileged_role: bool,
}

/// A connection checked out of a pool. Return it with [`PoolManager::release`].
/// Dropping it without releasing closes the connection and frees its slot.
pub struct PooledConnection {
    /// The backend connection.
    pub conn: BackendConnection,
    /// True if this connection was opened for this checkout (not reused).
    pub fresh: bool,
    /// When the backend connection was opened.
    pub created_at: Instant,
    _guard: Box<dyn Send + Sync>,
}

impl PooledConnection {
    /// Backend name.
    pub fn backend(&self) -> &str {
        todo!("pgbearer-pool: PooledConnection::backend")
    }
}

/// Snapshot of one pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStats {
    /// Backend.
    pub backend: String,
    /// Database.
    pub database: String,
    /// Role.
    pub role: String,
    /// Idle connections.
    pub idle: usize,
    /// Checked-out connections.
    pub active: usize,
}

/// All pools.
pub struct PoolManager {
    _private: (),
}

impl PoolManager {
    /// Build from backend configs (creates [`BackendTls`] per backend; no network I/O).
    pub fn new(
        backends: &[BackendConfig],
        metrics: Arc<Metrics>,
    ) -> Result<Arc<PoolManager>, PoolError> {
        let _ = (backends, metrics);
        todo!("pgbearer-pool: PoolManager::new")
    }

    /// Check out a connection (see crate docs).
    pub async fn acquire(&self, req: &AcquireRequest) -> Result<PooledConnection, PoolError> {
        let _ = req;
        todo!("pgbearer-pool: PoolManager::acquire")
    }

    /// Return a connection. See crate docs for reset and discard rules.
    pub async fn release(&self, conn: PooledConnection, reusable: bool) {
        let _ = (conn, reusable);
        todo!("pgbearer-pool: PoolManager::release")
    }

    /// Mark all current connections of `backend` as stale: idle ones are closed
    /// now, checked-out ones are closed on release (CNPG switchover).
    pub fn invalidate_backend(&self, backend: &str) {
        let _ = backend;
        todo!("pgbearer-pool: PoolManager::invalidate_backend")
    }

    /// Spawn the maintenance task (idle/lifetime reaping), stopped by `shutdown`.
    pub fn spawn_maintenance(
        self: &Arc<Self>,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let _ = shutdown;
        todo!("pgbearer-pool: PoolManager::spawn_maintenance")
    }

    /// Close all idle connections and refuse further acquisitions.
    pub async fn close(&self) {
        todo!("pgbearer-pool: PoolManager::close")
    }

    /// Pool snapshots.
    pub fn stats(&self) -> Vec<PoolStats> {
        todo!("pgbearer-pool: PoolManager::stats")
    }

    /// The configured pool settings for a backend.
    pub fn backend_config(&self, backend: &str) -> Option<&BackendConfig> {
        let _ = backend;
        todo!("pgbearer-pool: PoolManager::backend_config")
    }
}

/// Default for jitter calculations.
pub const LIFETIME_JITTER: f64 = 0.10;

/// Compute a jittered lifetime in `[d * (1 - j), d * (1 + j)]`.
pub fn jittered(d: Duration, jitter: f64) -> Duration {
    let factor = 1.0 + (rand::random::<f64>() * 2.0 - 1.0) * jitter;
    d.mul_f64(factor.max(0.0))
}
