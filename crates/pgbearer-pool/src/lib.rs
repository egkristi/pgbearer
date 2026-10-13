//! Backend connections and the connection pool (ARCHITECTURE.md §10, §11).
//!
//! This release implements the **identity pilot** behaviour: every client
//! session gets its own backend connection (`pool.reuse: none`), and the
//! pool is a fair, bounded connection limiter. Reuse arrives in Phase 3a.
//!
//! # Connecting ([`BackendConnection::connect`])
//!
//! 1. **TCP.** Resolve `host:port` from the backend config (DNS on every
//!    connect) and try the addresses in order until one connects. Set
//!    `TCP_NODELAY`, and when `backends[].keepalive.enabled`, `SO_KEEPALIVE`
//!    with `idle`/`interval`/`count` and (Linux) `TCP_USER_TIMEOUT`.
//! 2. **TLS** (mode ≠ `disable`): write `SSLRequest`, then read **exactly one
//!    byte** from the raw socket. `'S'`: if any further byte is already
//!    readable (`try_read` returns data) → [`BackendError::Protocol`] (the
//!    server, or an attacker on the path, injected plaintext before the TLS
//!    handshake; CVE-2021-23222 class); otherwise run the handshake with
//!    [`BackendTls::connector`] (presenting the role's client certificate for
//!    a `Cert` credential). `'N'` → [`BackendError::Tls`] ("server does not
//!    support TLS"). Anything else → [`BackendError::Protocol`]. The stream is
//!    never wrapped in a buffered reader before the handshake.
//! 3. **StartupMessage**, protocol 3.0: `user` = role, `database`, then
//!    `ConnectParams::parameters` in order, encoded with
//!    [`pgbearer_wire::startup::encode_startup_message`] (which rejects NUL
//!    bytes and packets over 10 000 bytes → [`BackendError::StartupTooLarge`]
//!    or [`BackendError::Protocol`]).
//! 4. **Authentication**:
//!    * `AuthenticationOk` (certificate or trust);
//!    * SASL: `SCRAM-SHA-256-PLUS` when offered and TLS is used (channel
//!      binding `tls-server-end-point`, from the server certificate), else
//!      `SCRAM-SHA-256` (`postgres_protocol::authentication::sasl`); the
//!      server's final signature is verified;
//!    * `AuthenticationMD5Password` and `AuthenticationCleartextPassword`
//!      only over TLS;
//!    * anything else, or a password method with a `Cert` credential →
//!      [`BackendError::Auth`].
//!
//!    Password files are read on every connect (rotation) and the bytes are
//!    zeroized after use.
//! 5. Collect `ParameterStatus` and `BackendKeyData` until `ReadyForQuery`.
//!    `NoticeResponse` is ignored. An `ErrorResponse` at any point →
//!    [`BackendError::Server`].
//!
//! Steps 1–5 together must finish within `pool.connect_timeout`, else
//! [`BackendError::Timeout`].
//!
//! # Inspection ([`BackendConnection::inspect`])
//!
//! Runs [`INSPECT_QUERY`] (one simple-query message) on every new
//! connection. Because the client's startup settings (including
//! `search_path` and `statement_timeout`) apply to it, the query is fully
//! schema-qualified, sets `search_path` and `statement_timeout` with
//! `SET LOCAL` inside its own transaction, and interpolates no values. It
//! returns:
//!
//! * the roles reachable from `current_user` through SET, INHERIT and ADMIN
//!   membership edges (PostgreSQL 16+ semantics), each with its attributes,
//!   classified into [`RoleRisk`]s by [`classify_risks`];
//! * `pg_backend_pid()`, `inet_server_addr()`/`inet_server_port()`
//!   (the physical endpoint), `pg_is_in_recovery()`,
//!   `server_version_num`, and the database session id (`%c` format:
//!   hex `backend_start` epoch, `.`, hex pid).
//!
//! An error caused by the client's startup settings (for example a broken
//! `default_transaction_isolation`) surfaces as [`BackendError::Server`]
//! and is classified like any other server error.
//!
//! # The pool ([`PoolManager`])
//!
//! [`PoolManager::acquire`]:
//!
//! 1. Refuse when closed ([`PoolError::Closed`]), for an unknown backend
//!    ([`PoolError::UnknownBackend`]) or a role without credential
//!    ([`PoolError::NoCredential`]).
//! 2. Wait **in FIFO order** for one slot of the backend
//!    (`max_backend_connections`) and one of the `(backend, database, role)`
//!    pool (`pool.max_connections`), and for any connect backoff of the
//!    backend to end — all within `pool.acquire_timeout`, else
//!    [`PoolError::Timeout`].
//! 3. Connect. On failure: if the error is **client-caused**
//!    ([`BackendError::is_client_caused`]: SQLSTATE `22023`, `42704`, `42501`,
//!    `3D000`, `22P02`), return it without touching the backoff; otherwise
//!    record a failure: after a failure the backend backs off exponentially
//!    (100 ms doubling to 5 s, ±20 % jitter) for *new* connects; a success
//!    resets it.
//! 4. Inspect. Then **target suitability** for CNPG backends: service `rw`
//!    requires `in_recovery = false`, `ro` requires `true` (`r`: any). A
//!    mismatch closes the connection, records a backoff failure with reason
//!    `wrong_role`, and retries (steps 2–4) until `acquire_timeout`.
//! 5. **Role risks**: every risk in the inspection result that
//!    [`RoleRisk::blocks_by_default`] and that the request does not
//!    acknowledge → [`PoolError::RoleRisk`] (the connection is closed).
//!    Non-blocking unacknowledged risks are allowed and reported in
//!    [`Lease::unacknowledged_risks`] (the session logs and audits them).
//! 6. Build the [`CancelTarget`]: the physical endpoint is the discovered
//!    `inet_server_addr()`/`inet_server_port()` when
//!    `backends[].cancel_endpoint` is `discovered` (default for `cnpg`), the
//!    discovered pid equals the `BackendKeyData` pid and the address is not
//!    NULL; otherwise the address the TCP connection is connected to
//!    (`connected`, the default for `static`), counting a fallback in
//!    `pgbearer_cancel_endpoint_fallback_total{backend, reason}`.
//!
//! Every lease gets a process-unique `lease_id` and records the backend's
//! current **generation**. [`PoolManager::release`] closes the connection
//! (`Terminate`) and frees both slots — with `reuse: none` it never keeps a
//! connection; the verdict is still taken so Phase 3a needs no API change.
//! Dropping a [`Lease`] without releasing it also frees its slots (the
//! socket is closed by drop).
//!
//! [`PoolManager::retire`] bumps a backend's generation and publishes a
//! [`GenerationNotice`] to [`subscribers`](PoolManager::subscribe): sessions
//! on an older generation end according to its [`RetireMode`] (used for
//! credential compromise and, in Phase 4, CNPG failover).
//!
//! # Errors to clients ([`PoolError::to_client_error`])
//!
//! | Error | SQLSTATE | Message |
//! |---|---|---|
//! | `Timeout` | `53300` | "too many connections for this database role; try again later" |
//! | `Backend(Server)` with `53300` | `53300` | "the database has no free connection slots" |
//! | `Backend(Server)`, client-caused (`22023`, `42704`, `42501`, `3D000`, `22P02`) | the server's code | the server's message |
//! | `Backend(Server)` with class `28`, `RoleRisk`, `NoCredential`, `Backend(Auth)` | `28000` | "backend login for the mapped role failed" |
//! | `Backend(Server)` with `57P03` | `57P03` | the server's message |
//! | `UnknownBackend`, `Closed` | `57P03` | "service unavailable" |
//! | anything else | `08006` | "database unavailable" |
//!
//! The internal reason (full error) is attached for audit and logs, never
//! sent to the client.

// Some public items are still `todo!()` stubs (issue #5); remove this
// allowance in the commit that implements the crate.
#![allow(clippy::todo)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use pgbearer_config::{BackendConfig, ResolvedCredential};
use pgbearer_core::{ClientError, RoleRisk};
use pgbearer_telemetry::Metrics;
use pgbearer_tls::BackendTls;
use pgbearer_wire::messages::{ErrorFields, TxStatus};
use pgbearer_wire::{FrameReader, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, BufWriter, ReadHalf, WriteHalf};
use tokio::sync::watch;

/// The inspection query (see the crate documentation). One simple-query
/// message with two result sets: reachable roles, then connection facts.
pub const INSPECT_QUERY: &str = "\
BEGIN; \
SET LOCAL search_path TO pg_catalog, pg_temp; \
SET LOCAL statement_timeout TO '10s'; \
WITH RECURSIVE walk(roleid, can_set, can_inherit, via_admin, path) AS ( \
  SELECT r.oid, true, true, false, ARRAY[r.oid] \
  FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) current_user \
  UNION ALL \
  SELECT m.roleid, \
    (w.can_set AND m.set_option) OR ((w.can_set OR w.can_inherit) AND m.admin_option), \
    (w.can_inherit AND m.inherit_option) OR ((w.can_set OR w.can_inherit) AND m.admin_option), \
    w.via_admin OR ((w.can_set OR w.can_inherit) AND m.admin_option), \
    pg_catalog.array_append(w.path, m.roleid) \
  FROM walk w JOIN pg_catalog.pg_auth_members m ON m.member OPERATOR(pg_catalog.=) w.roleid \
  WHERE m.roleid OPERATOR(pg_catalog.<>) ALL (w.path) \
    AND pg_catalog.cardinality(w.path) OPERATOR(pg_catalog.<) 64 \
), reach AS ( \
  SELECT roleid, pg_catalog.bool_or(can_set) AS s, pg_catalog.bool_or(can_inherit) AS i, \
         pg_catalog.bool_or(via_admin) AS a \
  FROM walk GROUP BY roleid \
) \
SELECT r.rolname, x.s, x.i, x.a, r.rolsuper, r.rolcreaterole, r.rolreplication, \
       r.rolbypassrls, r.rolcreatedb, \
       EXISTS (SELECT 1 FROM pg_catalog.pg_database d WHERE d.datdba OPERATOR(pg_catalog.=) r.oid) \
FROM reach x JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) x.roleid \
WHERE x.s OR x.i OR x.a; \
SELECT pg_catalog.pg_backend_pid(), \
       pg_catalog.host(pg_catalog.inet_server_addr()), \
       pg_catalog.inet_server_port(), \
       pg_catalog.pg_is_in_recovery(), \
       pg_catalog.current_setting('server_version_num'), \
       pg_catalog.concat(pg_catalog.to_hex(pg_catalog.trunc(pg_catalog.date_part('epoch', a.backend_start))::pg_catalog.int8), \
                         '.', pg_catalog.to_hex(a.pid)) \
FROM pg_catalog.pg_stat_activity a WHERE a.pid OPERATOR(pg_catalog.=) pg_catalog.pg_backend_pid(); \
COMMIT";

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
    /// The StartupMessage would exceed PostgreSQL's 10 000-byte limit.
    #[error("startup packet too large ({0} bytes)")]
    StartupTooLarge(usize),
    /// The server sent an ErrorResponse.
    #[error("backend error {}: {}", .0.code.as_deref().unwrap_or("?"), .0.message.as_deref().unwrap_or("?"))]
    Server(Box<ErrorFields>),
    /// The operation timed out.
    #[error("backend operation timed out")]
    Timeout,
}

impl BackendError {
    /// True for server errors caused by the client's own startup settings or
    /// database name (`22023`, `42704`, `42501`, `3D000`, `22P02`): passed
    /// through to the client and never counted as a backend failure.
    pub fn is_client_caused(&self) -> bool {
        todo!("pgbearer-pool: BackendError::is_client_caused")
    }
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
    /// The role can reach privileges the grant does not acknowledge.
    #[error("role {role:?} can reach unacknowledged privileges: {}", format_risks(.risks))]
    RoleRisk {
        /// Role.
        role: String,
        /// Unacknowledged blocking risks.
        risks: BTreeSet<RoleRisk>,
    },
    /// The pool manager is shutting down.
    #[error("pool is closed")]
    Closed,
    /// Connecting to the backend failed.
    #[error(transparent)]
    Backend(Box<BackendError>),
}

impl From<BackendError> for PoolError {
    fn from(e: BackendError) -> Self {
        PoolError::Backend(Box::new(e))
    }
}

fn format_risks(risks: &BTreeSet<RoleRisk>) -> String {
    risks
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl PoolError {
    /// The error to send to the client (see the crate documentation).
    pub fn to_client_error(&self) -> ClientError {
        todo!("pgbearer-pool: PoolError::to_client_error")
    }

    /// Short metric/audit reason code.
    pub fn reason_code(&self) -> &'static str {
        todo!("pgbearer-pool: PoolError::reason_code")
    }
}

/// One role reachable from the login role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableRole {
    /// Role name.
    pub name: String,
    /// Reachable with `SET ROLE`.
    pub via_set: bool,
    /// Privileges inherited.
    pub via_inherit: bool,
    /// Reached through an ADMIN OPTION edge (can be self-granted).
    pub via_admin: bool,
    /// Risks of this role.
    pub risks: BTreeSet<RoleRisk>,
}

/// Facts about a backend connection, from [`INSPECT_QUERY`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInfo {
    /// Every reachable role (including the login role itself).
    pub reachable_roles: Vec<ReachableRole>,
    /// Union of all risks (including [`RoleRisk::AdminOption`] when any role is
    /// reached through an ADMIN edge).
    pub role_risks: BTreeSet<RoleRisk>,
    /// `pg_backend_pid()`.
    pub backend_pid: u32,
    /// `inet_server_addr()`:`inet_server_port()`, if not NULL.
    pub server_addr: Option<SocketAddr>,
    /// `pg_is_in_recovery()`.
    pub in_recovery: bool,
    /// `server_version_num`.
    pub server_version_num: u32,
    /// Database session id in `%c` format.
    pub backend_session_id: String,
}

/// One row of the first result set of [`INSPECT_QUERY`], parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRow {
    /// `rolname`.
    pub name: String,
    /// Reachable with SET.
    pub via_set: bool,
    /// Reachable with INHERIT.
    pub via_inherit: bool,
    /// Reached through ADMIN.
    pub via_admin: bool,
    /// `rolsuper`.
    pub superuser: bool,
    /// `rolcreaterole`.
    pub createrole: bool,
    /// `rolreplication`.
    pub replication: bool,
    /// `rolbypassrls`.
    pub bypassrls: bool,
    /// `rolcreatedb`.
    pub createdb: bool,
    /// Owns a database.
    pub database_owner: bool,
}

/// Classify reachable roles into risks (pure; see [`RoleRisk`] for the
/// predefined-role lists). `AdminOption` is added when any row has
/// `via_admin`.
pub fn classify_risks(rows: &[RoleRow]) -> (Vec<ReachableRole>, BTreeSet<RoleRisk>) {
    let _ = rows;
    todo!("pgbearer-pool: classify_risks")
}

/// Where and how to send a cancel request for one backend connection.
#[derive(Clone)]
pub struct CancelTarget {
    _private: (),
}

impl CancelTarget {
    /// Connect to the physical endpoint, use TLS when the session's
    /// connection did (`SSLRequest`; `'N'` is an error so the secret is never
    /// sent in clear; the certificate is verified against the backend's
    /// configured server name), write `CancelRequest` with the real key, then
    /// wait for the server to close the connection. Everything within 5 s.
    pub async fn send(&self) -> Result<(), BackendError> {
        todo!("pgbearer-pool: CancelTarget::send")
    }

    /// The physical endpoint the cancel goes to.
    pub fn endpoint(&self) -> SocketAddr {
        todo!("pgbearer-pool: CancelTarget::endpoint")
    }

    /// The backend pid (safe to log; the secret is never exposed).
    pub fn backend_pid(&self) -> u32 {
        todo!("pgbearer-pool: CancelTarget::backend_pid")
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
    /// Real backend secret key; never exposed (only via [`CancelTarget`]).
    #[allow(dead_code)] // Read by the implementation when it builds the cancel target.
    secret_key: Bytes,
}

impl BackendConnection {
    /// Connect and authenticate (see the crate documentation).
    pub async fn connect(params: &ConnectParams<'_>) -> Result<BackendConnection, BackendError> {
        let _ = params;
        todo!("pgbearer-pool: BackendConnection::connect")
    }

    /// Run [`INSPECT_QUERY`] and parse the result (see the crate documentation).
    pub async fn inspect(&mut self) -> Result<BackendInfo, BackendError> {
        todo!("pgbearer-pool: BackendConnection::inspect")
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
        let _ = (name, value);
        todo!("pgbearer-pool: BackendConnection::note_parameter_status")
    }

    /// Send `Terminate` and close (best effort, bounded by 1 s).
    pub async fn terminate(self) {
        todo!("pgbearer-pool: BackendConnection::terminate")
    }
}

/// What a session needs from the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireRequest {
    /// Backend name.
    pub backend: String,
    /// Database.
    pub database: String,
    /// Role to log in as.
    pub role: String,
    /// StartupMessage parameters after `user` and `database` (client profile
    /// plus pgbearer's own).
    pub parameters: Vec<(String, String)>,
    /// Role risks the policy decision acknowledges.
    pub acknowledged_role_risks: BTreeSet<RoleRisk>,
}

/// A backend connection leased to one session.
pub struct Lease {
    /// The backend connection.
    pub conn: BackendConnection,
    /// Inspection result.
    pub info: BackendInfo,
    /// Process-unique lease id.
    pub lease_id: u64,
    /// Backend generation at acquire time.
    pub generation: u64,
    /// True if the connection was opened for this lease (always true with `reuse: none`).
    pub fresh: bool,
    /// Non-blocking risks the request did not acknowledge (log and audit them).
    pub unacknowledged_risks: BTreeSet<RoleRisk>,
    /// Where to send cancel requests for this connection.
    pub cancel: CancelTarget,
    /// When the backend connection was opened.
    pub created_at: Instant,
    _slots: Box<dyn Send + Sync>,
}

impl Lease {
    /// Backend name.
    pub fn backend(&self) -> &str {
        todo!("pgbearer-pool: Lease::backend")
    }
}

/// How sessions on a retired generation end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireMode {
    /// At the session's next safe point, and at the latest after the deadline.
    DrainBy(Duration),
    /// At once (cancel the running statement first).
    TerminateNow,
}

/// Published when a backend's generation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationNotice {
    /// The new (current) generation.
    pub generation: u64,
    /// How sessions on older generations must end.
    pub mode: RetireMode,
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
    /// Leased connections.
    pub active: usize,
    /// Sessions waiting in `acquire`.
    pub waiting: usize,
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

    /// Lease a backend connection (see the crate documentation).
    pub async fn acquire(&self, req: &AcquireRequest) -> Result<Lease, PoolError> {
        let _ = req;
        todo!("pgbearer-pool: PoolManager::acquire")
    }

    /// Return a lease. With `reuse: none` the connection is always closed.
    /// `reusable` is the relay's verdict (ignored until Phase 3a).
    pub async fn release(&self, lease: Lease, reusable: bool) {
        let _ = (lease, reusable);
        todo!("pgbearer-pool: PoolManager::release")
    }

    /// Bump `backend`'s generation and tell subscribers how sessions on older
    /// generations end. Returns the new generation, or `None` for an unknown
    /// backend.
    pub fn retire(&self, backend: &str, mode: RetireMode) -> Option<u64> {
        let _ = (backend, mode);
        todo!("pgbearer-pool: PoolManager::retire")
    }

    /// Generation notices for `backend` (`None` for an unknown backend).
    pub fn subscribe(&self, backend: &str) -> Option<watch::Receiver<GenerationNotice>> {
        let _ = backend;
        todo!("pgbearer-pool: PoolManager::subscribe")
    }

    /// Refuse further acquisitions.
    pub fn close(&self) {
        todo!("pgbearer-pool: PoolManager::close")
    }

    /// Pool snapshots.
    pub fn stats(&self) -> Vec<PoolStats> {
        todo!("pgbearer-pool: PoolManager::stats")
    }

    /// The configuration of a backend.
    pub fn backend_config(&self, backend: &str) -> Option<&BackendConfig> {
        let _ = backend;
        todo!("pgbearer-pool: PoolManager::backend_config")
    }
}
