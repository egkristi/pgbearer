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

mod auth;
mod backoff;
mod cancel;
mod connect;
mod error;
mod inspect;
mod manager;
#[cfg(test)]
mod tests;

pub use cancel::CancelTarget;
pub use connect::{BackendAuthMethod, BackendConnection, ConnectParams, SimpleQueryResult};
pub use error::{BackendError, PoolError};
pub use inspect::{BackendInfo, ReachableRole, RoleRow, classify_risks};
pub use manager::{AcquireRequest, GenerationNotice, Lease, PoolManager, PoolStats, RetireMode};

use tokio::io::{AsyncRead, AsyncWrite};

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
