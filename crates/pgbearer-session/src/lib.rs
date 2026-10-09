//! Client session handling (ARCHITECTURE.md §6, §7, §11, §12, §4.3).
//!
//! [`serve_connection`] owns one client connection from TCP accept to close:
//!
//! 1. **PROXY v2** per listener mode (`off` / `optional` via peek / `required`).
//! 2. **Encryption negotiation**: peek the first byte; `0x16` → direct TLS
//!    (only if the listener allows it; ALPN must be `postgresql`, else close).
//!    Otherwise read startup packets with exact reads:
//!    `SSLRequest` → `'S'` and TLS handshake if TLS is configured, else `'N'`;
//!    `GSSENCRequest` → `'N'`; `CancelRequest` → [`CancelRegistry`] and close;
//!    a second `SSLRequest` after TLS is a protocol error.
//! 3. **Startup**: protocol version 3.x. For minor > 2 or any `_pq_.*` options,
//!    send `NegotiateProtocolVersion` (newest minor 2, unrecognized options)
//!    and continue with 3.2 / 3.0 as appropriate. `replication` startup
//!    parameter → FATAL `0A000`. `options` with `-c role=`,
//!    `session_authorization`, or `pgbearer.*` → FATAL `28000`.
//! 4. **Routing** with [`Router`] (listener, SNI, database). No route → FATAL `3D000`.
//! 5. **Authentication**:
//!    * `token_password`: refuse on non-TLS unless the listener allows
//!      plaintext (FATAL `28000` "TLS required"), send
//!      `AuthenticationCleartextPassword`, read `PasswordMessage` (size limit
//!      `limits.max_auth_message_bytes`), validate with
//!      [`pgbearer_auth::TokenValidator`].
//!    * `oauthbearer`: SASL exchange per [`pgbearer_auth::oauthbearer`].
//!
//!    The whole startup must finish within `session.auth_timeout`. Failures
//!    → FATAL `28P01` "authentication failed" (generic), audit `connection.denied`
//!    with the precise reason, per-IP failure rate limiting.
//! 6. **Policy** with [`pgbearer_policy::PolicyEngine`]. Deny → FATAL `28000`
//!    "access denied" (generic). Per-identity connection limit → FATAL `53300`.
//! 7. **Attach**: acquire a backend connection for `(backend, database, role)`,
//!    apply tracked client parameters with `SET` (`application_name`,
//!    `client_encoding`, `DateStyle`, `TimeZone`, `IntervalStyle`,
//!    `extra_float_digits`, `search_path`, plus `-c` entries from `options`;
//!    values are quoted as string literals, names validated as identifiers),
//!    and the propagation GUCs (`pgbearer.sub`, `pgbearer.username`,
//!    `pgbearer.session_id`) when enabled. Then send `AuthenticationOk`, one
//!    `ParameterStatus` per server parameter, `BackendKeyData` with a
//!    **proxy-generated** key (4-byte secret for 3.0, 32-byte for 3.2), and
//!    `ReadyForQuery`. Audit `connection.authenticated` and `session.attached`.
//! 8. **Relay** (session mode): full-duplex, frame-aware (two pump futures
//!    over split halves joined with `select!`), tracking `ReadyForQuery`
//!    status, `ParameterStatus` (kept in the backend's `server_params`),
//!    FATAL errors, and intercepting the client's `Terminate`. Writers are
//!    flushed whenever the corresponding reader has no buffered input.
//!    Timers: `idle_timeout`, `idle_in_transaction_timeout`, token expiry
//!    (`on_token_expiry` with `token_expiry_grace`), `max_lifetime`; drain
//!    signal. "At idle" terminations happen only when the last
//!    `ReadyForQuery` was `I` and no client message is in flight; they send
//!    FATAL (`57P01` drain, `57P05` idle, `25P03` idle in transaction,
//!    `28000` "credentials expired") then close.
//! 9. **End**: release the backend (`reusable` only if the session ended at an
//!    idle point with no protocol error and no FATAL), unregister the cancel
//!    key, audit `session.ended`, update metrics.
//!
//! Transaction pooling is not implemented yet: grants with `pool_mode:
//! transaction` run in session mode with a warning logged once.

pub mod cancel;
pub mod drain;
pub mod routing;

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use pgbearer_audit::AuditSink;
use pgbearer_auth::TokenValidator;
use pgbearer_config::{Config, LimitsConfig, ListenerConfig, PropagationConfig, SessionConfig};
use pgbearer_policy::PolicyEngine;
use pgbearer_pool::PoolManager;
use pgbearer_telemetry::Metrics;
use pgbearer_tls::ServerTls;
use tokio::net::TcpStream;

pub use cancel::CancelRegistry;
pub use drain::{DrainController, DrainState};
pub use routing::Router;

/// Hot-reloadable settings used by sessions.
#[derive(Debug, Clone)]
pub struct SessionSettings {
    /// Session lifetime settings.
    pub session: SessionConfig,
    /// Limits.
    pub limits: LimitsConfig,
    /// Identity propagation.
    pub propagation: PropagationConfig,
}

impl SessionSettings {
    /// Extract from a config.
    pub fn from_config(config: &Config) -> SessionSettings {
        SessionSettings {
            session: config.session.clone(),
            limits: config.limits.clone(),
            propagation: config.propagation.clone(),
        }
    }
}

/// A listener at runtime.
pub struct ListenerRuntime {
    /// Listener configuration.
    pub config: ListenerConfig,
    /// TLS, if configured.
    pub tls: Option<Arc<ServerTls>>,
}

/// Shared services for all sessions.
pub struct Services {
    /// Token validation.
    pub validator: Arc<TokenValidator>,
    /// Current policy (swapped on reload).
    pub policy: ArcSwap<PolicyEngine>,
    /// Current routes (swapped on reload).
    pub router: ArcSwap<Router>,
    /// Current session settings (swapped on reload).
    pub settings: ArcSwap<SessionSettings>,
    /// Backend pools.
    pub pools: Arc<PoolManager>,
    /// Cancel key registry.
    pub cancels: Arc<CancelRegistry>,
    /// Audit sink.
    pub audit: Arc<dyn AuditSink>,
    /// Metrics.
    pub metrics: Arc<Metrics>,
    /// Drain state.
    pub drain: DrainController,
    /// Connection admission limits (global, pending-auth, per-identity, per-IP failures).
    pub admission: Admission,
}

/// Connection admission control.
///
/// * at most `max_client_connections` concurrent client connections;
/// * at most `max_pending_auth` connections that have not finished authentication;
/// * per-identity session counts (keyed by `provider` + `subject` and grant) for
///   `max_connections_per_identity`;
/// * per-client-IP authentication failure counts in a sliding one-minute window
///   (`auth_failures_per_ip_per_minute`); when exceeded, new connections from
///   that IP are refused before authentication with FATAL `53300`
///   (memory bounded: at most 100 000 tracked IPs, oldest evicted).
pub struct Admission {
    _private: (),
}

impl Admission {
    /// Create from limits.
    pub fn new(limits: &LimitsConfig) -> Admission {
        let _ = limits;
        todo!("pgbearer-session: Admission::new")
    }
}

/// Serve one client connection until it closes. Never panics on client input;
/// all errors are reported to the client (when possible), logged and audited.
pub async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    listener: Arc<ListenerRuntime>,
    services: Arc<Services>,
) {
    let _ = (stream, peer, listener, services);
    todo!("pgbearer-session: serve_connection")
}
