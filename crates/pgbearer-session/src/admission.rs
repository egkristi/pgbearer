//! Connection admission control (ARCHITECTURE.md §10.3, §17.1). Every limit
//! is **per replica**.
//!
//! * [`Admission::admit_connection`]: called right after TCP accept (after a
//!   trusted PROXY header, if any, so the real client IP is used). Refuses
//!   when `max_client_connections` connections are open
//!   ([`AdmissionError::ClientConnections`]) or when the client IP is locked
//!   out after too many authentication failures
//!   ([`AdmissionError::AuthFailures`]). The returned [`ConnectionPermit`]
//!   frees the slot on drop.
//! * [`ConnectionPermit::begin_auth`]: at most `max_pending_auth`
//!   connections may be between accept and the end of authentication
//!   ([`AdmissionError::PendingAuth`]). The [`PendingAuthPermit`] frees its
//!   slot on drop (when authentication finished, either way).
//! * [`Admission::record_auth_failure`]: counts authentication failures per
//!   client IP in a sliding one-minute window. When a count exceeds
//!   `auth_failures_per_ip_per_minute`, new connections from that IP are
//!   refused until the window has moved on. Memory is bounded: at most
//!   [`MAX_TRACKED_IPS`] addresses; when full, the address with the oldest
//!   last failure is evicted. A limit of 0 disables lockout.
//! * [`Admission::admit_session`]: per-identity session limits from the
//!   policy decision (`max_sessions_per_identity_per_replica` of every
//!   contributing grant). Counts are keyed by (provider, subject, grant). All
//!   limits are checked and taken atomically: either every count is
//!   incremented or none is ([`AdmissionError::IdentitySessions`] names the
//!   first grant whose limit is reached). The [`SessionPermit`] decrements
//!   every count on drop. Entries whose count drops to zero are removed.
//! * [`Admission::update_limits`]: applies new limits on reload. Lowering a
//!   limit never closes existing connections or sessions; it only refuses new
//!   ones until counts fall below it.
//!
//! All operations are synchronous, never block, and are safe to call from
//! many tasks concurrently.

use std::net::IpAddr;
use std::sync::Arc;

use pgbearer_config::LimitsConfig;
use pgbearer_core::{ClientError, sqlstate};
use pgbearer_policy::SessionLimit;

/// Maximum number of client IPs tracked for authentication failures.
pub const MAX_TRACKED_IPS: usize = 100_000;

/// Why a connection or session was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// `max_client_connections` reached.
    #[error("too many client connections on this gateway instance")]
    ClientConnections,
    /// `max_pending_auth` reached.
    #[error("too many connections waiting for authentication")]
    PendingAuth,
    /// The client IP is locked out after authentication failures.
    #[error("too many authentication failures from this address")]
    AuthFailures,
    /// A per-identity session limit is reached.
    #[error("too many sessions for this identity under grant {grant:?} on this gateway instance")]
    IdentitySessions {
        /// The grant whose limit is reached.
        grant: String,
    },
}

impl AdmissionError {
    /// The client-facing error: always `53300` with a short message (the
    /// grant name is not revealed).
    pub fn to_client_error(&self) -> ClientError {
        let _ = sqlstate::TOO_MANY_CONNECTIONS;
        todo!("pgbearer-session: AdmissionError::to_client_error")
    }

    /// Metric/audit reason (`client_connections_per_replica`,
    /// `pending_auth`, `auth_failures_per_ip`,
    /// `identity_sessions_per_replica`).
    pub fn reason(&self) -> &'static str {
        match self {
            AdmissionError::ClientConnections => "client_connections_per_replica",
            AdmissionError::PendingAuth => "pending_auth",
            AdmissionError::AuthFailures => "auth_failures_per_ip",
            AdmissionError::IdentitySessions { .. } => "identity_sessions_per_replica",
        }
    }
}

/// Counts of admitted connections and sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdmissionStats {
    /// Open client connections.
    pub client_connections: usize,
    /// Connections still authenticating.
    pub pending_auth: usize,
    /// Distinct (provider, subject, grant) keys with sessions.
    pub identity_keys: usize,
    /// Client IPs with recorded authentication failures.
    pub tracked_ips: usize,
}

/// Admission state shared by all sessions.
pub struct Admission {
    _private: (),
}

/// A client connection slot; freed on drop.
pub struct ConnectionPermit {
    _private: (),
}

/// A pending-authentication slot; freed on drop.
pub struct PendingAuthPermit {
    _private: (),
}

/// Per-identity session counts; decremented on drop.
pub struct SessionPermit {
    _private: (),
}

impl Admission {
    /// Create from limits.
    pub fn new(limits: &LimitsConfig) -> Arc<Admission> {
        let _ = limits;
        todo!("pgbearer-session: Admission::new")
    }

    /// Apply new limits (reload).
    pub fn update_limits(&self, limits: &LimitsConfig) {
        let _ = limits;
        todo!("pgbearer-session: Admission::update_limits")
    }

    /// Admit a new client connection from `ip`.
    pub fn admit_connection(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> Result<ConnectionPermit, AdmissionError> {
        let _ = ip;
        todo!("pgbearer-session: Admission::admit_connection")
    }

    /// Record an authentication failure from `ip`.
    pub fn record_auth_failure(&self, ip: IpAddr) {
        let _ = ip;
        todo!("pgbearer-session: Admission::record_auth_failure")
    }

    /// Admit a session for an identity under the given limits.
    pub fn admit_session(
        self: &Arc<Self>,
        provider: &str,
        subject: &str,
        limits: &[SessionLimit],
    ) -> Result<SessionPermit, AdmissionError> {
        let _ = (provider, subject, limits);
        todo!("pgbearer-session: Admission::admit_session")
    }

    /// Current counts.
    pub fn stats(&self) -> AdmissionStats {
        todo!("pgbearer-session: Admission::stats")
    }
}

impl ConnectionPermit {
    /// Take a pending-authentication slot.
    pub fn begin_auth(&self) -> Result<PendingAuthPermit, AdmissionError> {
        todo!("pgbearer-session: ConnectionPermit::begin_auth")
    }
}
