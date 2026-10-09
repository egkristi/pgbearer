//! Proxy-generated cancel keys and cancel forwarding (ARCHITECTURE.md §11).
//!
//! Each client session gets a key that is unrelated to the backend's real
//! key: `process_id` = `replica_tag (12 bits) << 20 | session_seq (20 bits)`
//! and a CSPRNG secret (4 bytes for protocol 3.0, 32 bytes for 3.2). The
//! registry maps the key to the session's *currently attached* backend
//! cancel target. Lookups compare secrets in constant time. Cross-replica
//! forwarding (peer port) is not implemented yet: unknown keys are dropped
//! silently, as PostgreSQL does.

use bytes::Bytes;
use pgbearer_core::SessionId;
use pgbearer_pool::CancelTarget;

/// A key handed to a client in `BackendKeyData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCancelKey {
    /// Process id field.
    pub process_id: u32,
    /// Secret key field.
    pub secret_key: Bytes,
}

/// Outcome of a cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Forwarded to the backend.
    Forwarded,
    /// No session has this key.
    Unknown,
    /// The session exists but has no backend attached.
    NoBackend,
    /// Forwarding failed.
    Error,
}

impl CancelOutcome {
    /// Metric/audit label.
    pub fn as_str(self) -> &'static str {
        match self {
            CancelOutcome::Forwarded => "forwarded",
            CancelOutcome::Unknown => "unknown",
            CancelOutcome::NoBackend => "no_backend",
            CancelOutcome::Error => "error",
        }
    }
}

/// Handle owned by a session; unregisters the key on drop.
pub struct CancelRegistration {
    _private: (),
}

impl CancelRegistration {
    /// The key to send to the client.
    pub fn key(&self) -> &ProxyCancelKey {
        todo!("pgbearer-session: CancelRegistration::key")
    }

    /// Set (or clear) the backend currently attached to this session.
    pub fn set_target(&self, target: Option<CancelTarget>) {
        let _ = target;
        todo!("pgbearer-session: CancelRegistration::set_target")
    }

    /// True while a forwarded cancel for this session is in flight; the
    /// session should delay releasing its backend until it clears (bounded
    /// wait, 200 ms) so a late cancel cannot hit the next user of that connection.
    pub fn cancel_in_flight(&self) -> bool {
        todo!("pgbearer-session: CancelRegistration::cancel_in_flight")
    }
}

/// Registry of active sessions' cancel keys.
pub struct CancelRegistry {
    _private: (),
}

impl CancelRegistry {
    /// Create a registry. `replica_tag` (12 bits) is derived from the pod name by the caller.
    pub fn new(replica_tag: u16) -> CancelRegistry {
        let _ = replica_tag;
        todo!("pgbearer-session: CancelRegistry::new")
    }

    /// Register a session; `long_key` selects a 32-byte secret (protocol 3.2).
    pub fn register(
        self: &std::sync::Arc<Self>,
        session_id: SessionId,
        long_key: bool,
    ) -> CancelRegistration {
        let _ = (session_id, long_key);
        todo!("pgbearer-session: CancelRegistry::register")
    }

    /// Handle a client `CancelRequest`: look up the key and forward to the
    /// attached backend. Returns the outcome and the session id if found.
    pub async fn cancel(
        &self,
        process_id: u32,
        secret_key: &[u8],
    ) -> (CancelOutcome, Option<SessionId>) {
        let _ = (process_id, secret_key);
        todo!("pgbearer-session: CancelRegistry::cancel")
    }

    /// Number of registered sessions.
    pub fn len(&self) -> usize {
        todo!("pgbearer-session: CancelRegistry::len")
    }

    /// True if no sessions are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
