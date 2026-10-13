//! Proxy-generated cancel keys and lease ownership (ARCHITECTURE.md §11,
//! ADR-005).
//!
//! **Keys.** Each client session gets a key unrelated to any backend key:
//! `process_id = (replica_tag & 0x7FF) << 20 | session_seq` (11-bit tag,
//! 20-bit sequence, top bit clear so the pid is positive as an `i32`) and a
//! CSPRNG secret (4 bytes for protocol 3.0, 32 bytes for 3.2). Sequence
//! numbers wrap; a number still used by a live session is skipped. If all
//! 2^20 numbers are in use, [`CancelRegistry::register`] fails.
//!
//! **Ownership, not timing.** The registry maps a key to the session's
//! *current lease*: the backend connection attached right now, if any. A
//! session calls [`CancelRegistration::attach`] when it attaches a backend and
//! [`CancelRegistration::detach`] before it releases it.
//!
//! [`CancelRegistry::cancel`] does, in one critical section per session
//! (never a global lock held across the lookup and the state change):
//!
//! 1. find the slot by `process_id`; compare the secret in constant time
//!    (length mismatch = no match) → [`CancelOutcome::UnknownKey`] if absent
//!    or wrong;
//! 2. no lease attached → [`CancelOutcome::NoBackend`];
//! 3. a cancel for this lease already in flight → [`CancelOutcome::Coalesced`];
//! 4. otherwise mark the lease **poisoned** and in flight, and clone its
//!    sender.
//!
//! Then, outside the lock, it dispatches with [`CancelSender::send`] and
//! clears the in-flight flag: [`CancelOutcome::Dispatched`] or
//! [`CancelOutcome::Failed`]. "Dispatched" never means the query was
//! cancelled: PostgreSQL gives no acknowledgement.
//!
//! [`CancelRegistration::detach`] returns whether the lease was poisoned; a
//! poisoned backend connection must be discarded, never reused, because a
//! delayed cancel could otherwise hit the next borrower. After `detach`, a
//! cancel cannot reach the old backend. Dropping the registration
//! unregisters the key.
//!
//! The session itself uses [`CancelRegistration::cancel_current`] to cancel
//! the running statement before a forced close (revocation, expiry hard
//! deadline, drain hard timeout); it also poisons the lease.
//!
//! Cross-replica forwarding is Phase 4; until then a key from another
//! replica is [`CancelOutcome::UnknownKey`] and is dropped silently, as
//! PostgreSQL does.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use pgbearer_core::SessionId;

/// Sends a cancel request for one backend connection. Implemented by
/// [`pgbearer_pool::CancelTarget`]; tests use their own implementations.
pub trait CancelSender: Send + Sync {
    /// Send the backend `CancelRequest` (new connection, same TLS mode as the
    /// session, real backend key). Resolves when the server closed the cancel
    /// connection or after a timeout.
    fn send(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

impl CancelSender for pgbearer_pool::CancelTarget {
    fn send(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            pgbearer_pool::CancelTarget::send(self)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// A key handed to a client in `BackendKeyData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCancelKey {
    /// Process id field.
    pub process_id: u32,
    /// Secret key field.
    pub secret_key: Bytes,
}

/// Outcome of a client cancel request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Sent to the backend (no acknowledgement exists).
    Dispatched,
    /// A cancel for the same lease was already in flight; nothing sent.
    Coalesced,
    /// The session exists but has no backend attached.
    NoBackend,
    /// No session has this key (or the secret is wrong).
    UnknownKey,
    /// Sending to the backend failed.
    Failed,
}

impl CancelOutcome {
    /// Metric/audit label.
    pub fn as_str(self) -> &'static str {
        match self {
            CancelOutcome::Dispatched => "dispatched",
            CancelOutcome::Coalesced => "coalesced",
            CancelOutcome::NoBackend => "no_backend",
            CancelOutcome::UnknownKey => "unknown_key",
            CancelOutcome::Failed => "failed",
        }
    }
}

/// Result of [`CancelRegistration::detach`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachOutcome {
    /// A cancel was sent (or was being sent) to this lease's backend; the
    /// connection must be discarded.
    pub poisoned: bool,
}

/// Errors from [`CancelRegistry::register`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// All 2^20 sequence numbers are in use.
    #[error("too many sessions on this replica to issue a cancel key")]
    Exhausted,
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

    /// The session id this key belongs to.
    pub fn session_id(&self) -> &SessionId {
        todo!("pgbearer-session: CancelRegistration::session_id")
    }

    /// Attach a lease. Replaces any previous lease (callers detach first).
    pub fn attach(&self, lease_id: u64, sender: Arc<dyn CancelSender>) {
        let _ = (lease_id, sender);
        todo!("pgbearer-session: CancelRegistration::attach")
    }

    /// Detach the current lease (no-op if none) and report whether it was
    /// poisoned.
    pub fn detach(&self) -> DetachOutcome {
        todo!("pgbearer-session: CancelRegistration::detach")
    }

    /// True if the current lease is poisoned.
    pub fn poisoned(&self) -> bool {
        todo!("pgbearer-session: CancelRegistration::poisoned")
    }

    /// Cancel the current lease's running statement on the session's own
    /// behalf (poisons the lease; coalesces like a client cancel).
    pub async fn cancel_current(&self) -> CancelOutcome {
        todo!("pgbearer-session: CancelRegistration::cancel_current")
    }
}

/// Registry of active sessions' cancel keys.
pub struct CancelRegistry {
    _private: (),
}

impl CancelRegistry {
    /// Create a registry. Only the low 11 bits of `replica_tag` are used.
    pub fn new(replica_tag: u16) -> CancelRegistry {
        let _ = replica_tag;
        todo!("pgbearer-session: CancelRegistry::new")
    }

    /// Register a session; `long_key` selects a 32-byte secret (protocol 3.2).
    pub fn register(
        self: &Arc<Self>,
        session_id: SessionId,
        long_key: bool,
    ) -> Result<CancelRegistration, RegisterError> {
        let _ = (session_id, long_key);
        todo!("pgbearer-session: CancelRegistry::register")
    }

    /// Handle a client `CancelRequest` (see the module documentation).
    /// Returns the outcome and, when the key matched, the session id.
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
