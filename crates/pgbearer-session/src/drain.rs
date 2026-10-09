//! Graceful drain (ARCHITECTURE.md §4.3).
//!
//! The binary calls [`DrainController::start_drain`] on SIGTERM. Sessions
//! watch the state: in `Draining`, a session-mode session is terminated at
//! its next idle point once `session_deadline` has passed (immediately at idle
//! for transaction mode), and unconditionally at `hard_deadline`.

use std::time::Instant;

use tokio::sync::watch;

/// Drain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainState {
    /// Normal operation.
    Running,
    /// Shutting down.
    Draining {
        /// After this, idle sessions are terminated.
        session_deadline: Instant,
        /// After this, all sessions are terminated.
        hard_deadline: Instant,
    },
}

/// Shared drain state (cheap to clone).
#[derive(Debug, Clone)]
pub struct DrainController {
    tx: watch::Sender<DrainState>,
}

impl DrainController {
    /// Create in `Running` state.
    pub fn new() -> DrainController {
        let (tx, _rx) = watch::channel(DrainState::Running);
        DrainController { tx }
    }

    /// Switch to draining.
    pub fn start_drain(&self, session_deadline: Instant, hard_deadline: Instant) {
        self.tx.send_replace(DrainState::Draining {
            session_deadline,
            hard_deadline,
        });
    }

    /// Current state.
    pub fn state(&self) -> DrainState {
        *self.tx.borrow()
    }

    /// True while draining.
    pub fn is_draining(&self) -> bool {
        matches!(self.state(), DrainState::Draining { .. })
    }

    /// Subscribe to state changes.
    pub fn subscribe(&self) -> watch::Receiver<DrainState> {
        self.tx.subscribe()
    }
}

impl Default for DrainController {
    fn default() -> Self {
        Self::new()
    }
}
