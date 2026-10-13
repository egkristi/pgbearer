//! Protocol state tracked by the relay to decide safe points and reuse
//! (ARCHITECTURE.md §7.3, ADR-017).
//!
//! A `ReadyForQuery 'I'` alone does not mean a connection is idle: with
//! pipelining, later Queries, an open extended batch or a partly forwarded
//! frame can still be in flight. [`RelayState`] tracks what the relay has
//! forwarded and derives three predicates from it.
//!
//! **Update rule.** The relay calls [`RelayState::frontend_frame`] after a
//! client frame has been *completely* written to the backend, and
//! [`RelayState::backend_frame`] after a backend frame has been completely
//! written to the client. While a frame is only partly forwarded, the relay
//! marks the direction with [`RelayState::set_partial`].
//!
//! The state keeps an ordered queue of the `ReadyForQuery` messages the
//! backend still owes, one entry per forwarded `Query`, `FunctionCall` or
//! `Sync` (run-length encoded; `expected_rfq` is its length).
//!
//! **Frontend frames** (by type byte):
//!
//! | Tag | Message | Effect |
//! |---|---|---|
//! | `Q` | Query | push `Q`; if `ext_open` → `mixed`; if `copy_in` → `uncertain` |
//! | `F` | FunctionCall | push `F`; if `ext_open` → `mixed`; if `copy_in` → `uncertain` |
//! | `S` | Sync | if `copy_in`: nothing (the backend ignores a Sync during copy-in); else push `S` and `ext_open = false` |
//! | `P` `B` `D` `E` `C` `H` | Parse, Bind, Describe, Execute, Close, Flush | `ext_open = true` |
//! | `d` `c` `f` | CopyData, CopyDone, CopyFail | `c`/`f` set `copy_in = false`; otherwise no effect |
//! | `X` | Terminate | never forwarded (the session intercepts it); no effect |
//! | `p` | password / SASL | `protocol_error` (not valid after authentication) |
//! | anything else | — | `protocol_error` |
//!
//! **Backend frames:**
//!
//! | Tag | Message | Effect |
//! |---|---|---|
//! | `Z` | ReadyForQuery | `tx_status` = body byte; pop the front entry, or `protocol_error` if the queue is empty |
//! | `G` | CopyInResponse | `copy_in = true`; then fix up the queue (below) |
//! | `H` | CopyOutResponse | `copy_out = true` |
//! | `W` | CopyBothResponse | `uncertain` (replication protocol; never expected) |
//! | `c` | CopyDone | `copy_out = false` |
//! | `E` | ErrorResponse | `copy_in = false`, `copy_out = false`; if severity is `FATAL` or `PANIC` → `fatal` |
//! | `R` `K` `v` | Authentication, BackendKeyData, NegotiateProtocolVersion | `protocol_error` (only valid during startup) |
//! | others | DataRow, CommandComplete, notices, notifications, ParameterStatus, … | no effect |
//!
//! **COPY FROM STDIN fix-up.** Every `Sync` the client sent before it saw
//! `CopyInResponse` reached the backend during copy-in and is *ignored* (no
//! `ReadyForQuery` will answer it). So on `G`:
//!
//! * empty queue → `protocol_error`;
//! * front entry is `S` (the COPY came from an extended batch): remove every
//!   `S` entry, and set `ext_open = true` (the backend now waits for a new
//!   Sync after CopyDone/CopyFail);
//! * front entry is `Q` or `F` (a simple-query COPY): remove every `S` entry
//!   behind it;
//! * if any `Q` or `F` entry remains behind the front → `uncertain` (a Query
//!   that arrives during copy-in is an error whose effects are hard to
//!   predict).
//!
//! **Sync during copy-in.** A `Sync` forwarded while `copy_in` is set is
//! ignored only if the backend is still in copy-in when it reads it. If the
//! COPY ends on the backend's side first (bad data, a timeout, a cancel), the
//! backend reads that Sync in normal mode and answers it, and the relay cannot
//! tell the two cases apart. So once such a Sync was forwarded, the COPY's
//! outcome decides: a backend `CommandComplete` (the COPY succeeded, so every
//! such Sync was read during copy-in) closes the window; an `ErrorResponse`
//! sets `uncertain`. Without a Sync during copy-in nothing changes.
//!
//! With these rules the count is exact for well-behaved clients. Where it
//! cannot be exact (`mixed`: a Query or FunctionCall inside an open extended
//! batch, which the backend may discard after an error; `uncertain`), it can
//! only be *too high*, which is safe: such a session never reaches a safe
//! point again (soft actions wait; hard deadlines still apply), and its
//! connection is never reused. The count must never be too low while the
//! backend still owes a `ReadyForQuery`.
//!
//! **Predicates:**
//!
//! * [`quiescent`](RelayState::quiescent): `expected_rfq == 0`, not
//!   `ext_open`, not `copy_in`, not `copy_out`, no partial frame in either
//!   direction, `tx_status == I`, and none of `fatal`, `protocol_error`,
//!   `mixed`, `uncertain`.
//! * [`idle_safe_point`](RelayState::idle_safe_point): quiescent and the
//!   client reader has no buffered bytes and the backend writer is flushed.
//!   Idle timeout, drain, token expiry and revocation act here first.
//! * [`verdict`](RelayState::verdict): `Reusable` only when quiescent, no
//!   cancel was forwarded during the lease, and the backend reader is at a
//!   frame boundary with nothing buffered; otherwise `NotReusable` with the
//!   first failing reason in the order of [`NotReusable`]'s variants.
//! * [`request_in_flight`](RelayState::request_in_flight): `expected_rfq > 0`,
//!   `ext_open`, `copy_in`, a partial frame toward the backend, or `mixed` /
//!   `uncertain`. When the backend is lost or a hard deadline fires while this
//!   is true, the client gets `08007` (outcome unknown), never a retry-safe
//!   code.
//! * [`in_transaction`](RelayState::in_transaction): `tx_status` is `T` or
//!   `E` (used for `idle_in_transaction_timeout` and for the "transaction was
//!   not committed" detail).
//!
//! When `expected_rfq` reaches [`MAX_EXPECTED_RFQ`],
//! [`backpressure`](RelayState::backpressure) is true and the relay stops
//! reading from the client until responses drain.

use std::collections::VecDeque;

use pgbearer_wire::messages::{TxStatus, decode};
use pgbearer_wire::tag;

/// Upper bound on outstanding `ReadyForQuery` messages before the relay
/// applies backpressure to the client.
pub const MAX_EXPECTED_RFQ: u32 = 1_000_000;

/// A relay direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to backend.
    ToBackend,
    /// Backend to client.
    ToClient,
}

/// Why a backend connection may not be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReusable {
    /// A FATAL or PANIC error was seen.
    Fatal,
    /// A protocol violation was seen.
    ProtocolError,
    /// The `ReadyForQuery` count can no longer be trusted (`mixed` or `uncertain`).
    Uncertain,
    /// A frame was only partly forwarded.
    PartialFrame,
    /// The backend still owes responses, or an extended batch is open.
    Busy,
    /// COPY is in progress.
    Copy,
    /// A transaction is open or failed.
    InTransaction,
    /// A cancel was forwarded to this backend during the lease.
    Cancelled,
    /// The backend reader has buffered bytes or is mid-frame.
    BackendBuffered,
}

impl NotReusable {
    /// Metric/audit label.
    pub fn as_str(self) -> &'static str {
        match self {
            NotReusable::Fatal => "fatal",
            NotReusable::ProtocolError => "protocol_error",
            NotReusable::Uncertain => "uncertain",
            NotReusable::PartialFrame => "partial_frame",
            NotReusable::Busy => "busy",
            NotReusable::Copy => "copy",
            NotReusable::InTransaction => "in_transaction",
            NotReusable::Cancelled => "cancelled",
            NotReusable::BackendBuffered => "backend_buffered",
        }
    }
}

/// Whether a backend connection may go back to a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseVerdict {
    /// Quiescent and clean.
    Reusable,
    /// Must be closed.
    NotReusable(NotReusable),
}


/// What an outstanding `ReadyForQuery` will answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owed {
    /// A forwarded `Query`.
    Query,
    /// A forwarded `FunctionCall`.
    FunctionCall,
    /// A forwarded `Sync`.
    Sync,
}

/// The ordered, run-length encoded queue of `ReadyForQuery` messages the
/// backend still owes.
#[derive(Debug, Clone, Default)]
struct OwedQueue {
    /// `(kind, count)` runs, oldest first. Adjacent runs never share a kind,
    /// and no run is empty.
    runs: VecDeque<(Owed, u32)>,
    /// Sum of all run counts.
    len: u32,
}

impl OwedQueue {
    fn len(&self) -> u32 {
        self.len
    }

    fn front(&self) -> Option<Owed> {
        self.runs.front().map(|&(kind, _)| kind)
    }

    /// Append one entry. Returns `false` (and changes nothing) if the count
    /// would overflow.
    fn push(&mut self, kind: Owed) -> bool {
        let Some(len) = self.len.checked_add(1) else {
            return false;
        };
        self.len = len;
        match self.runs.back_mut() {
            // A run is never longer than `len`, so this cannot overflow.
            Some((last, count)) if *last == kind => *count += 1,
            _ => self.runs.push_back((kind, 1)),
        }
        true
    }

    /// Remove the front entry.
    fn pop(&mut self) -> Option<Owed> {
        let (kind, count) = self.runs.front_mut()?;
        let kind = *kind;
        *count -= 1;
        if *count == 0 {
            self.runs.pop_front();
        }
        self.len -= 1;
        Some(kind)
    }

    /// Remove every `Sync` entry, merging the runs that become adjacent.
    fn remove_syncs(&mut self) {
        let mut kept: VecDeque<(Owed, u32)> = VecDeque::with_capacity(self.runs.len());
        let mut len = 0u32;
        for (kind, count) in self.runs.drain(..) {
            if kind == Owed::Sync {
                continue;
            }
            len += count;
            match kept.back_mut() {
                Some((last, total)) if *last == kind => *total += count,
                _ => kept.push_back((kind, count)),
            }
        }
        self.runs = kept;
        self.len = len;
    }
}

/// Relay protocol state (see the module documentation).
#[derive(Debug, Clone)]
pub struct RelayState {
    /// `ReadyForQuery` messages the backend still owes.
    owed: OwedQueue,
    /// Status of the last `ReadyForQuery`.
    tx_status: TxStatus,
    /// An extended-protocol batch was started and not yet closed by `Sync`.
    ext_open: bool,
    /// COPY FROM STDIN is in progress.
    copy_in: bool,
    /// COPY TO STDOUT is in progress.
    copy_out: bool,
    /// A `Sync` was forwarded during the current copy-in, and the COPY's
    /// outcome (`CommandComplete` or `ErrorResponse`) has not been seen yet.
    sync_during_copy_in: bool,
    /// A `Query` or `FunctionCall` was forwarded inside an open extended batch.
    mixed: bool,
    /// The count can no longer be trusted for another reason.
    uncertain: bool,
    /// A FATAL or PANIC error was forwarded.
    fatal: bool,
    /// A protocol violation was seen.
    protocol_error: bool,
    /// A cancel request was forwarded during this lease.
    cancel_forwarded: bool,
    /// A client frame is only partly forwarded to the backend.
    partial_to_backend: bool,
    /// A backend frame is only partly forwarded to the client.
    partial_to_client: bool,
}

impl Default for RelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayState {
    /// State right after attach: `ReadyForQuery 'I'` was sent to the client,
    /// nothing is in flight.
    pub fn new() -> RelayState {
        RelayState {
            owed: OwedQueue::default(),
            tx_status: TxStatus::Idle,
            ext_open: false,
            copy_in: false,
            copy_out: false,
            sync_during_copy_in: false,
            mixed: false,
            uncertain: false,
            fatal: false,
            protocol_error: false,
            cancel_forwarded: false,
            partial_to_backend: false,
            partial_to_client: false,
        }
    }

    /// A client frame with this type byte was completely forwarded.
    pub fn frontend_frame(&mut self, tag: u8) {
        match tag {
            tag::QUERY => self.simple_command(Owed::Query),
            tag::FUNCTION_CALL => self.simple_command(Owed::FunctionCall),
            tag::SYNC => {
                if self.copy_in {
                    // Ignored by a backend in copy-in; see "Sync during copy-in".
                    self.sync_during_copy_in = true;
                } else {
                    self.push(Owed::Sync);
                    self.ext_open = false;
                }
            }
            tag::PARSE | tag::BIND | tag::DESCRIBE | tag::EXECUTE | tag::CLOSE | tag::FLUSH => {
                self.ext_open = true;
            }
            tag::COPY_DONE | tag::COPY_FAIL => self.copy_in = false,
            tag::COPY_DATA | tag::TERMINATE => {}
            // `PASSWORD` (not valid after authentication) and unknown tags.
            _ => self.protocol_error = true,
        }
    }

    /// A backend frame was completely forwarded. `body` is required for `Z`
    /// (status byte) and `E` (to find the severity); it may be `None` for
    /// other tags. A missing or malformed body where one is required →
    /// `protocol_error`.
    pub fn backend_frame(&mut self, tag: u8, body: Option<&[u8]>) {
        match tag {
            tag::READY_FOR_QUERY => {
                match body.map(decode::ready_for_query) {
                    Some(Ok(status)) => self.tx_status = status,
                    // The frame still answers a request: count it below,
                    // but keep the last known status.
                    _ => self.protocol_error = true,
                }
                if self.owed.pop().is_none() {
                    self.protocol_error = true;
                }
            }
            tag::COPY_IN_RESPONSE => self.copy_in_response(),
            tag::COPY_OUT_RESPONSE => self.copy_out = true,
            tag::COPY_BOTH_RESPONSE => self.uncertain = true,
            tag::COPY_DONE => self.copy_out = false,
            tag::COMMAND_COMPLETE => {
                // Only a COPY's own CommandComplete can follow a Sync that was
                // forwarded during its copy-in: that COPY succeeded.
                self.sync_during_copy_in = false;
            }
            tag::ERROR_RESPONSE => {
                self.copy_in = false;
                self.copy_out = false;
                if std::mem::take(&mut self.sync_during_copy_in) {
                    self.uncertain = true;
                }
                match body.map(decode::error_fields) {
                    Some(Ok(fields)) => {
                        if fields.is_fatal() {
                            self.fatal = true;
                        }
                    }
                    _ => self.protocol_error = true,
                }
            }
            tag::AUTHENTICATION | tag::BACKEND_KEY_DATA | tag::NEGOTIATE_PROTOCOL_VERSION => {
                self.protocol_error = true;
            }
            _ => {}
        }
    }

    /// Mark (or clear) a partly forwarded frame in one direction.
    pub fn set_partial(&mut self, direction: Direction, partial: bool) {
        match direction {
            Direction::ToBackend => self.partial_to_backend = partial,
            Direction::ToClient => self.partial_to_client = partial,
        }
    }

    /// A cancel request was forwarded to the backend during this lease.
    pub fn note_cancel_forwarded(&mut self) {
        self.cancel_forwarded = true;
    }

    /// The relay detected a protocol problem of its own (for example an
    /// oversized message it could not inspect).
    pub fn note_protocol_error(&mut self) {
        self.protocol_error = true;
    }

    /// Last `ReadyForQuery` status.
    pub fn tx_status(&self) -> TxStatus {
        self.tx_status
    }

    /// Outstanding `ReadyForQuery` count.
    pub fn expected_rfq(&self) -> u32 {
        self.owed.len()
    }

    /// True when the relay should stop reading from the client.
    pub fn backpressure(&self) -> bool {
        self.owed.len() >= MAX_EXPECTED_RFQ
    }

    /// See the module documentation.
    pub fn quiescent(&self) -> bool {
        self.blocker().is_none()
    }

    /// See the module documentation.
    pub fn idle_safe_point(&self, client_buffered: usize, backend_writer_flushed: bool) -> bool {
        self.quiescent() && client_buffered == 0 && backend_writer_flushed
    }

    /// See the module documentation.
    pub fn verdict(&self, backend_buffered: usize) -> ReleaseVerdict {
        let reason = self.blocker().or(if self.cancel_forwarded {
            Some(NotReusable::Cancelled)
        } else if backend_buffered > 0 {
            Some(NotReusable::BackendBuffered)
        } else {
            None
        });
        match reason {
            Some(reason) => ReleaseVerdict::NotReusable(reason),
            None => ReleaseVerdict::Reusable,
        }
    }

    /// See the module documentation.
    pub fn request_in_flight(&self) -> bool {
        self.owed.len() > 0
            || self.ext_open
            || self.copy_in
            || self.partial_to_backend
            || self.mixed
            || self.uncertain
    }

    /// See the module documentation.
    pub fn in_transaction(&self) -> bool {
        matches!(self.tx_status, TxStatus::InTransaction | TxStatus::Failed)
    }

    /// True once a FATAL/PANIC error was forwarded.
    pub fn fatal(&self) -> bool {
        self.fatal
    }

    /// The first reason (in the order of [`NotReusable`]'s variants) why the
    /// state is not quiescent, or `None` when it is.
    fn blocker(&self) -> Option<NotReusable> {
        if self.fatal {
            Some(NotReusable::Fatal)
        } else if self.protocol_error {
            Some(NotReusable::ProtocolError)
        } else if self.mixed || self.uncertain {
            Some(NotReusable::Uncertain)
        } else if self.partial_to_backend || self.partial_to_client {
            Some(NotReusable::PartialFrame)
        } else if self.owed.len() > 0 || self.ext_open {
            Some(NotReusable::Busy)
        } else if self.copy_in || self.copy_out {
            Some(NotReusable::Copy)
        } else if self.tx_status != TxStatus::Idle {
            Some(NotReusable::InTransaction)
        } else {
            None
        }
    }

    /// A forwarded `Query` or `FunctionCall`.
    fn simple_command(&mut self, kind: Owed) {
        self.push(kind);
        if self.ext_open {
            self.mixed = true;
        }
        if self.copy_in {
            self.uncertain = true;
        }
    }

    fn push(&mut self, kind: Owed) {
        if !self.owed.push(kind) {
            // Unreachable while backpressure works; an entry that cannot be
            // counted must never let the state look idle.
            self.protocol_error = true;
        }
    }

    /// `CopyInResponse`: enter copy-in and drop the Syncs the backend ignores
    /// (see "COPY FROM STDIN fix-up").
    fn copy_in_response(&mut self) {
        self.copy_in = true;
        let Some(front) = self.owed.front() else {
            self.protocol_error = true;
            return;
        };
        self.owed.remove_syncs();
        let behind = match front {
            Owed::Sync => {
                self.ext_open = true;
                self.owed.len()
            }
            Owed::Query | Owed::FunctionCall => self.owed.len() - 1,
        };
        if behind > 0 {
            self.uncertain = true;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;
