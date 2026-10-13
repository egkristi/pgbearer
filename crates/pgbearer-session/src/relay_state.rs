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

use pgbearer_wire::messages::TxStatus;

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

/// Relay protocol state (see the module documentation).
#[derive(Debug, Clone)]
pub struct RelayState {
    _private: (),
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
        todo!("pgbearer-session: RelayState::new")
    }

    /// A client frame with this type byte was completely forwarded.
    pub fn frontend_frame(&mut self, tag: u8) {
        let _ = tag;
        todo!("pgbearer-session: RelayState::frontend_frame")
    }

    /// A backend frame was completely forwarded. `body` is required for `Z`
    /// (status byte) and `E` (to find the severity); it may be `None` for
    /// other tags. A missing or malformed body where one is required →
    /// `protocol_error`.
    pub fn backend_frame(&mut self, tag: u8, body: Option<&[u8]>) {
        let _ = (tag, body);
        todo!("pgbearer-session: RelayState::backend_frame")
    }

    /// Mark (or clear) a partly forwarded frame in one direction.
    pub fn set_partial(&mut self, direction: Direction, partial: bool) {
        let _ = (direction, partial);
        todo!("pgbearer-session: RelayState::set_partial")
    }

    /// A cancel request was forwarded to the backend during this lease.
    pub fn note_cancel_forwarded(&mut self) {
        todo!("pgbearer-session: RelayState::note_cancel_forwarded")
    }

    /// The relay detected a protocol problem of its own (for example an
    /// oversized message it could not inspect).
    pub fn note_protocol_error(&mut self) {
        todo!("pgbearer-session: RelayState::note_protocol_error")
    }

    /// Last `ReadyForQuery` status.
    pub fn tx_status(&self) -> TxStatus {
        todo!("pgbearer-session: RelayState::tx_status")
    }

    /// Outstanding `ReadyForQuery` count.
    pub fn expected_rfq(&self) -> u32 {
        todo!("pgbearer-session: RelayState::expected_rfq")
    }

    /// True when the relay should stop reading from the client.
    pub fn backpressure(&self) -> bool {
        todo!("pgbearer-session: RelayState::backpressure")
    }

    /// See the module documentation.
    pub fn quiescent(&self) -> bool {
        todo!("pgbearer-session: RelayState::quiescent")
    }

    /// See the module documentation.
    pub fn idle_safe_point(&self, client_buffered: usize, backend_writer_flushed: bool) -> bool {
        let _ = (client_buffered, backend_writer_flushed);
        todo!("pgbearer-session: RelayState::idle_safe_point")
    }

    /// See the module documentation.
    pub fn verdict(&self, backend_buffered: usize) -> ReleaseVerdict {
        let _ = backend_buffered;
        todo!("pgbearer-session: RelayState::verdict")
    }

    /// See the module documentation.
    pub fn request_in_flight(&self) -> bool {
        todo!("pgbearer-session: RelayState::request_in_flight")
    }

    /// See the module documentation.
    pub fn in_transaction(&self) -> bool {
        todo!("pgbearer-session: RelayState::in_transaction")
    }

    /// True once a FATAL/PANIC error was forwarded.
    pub fn fatal(&self) -> bool {
        todo!("pgbearer-session: RelayState::fatal")
    }
}
