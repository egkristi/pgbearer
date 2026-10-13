//! The client's startup settings, normalised for forwarding to the backend
//! (ARCHITECTURE.md §7.4, ADR-016).
//!
//! PostgreSQL treats settings in the StartupMessage as *session defaults*:
//! they set the value that `RESET`, `RESET ALL` and `DISCARD ALL` return to.
//! `SET` and `set_config()` cannot reproduce that, so pgbearer forwards the
//! client's settings as individual keys of the backend StartupMessage.
//!
//! [`StartupProfile::from_startup`] builds the profile from the client's
//! StartupMessage parameters (in packet order):
//!
//! 1. **Reserved keys.**
//!    * `user`, `database`: taken out of the settings. A missing or empty
//!      `database` defaults to `user` (as in PostgreSQL); if both are empty →
//!      [`ProfileErrorKind::Malformed`] ("no database name in the startup
//!      packet"). An empty `user` is allowed (policy treats it as the
//!      identity's own name).
//!    * `replication`: absent, or `false`/`off`/`0`/`no` (ASCII
//!      case-insensitive) is accepted and not forwarded; any other value →
//!      [`ProfileErrorKind::Unsupported`] ("replication connections are not
//!      supported").
//!    * `options`: parsed as below, never forwarded raw.
//!    * Keys starting with `_pq_.` (protocol options, handled during version
//!      negotiation) are ignored and never forwarded.
//!    * A reserved key (`user`, `database`, `options`, `replication`) that
//!      appears more than once → [`ProfileErrorKind::Malformed`].
//! 2. **`options`** is split exactly like PostgreSQL's `pg_split_opts`:
//!    arguments are separated by runs of ASCII whitespace (space, `\t`, `\n`,
//!    `\r`, `\x0B`, `\x0C`); a backslash makes the next character literal
//!    (`\\` is a backslash, `\ ` a space). The arguments must be
//!    * `-c` followed by a separate argument `name=value`,
//!    * `-cname=value` (attached), or
//!    * `--name=value`.
//!
//!    Any other argument (`-P`, `-W 10`, `-d 5`, `-e`, `-f s`, `-S 1000`, a
//!    bare word, `-c` at the end) → [`ProfileErrorKind::Unsupported`]
//!    ("startup option … is not supported; only -c name=value"). A `name`
//!    without `=` → [`ProfileErrorKind::Malformed`]. The value is everything
//!    after the first `=` (it may be empty or contain `=`). In names from
//!    `options`, `-` becomes `_` (as PostgreSQL does).
//! 3. **Names** are ASCII-lower-cased (GUC names are case-insensitive, so
//!    `TimeZone`, `timezone` and `TIMEZONE` are one setting). A valid name is
//!    one or more dot-separated parts, each 1–63 bytes of ASCII letters,
//!    digits and `_`, not starting with a digit. Otherwise →
//!    [`ProfileErrorKind::Malformed`].
//! 4. **Precedence** (as PostgreSQL): settings from `options` first (a later
//!    `-c` for the same name replaces an earlier one), then direct keys,
//!    which replace `options` values. Two *direct* keys that normalise to the
//!    same name (`TimeZone` and `timezone`) → [`ProfileErrorKind::Malformed`]
//!    ("duplicate startup parameter").
//! 5. **Deny-list** → [`ProfileErrorKind::Forbidden`] ("startup parameter …
//!    may not be set through pgbearer"): `role`, `session_authorization`,
//!    `replication` (as a setting from `options`), `post_auth_delay`,
//!    `ignore_system_indexes`, `local_preload_libraries`,
//!    `session_preload_libraries`, `jit_debugging_support`,
//!    `jit_profiling_support`, `log_connections`, `log_disconnections`, and
//!    every name in the `pgbearer` namespace (`pgbearer.*`). Everything else
//!    is forwarded; the backend validates it exactly as for a direct
//!    connection (a user-settable setting sent at startup is no more powerful
//!    than the same `SET` after login, and superuser-only settings fail for
//!    the mapped role).
//! 6. **Limits**: at most [`MAX_SETTINGS`] settings after merging →
//!    [`ProfileErrorKind::TooMany`].
//!
//! The resulting [`StartupProfile::settings`] are sorted by name, so equal
//! profiles compare and hash equal (they can be part of a pool key).
//!
//! [`StartupProfile::backend_parameters`] produces the parameters for the
//! backend StartupMessage (after `user` and `database`, which the pool sets):
//! the profile's settings followed by `extra` (identity propagation and
//! keepalive settings chosen by pgbearer). An `extra` name that the client
//! also set: the client's value wins for keepalive and connection-check
//! settings; `pgbearer.*` names can never come from the client (deny-list).
//! The caller checks the total packet size with
//! [`pgbearer_wire::startup::encode_startup_message`], which rejects packets
//! over 10 000 bytes.

use pgbearer_core::sqlstate;

/// Maximum number of forwarded settings.
pub const MAX_SETTINGS: usize = 64;

/// Settings that can never be set through pgbearer.
pub const DENIED_SETTINGS: &[&str] = &[
    "role",
    "session_authorization",
    "replication",
    "post_auth_delay",
    "ignore_system_indexes",
    "local_preload_libraries",
    "session_preload_libraries",
    "jit_debugging_support",
    "jit_profiling_support",
    "log_connections",
    "log_disconnections",
];

/// Why a startup packet was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileErrorKind {
    /// A feature pgbearer does not support (`0A000`).
    Unsupported,
    /// A setting that may not be set through pgbearer (`42501`).
    Forbidden,
    /// A malformed or ambiguous packet (`08P01`).
    Malformed,
    /// Too many settings (`54023`).
    TooMany,
}

/// A refused startup packet. `message` is safe to send to the client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ProfileError {
    /// Category.
    pub kind: ProfileErrorKind,
    /// Client-facing message (names the offending parameter; never echoes
    /// more than 64 bytes of a value).
    pub message: String,
}

impl ProfileError {
    /// The SQLSTATE for the client's FATAL error.
    pub fn sqlstate(&self) -> &'static str {
        match self.kind {
            ProfileErrorKind::Unsupported => sqlstate::FEATURE_NOT_SUPPORTED,
            ProfileErrorKind::Forbidden => sqlstate::INSUFFICIENT_PRIVILEGE,
            ProfileErrorKind::Malformed => sqlstate::PROTOCOL_VIOLATION,
            ProfileErrorKind::TooMany => sqlstate::TOO_MANY_ARGUMENTS,
        }
    }
}

/// The normalised startup settings of one client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StartupProfile {
    /// Startup `user` (may be empty).
    pub user: String,
    /// Startup `database` (defaults to `user`).
    pub database: String,
    /// Settings to forward, sorted by (lower-case) name.
    pub settings: Vec<(String, String)>,
}

impl StartupProfile {
    /// Build a profile from the client's StartupMessage parameters, in packet
    /// order (see the module documentation).
    pub fn from_startup(params: &[(String, String)]) -> Result<StartupProfile, ProfileError> {
        let _ = params;
        todo!("pgbearer-session: StartupProfile::from_startup")
    }

    /// The value of a setting, by lower-case name.
    pub fn get(&self, name: &str) -> Option<&str> {
        let _ = name;
        todo!("pgbearer-session: StartupProfile::get")
    }

    /// Parameters for the backend StartupMessage after `user` and `database`
    /// (see the module documentation for how `extra` merges).
    pub fn backend_parameters(&self, extra: &[(String, String)]) -> Vec<(String, String)> {
        let _ = extra;
        todo!("pgbearer-session: StartupProfile::backend_parameters")
    }
}

/// Split a libpq `options` string into arguments exactly like PostgreSQL's
/// `pg_split_opts` (exposed for testing).
pub fn split_options(options: &str) -> Vec<String> {
    let _ = options;
    todo!("pgbearer-session: split_options")
}
