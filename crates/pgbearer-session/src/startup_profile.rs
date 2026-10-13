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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

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

/// The StartupMessage keys with a meaning of their own (never settings).
const RESERVED_KEYS: &[&str] = &["user", "database", "options", "replication"];

/// Prefix of protocol options (`_pq_.*`), handled during version negotiation.
const PROTOCOL_OPTION_PREFIX: &str = "_pq_.";

/// Prefix of pgbearer's own settings (identity propagation).
const PGBEARER_NAMESPACE: &str = "pgbearer.";

/// Maximum length of one dot-separated part of a setting name
/// (PostgreSQL's `NAMEDATALEN - 1`).
const MAX_NAME_PART_LEN: usize = 63;

/// Maximum number of bytes of client-supplied text quoted in an error message.
const MAX_ECHO_BYTES: usize = 64;

/// The `replication` values that mean "not a replication connection".
const REPLICATION_OFF: &[&str] = &["false", "off", "0", "no"];

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

    fn new(kind: ProfileErrorKind, message: String) -> Self {
        ProfileError { kind, message }
    }

    fn malformed(message: String) -> Self {
        Self::new(ProfileErrorKind::Malformed, message)
    }

    fn duplicate(name: &str) -> Self {
        Self::malformed(format!("duplicate startup parameter {}", quoted(name)))
    }

    fn unsupported_option(arg: &str) -> Self {
        Self::new(
            ProfileErrorKind::Unsupported,
            format!(
                "startup option {} is not supported; only -c name=value",
                quoted(arg)
            ),
        )
    }

    fn forbidden(name: &str) -> Self {
        Self::new(
            ProfileErrorKind::Forbidden,
            format!(
                "startup parameter {} may not be set through pgbearer",
                quoted(name)
            ),
        )
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
    ///
    /// The checks run in the order of the module documentation, so the first
    /// failing rule decides the error: reserved keys (in packet order), the
    /// database name, the syntax of `options`, names (`options` first, then
    /// direct keys), duplicate direct keys, the deny-list (by sorted name),
    /// and finally the limit.
    ///
    /// Beyond the deny-list, a setting can never be named like a reserved
    /// key (`user`, `database`, `options`, `replication`, in any case) or lie
    /// in the `_pq_` namespace (except an exact `_pq_.` direct key, which is
    /// a protocol option and ignored): forwarded, the backend would read it
    /// as that key or as a protocol option. Such a setting is
    /// [`ProfileErrorKind::Forbidden`] (see [`is_denied_setting`]). A value
    /// containing a NUL byte (impossible in a real StartupMessage) is
    /// [`ProfileErrorKind::Malformed`].
    pub fn from_startup(params: &[(String, String)]) -> Result<StartupProfile, ProfileError> {
        // 1. Reserved keys, in packet order.
        let mut user: Option<&str> = None;
        let mut database: Option<&str> = None;
        let mut options: Option<&str> = None;
        let mut replication_seen = false;
        let mut direct: Vec<(&str, &str)> = Vec::new();
        for (key, value) in params {
            if value.contains('\0') {
                return Err(ProfileError::malformed(format!(
                    "startup parameter {} contains a NUL byte",
                    quoted(key)
                )));
            }
            match key.as_str() {
                "user" => set_once(&mut user, key, value)?,
                "database" => set_once(&mut database, key, value)?,
                "options" => set_once(&mut options, key, value)?,
                "replication" => {
                    if replication_seen {
                        return Err(ProfileError::duplicate(key));
                    }
                    replication_seen = true;
                    if !REPLICATION_OFF
                        .iter()
                        .any(|off| value.eq_ignore_ascii_case(off))
                    {
                        return Err(ProfileError::new(
                            ProfileErrorKind::Unsupported,
                            "replication connections are not supported".to_owned(),
                        ));
                    }
                }
                k if k.starts_with(PROTOCOL_OPTION_PREFIX) => {}
                _ => direct.push((key.as_str(), value.as_str())),
            }
        }

        let user = user.unwrap_or_default().to_owned();
        let database = match database {
            Some(db) if !db.is_empty() => db.to_owned(),
            _ => user.clone(),
        };
        if database.is_empty() {
            return Err(ProfileError::malformed(
                "no database name in the startup packet".to_owned(),
            ));
        }

        // 2. `options` syntax (names keep their raw spelling, `-` → `_`).
        let from_options = match options {
            Some(options) => parse_options(options)?,
            None => Vec::new(),
        };

        // 3. Names: lower-cased and validated, `options` first.
        let mut normalised_options = Vec::with_capacity(from_options.len());
        for (name, value) in from_options {
            normalised_options.push((normalise_name(&name)?, value));
        }
        let mut normalised_direct = Vec::with_capacity(direct.len());
        for (name, value) in direct {
            normalised_direct.push((normalise_name(name)?, value.to_owned()));
        }

        // 4. Precedence: `options` in order (last wins), then direct keys,
        //    which must be unique among themselves.
        let mut settings: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in normalised_options {
            settings.insert(name, value);
        }
        let mut direct_names: BTreeSet<&str> = BTreeSet::new();
        for (name, _) in &normalised_direct {
            if !direct_names.insert(name.as_str()) {
                return Err(ProfileError::duplicate(name));
            }
        }
        for (name, value) in normalised_direct {
            settings.insert(name, value);
        }

        // 5. Deny-list.
        if let Some(name) = settings.keys().find(|name| is_denied_setting(name)) {
            return Err(ProfileError::forbidden(name));
        }

        // 6. Limits.
        if settings.len() > MAX_SETTINGS {
            return Err(ProfileError::new(
                ProfileErrorKind::TooMany,
                format!(
                    "too many startup parameters: {} (at most {MAX_SETTINGS})",
                    settings.len()
                ),
            ));
        }

        Ok(StartupProfile {
            user,
            database,
            settings: settings.into_iter().collect(),
        })
    }

    /// The value of a setting, by lower-case name.
    ///
    /// The lookup ignores ASCII case, so `TimeZone` finds `timezone`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.settings
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Parameters for the backend StartupMessage after `user` and `database`
    /// (see the module documentation for how `extra` merges).
    ///
    /// The result never names a setting twice: an `extra` entry whose name
    /// (ignoring ASCII case) the client already set, or that appears earlier
    /// in `extra`, is left out.
    pub fn backend_parameters(&self, extra: &[(String, String)]) -> Vec<(String, String)> {
        let mut params = Vec::with_capacity(self.settings.len() + extra.len());
        params.extend(self.settings.iter().cloned());
        for (name, value) in extra {
            if !params.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                params.push((name.clone(), value.clone()));
            }
        }
        params
    }
}

/// Whether a setting name may never be set by a client through pgbearer
/// (ASCII case is ignored).
///
/// True for [`DENIED_SETTINGS`], the `pgbearer.*` namespace, the reserved
/// startup keys (`user`, `database`, `options`, `replication`) and the
/// protocol-option namespace `_pq_.*`. The last two are not settings at all:
/// forwarded as a backend startup key they would change the login (`user`,
/// `database`), be parsed again (`options`) or be read as a protocol option.
pub fn is_denied_setting(name: &str) -> bool {
    DENIED_SETTINGS
        .iter()
        .chain(RESERVED_KEYS)
        .any(|denied| name.eq_ignore_ascii_case(denied))
        || starts_with_ignore_ascii_case(name, PGBEARER_NAMESPACE)
        || starts_with_ignore_ascii_case(name, PROTOCOL_OPTION_PREFIX)
}

/// Split a libpq `options` string into arguments exactly like PostgreSQL's
/// `pg_split_opts` (exposed for testing).
///
/// Arguments are separated by runs of ASCII whitespace (space, `\t`, `\n`,
/// `\r`, `\x0B`, `\x0C`); a backslash makes the next character literal and is
/// itself dropped, so a trailing backslash disappears (and a lone `\` is an
/// empty argument).
pub fn split_options(options: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = options.chars().peekable();
    loop {
        while chars.next_if(|&c| is_option_space(c)).is_some() {}
        if chars.peek().is_none() {
            return args;
        }
        let mut arg = String::new();
        let mut escaped = false;
        while let Some(c) = chars.next_if(|&c| escaped || !is_option_space(c)) {
            if !escaped && c == '\\' {
                escaped = true;
            } else {
                escaped = false;
                arg.push(c);
            }
        }
        args.push(arg);
    }
}

/// The whitespace of C's `isspace` in the C locale.
fn is_option_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C')
}

/// Record a reserved key, rejecting a second occurrence.
fn set_once<'a>(slot: &mut Option<&'a str>, key: &str, value: &'a str) -> Result<(), ProfileError> {
    if slot.is_some() {
        return Err(ProfileError::duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Parse the arguments of `options` into `(name, value)` pairs, in order.
/// Names are raw except that `-` becomes `_`.
fn parse_options(options: &str) -> Result<Vec<(String, String)>, ProfileError> {
    let args = split_options(options);
    let mut settings = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let assignment = if arg == "-c" {
            match args.next() {
                Some(next) => next.as_str(),
                None => {
                    return Err(ProfileError::new(
                        ProfileErrorKind::Unsupported,
                        "startup option \"-c\" without an argument is not supported; \
                         only -c name=value"
                            .to_owned(),
                    ));
                }
            }
        } else if let Some(rest) = arg.strip_prefix("--") {
            rest
        } else if let Some(rest) = arg.strip_prefix("-c") {
            rest
        } else {
            return Err(ProfileError::unsupported_option(arg));
        };
        let Some((name, value)) = assignment.split_once('=') else {
            return Err(ProfileError::malformed(format!(
                "startup option {} has no value; expected -c name=value",
                quoted(assignment)
            )));
        };
        settings.push((name.replace('-', "_"), value.to_owned()));
    }
    Ok(settings)
}

/// Lower-case and validate a setting name.
fn normalise_name(raw: &str) -> Result<String, ProfileError> {
    let name = raw.to_ascii_lowercase();
    if is_valid_name(&name) {
        Ok(name)
    } else {
        Err(ProfileError::malformed(format!(
            "invalid startup parameter name {}",
            quoted(raw)
        )))
    }
}

/// One or more dot-separated parts, each 1–63 bytes of ASCII letters, digits
/// and `_`, not starting with a digit.
fn is_valid_name(name: &str) -> bool {
    name.split('.').all(|part| {
        let bytes = part.as_bytes();
        (1..=MAX_NAME_PART_LEN).contains(&bytes.len())
            && bytes.first().is_some_and(|b| !b.is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    })
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Quote client-supplied text for an error message: at most
/// [`MAX_ECHO_BYTES`] bytes of it (cut at a character boundary, marked with
/// `...`), with quotes, backslashes and control characters escaped.
fn quoted(text: &str) -> String {
    let mut end = text.len().min(MAX_ECHO_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let shown = text.get(..end).unwrap_or_default();
    let mut out = String::with_capacity(shown.len() + 5);
    out.push('"');
    for c in shown.chars() {
        if c == '"' || c == '\\' || c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out.push('"');
    if end < text.len() {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod proptests;
