//! Shared types used across all pgbearer crates.
//!
//! This crate is intentionally small and dependency-light: it holds the
//! [`Identity`] model produced by token validation and consumed by policy,
//! audit and session code, plus SQLSTATE codes and a few common enums.

pub mod sqlstate;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Whether an identity belongs to a person or to a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// A human user (delegated token).
    Human,
    /// A workload: service principal, Kubernetes ServiceAccount, CI pipeline.
    Workload,
    /// The token did not say.
    #[default]
    Unknown,
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IdentityKind::Human => "human",
            IdentityKind::Workload => "workload",
            IdentityKind::Unknown => "unknown",
        })
    }
}

/// A validated identity, produced from a verified access token.
///
/// All fields come from a token whose signature, issuer, audience and
/// lifetime have been verified. `claims` holds the raw (verified) claim set
/// so that policy rules can match on arbitrary claims.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Identity {
    /// Name of the configured identity provider that issued the token
    /// (the `name` field in `identity_providers`), not the issuer URL.
    pub provider: String,
    /// The issuer URL (`iss` claim).
    pub issuer: String,
    /// Stable subject identifier (for example Entra `oid`, or `sub`).
    pub subject: String,
    /// Human-readable name for display and audit only (never for authorization).
    pub username: Option<String>,
    /// Tenant identifier (for example Entra `tid`).
    pub tenant: Option<String>,
    /// Group identifiers or names.
    pub groups: BTreeSet<String>,
    /// Application roles.
    pub roles: BTreeSet<String>,
    /// OAuth scopes.
    pub scopes: BTreeSet<String>,
    /// The OAuth client that requested the token (`azp`, `appid`, `client_id`).
    pub client_id: Option<String>,
    /// Human or workload.
    pub kind: IdentityKind,
    /// Token expiry (`exp`).
    pub expires_at: SystemTime,
    /// Token identifier (`jti` or `uti`), if present.
    pub token_id: Option<String>,
    /// True when the IdP signalled that the groups claim was omitted because
    /// the user is in too many groups (Entra ID "groups overage").
    pub groups_overage: bool,
    /// The full verified claim set.
    #[serde(skip)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

impl Identity {
    /// A short, log-safe description such as `entra:3f2b…(alice@example.com)`.
    pub fn display_name(&self) -> String {
        match &self.username {
            Some(u) => format!("{}:{} ({})", self.provider, self.subject, u),
            None => format!("{}:{}", self.provider, self.subject),
        }
    }

    /// Look up a claim by name; see [`lookup_claim`] for the name syntax.
    pub fn claim(&self, name: &str) -> Option<&serde_json::Value> {
        lookup_claim(&self.claims, name)
    }
}

/// Look up a claim in a verified claim set. This is the one lookup used by
/// token validation (claim mapping) and by policy, so both always agree on
/// what a claim name means.
///
/// * A name starting with `/` is an RFC 6901 JSON Pointer, for example
///   `/kubernetes.io/serviceaccount/uid` (`~1` stands for `/`, `~0` for `~`;
///   array elements are addressed by index).
/// * Otherwise a claim whose literal name matches wins, so namespaced claims
///   such as `https://example.com/roles` or `kubernetes.io` work.
/// * Otherwise a dotted name is a path into nested objects, for example
///   `realm_access.roles`.
pub fn lookup_claim<'a>(
    claims: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(pointer) = name.strip_prefix('/') {
        let mut tokens = pointer.split('/');
        let mut current = claims.get(&unescape_pointer_token(tokens.next()?)?)?;
        for token in tokens {
            let token = unescape_pointer_token(token)?;
            current = match current {
                serde_json::Value::Object(map) => map.get(&token)?,
                serde_json::Value::Array(items) => items.get(parse_array_index(&token)?)?,
                _ => return None,
            };
        }
        return Some(current);
    }
    if let Some(value) = claims.get(name) {
        return Some(value);
    }
    if !name.contains('.') {
        return None;
    }
    let mut parts = name.split('.');
    let mut current = claims.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

/// Check that a claim name is usable with [`lookup_claim`]: non-empty, and a
/// well-formed JSON Pointer if it starts with `/`.
pub fn validate_claim_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("claim name must not be empty".into());
    }
    if let Some(pointer) = name.strip_prefix('/') {
        for token in pointer.split('/') {
            if unescape_pointer_token(token).is_none() {
                return Err(format!(
                    "claim name {name:?} is not a valid JSON Pointer: '~' must be followed by '0' or '1'"
                ));
            }
        }
    }
    Ok(())
}

/// Undo RFC 6901 escaping (`~1` → `/`, then `~0` → `~`). `None` for an
/// invalid escape.
fn unescape_pointer_token(token: &str) -> Option<String> {
    if !token.contains('~') {
        return Some(token.to_owned());
    }
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// An RFC 6901 array index: `0` or digits without a leading zero.
fn parse_array_index(token: &str) -> Option<usize> {
    if token.is_empty()
        || !token.bytes().all(|b| b.is_ascii_digit())
        || (token.len() > 1 && token.starts_with('0'))
    {
        return None;
    }
    token.parse().ok()
}

/// Backend pooling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PoolMode {
    /// One backend connection for the whole client session.
    #[default]
    Session,
    /// A backend connection only for the duration of a transaction.
    Transaction,
}

impl fmt::Display for PoolMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PoolMode::Session => "session",
            PoolMode::Transaction => "transaction",
        })
    }
}

/// What to do when the client's access token expires during a session.
///
/// Whatever the action, a session never outlives
/// `exp + token_expiry_grace + token_expiry_hard_timeout` (ARCHITECTURE §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenExpiryAction {
    /// Close the session at its next safe point after `exp + grace`.
    #[default]
    TerminateWhenIdle,
    /// Close the session at `exp + grace`, even in the middle of a transaction.
    Terminate,
}

impl TokenExpiryAction {
    /// The stricter of two actions (`Terminate` is stricter).
    pub fn strictest(self, other: TokenExpiryAction) -> TokenExpiryAction {
        if self == TokenExpiryAction::Terminate || other == TokenExpiryAction::Terminate {
            TokenExpiryAction::Terminate
        } else {
            TokenExpiryAction::TerminateWhenIdle
        }
    }
}

/// A privilege risk of a PostgreSQL role, found by walking everything the
/// login role can reach through SET, INHERIT and ADMIN membership edges
/// (ARCHITECTURE §9.2). Grants acknowledge the risks they accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleRisk {
    /// SUPERUSER.
    Superuser,
    /// CREATEROLE.
    Createrole,
    /// REPLICATION.
    Replication,
    /// BYPASSRLS.
    Bypassrls,
    /// `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`.
    ServerFiles,
    /// ADMIN OPTION on a reachable role (the role can grant itself more roles).
    AdminOption,
    /// `pg_signal_backend`, `pg_write_all_data`, `pg_create_subscription`,
    /// `pg_use_reserved_connections`, `pg_maintain`, `pg_checkpoint`,
    /// `pg_signal_autovacuum_worker`.
    PredefinedAdmin,
    /// Owns a database.
    DatabaseOwner,
    /// CREATEDB.
    Createdb,
    /// `pg_read_all_data`, `pg_read_all_settings`, `pg_read_all_stats`,
    /// `pg_monitor`, `pg_stat_scan_tables`.
    ReadAll,
}

impl RoleRisk {
    /// Every risk class.
    pub const ALL: [RoleRisk; 10] = [
        RoleRisk::Superuser,
        RoleRisk::Createrole,
        RoleRisk::Replication,
        RoleRisk::Bypassrls,
        RoleRisk::ServerFiles,
        RoleRisk::AdminOption,
        RoleRisk::PredefinedAdmin,
        RoleRisk::DatabaseOwner,
        RoleRisk::Createdb,
        RoleRisk::ReadAll,
    ];

    /// Whether an unacknowledged risk of this class refuses the connection.
    /// The others are allowed but warned about and audited.
    pub fn blocks_by_default(self) -> bool {
        !matches!(
            self,
            RoleRisk::DatabaseOwner | RoleRisk::Createdb | RoleRisk::ReadAll
        )
    }

    /// The configuration name (`snake_case`).
    pub fn as_str(self) -> &'static str {
        match self {
            RoleRisk::Superuser => "superuser",
            RoleRisk::Createrole => "createrole",
            RoleRisk::Replication => "replication",
            RoleRisk::Bypassrls => "bypassrls",
            RoleRisk::ServerFiles => "server_files",
            RoleRisk::AdminOption => "admin_option",
            RoleRisk::PredefinedAdmin => "predefined_admin",
            RoleRisk::DatabaseOwner => "database_owner",
            RoleRisk::Createdb => "createdb",
            RoleRisk::ReadAll => "read_all",
        }
    }
}

impl fmt::Display for RoleRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A random, unguessable session identifier (128 bits, hex encoded).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a new random session id.
    pub fn new() -> Self {
        let bytes: [u8; 16] = rand::random();
        SessionId(hex::encode(bytes))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An error to report to a PostgreSQL client as an `ErrorResponse`.
///
/// `message` is what the client sees. `detail` is internal and must only go
/// to logs and audit, never to the client, because it may reveal why
/// authentication or authorization failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError {
    /// SQLSTATE code, see [`sqlstate`].
    pub code: &'static str,
    /// Severity, usually `FATAL` during startup.
    pub severity: Severity,
    /// Message sent to the client.
    pub message: String,
    /// Optional hint sent to the client.
    pub hint: Option<String>,
    /// Internal reason, for logs/audit only.
    pub internal_reason: Option<String>,
}

impl ClientError {
    /// A FATAL error with the given code and client-visible message.
    pub fn fatal(code: &'static str, message: impl Into<String>) -> Self {
        ClientError {
            code,
            severity: Severity::Fatal,
            message: message.into(),
            hint: None,
            internal_reason: None,
        }
    }

    /// Attach a client-visible hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attach an internal reason (logs and audit only).
    pub fn with_internal_reason(mut self, reason: impl Into<String>) -> Self {
        self.internal_reason = Some(reason.into());
        self
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.severity.as_str(),
            self.code,
            self.message
        )?;
        if let Some(r) = &self.internal_reason {
            write!(f, " ({r})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ClientError {}

/// ErrorResponse severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// `ERROR`: the current command failed; the session continues.
    Error,
    /// `FATAL`: the session is terminated.
    Fatal,
}

impl Severity {
    /// The protocol string (`ERROR` or `FATAL`).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Fatal => "FATAL",
        }
    }
}

/// Free-form key/value labels (used for audit context).
pub type Labels = BTreeMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_with_claims(claims: serde_json::Value) -> Identity {
        Identity {
            provider: "test".into(),
            issuer: "https://issuer.example".into(),
            subject: "sub-1".into(),
            username: Some("alice@example.com".into()),
            tenant: None,
            groups: BTreeSet::new(),
            roles: BTreeSet::new(),
            scopes: BTreeSet::new(),
            client_id: None,
            kind: IdentityKind::Human,
            expires_at: SystemTime::UNIX_EPOCH,
            token_id: None,
            groups_overage: false,
            claims: claims.as_object().cloned().unwrap_or_default(),
        }
    }

    #[test]
    fn claim_lookup_by_dotted_path() {
        let id = identity_with_claims(serde_json::json!({
            "acct": 1,
            "realm_access": {"roles": ["a", "b"]}
        }));
        assert_eq!(id.claim("acct"), Some(&serde_json::json!(1)));
        assert_eq!(
            id.claim("realm_access.roles"),
            Some(&serde_json::json!(["a", "b"]))
        );
        assert_eq!(id.claim("realm_access.missing"), None);
        assert_eq!(id.claim("acct.deeper"), None);
    }

    #[test]
    fn claim_lookup_prefers_literal_names_with_dots() {
        let id = identity_with_claims(serde_json::json!({
            "https://example.com/roles": ["admin"],
            "kubernetes.io": {
                "namespace": "orders",
                "serviceaccount": {"name": "api", "uid": "u-1"}
            },
            "a.b": "literal",
            "a": {"b": "nested"}
        }));
        assert_eq!(
            id.claim("https://example.com/roles"),
            Some(&serde_json::json!(["admin"]))
        );
        // A literal key with a dot wins over the nested path.
        assert_eq!(id.claim("a.b"), Some(&serde_json::json!("literal")));
        // Nested keys under a dotted top-level name need a JSON Pointer.
        assert_eq!(id.claim("kubernetes.io.namespace"), None);
        assert_eq!(
            id.claim("/kubernetes.io/namespace"),
            Some(&serde_json::json!("orders"))
        );
        assert_eq!(
            id.claim("/kubernetes.io/serviceaccount/uid"),
            Some(&serde_json::json!("u-1"))
        );
        assert_eq!(id.claim("/a/b"), Some(&serde_json::json!("nested")));
    }

    #[test]
    fn claim_lookup_json_pointer_escapes_and_arrays() {
        let id = identity_with_claims(serde_json::json!({
            "x/y": {"m~n": 1},
            "list": [{"v": "first"}, {"v": "second"}]
        }));
        assert_eq!(id.claim("/x~1y/m~0n"), Some(&serde_json::json!(1)));
        assert_eq!(id.claim("/list/1/v"), Some(&serde_json::json!("second")));
        assert_eq!(id.claim("/list/01/v"), None);
        assert_eq!(id.claim("/list/9"), None);
        assert_eq!(id.claim("/x~2y"), None);
        assert_eq!(id.claim("/missing"), None);
    }

    #[test]
    fn claim_names_are_validated() {
        assert!(validate_claim_name("acct").is_ok());
        assert!(validate_claim_name("https://example.com/roles").is_ok());
        assert!(validate_claim_name("/kubernetes.io/serviceaccount/uid").is_ok());
        assert!(validate_claim_name("/a~1b~0c").is_ok());
        assert!(validate_claim_name("").is_err());
        assert!(validate_claim_name("/a~2").is_err());
        assert!(validate_claim_name("/a~").is_err());
    }

    #[test]
    fn session_ids_are_unique_and_hex() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 32);
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn display_name_includes_username() {
        let id = identity_with_claims(serde_json::json!({}));
        assert_eq!(id.display_name(), "test:sub-1 (alice@example.com)");
    }
}
