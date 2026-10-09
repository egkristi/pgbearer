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

    /// Look up a claim by a dotted path, for example `realm_access.roles`.
    pub fn claim(&self, path: &str) -> Option<&serde_json::Value> {
        let mut parts = path.split('.');
        let first = parts.next()?;
        let mut current = self.claims.get(first)?;
        for part in parts {
            current = current.as_object()?.get(part)?;
        }
        Some(current)
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenExpiryAction {
    /// Close the session at the next idle point after `exp + grace`.
    #[default]
    TerminateWhenIdle,
    /// Close the session at `exp + grace`, even in the middle of a transaction.
    Terminate,
    /// Do nothing; only `max_lifetime` applies.
    Ignore,
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
