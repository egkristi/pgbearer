//! Audit events for pgbearer.
//!
//! Audit events are a separate, stable stream (schema `pgbearer.audit/v1`)
//! that records who connected, which decision was made and why, and how the
//! session ended. Each event is one JSON line:
//!
//! ```json
//! {"log.type":"audit","schema":"pgbearer.audit/v1","timestamp":"2026-10-09T12:00:00Z",
//!  "event":"connection.denied","session_id":"…","stage":"policy","reason":"no matching grant", …}
//! ```
//!
//! The precise denial reason is recorded here; clients only ever see a
//! generic message.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use pgbearer_core::{Identity, IdentityKind, PoolMode, SessionId};
use serde::Serialize;

/// Audit schema identifier.
pub const SCHEMA: &str = "pgbearer.audit/v1";

/// TLS details of a client connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsInfo {
    /// Negotiated protocol version, for example `TLSv1_3`.
    pub version: String,
    /// SNI host name sent by the client.
    pub sni: Option<String>,
    /// Negotiated ALPN protocol.
    pub alpn: Option<String>,
    /// Whether the connection used direct TLS (no SSLRequest).
    pub direct: bool,
}

/// Facts about a client connection, known before authentication completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionInfo {
    /// Session id.
    pub session_id: SessionId,
    /// Client address (from PROXY protocol if used).
    pub client_addr: SocketAddr,
    /// Listener name.
    pub listener: String,
    /// TLS details; `None` for plaintext connections.
    pub tls: Option<TlsInfo>,
    /// `token_password` or `oauthbearer`.
    pub auth_method: String,
    /// Startup `user` parameter.
    pub requested_user: Option<String>,
    /// Startup `database` parameter.
    pub requested_database: Option<String>,
    /// Startup `application_name` parameter.
    pub application_name: Option<String>,
}

/// The audit-relevant subset of an [`Identity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityInfo {
    /// Identity provider name.
    pub provider: String,
    /// Issuer URL.
    pub issuer: String,
    /// Stable subject.
    pub subject: String,
    /// Display name.
    pub username: Option<String>,
    /// Tenant.
    pub tenant: Option<String>,
    /// OAuth client id.
    pub client_id: Option<String>,
    /// Human or workload.
    pub kind: IdentityKind,
    /// Token id (`jti`/`uti`).
    pub token_id: Option<String>,
    /// Token expiry, RFC 3339.
    pub token_expires_at: String,
    /// Number of groups (not the groups themselves).
    pub group_count: usize,
    /// Roles from the token.
    pub roles: Vec<String>,
}

impl From<&Identity> for IdentityInfo {
    fn from(id: &Identity) -> Self {
        IdentityInfo {
            provider: id.provider.clone(),
            issuer: id.issuer.clone(),
            subject: id.subject.clone(),
            username: id.username.clone(),
            tenant: id.tenant.clone(),
            client_id: id.client_id.clone(),
            kind: id.kind,
            token_id: id.token_id.clone(),
            token_expires_at: rfc3339(id.expires_at),
            group_count: id.groups.len(),
            roles: id.roles.iter().cloned().collect(),
        }
    }
}

/// Where in the connection flow a denial happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyStage {
    /// Protocol, TLS or PROXY-protocol failure before authentication.
    Protocol,
    /// No route for the requested SNI/database.
    Route,
    /// The token was missing or invalid.
    Token,
    /// The policy denied the connection.
    Policy,
    /// A limit was hit (connections per identity, pool exhausted, rate limit).
    Limit,
    /// The backend could not be reached or refused the login.
    Backend,
}

/// An audit event.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event")]
pub enum AuditEvent {
    /// A token was validated successfully.
    #[serde(rename = "connection.authenticated")]
    ConnectionAuthenticated {
        /// Connection facts.
        connection: ConnectionInfo,
        /// The identity.
        identity: IdentityInfo,
    },
    /// A connection was refused.
    #[serde(rename = "connection.denied")]
    ConnectionDenied {
        /// Connection facts.
        connection: ConnectionInfo,
        /// The identity, if the token was valid.
        identity: Option<IdentityInfo>,
        /// Stage of the denial.
        stage: DenyStage,
        /// Precise internal reason.
        reason: String,
    },
    /// The session was attached to a backend role.
    #[serde(rename = "session.attached")]
    SessionAttached {
        /// Session id.
        session_id: SessionId,
        /// Backend name.
        backend: String,
        /// Database.
        database: String,
        /// PostgreSQL role used.
        pg_role: String,
        /// Names of grants that matched.
        matched_grants: Vec<String>,
        /// Pool mode.
        pool_mode: PoolMode,
        /// Backend process id (joins with PostgreSQL logs `%p`).
        backend_pid: u32,
    },
    /// The session ended.
    #[serde(rename = "session.ended")]
    SessionEnded {
        /// Session id.
        session_id: SessionId,
        /// Session duration in milliseconds.
        duration_ms: u64,
        /// Bytes received from the client.
        bytes_from_client: u64,
        /// Bytes sent to the client.
        bytes_to_client: u64,
        /// Completed transactions (ReadyForQuery after a statement).
        transactions: u64,
        /// Why it ended (`client_terminate`, `client_disconnect`, `token_expired`, `drain`, `idle_timeout`, `backend_error`, …).
        end_reason: String,
    },
    /// A cancel request was processed.
    #[serde(rename = "cancel")]
    Cancel {
        /// The session whose query was cancelled, if known.
        session_id: Option<SessionId>,
        /// Address the cancel request came from.
        client_addr: SocketAddr,
        /// `forwarded`, `unknown`, `no_backend`, `rate_limited`, `error`.
        result: String,
    },
}

#[derive(Serialize)]
struct Envelope<'a> {
    #[serde(rename = "log.type")]
    log_type: &'static str,
    schema: &'static str,
    timestamp: String,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

/// Serialize an event to a single JSON line (without trailing newline).
pub fn to_json_line(event: &AuditEvent) -> String {
    let env = Envelope {
        log_type: "audit",
        schema: SCHEMA,
        timestamp: rfc3339(SystemTime::now()),
        event,
    };
    serde_json::to_string(&env).unwrap_or_else(|e| {
        format!(r#"{{"log.type":"audit","schema":"{SCHEMA}","error":"serialization failed: {e}"}}"#)
    })
}

/// Destination for audit events.
pub trait AuditSink: Send + Sync {
    /// Record an event. Must not block for long; failures are logged, not returned.
    fn emit(&self, event: &AuditEvent);
}

/// Writes JSON lines to stdout and/or a file.
pub struct JsonLinesSink {
    stdout: bool,
    file: Option<Mutex<File>>,
}

impl JsonLinesSink {
    /// Create a sink. `file` is opened in append mode.
    pub fn new(stdout: bool, file: Option<&Path>) -> std::io::Result<Self> {
        let file = match file {
            Some(p) => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(p)?,
            )),
            None => None,
        };
        Ok(JsonLinesSink { stdout, file })
    }
}

impl AuditSink for JsonLinesSink {
    fn emit(&self, event: &AuditEvent) {
        let line = to_json_line(event);
        if self.stdout {
            let mut out = std::io::stdout().lock();
            if let Err(e) = writeln!(out, "{line}") {
                tracing::warn!(error = %e, "failed to write audit event to stdout");
            }
        }
        if let Some(f) = &self.file {
            match f.lock() {
                Ok(mut f) => {
                    if let Err(e) = writeln!(f, "{line}") {
                        tracing::warn!(error = %e, "failed to write audit event to file");
                    }
                }
                Err(_) => tracing::warn!("audit file lock poisoned"),
            }
        }
    }
}

/// Collects events in memory. Intended for tests.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemorySink {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of all events recorded so far.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl AuditSink for MemorySink {
    fn emit(&self, event: &AuditEvent) {
        if let Ok(mut e) = self.events.lock() {
            e.push(event.clone());
        }
    }
}

/// Discards all events.
pub struct NullSink;

impl AuditSink for NullSink {
    fn emit(&self, _event: &AuditEvent) {}
}

fn rfc3339(t: SystemTime) -> String {
    time::OffsetDateTime::from(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> ConnectionInfo {
        ConnectionInfo {
            session_id: SessionId::new(),
            client_addr: "10.0.0.7:51000".parse().expect("addr"),
            listener: "postgres".into(),
            tls: Some(TlsInfo {
                version: "TLSv1_3".into(),
                sni: Some("orders.db.example.com".into()),
                alpn: None,
                direct: false,
            }),
            auth_method: "token_password".into(),
            requested_user: Some("orders_readonly".into()),
            requested_database: Some("orders".into()),
            application_name: Some("psql".into()),
        }
    }

    #[test]
    fn denied_event_serializes_with_envelope() {
        let ev = AuditEvent::ConnectionDenied {
            connection: conn(),
            identity: None,
            stage: DenyStage::Token,
            reason: "token expired".into(),
        };
        let line = to_json_line(&ev);
        let v: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(v["log.type"], "audit");
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["event"], "connection.denied");
        assert_eq!(v["stage"], "token");
        assert_eq!(v["reason"], "token expired");
        assert_eq!(v["connection"]["listener"], "postgres");
        assert_eq!(v["connection"]["tls"]["sni"], "orders.db.example.com");
        assert!(v["timestamp"].as_str().is_some_and(|t| t.ends_with('Z')));
    }

    #[test]
    fn memory_sink_collects() {
        let sink = MemorySink::new();
        sink.emit(&AuditEvent::Cancel {
            session_id: None,
            client_addr: "127.0.0.1:1".parse().expect("addr"),
            result: "unknown".into(),
        });
        assert_eq!(sink.events().len(), 1);
    }
}
