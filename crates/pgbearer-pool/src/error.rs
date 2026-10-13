//! Backend and pool errors, and how they are reported to clients.

use std::collections::BTreeSet;

use pgbearer_core::{ClientError, RoleRisk, sqlstate};
use pgbearer_wire::messages::ErrorFields;

/// `22P02` invalid_text_representation (not in [`pgbearer_core::sqlstate`]).
const INVALID_TEXT_REPRESENTATION: &str = "22P02";

/// SQLSTATEs caused by the client's own startup settings or database name.
/// The `&'static str` is what [`PoolError::to_client_error`] reports.
const CLIENT_CAUSED: [&str; 5] = [
    sqlstate::INVALID_PARAMETER_VALUE,
    sqlstate::UNDEFINED_OBJECT,
    sqlstate::INSUFFICIENT_PRIVILEGE,
    sqlstate::INVALID_CATALOG_NAME,
    INVALID_TEXT_REPRESENTATION,
];

/// Client message for every login failure (the reason stays internal).
const LOGIN_FAILED: &str = "backend login for the mapped role failed";
/// Client message for errors that are not the client's to see.
const UNAVAILABLE: &str = "database unavailable";

/// Errors talking to a backend.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// TCP connect or I/O failure.
    #[error("backend i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS negotiation failed or the server refused TLS.
    #[error("backend tls error: {0}")]
    Tls(String),
    /// Authentication failed or used an unsupported method.
    #[error("backend authentication failed: {0}")]
    Auth(String),
    /// The server sent something unexpected.
    #[error("backend protocol error: {0}")]
    Protocol(String),
    /// The StartupMessage would exceed PostgreSQL's 10 000-byte limit.
    #[error("startup packet too large ({0} bytes)")]
    StartupTooLarge(usize),
    /// The server sent an ErrorResponse.
    #[error("backend error {}: {}", .0.code.as_deref().unwrap_or("?"), .0.message.as_deref().unwrap_or("?"))]
    Server(Box<ErrorFields>),
    /// The operation timed out.
    #[error("backend operation timed out")]
    Timeout,
}

impl BackendError {
    /// True for server errors caused by the client's own startup settings or
    /// database name (`22023`, `42704`, `42501`, `3D000`, `22P02`): passed
    /// through to the client and never counted as a backend failure.
    pub fn is_client_caused(&self) -> bool {
        self.server_code().and_then(client_caused_code).is_some()
    }

    /// Short metric/audit reason code (the `reason` label of
    /// `pgbearer_backend_connect_errors_total`): `connect`, `tls`, `auth`,
    /// `protocol`, `startup_too_large`, `connect_timeout`, and for server
    /// errors `backend_too_many_connections`, `client_error`,
    /// `cannot_connect_now` or `server_error`.
    pub fn reason_code(&self) -> &'static str {
        match self {
            BackendError::Io(_) => "connect",
            BackendError::Tls(_) => "tls",
            BackendError::Auth(_) => "auth",
            BackendError::Protocol(_) => "protocol",
            BackendError::StartupTooLarge(_) => "startup_too_large",
            BackendError::Timeout => "connect_timeout",
            BackendError::Server(fields) => {
                let code = fields.code.as_deref().unwrap_or("");
                if code == sqlstate::TOO_MANY_CONNECTIONS {
                    "backend_too_many_connections"
                } else if client_caused_code(code).is_some() {
                    "client_error"
                } else if code.starts_with("28") {
                    "auth"
                } else if code == sqlstate::CANNOT_CONNECT_NOW {
                    "cannot_connect_now"
                } else {
                    "server_error"
                }
            }
        }
    }

    /// The SQLSTATE of a server error.
    fn server_code(&self) -> Option<&str> {
        match self {
            BackendError::Server(fields) => fields.code.as_deref(),
            _ => None,
        }
    }

    /// A server error from the body of an `ErrorResponse`.
    pub(crate) fn from_error_response(body: &[u8]) -> BackendError {
        match pgbearer_wire::messages::decode::error_fields(body) {
            Ok(fields) => BackendError::Server(Box::new(fields)),
            Err(e) => BackendError::Protocol(format!("malformed ErrorResponse: {e}")),
        }
    }
}

impl From<pgbearer_wire::WireError> for BackendError {
    fn from(e: pgbearer_wire::WireError) -> Self {
        match e {
            pgbearer_wire::WireError::Io(io) => BackendError::Io(io),
            other => BackendError::Protocol(other.to_string()),
        }
    }
}

/// The static form of a client-caused SQLSTATE.
fn client_caused_code(code: &str) -> Option<&'static str> {
    CLIENT_CAUSED.iter().copied().find(|c| *c == code)
}

/// Pool errors.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// No backend with this name.
    #[error("unknown backend {0:?}")]
    UnknownBackend(String),
    /// No credential configured for the role.
    #[error("no login credential for role {role:?} on backend {backend:?}")]
    NoCredential {
        /// Backend.
        backend: String,
        /// Role.
        role: String,
    },
    /// Waited `acquire_timeout` without getting a connection.
    #[error("timed out waiting for a backend connection to {0:?}")]
    Timeout(String),
    /// The role can reach privileges the grant does not acknowledge.
    #[error("role {role:?} can reach unacknowledged privileges: {}", format_risks(.risks))]
    RoleRisk {
        /// Role.
        role: String,
        /// Unacknowledged blocking risks.
        risks: BTreeSet<RoleRisk>,
    },
    /// The pool manager is shutting down.
    #[error("pool is closed")]
    Closed,
    /// Connecting to the backend failed.
    #[error(transparent)]
    Backend(Box<BackendError>),
}

impl From<BackendError> for PoolError {
    fn from(e: BackendError) -> Self {
        PoolError::Backend(Box::new(e))
    }
}

fn format_risks(risks: &BTreeSet<RoleRisk>) -> String {
    risks
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl PoolError {
    /// The error to send to the client (see the crate documentation).
    ///
    /// The severity is always `FATAL` (the session cannot continue without
    /// a backend). The full error is attached as the internal reason.
    pub fn to_client_error(&self) -> ClientError {
        let (code, message): (&'static str, String) = match self {
            PoolError::Timeout(_) => (
                sqlstate::TOO_MANY_CONNECTIONS,
                "too many connections for this database role; try again later".into(),
            ),
            PoolError::RoleRisk { .. } | PoolError::NoCredential { .. } => {
                (sqlstate::INVALID_AUTHORIZATION_SPECIFICATION, LOGIN_FAILED.into())
            }
            PoolError::UnknownBackend(_) | PoolError::Closed => {
                (sqlstate::CANNOT_CONNECT_NOW, "service unavailable".into())
            }
            PoolError::Backend(e) => match &**e {
                BackendError::Auth(_) => {
                    (sqlstate::INVALID_AUTHORIZATION_SPECIFICATION, LOGIN_FAILED.into())
                }
                BackendError::Server(fields) => server_client_error(fields),
                _ => (sqlstate::CONNECTION_FAILURE, UNAVAILABLE.into()),
            },
        };
        ClientError::fatal(code, message).with_internal_reason(self.to_string())
    }

    /// Short metric/audit reason code: `unknown_backend`, `no_credential`,
    /// `acquire_timeout`, `role_risk`, `closed`, or
    /// [`BackendError::reason_code`].
    pub fn reason_code(&self) -> &'static str {
        match self {
            PoolError::UnknownBackend(_) => "unknown_backend",
            PoolError::NoCredential { .. } => "no_credential",
            PoolError::Timeout(_) => "acquire_timeout",
            PoolError::RoleRisk { .. } => "role_risk",
            PoolError::Closed => "closed",
            PoolError::Backend(e) => e.reason_code(),
        }
    }
}

/// Code and message for a server `ErrorResponse` (see the table in the
/// crate documentation).
fn server_client_error(fields: &ErrorFields) -> (&'static str, String) {
    let code = fields.code.as_deref().unwrap_or("");
    let server_message = || fields.message.clone().unwrap_or_else(|| UNAVAILABLE.into());
    if code == sqlstate::TOO_MANY_CONNECTIONS {
        (
            sqlstate::TOO_MANY_CONNECTIONS,
            "the database has no free connection slots".into(),
        )
    } else if let Some(code) = client_caused_code(code) {
        (code, server_message())
    } else if code.starts_with("28") {
        (
            sqlstate::INVALID_AUTHORIZATION_SPECIFICATION,
            LOGIN_FAILED.into(),
        )
    } else if code == sqlstate::CANNOT_CONNECT_NOW {
        (sqlstate::CANNOT_CONNECT_NOW, server_message())
    } else {
        (sqlstate::CONNECTION_FAILURE, UNAVAILABLE.into())
    }
}
