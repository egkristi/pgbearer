//! SQLSTATE codes used by pgbearer when it reports errors to clients.
//!
//! See <https://www.postgresql.org/docs/current/errcodes-appendix.html>.

/// `08001` sqlclient_unable_to_establish_sqlconnection.
pub const UNABLE_TO_ESTABLISH_CONNECTION: &str = "08001";
/// `08006` connection_failure.
pub const CONNECTION_FAILURE: &str = "08006";
/// `08P01` protocol_violation.
pub const PROTOCOL_VIOLATION: &str = "08P01";
/// `0A000` feature_not_supported.
pub const FEATURE_NOT_SUPPORTED: &str = "0A000";
/// `28000` invalid_authorization_specification.
pub const INVALID_AUTHORIZATION_SPECIFICATION: &str = "28000";
/// `28P01` invalid_password (used for rejected tokens).
pub const INVALID_PASSWORD: &str = "28P01";
/// `3D000` invalid_catalog_name (unknown database / no route).
pub const INVALID_CATALOG_NAME: &str = "3D000";
/// `25P03` idle_in_transaction_session_timeout.
pub const IDLE_IN_TRANSACTION_SESSION_TIMEOUT: &str = "25P03";
/// `53300` too_many_connections.
pub const TOO_MANY_CONNECTIONS: &str = "53300";
/// `53400` configuration_limit_exceeded.
pub const CONFIGURATION_LIMIT_EXCEEDED: &str = "53400";
/// `57P01` admin_shutdown.
pub const ADMIN_SHUTDOWN: &str = "57P01";
/// `57P03` cannot_connect_now.
pub const CANNOT_CONNECT_NOW: &str = "57P03";
/// `57P05` idle_session_timeout.
pub const IDLE_SESSION_TIMEOUT: &str = "57P05";
/// `XX000` internal_error.
pub const INTERNAL_ERROR: &str = "XX000";
