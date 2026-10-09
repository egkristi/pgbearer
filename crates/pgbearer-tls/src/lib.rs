//! TLS for pgbearer.
//!
//! * [`ServerTls`]: listener TLS with hot reload of certificate files
//!   (cert-manager / Kubernetes Secret rotation), ALPN `postgresql`, SNI
//!   capture, TLS 1.2+.
//! * [`BackendTls`]: client-side TLS to PostgreSQL backends with the libpq
//!   `sslmode` semantics `require`, `verify-ca`, `verify-full`, and optional
//!   client certificates (for PostgreSQL `cert` authentication) that are
//!   re-read when the files change.
//! * [`tls_server_end_point`]: SCRAM channel-binding data (RFC 5929).
//!
//! The process-wide rustls crypto provider is aws-lc-rs; call
//! [`install_crypto_provider`] once at startup (it is idempotent).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pgbearer_config::{BackendTlsConfig, BackendTlsMode, ListenerTlsConfig};
use pgbearer_telemetry::Metrics;
use rustls_pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

/// ALPN protocol id for PostgreSQL (IANA registry).
pub const ALPN_POSTGRESQL: &[u8] = b"postgresql";

/// TLS errors.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// PEM/DER content was invalid or empty.
    #[error("invalid certificate or key in {path}: {reason}")]
    InvalidPem {
        /// File path.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },
    /// rustls rejected the configuration.
    #[error("tls configuration error: {0}")]
    Config(String),
    /// Invalid server name for verification.
    #[error("invalid tls server name {0:?}")]
    ServerName(String),
}

/// Install aws-lc-rs as the process-wide rustls crypto provider. Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Listener TLS with hot reload.
///
/// Behaviour:
/// * `load` reads `cert_file` and `key_file` (PEM; key may be PKCS#8, PKCS#1
///   or SEC1), builds a `rustls::ServerConfig` with the configured minimum
///   version, no client authentication, and ALPN `["postgresql"]`. A client
///   that offers ALPN without `postgresql` fails the handshake (rustls default);
///   a client offering no ALPN is accepted (classic SSLRequest negotiation by
///   older libpq).
/// * The current config is held in an `ArcSwap`; [`acceptor`](Self::acceptor)
///   returns an acceptor for the current config.
/// * [`spawn_reloader`](Self::spawn_reloader) polls the files every
///   `interval`; when their contents change it rebuilds the config and swaps
///   it in. Invalid new files are logged and the old config stays active.
///   Polling (rather than inotify) is used because Kubernetes updates Secret
///   volumes with symlink swaps.
/// * Certificate expiry (leaf `notAfter`) is exported to
///   `pgbearer_tls_cert_expiry_timestamp_seconds{cert=<label>}`.
pub struct ServerTls {
    _private: (),
}

impl ServerTls {
    /// Load the certificate and key and build the initial config.
    pub fn load(cfg: &ListenerTlsConfig) -> Result<ServerTls, TlsError> {
        let _ = cfg;
        todo!("pgbearer-tls: ServerTls::load")
    }

    /// Build from PEM bytes (used by tests).
    pub fn from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
        min_tls13: bool,
    ) -> Result<ServerTls, TlsError> {
        let _ = (cert_pem, key_pem, min_tls13);
        todo!("pgbearer-tls: ServerTls::from_pem")
    }

    /// An acceptor for the current configuration.
    pub fn acceptor(&self) -> TlsAcceptor {
        todo!("pgbearer-tls: ServerTls::acceptor")
    }

    /// Leaf certificate expiry, if known.
    pub fn not_after(&self) -> Option<SystemTime> {
        todo!("pgbearer-tls: ServerTls::not_after")
    }

    /// Re-read the files now; returns `Ok(true)` if the config changed.
    pub fn reload_if_changed(&self) -> Result<bool, TlsError> {
        todo!("pgbearer-tls: ServerTls::reload_if_changed")
    }

    /// Poll for file changes every `interval` until `shutdown` is cancelled.
    pub fn spawn_reloader(
        self: &Arc<Self>,
        interval: Duration,
        metrics: Arc<Metrics>,
        cert_label: String,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let _ = (interval, metrics, cert_label, shutdown);
        todo!("pgbearer-tls: ServerTls::spawn_reloader")
    }
}

/// Paths of a client certificate and key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientCertPaths {
    /// PEM certificate chain.
    pub cert_file: PathBuf,
    /// PEM private key.
    pub key_file: PathBuf,
}

/// Client TLS to a backend.
///
/// Behaviour:
/// * `verify-full`: verify the chain against `ca_file` (or the webpki roots
///   when no `ca_file` is set) and the host name `server_name`.
/// * `verify-ca`: verify the chain but not the host name (custom verifier that
///   delegates chain validation to the webpki verifier and ignores name mismatch).
/// * `require`: accept any certificate (still encrypt). Logged as a warning at startup.
/// * `disable`: [`connector`](Self::connector) returns `Ok(None)`.
/// * Client certificates are loaded from files and cached keyed by path and
///   file modification time, so rotated certificates are picked up for new
///   connections without a restart.
pub struct BackendTls {
    _private: (),
}

impl BackendTls {
    /// Build from config. `server_name` is the host name to verify and send as SNI.
    pub fn new(cfg: &BackendTlsConfig, server_name: &str) -> Result<BackendTls, TlsError> {
        let _ = (cfg, server_name);
        todo!("pgbearer-tls: BackendTls::new")
    }

    /// The configured mode.
    pub fn mode(&self) -> BackendTlsMode {
        todo!("pgbearer-tls: BackendTls::mode")
    }

    /// A connector and server name for a new connection, optionally presenting
    /// a client certificate. `Ok(None)` when the mode is `disable`.
    pub fn connector(
        &self,
        client_cert: Option<&ClientCertPaths>,
    ) -> Result<Option<(TlsConnector, ServerName<'static>)>, TlsError> {
        let _ = client_cert;
        todo!("pgbearer-tls: BackendTls::connector")
    }
}

/// `tls-server-end-point` channel binding data: hash of the server's leaf
/// certificate (DER) using the certificate's signature hash algorithm, with
/// MD5 and SHA-1 upgraded to SHA-256 (RFC 5929 §4.1). Falls back to SHA-256
/// when the algorithm cannot be determined.
pub fn tls_server_end_point(cert_der: &[u8]) -> Vec<u8> {
    let _ = cert_der;
    todo!("pgbearer-tls: tls_server_end_point")
}

/// Read a PEM certificate chain file.
pub fn load_certs(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, TlsError> {
    let _ = path;
    todo!("pgbearer-tls: load_certs")
}

/// Read a PEM private key file (PKCS#8, PKCS#1 or SEC1).
pub fn load_private_key(path: &Path) -> Result<rustls_pki_types::PrivateKeyDer<'static>, TlsError> {
    let _ = path;
    todo!("pgbearer-tls: load_private_key")
}
