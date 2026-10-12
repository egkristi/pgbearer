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
//! [`install_crypto_provider`] once at startup (it is idempotent). Configs
//! built by this crate use the installed process-wide provider when there is
//! one (so a FIPS provider installed at startup is honoured) and aws-lc-rs
//! otherwise, so they also work when nothing was installed (tests).

mod endpoint;
mod verify;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use pgbearer_config::{BackendTlsConfig, BackendTlsMode, ListenerTlsConfig, TlsVersion};
use pgbearer_telemetry::{CertLabels, Metrics};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// ALPN protocol id for PostgreSQL (IANA registry).
pub const ALPN_POSTGRESQL: &[u8] = b"postgresql";

/// Largest certificate or key file that is read (8 MiB). Real files are a
/// few KiB (a full public CA bundle is a few hundred KiB); the limit only
/// guards against pointing a path at something like `/dev/zero`.
const MAX_PEM_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Shortest polling interval accepted by [`ServerTls::spawn_reloader`].
const MIN_RELOAD_INTERVAL: Duration = Duration::from_millis(10);

/// Upper bound on cached backend client-certificate configs. The keys come
/// from configuration, so this is only reached after many config reloads
/// that changed certificate paths; the cache is then simply cleared.
const MAX_CACHED_CLIENT_CERTS: usize = 1024;

/// Both TLS 1.3 and TLS 1.2, in preference order.
static TLS12_AND_TLS13: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// TLS 1.3 only.
static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

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

/// The crypto provider for configs built here: the installed process-wide
/// provider if there is one, aws-lc-rs otherwise.
fn crypto_provider() -> Arc<CryptoProvider> {
    if let Some(provider) = CryptoProvider::get_default() {
        return Arc::clone(provider);
    }
    static FALLBACK: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(FALLBACK.get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())))
}

// ---------------------------------------------------------------------------
// Listener TLS
// ---------------------------------------------------------------------------

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
///
/// The SNI host name a client sent is available after the handshake from the
/// accepted stream: `stream.get_ref().1.server_name()`.
pub struct ServerTls {
    /// The active configuration.
    current: ArcSwap<ServerState>,
    /// Where the certificate and key come from; `None` for [`ServerTls::from_pem`].
    files: Option<CertKeyFiles>,
    /// Whether TLS 1.2 is disabled.
    min_tls13: bool,
    /// Serialises reloads so that concurrent callers cannot swap in an older
    /// config after a newer one.
    reload_lock: Mutex<()>,
}

/// Certificate and key file paths of a listener.
#[derive(Debug, Clone)]
struct CertKeyFiles {
    cert_file: PathBuf,
    key_file: PathBuf,
}

/// One loaded listener configuration.
struct ServerState {
    config: Arc<ServerConfig>,
    not_after: Option<SystemTime>,
    /// SHA-256 over the certificate and key file contents, used to detect
    /// changes without rebuilding the config.
    fingerprint: [u8; 32],
}

impl ServerTls {
    /// Load the certificate and key and build the initial config.
    pub fn load(cfg: &ListenerTlsConfig) -> Result<ServerTls, TlsError> {
        let min_tls13 = match cfg.min_version {
            TlsVersion::Tls12 => false,
            TlsVersion::Tls13 => true,
        };
        let files = CertKeyFiles {
            cert_file: cfg.cert_file.clone(),
            key_file: cfg.key_file.clone(),
        };
        let cert_pem = read_file(&files.cert_file)?;
        let key_pem = SecretBytes(read_file(&files.key_file)?);
        let state = build_server_state(
            &cert_pem,
            &key_pem.0,
            &files.cert_file,
            &files.key_file,
            min_tls13,
        )?;
        warn_if_expired(state.not_after, &files.cert_file);
        debug!(
            cert_file = %files.cert_file.display(),
            not_after = ?state.not_after.and_then(unix_seconds),
            "listener TLS certificate loaded"
        );
        Ok(ServerTls {
            current: ArcSwap::from_pointee(state),
            files: Some(files),
            min_tls13,
            reload_lock: Mutex::new(()),
        })
    }

    /// Build from PEM bytes (used by tests).
    ///
    /// There are no files to watch, so [`reload_if_changed`](Self::reload_if_changed)
    /// always returns `Ok(false)` for such an instance.
    pub fn from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
        min_tls13: bool,
    ) -> Result<ServerTls, TlsError> {
        let state = build_server_state(
            cert_pem,
            key_pem,
            Path::new("<certificate PEM>"),
            Path::new("<key PEM>"),
            min_tls13,
        )?;
        Ok(ServerTls {
            current: ArcSwap::from_pointee(state),
            files: None,
            min_tls13,
            reload_lock: Mutex::new(()),
        })
    }

    /// An acceptor for the current configuration.
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::clone(&self.current.load().config))
    }

    /// Leaf certificate expiry, if known.
    pub fn not_after(&self) -> Option<SystemTime> {
        self.current.load().not_after
    }

    /// Re-read the files now; returns `Ok(true)` if the config changed.
    ///
    /// The files are compared by content (SHA-256), not by modification time.
    /// If the contents changed but do not form a valid certificate/key pair
    /// (unreadable, malformed, or a key that does not match the certificate),
    /// the error is returned and the current config stays active; the next
    /// call tries again. This does blocking file I/O.
    pub fn reload_if_changed(&self) -> Result<bool, TlsError> {
        let Some(files) = &self.files else {
            return Ok(false);
        };
        let _guard = self
            .reload_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let cert_pem = read_file(&files.cert_file)?;
        let key_pem = SecretBytes(read_file(&files.key_file)?);
        if fingerprint(&cert_pem, &key_pem.0) == self.current.load().fingerprint {
            return Ok(false);
        }
        let state = build_server_state(
            &cert_pem,
            &key_pem.0,
            &files.cert_file,
            &files.key_file,
            self.min_tls13,
        )?;
        warn_if_expired(state.not_after, &files.cert_file);
        self.current.store(Arc::new(state));
        Ok(true)
    }

    /// Poll for file changes every `interval` until `shutdown` is cancelled.
    ///
    /// Sets `pgbearer_tls_cert_expiry_timestamp_seconds{cert=<cert_label>}`
    /// when started and after every successful reload. Reload failures are
    /// logged (once per distinct error) and the previous certificate stays in
    /// use. File I/O runs on Tokio's blocking pool. An `interval` below 10 ms
    /// is raised to 10 ms.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime (like [`tokio::spawn`]).
    pub fn spawn_reloader(
        self: &Arc<Self>,
        interval: Duration,
        metrics: Arc<Metrics>,
        cert_label: String,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        let interval = interval.max(MIN_RELOAD_INTERVAL);
        tokio::spawn(async move {
            this.export_expiry(&metrics, &cert_label);
            if this.files.is_none() {
                // Nothing to watch.
                shutdown.cancelled().await;
                return;
            }
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_error: Option<String> = None;
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let worker = Arc::clone(&this);
                let result = match tokio::task::spawn_blocking(move || worker.reload_if_changed())
                    .await
                {
                    Ok(result) => result,
                    Err(join_error) => {
                        warn!(cert = %cert_label, error = %join_error, "TLS certificate reload task failed");
                        continue;
                    }
                };
                match result {
                    Ok(true) => {
                        last_error = None;
                        this.export_expiry(&metrics, &cert_label);
                        info!(
                            cert = %cert_label,
                            not_after = ?this.not_after().and_then(unix_seconds),
                            "TLS certificate reloaded"
                        );
                    }
                    Ok(false) => {
                        if last_error.take().is_some() {
                            info!(
                                cert = %cert_label,
                                "TLS certificate files are valid again and unchanged; keeping the current certificate"
                            );
                        }
                    }
                    Err(error) => {
                        let message = error.to_string();
                        if last_error.as_deref() == Some(message.as_str()) {
                            debug!(cert = %cert_label, error = %message, "TLS certificate reload still failing");
                        } else {
                            warn!(
                                cert = %cert_label,
                                error = %message,
                                "TLS certificate reload failed; keeping the previous certificate"
                            );
                        }
                        last_error = Some(message);
                    }
                }
            }
            debug!(cert = %cert_label, "TLS certificate reloader stopped");
        })
    }

    /// Export the current leaf expiry to the metrics (or remove the series
    /// when it is unknown).
    fn export_expiry(&self, metrics: &Metrics, cert_label: &str) {
        let labels = CertLabels {
            cert: cert_label.to_string(),
        };
        match self.not_after().and_then(unix_seconds) {
            Some(seconds) => {
                metrics.tls_cert_expiry.get_or_create(&labels).set(seconds);
            }
            None => {
                metrics.tls_cert_expiry.remove(&labels);
            }
        }
    }
}

impl fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTls")
            .field("cert_file", &self.files.as_ref().map(|f| &f.cert_file))
            .field("key_file", &self.files.as_ref().map(|f| &f.key_file))
            .field("min_tls13", &self.min_tls13)
            .field("not_after", &self.not_after())
            .finish_non_exhaustive()
    }
}

/// Parse a certificate chain and key and build the listener config.
fn build_server_state(
    cert_pem: &[u8],
    key_pem: &[u8],
    cert_path: &Path,
    key_path: &Path,
    min_tls13: bool,
) -> Result<ServerState, TlsError> {
    let fingerprint = fingerprint(cert_pem, key_pem);
    let certs = parse_certs(cert_pem, cert_path)?;
    let key = parse_private_key(key_pem, key_path)?;
    let not_after = certs
        .first()
        .and_then(|leaf| certificate_not_after(leaf.as_ref()));
    let versions = if min_tls13 {
        TLS13_ONLY
    } else {
        TLS12_AND_TLS13
    };
    let mut config = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(versions)
        .map_err(|e| TlsError::Config(format!("unsupported TLS protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            TlsError::Config(format!(
                "cannot use certificate {} with key {}: {e}",
                cert_path.display(),
                key_path.display()
            ))
        })?;
    config.alpn_protocols = vec![ALPN_POSTGRESQL.to_vec()];
    Ok(ServerState {
        config: Arc::new(config),
        not_after,
        fingerprint,
    })
}

/// Change-detection fingerprint of a certificate and key file pair.
fn fingerprint(cert_pem: &[u8], key_pem: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pgbearer-tls listener files v1\0");
    hasher.update((cert_pem.len() as u64).to_be_bytes());
    hasher.update(cert_pem);
    hasher.update((key_pem.len() as u64).to_be_bytes());
    hasher.update(key_pem);
    hasher.finalize().into()
}

fn warn_if_expired(not_after: Option<SystemTime>, cert_file: &Path) {
    if let Some(not_after) = not_after
        && not_after <= SystemTime::now()
    {
        warn!(
            cert_file = %cert_file.display(),
            not_after = ?unix_seconds(not_after),
            "listener TLS certificate has expired; clients will reject it"
        );
    }
}

// ---------------------------------------------------------------------------
// Backend TLS
// ---------------------------------------------------------------------------

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
///
/// Details:
/// * The CA file is read once, in [`new`](Self::new); rotating the CA bundle
///   needs a restart (or a new `BackendTls`, for example on config reload).
/// * The client offers ALPN `postgresql` (as libpq 17+ does). Servers before
///   PostgreSQL 17 ignore it; newer servers require it for direct TLS.
/// * The client-certificate cache entry is keyed by both paths and validated
///   against each file's modification time and length (and inode on Unix);
///   `metadata` follows symlinks, so Kubernetes `..data` symlink swaps are
///   detected. If rotated files cannot be loaded (for example the
///   certificate was replaced but the key not yet), the previously loaded
///   certificate keeps being used and a warning is logged once per change;
///   without a previous certificate the error is returned.
pub struct BackendTls {
    mode: BackendTlsMode,
    /// `None` for `disable`.
    inner: Option<BackendTlsInner>,
}

struct BackendTlsInner {
    server_name: ServerName<'static>,
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
    /// Trust source, for `Debug` and logs.
    roots: String,
    /// Config without a client certificate.
    base: Arc<ClientConfig>,
    client_certs: Mutex<HashMap<ClientCertPaths, CachedClientConfig>>,
}

/// A loaded client-certificate config and the file identities it came from.
struct CachedClientConfig {
    loaded: (FileStamp, FileStamp),
    config: Arc<ClientConfig>,
    /// File identities whose load failed (we then keep `config`); avoids
    /// re-reading and re-logging until the files change again.
    failed: Option<(Option<FileStamp>, Option<FileStamp>)>,
}

/// Identity of a file version: modification time, length and (on Unix) the
/// device and inode numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileStamp {
    /// Stamp of the file at `path` (following symlinks); `None` if it cannot
    /// be stat'ed.
    fn of(path: &Path) -> Option<FileStamp> {
        let meta = std::fs::metadata(path).ok()?;
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Some(FileStamp {
            modified: meta.modified().ok(),
            len: meta.len(),
            #[cfg(unix)]
            dev: meta.dev(),
            #[cfg(unix)]
            ino: meta.ino(),
        })
    }
}

impl BackendTls {
    /// Build from config. `server_name` is the host name to verify and send as SNI.
    ///
    /// `server_name` must be a DNS name or an IP address (an IPv6 address may
    /// be written in brackets); it is not validated for `disable`. For
    /// `verify-ca` and `verify-full` the trust anchors are loaded here from
    /// `ca_file`, or the Mozilla roots from `webpki-roots` when no `ca_file`
    /// is configured. `ca_file` is ignored for `require`.
    pub fn new(cfg: &BackendTlsConfig, server_name: &str) -> Result<BackendTls, TlsError> {
        let provider = crypto_provider();
        let (verifier, roots): (Arc<dyn ServerCertVerifier>, String) = match cfg.mode {
            BackendTlsMode::Disable => {
                warn!(
                    server_name,
                    "backend TLS is disabled; credentials and data are sent in cleartext"
                );
                return Ok(BackendTls {
                    mode: cfg.mode,
                    inner: None,
                });
            }
            BackendTlsMode::Require => {
                warn!(
                    server_name,
                    "backend TLS mode `require` does not verify the server certificate; \
                     connections are encrypted but not protected against a man in the middle"
                );
                if let Some(ca_file) = &cfg.ca_file {
                    warn!(
                        server_name,
                        ca_file = %ca_file.display(),
                        "ca_file is ignored in backend TLS mode `require`; use `verify-ca` or `verify-full` to verify against it"
                    );
                }
                (
                    Arc::new(verify::AcceptAnyServerCert::new(
                        provider.signature_verification_algorithms,
                    )),
                    "none (require)".to_string(),
                )
            }
            BackendTlsMode::VerifyCa => {
                if cfg.ca_file.is_none() {
                    warn!(
                        server_name,
                        "backend TLS mode `verify-ca` without ca_file accepts any publicly trusted certificate for any host name"
                    );
                }
                let (webpki, roots) = webpki_verifier(cfg.ca_file.as_deref(), &provider)?;
                (Arc::new(verify::VerifyChainOnly::new(webpki)), roots)
            }
            BackendTlsMode::VerifyFull => {
                let (webpki, roots) = webpki_verifier(cfg.ca_file.as_deref(), &provider)?;
                (webpki, roots)
            }
        };
        let server_name = parse_server_name(server_name)?;
        let base = build_client_config(&provider, &verifier, None)?;
        Ok(BackendTls {
            mode: cfg.mode,
            inner: Some(BackendTlsInner {
                server_name,
                provider,
                verifier,
                roots,
                base,
                client_certs: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The configured mode.
    pub fn mode(&self) -> BackendTlsMode {
        self.mode
    }

    /// A connector and server name for a new connection, optionally presenting
    /// a client certificate. `Ok(None)` when the mode is `disable`.
    ///
    /// With a client certificate this may read the certificate files (when
    /// they changed since the last call), which is small blocking file I/O.
    pub fn connector(
        &self,
        client_cert: Option<&ClientCertPaths>,
    ) -> Result<Option<(TlsConnector, ServerName<'static>)>, TlsError> {
        let Some(inner) = &self.inner else {
            return Ok(None);
        };
        let config = match client_cert {
            None => Arc::clone(&inner.base),
            Some(paths) => inner.client_cert_config(paths)?,
        };
        Ok(Some((
            TlsConnector::from(config),
            inner.server_name.clone(),
        )))
    }
}

impl BackendTlsInner {
    /// The config presenting the client certificate at `paths`, from the
    /// cache when the files are unchanged.
    fn client_cert_config(&self, paths: &ClientCertPaths) -> Result<Arc<ClientConfig>, TlsError> {
        let stamps = (
            FileStamp::of(&paths.cert_file),
            FileStamp::of(&paths.key_file),
        );
        {
            let cache = self
                .client_certs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = cache.get(paths) {
                let unchanged = matches!(stamps, (Some(c), Some(k)) if (c, k) == entry.loaded);
                if unchanged || entry.failed == Some(stamps) {
                    return Ok(Arc::clone(&entry.config));
                }
            }
        }

        // Load outside the lock: concurrent connects for other certificates
        // must not wait for this file I/O.
        let loaded = load_certs(&paths.cert_file).and_then(|certs| {
            let key = load_private_key(&paths.key_file)?;
            build_client_config(&self.provider, &self.verifier, Some((certs, key)))
        });

        let mut cache = self
            .client_certs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match loaded {
            Ok(config) => {
                if let (Some(cert), Some(key)) = stamps {
                    if cache.len() >= MAX_CACHED_CLIENT_CERTS && !cache.contains_key(paths) {
                        cache.clear();
                    }
                    cache.insert(
                        paths.clone(),
                        CachedClientConfig {
                            loaded: (cert, key),
                            config: Arc::clone(&config),
                            failed: None,
                        },
                    );
                }
                debug!(
                    cert_file = %paths.cert_file.display(),
                    "backend client certificate loaded"
                );
                Ok(config)
            }
            Err(error) => match cache.get_mut(paths) {
                Some(entry) => {
                    if entry.failed != Some(stamps) {
                        warn!(
                            cert_file = %paths.cert_file.display(),
                            key_file = %paths.key_file.display(),
                            error = %error,
                            "cannot load the changed backend client certificate; keeping the previous one"
                        );
                        entry.failed = Some(stamps);
                    }
                    Ok(Arc::clone(&entry.config))
                }
                None => Err(error),
            },
        }
    }
}

impl fmt::Debug for BackendTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("BackendTls");
        d.field("mode", &self.mode);
        if let Some(inner) = &self.inner {
            let cached = inner
                .client_certs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len();
            d.field("server_name", &inner.server_name)
                .field("roots", &inner.roots)
                .field("cached_client_certs", &cached);
        }
        d.finish_non_exhaustive()
    }
}

/// Parse a backend host name or IP address for verification and SNI.
fn parse_server_name(name: &str) -> Result<ServerName<'static>, TlsError> {
    let candidate = name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(name);
    ServerName::try_from(candidate.to_string()).map_err(|_| TlsError::ServerName(name.to_string()))
}

/// A webpki verifier for the CA file (or the webpki roots), plus a
/// description of the trust source.
fn webpki_verifier(
    ca_file: Option<&Path>,
    provider: &Arc<CryptoProvider>,
) -> Result<(Arc<WebPkiServerVerifier>, String), TlsError> {
    let (roots, description) = match ca_file {
        Some(path) => {
            let certs = load_certs(path)?;
            let mut roots = RootCertStore::empty();
            let (added, ignored) = roots.add_parsable_certificates(certs);
            if added == 0 {
                return Err(invalid_pem(
                    path,
                    "none of the CA certificates could be used as a trust anchor",
                ));
            }
            if ignored > 0 {
                warn!(
                    ca_file = %path.display(),
                    ignored,
                    "ignored CA certificates that could not be parsed"
                );
            }
            (roots, format!("ca_file {}", path.display()))
        }
        None => (
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
            "webpki-roots".to_string(),
        ),
    };
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
            .build()
            .map_err(|e| TlsError::Config(format!("cannot build the certificate verifier: {e}")))?;
    Ok((verifier, description))
}

/// A backend client config with the given verifier and optional client
/// certificate.
fn build_client_config(
    provider: &Arc<CryptoProvider>,
    verifier: &Arc<dyn ServerCertVerifier>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let builder = ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(TLS12_AND_TLS13)
        .map_err(|e| TlsError::Config(format!("unsupported TLS protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(verifier));
    let mut config = match client_auth {
        None => builder.with_no_client_auth(),
        Some((certs, key)) => builder.with_client_auth_cert(certs, key).map_err(|e| {
            TlsError::Config(format!(
                "cannot use the backend client certificate and key: {e}"
            ))
        })?,
    };
    config.alpn_protocols = vec![ALPN_POSTGRESQL.to_vec()];
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Channel binding and certificate helpers
// ---------------------------------------------------------------------------

/// `tls-server-end-point` channel binding data: hash of the server's leaf
/// certificate (DER) using the certificate's signature hash algorithm, with
/// MD5 and SHA-1 upgraded to SHA-256 (RFC 5929 §4.1). Falls back to SHA-256
/// when the algorithm cannot be determined.
///
/// Recognised: RSA PKCS#1 v1.5, RSASSA-PSS (hash from its parameters),
/// ECDSA and DSA with SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 (and MD5 for
/// RSA). SHA-224 certificates hash with SHA-224, as PostgreSQL does. Ed25519,
/// Ed448 and unknown algorithms use SHA-256. Never panics; the input may be
/// arbitrary bytes.
pub fn tls_server_end_point(cert_der: &[u8]) -> Vec<u8> {
    endpoint::end_point_hash(cert_der).digest(cert_der)
}

/// [`tls_server_end_point`] of the peer's leaf certificate on an established
/// TLS connection (for example `tls_stream.get_ref().1` of a
/// `tokio_rustls::client::TlsStream`); `None` if the peer sent no
/// certificate.
pub fn peer_tls_server_end_point(connection: &rustls::CommonState) -> Option<Vec<u8>> {
    connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| tls_server_end_point(leaf.as_ref()))
}

/// The `notAfter` time of a DER certificate; `None` if it cannot be parsed.
pub fn certificate_not_after(cert_der: &[u8]) -> Option<SystemTime> {
    use x509_parser::nom::Parser;
    let mut parser =
        x509_parser::certificate::X509CertificateParser::new().with_deep_parse_extensions(false);
    let (_, cert) = parser.parse(cert_der).ok()?;
    system_time_from_unix(cert.validity().not_after.timestamp())
}

/// Read a PEM certificate chain file.
///
/// Every `CERTIFICATE` block is returned in file order (leaf first for a
/// chain); other blocks and text between blocks are ignored. Fails if the
/// file cannot be read, has a malformed block, or contains no certificate.
pub fn load_certs(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, TlsError> {
    parse_certs(&read_file(path)?, path)
}

/// Read a PEM private key file (PKCS#8, PKCS#1 or SEC1).
///
/// The first `PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY` block is
/// returned. Encrypted keys are not supported. The read buffer is
/// overwritten before it is freed (best effort).
pub fn load_private_key(path: &Path) -> Result<rustls_pki_types::PrivateKeyDer<'static>, TlsError> {
    let pem = SecretBytes(read_file(path)?);
    parse_private_key(&pem.0, path)
}

// ---------------------------------------------------------------------------
// File and PEM helpers
// ---------------------------------------------------------------------------

/// File contents that are overwritten with zeros when dropped (best effort:
/// earlier reallocations while reading are not covered).
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// Read a whole file of at most [`MAX_PEM_FILE_BYTES`].
fn read_file(path: &Path) -> Result<Vec<u8>, TlsError> {
    let io_error = |source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io_error)?;
    // Pre-size from the metadata to avoid reallocations (which would leave
    // copies of key material behind); fall back to growing.
    let expected = file
        .metadata()
        .map(|m| m.len().min(MAX_PEM_FILE_BYTES))
        .unwrap_or(0);
    let mut buf = Vec::with_capacity(usize::try_from(expected).unwrap_or(0).saturating_add(1));
    file.take(MAX_PEM_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(io_error)?;
    if buf.len() as u64 > MAX_PEM_FILE_BYTES {
        buf.fill(0);
        return Err(invalid_pem(
            path,
            format!("file is larger than {MAX_PEM_FILE_BYTES} bytes"),
        ));
    }
    Ok(buf)
}

fn invalid_pem(path: &Path, reason: impl Into<String>) -> TlsError {
    TlsError::InvalidPem {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// Describe a PEM error without echoing file contents (which may be key
/// material).
fn describe_pem_error(error: &pem::Error) -> String {
    match error {
        pem::Error::MissingSectionEnd { .. } => "a PEM block has no matching END line".to_string(),
        pem::Error::IllegalSectionStart { .. } => "malformed PEM BEGIN line".to_string(),
        pem::Error::Base64Decode(_) => "invalid base64 in a PEM block".to_string(),
        pem::Error::NoItemsFound => "no matching PEM block found".to_string(),
        pem::Error::SectionTooLarge => "a PEM block is too large".to_string(),
        pem::Error::Io(e) => format!("read error: {e}"),
        _ => "malformed PEM".to_string(),
    }
}

/// All `CERTIFICATE` blocks in `pem`.
fn parse_certs(pem: &[u8], path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut certs = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem) {
        certs.push(item.map_err(|e| invalid_pem(path, describe_pem_error(&e)))?);
    }
    if certs.is_empty() {
        return Err(invalid_pem(path, "no CERTIFICATE PEM block found"));
    }
    Ok(certs)
}

/// The first private key block in `pem`.
fn parse_private_key(pem: &[u8], path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    match PrivateKeyDer::from_pem_slice(pem) {
        Ok(key) => Ok(key),
        Err(pem::Error::NoItemsFound) => {
            let reason = if contains(pem, b"-----BEGIN ENCRYPTED PRIVATE KEY-----") {
                "encrypted private keys are not supported; provide an unencrypted PKCS#8, PKCS#1 or SEC1 key"
            } else {
                "no private key found (expected a PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY PEM block)"
            };
            Err(invalid_pem(path, reason))
        }
        Err(e) => Err(invalid_pem(path, describe_pem_error(&e))),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Unix seconds (negative before 1970) to `SystemTime`.
fn system_time_from_unix(seconds: i64) -> Option<SystemTime> {
    match u64::try_from(seconds) {
        Ok(secs) => UNIX_EPOCH.checked_add(Duration::from_secs(secs)),
        Err(_) => UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs())),
    }
}

/// `SystemTime` to Unix seconds (negative before 1970).
fn unix_seconds(time: SystemTime) -> Option<i64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).ok(),
        Err(before) => i64::try_from(before.duration().as_secs()).ok().map(|s| -s),
    }
}
