//! Configuration model for pgbearer.
//!
//! The configuration is a single YAML document (`pgbearer.yaml`):
//!
//! ```yaml
//! apiVersion: pgbearer/v1alpha1
//! kind: ProxyConfig
//! listeners: [...]
//! identity_providers: [...]
//! backends: [...]
//! routes: [...]
//! policies: [...]
//! ```
//!
//! Every struct rejects unknown fields so that typos fail loudly. Secrets are
//! never inlined: they are referenced as files (`*_file`) so they can be
//! mounted from Kubernetes Secrets and rotated without a restart.
//!
//! [`Config::load`] parses and validates. Validation checks cross-references
//! (routes → backends, grants → backends/providers), required fields per
//! provider type, and value ranges. See [`Config::validate`].

pub mod duration;
mod validate;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use pgbearer_core::{IdentityKind, PoolMode, TokenExpiryAction};

/// The only supported `apiVersion`.
pub const API_VERSION: &str = "pgbearer/v1alpha1";
/// The only supported `kind`.
pub const KIND: &str = "ProxyConfig";

/// Errors from loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Io {
        /// Path of the file.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The YAML could not be parsed into the model.
    #[error("invalid config syntax: {0}")]
    Parse(String),
    /// The configuration parsed but is semantically invalid.
    #[error("invalid config:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// Root of the configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Must be [`API_VERSION`].
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Must be [`KIND`].
    pub kind: String,
    /// Admin HTTP server (health, metrics).
    #[serde(default)]
    pub admin: AdminConfig,
    /// PostgreSQL-protocol listeners.
    pub listeners: Vec<ListenerConfig>,
    /// Trusted token issuers.
    pub identity_providers: Vec<IdentityProviderConfig>,
    /// PostgreSQL backends (clusters).
    pub backends: Vec<BackendConfig>,
    /// Routing from SNI / database name to backends.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Grants: who may connect to what, as which role.
    #[serde(default)]
    pub policies: Vec<GrantRule>,
    /// Deny rules; they take precedence over grants.
    #[serde(default)]
    pub deny: Vec<DenyRule>,
    /// Session lifetime settings.
    #[serde(default)]
    pub session: SessionConfig,
    /// Resource limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Graceful shutdown.
    #[serde(default)]
    pub drain: DrainConfig,
    /// Audit logging.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Process logging.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Identity propagation to PostgreSQL (GUCs, application_name).
    #[serde(default)]
    pub propagation: PropagationConfig,
}

impl Config {
    /// Parse a configuration from YAML text and validate it.
    pub fn from_yaml_str(text: &str) -> Result<Config, ConfigError> {
        let config: Config =
            serde_saphyr::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Read, parse and validate a configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_yaml_str(&text)
    }

    /// Semantic validation. Returns every problem found, not just the first.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let problems = validate::validate(self);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems))
        }
    }

    /// Find a backend by name.
    pub fn backend(&self, name: &str) -> Option<&BackendConfig> {
        self.backends.iter().find(|b| b.name == name)
    }

    /// Find an identity provider by name.
    pub fn identity_provider(&self, name: &str) -> Option<&IdentityProviderConfig> {
        self.identity_providers.iter().find(|p| p.name == name)
    }
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

/// Admin HTTP server: `/livez`, `/readyz`, `/metrics`, and the optional admin API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// Listen address. Set to `null` to disable the admin server.
    pub address: Option<SocketAddr>,
    /// Enable `POST /admin/reload` and `POST /admin/drain`. Off by default; when
    /// enabled, bind `address` to localhost or protect it with NetworkPolicy.
    pub enable_admin_api: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        AdminConfig {
            address: Some(SocketAddr::from(([0, 0, 0, 0], 9090))),
            enable_admin_api: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

/// A PostgreSQL-protocol listener.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Unique name (used in metrics, audit and policy predicates).
    pub name: String,
    /// Listen address, for example `0.0.0.0:5432`.
    pub address: SocketAddr,
    /// TLS settings. Required unless `insecure_allow_plaintext_auth` is set.
    #[serde(default)]
    pub tls: Option<ListenerTlsConfig>,
    /// PROXY protocol v2 handling.
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolMode,
    /// How clients authenticate on this listener.
    #[serde(default)]
    pub client_auth: ClientAuthMethod,
    /// For `client_auth: oauthbearer`: the identity provider whose issuer and
    /// scope are advertised to clients in the OAUTHBEARER discovery exchange.
    #[serde(default)]
    pub oauthbearer_provider: Option<String>,
    /// Allow tokens over unencrypted connections. Development only.
    #[serde(default)]
    pub insecure_allow_plaintext_auth: bool,
}

/// Listener TLS settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerTlsConfig {
    /// PEM certificate chain.
    pub cert_file: PathBuf,
    /// PEM private key.
    pub key_file: PathBuf,
    /// Minimum TLS version.
    #[serde(default)]
    pub min_version: TlsVersion,
    /// Accept direct TLS (PostgreSQL 17+ `sslnegotiation=direct`, ALPN `postgresql`).
    #[serde(default = "default_true")]
    pub direct_tls: bool,
    /// How often to check the certificate files for changes.
    #[serde(default = "default_cert_reload_interval", with = "duration")]
    pub reload_interval: Duration,
}

/// Minimum TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TlsVersion {
    /// TLS 1.2 or newer.
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    /// TLS 1.3 only.
    #[serde(rename = "1.3")]
    Tls13,
}

/// PROXY protocol v2 handling on a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolMode {
    /// Never expect a PROXY header.
    #[default]
    Off,
    /// Accept a PROXY v2 header if present.
    Optional,
    /// Require a PROXY v2 header.
    Required,
}

/// Client authentication method on a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// Access token sent as the password (`AuthenticationCleartextPassword`).
    #[default]
    TokenPassword,
    /// SASL `OAUTHBEARER` (RFC 7628), for libpq/psql 18+.
    Oauthbearer,
}

// ---------------------------------------------------------------------------
// Identity providers
// ---------------------------------------------------------------------------

/// A trusted token issuer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProviderConfig {
    /// Unique name, used in policies (`when.issuer`) and audit.
    pub name: String,
    /// Provider type; selects defaults for claims and validation.
    #[serde(rename = "type", default)]
    pub kind: IdpType,
    /// Issuer URL; must equal the token's `iss` exactly. Optional for
    /// `github-actions` and `kubernetes`, which have well-known defaults.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Accepted audiences (`aud`). At least one is required.
    pub audiences: Vec<String>,
    /// Override the discovery document URL (default: issuer + `/.well-known/openid-configuration`).
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Use this JWKS URL directly and skip discovery.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Extra CA bundle (PEM) for HTTPS to the issuer, for example the
    /// Kubernetes API server CA.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Bearer token file sent when fetching discovery/JWKS, for example the
    /// pod's ServiceAccount token for the Kubernetes API server.
    #[serde(default)]
    pub bearer_token_file: Option<PathBuf>,
    /// Allowed signing algorithms.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<JwtAlgorithm>,
    /// Clock-skew leeway for `exp`, `nbf` and `iat`.
    #[serde(default = "default_leeway", with = "duration")]
    pub leeway: Duration,
    /// If true (default), the proxy is not ready until this issuer's JWKS is loaded.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Claim names; unset fields use the defaults for `type`.
    #[serde(default)]
    pub claims: ClaimMapping,
    /// Allowed tenants (`tid`). Required for `type: entra`.
    #[serde(default)]
    pub tenants: Vec<String>,
    /// Scopes that must all be present in delegated (user) tokens.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// If set, only tokens requested by these OAuth clients are accepted.
    #[serde(default)]
    pub allowed_client_ids: Vec<String>,
    /// If set, the JWT header `typ` must equal this value (for example `at+jwt`).
    #[serde(default)]
    pub expected_typ: Option<String>,
    /// JWKS cache behaviour.
    #[serde(default)]
    pub jwks: JwksConfig,
    /// Allow `http://` issuer URLs. Testing only.
    #[serde(default)]
    pub insecure_allow_http: bool,
    /// Settings used only by `oauthbearer` listeners.
    #[serde(default)]
    pub oauthbearer: Option<OauthBearerConfig>,
}

impl IdentityProviderConfig {
    /// The issuer URL, applying the default for the provider type.
    pub fn effective_issuer(&self) -> Option<String> {
        self.issuer.clone().or_else(|| match self.kind {
            IdpType::GithubActions => Some("https://token.actions.githubusercontent.com".into()),
            IdpType::Kubernetes => Some("https://kubernetes.default.svc.cluster.local".into()),
            _ => None,
        })
    }

    /// The claim mapping with type-specific defaults filled in.
    pub fn effective_claims(&self) -> EffectiveClaims {
        let d = EffectiveClaims::defaults_for(self.kind);
        let c = &self.claims;
        EffectiveClaims {
            subject: c.subject.clone().unwrap_or(d.subject),
            username: c.username.clone().or(d.username),
            groups: c.groups.clone().or(d.groups),
            roles: c.roles.clone().or(d.roles),
            scopes: c.scopes.clone().or(d.scopes),
            tenant: c.tenant.clone().or(d.tenant),
            client_id: c.client_id.clone().or(d.client_id),
        }
    }
}

/// Provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IdpType {
    /// Generic OpenID Connect provider (Keycloak, Okta, Auth0, Dex, Google, …).
    #[default]
    Oidc,
    /// Microsoft Entra ID (v2 access tokens).
    Entra,
    /// Kubernetes ServiceAccount tokens (projected tokens).
    Kubernetes,
    /// GitHub Actions OIDC tokens.
    GithubActions,
}

/// Allowed JWT signing algorithms. Symmetric algorithms and `none` are never allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RS512,
    /// RSASSA-PSS with SHA-256.
    PS256,
    /// RSASSA-PSS with SHA-384.
    PS384,
    /// RSASSA-PSS with SHA-512.
    PS512,
    /// ECDSA P-256 with SHA-256.
    ES256,
    /// ECDSA P-384 with SHA-384.
    ES384,
    /// Ed25519.
    EdDSA,
}

/// Claim names, overriding the per-type defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ClaimMapping {
    /// Stable subject claim (default `sub`; Entra `oid`).
    pub subject: Option<String>,
    /// Display-name claim.
    pub username: Option<String>,
    /// Groups claim (string or array). Dotted paths are allowed.
    pub groups: Option<String>,
    /// Roles claim (string or array). Dotted paths are allowed.
    pub roles: Option<String>,
    /// Scopes claim (space-separated string or array).
    pub scopes: Option<String>,
    /// Tenant claim.
    pub tenant: Option<String>,
    /// Client-id claim.
    pub client_id: Option<String>,
}

/// Claim names with defaults applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveClaims {
    /// Subject claim.
    pub subject: String,
    /// Username claim.
    pub username: Option<String>,
    /// Groups claim.
    pub groups: Option<String>,
    /// Roles claim.
    pub roles: Option<String>,
    /// Scopes claim.
    pub scopes: Option<String>,
    /// Tenant claim.
    pub tenant: Option<String>,
    /// Client-id claim.
    pub client_id: Option<String>,
}

impl EffectiveClaims {
    /// Defaults for a provider type.
    pub fn defaults_for(kind: IdpType) -> EffectiveClaims {
        match kind {
            IdpType::Oidc => EffectiveClaims {
                subject: "sub".into(),
                username: Some("preferred_username".into()),
                groups: Some("groups".into()),
                roles: Some("roles".into()),
                scopes: Some("scope".into()),
                tenant: None,
                client_id: Some("azp".into()),
            },
            IdpType::Entra => EffectiveClaims {
                subject: "oid".into(),
                username: Some("preferred_username".into()),
                groups: Some("groups".into()),
                roles: Some("roles".into()),
                scopes: Some("scp".into()),
                tenant: Some("tid".into()),
                client_id: Some("azp".into()),
            },
            IdpType::Kubernetes => EffectiveClaims {
                subject: "sub".into(),
                username: Some("sub".into()),
                groups: None,
                roles: None,
                scopes: None,
                tenant: None,
                client_id: None,
            },
            IdpType::GithubActions => EffectiveClaims {
                subject: "sub".into(),
                username: Some("repository".into()),
                groups: None,
                roles: None,
                scopes: None,
                tenant: Some("repository_owner".into()),
                client_id: None,
            },
        }
    }
}

/// JWKS cache behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct JwksConfig {
    /// Minimum interval between refreshes triggered by unknown `kid` values.
    #[serde(with = "duration")]
    pub min_refresh_interval: Duration,
    /// Maximum age before a background refresh.
    #[serde(with = "duration")]
    pub max_age: Duration,
    /// How long to keep using the last good key set when refresh fails.
    #[serde(with = "duration")]
    pub max_stale: Duration,
    /// HTTP timeout for discovery and JWKS requests.
    #[serde(with = "duration")]
    pub http_timeout: Duration,
}

impl Default for JwksConfig {
    fn default() -> Self {
        JwksConfig {
            min_refresh_interval: Duration::from_secs(30),
            max_age: Duration::from_secs(3600),
            max_stale: Duration::from_secs(24 * 3600),
            http_timeout: Duration::from_secs(10),
        }
    }
}

/// Settings for SASL OAUTHBEARER discovery responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthBearerConfig {
    /// Scope the client should request, for example `api://pgbearer/Database.Connect`.
    pub scope: String,
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// A PostgreSQL backend (cluster).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// Unique name, referenced from routes and grants.
    pub name: String,
    /// A static host and port. Exactly one of `static` and `cnpg` must be set.
    #[serde(default, rename = "static")]
    pub static_endpoint: Option<StaticEndpoint>,
    /// A CloudNativePG cluster service.
    #[serde(default)]
    pub cnpg: Option<CnpgEndpoint>,
    /// TLS to the backend.
    #[serde(default)]
    pub tls: BackendTlsConfig,
    /// How pgbearer logs in as the mapped role.
    pub login: BackendLoginConfig,
    /// Pool settings.
    #[serde(default)]
    pub pool: PoolConfig,
}

impl BackendConfig {
    /// Host and port to connect to.
    pub fn host_port(&self) -> Option<(String, u16)> {
        if let Some(s) = &self.static_endpoint {
            return Some((s.host.clone(), s.port));
        }
        self.cnpg.as_ref().map(|c| (c.service_host(), c.port))
    }

    /// The name to verify in the server certificate (and send as SNI).
    pub fn tls_server_name(&self) -> Option<String> {
        self.tls
            .server_name
            .clone()
            .or_else(|| self.host_port().map(|(h, _)| h))
    }
}

/// A static backend address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticEndpoint {
    /// Host name or IP address.
    pub host: String,
    /// Port.
    #[serde(default = "default_pg_port")]
    pub port: u16,
}

/// A CloudNativePG cluster, reached through its Kubernetes Service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CnpgEndpoint {
    /// `Cluster` resource name.
    pub cluster: String,
    /// Namespace of the cluster.
    pub namespace: String,
    /// Which CNPG service to use.
    #[serde(default)]
    pub service: CnpgService,
    /// Port.
    #[serde(default = "default_pg_port")]
    pub port: u16,
    /// Kubernetes cluster DNS domain.
    #[serde(default = "default_cluster_domain")]
    pub cluster_domain: String,
}

impl CnpgEndpoint {
    /// `<cluster>-<svc>.<namespace>.svc.<domain>`.
    pub fn service_host(&self) -> String {
        format!(
            "{}-{}.{}.svc.{}",
            self.cluster,
            self.service.suffix(),
            self.namespace,
            self.cluster_domain
        )
    }
}

/// CloudNativePG service selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CnpgService {
    /// Primary (read/write).
    #[default]
    Rw,
    /// Replicas (read-only).
    Ro,
    /// Any instance (read).
    R,
}

impl CnpgService {
    /// Service-name suffix.
    pub fn suffix(self) -> &'static str {
        match self {
            CnpgService::Rw => "rw",
            CnpgService::Ro => "ro",
            CnpgService::R => "r",
        }
    }
}

/// TLS to a backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendTlsConfig {
    /// Verification mode.
    #[serde(default)]
    pub mode: BackendTlsMode,
    /// CA bundle (PEM). Required for `verify-ca` and `verify-full`.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Override the name verified in the server certificate.
    #[serde(default)]
    pub server_name: Option<String>,
}

impl Default for BackendTlsConfig {
    fn default() -> Self {
        BackendTlsConfig {
            mode: BackendTlsMode::VerifyFull,
            ca_file: None,
            server_name: None,
        }
    }
}

/// Backend TLS mode (same meaning as libpq `sslmode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackendTlsMode {
    /// No TLS. Only for local development.
    Disable,
    /// TLS without certificate verification.
    Require,
    /// TLS, verify the chain but not the host name.
    VerifyCa,
    /// TLS, verify chain and host name.
    #[default]
    VerifyFull,
}

/// How pgbearer authenticates to the backend as the mapped role.
///
/// * Strategy A: `method: cert` with one `cert_file`/`key_file` for all roles
///   (PostgreSQL `cert` auth with a `pg_ident` map such as `+pgbearer_login`).
/// * Strategy B: `method: cert` with per-role entries in `roles`.
/// * Strategy C: `method: password` with per-role `password_file` entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLoginConfig {
    /// Default method.
    pub method: LoginMethod,
    /// Default client certificate (strategy A).
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    /// Default client key (strategy A).
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// Per-role credentials (strategies B and C).
    #[serde(default)]
    pub roles: BTreeMap<String, RoleCredentialConfig>,
}

/// Login method to the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    /// TLS client certificate.
    Cert,
    /// SCRAM-SHA-256 (or MD5/cleartext if the server asks) with a password file.
    Password,
}

/// Credentials for one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RoleCredentialConfig {
    /// Client certificate for this role.
    pub cert_file: Option<PathBuf>,
    /// Client key for this role.
    pub key_file: Option<PathBuf>,
    /// Password file for this role (read on every new backend connection).
    pub password_file: Option<PathBuf>,
}

/// Resolved credential for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCredential {
    /// Use this client certificate and key.
    Cert {
        /// Certificate chain file.
        cert_file: PathBuf,
        /// Private key file.
        key_file: PathBuf,
    },
    /// Use the password in this file.
    Password {
        /// Password file.
        password_file: PathBuf,
    },
}

impl BackendLoginConfig {
    /// Credential for `role`, or `None` if the role has none configured.
    pub fn credential_for(&self, role: &str) -> Option<ResolvedCredential> {
        if let Some(rc) = self.roles.get(role) {
            if let Some(password_file) = &rc.password_file {
                return Some(ResolvedCredential::Password {
                    password_file: password_file.clone(),
                });
            }
            if let (Some(c), Some(k)) = (&rc.cert_file, &rc.key_file) {
                return Some(ResolvedCredential::Cert {
                    cert_file: c.clone(),
                    key_file: k.clone(),
                });
            }
        }
        match (self.method, &self.cert_file, &self.key_file) {
            (LoginMethod::Cert, Some(c), Some(k)) => Some(ResolvedCredential::Cert {
                cert_file: c.clone(),
                key_file: k.clone(),
            }),
            _ => None,
        }
    }
}

/// Pool settings for a backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolConfig {
    /// Default pooling mode (grants may override).
    pub mode: PoolMode,
    /// Maximum backend connections to this backend across all pools (per replica).
    pub max_backend_connections: u32,
    /// Maximum connections per `(database, role)` pool.
    pub max_connections: u32,
    /// How long a client waits for a connection before `53300`.
    #[serde(with = "duration")]
    pub acquire_timeout: Duration,
    /// Close idle backend connections after this long.
    #[serde(with = "duration")]
    pub idle_timeout: Duration,
    /// Recycle backend connections after this long (±10 % jitter).
    #[serde(with = "duration")]
    pub max_lifetime: Duration,
    /// TCP + TLS + auth timeout for new backend connections.
    #[serde(with = "duration")]
    pub connect_timeout: Duration,
    /// Run a cheap health check on checkout if idle longer than this.
    #[serde(with = "duration")]
    pub health_check_idle: Duration,
    /// Query used to reset a session-mode connection before reuse.
    pub reset_query: String,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            mode: PoolMode::Session,
            max_backend_connections: 100,
            max_connections: 20,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            connect_timeout: Duration::from_secs(5),
            health_check_idle: Duration::from_secs(30),
            reset_query: "DISCARD ALL".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Map incoming connections to a backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Match conditions; all set conditions must match.
    #[serde(rename = "match", default)]
    pub matcher: RouteMatch,
    /// Target backend name.
    pub backend: String,
}

/// Route match conditions. An empty match matches everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RouteMatch {
    /// TLS SNI host name; a leading `*.` matches one label.
    pub sni: Option<String>,
    /// Database names (`*` matches any).
    pub databases: Vec<String>,
    /// Listener names.
    pub listeners: Vec<String>,
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// A grant: when the predicate matches, the identity may use these roles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRule {
    /// Unique name (recorded in audit events).
    pub name: String,
    /// Predicate over identity and connection.
    #[serde(default)]
    pub when: Predicate,
    /// What is granted.
    pub grant: Grant,
}

/// A deny rule; a match refuses the connection even if grants match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRule {
    /// Unique name.
    pub name: String,
    /// Predicate.
    #[serde(default)]
    pub when: Predicate,
}

/// A predicate. All set conditions must hold (logical AND). List conditions
/// ending in `_any` need at least one overlap; `_all` need all elements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Predicate {
    /// Identity provider name.
    pub issuer: Option<String>,
    /// Exact subject. A trailing `*` matches a prefix.
    pub subject: Option<String>,
    /// Any of these subjects (same matching as `subject`).
    pub subjects: Vec<String>,
    /// Exact username. A trailing `*` matches a prefix.
    pub username: Option<String>,
    /// At least one of these roles.
    pub roles_any: Vec<String>,
    /// All of these roles.
    pub roles_all: Vec<String>,
    /// At least one of these groups.
    pub groups_any: Vec<String>,
    /// All of these groups.
    pub groups_all: Vec<String>,
    /// At least one of these scopes.
    pub scopes_any: Vec<String>,
    /// Tenant is one of these.
    pub tenants: Vec<String>,
    /// Client id is one of these.
    pub client_ids: Vec<String>,
    /// Identity kind.
    pub kind: Option<IdentityKind>,
    /// Arbitrary claim conditions.
    pub claims: Vec<ClaimPredicate>,
    /// Client source address is in one of these networks.
    pub source_cidrs: Vec<ipnet::IpNet>,
    /// Connection arrived on one of these listeners.
    pub listeners: Vec<String>,
}

/// A condition on a claim (dotted path).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimPredicate {
    /// Claim name or dotted path.
    pub name: String,
    /// The claim equals this JSON value.
    #[serde(default)]
    pub equals: Option<serde_json::Value>,
    /// The claim (array) contains this value, or (string) equals it.
    #[serde(default)]
    pub contains: Option<serde_json::Value>,
    /// The claim equals one of these values.
    #[serde(default)]
    pub any_of: Vec<serde_json::Value>,
    /// The claim is present (true) or absent (false).
    #[serde(default)]
    pub exists: Option<bool>,
}

/// What a grant allows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Backend name.
    pub backend: String,
    /// Allowed databases (`*` for any).
    pub databases: Vec<String>,
    /// Allowed PostgreSQL roles.
    pub pg_roles: Vec<String>,
    /// Role used when the client does not name an entitled role.
    #[serde(default)]
    pub default_pg_role: Option<String>,
    /// Pool mode override.
    #[serde(default)]
    pub pool_mode: Option<PoolMode>,
    /// Maximum concurrent client sessions for one identity under this grant.
    #[serde(default)]
    pub max_connections_per_identity: Option<u32>,
    /// Session lifetime override.
    #[serde(default, with = "duration::option")]
    pub session_max_lifetime: Option<Duration>,
    /// Token-expiry behaviour override.
    #[serde(default)]
    pub on_token_expiry: Option<TokenExpiryAction>,
    /// Allow roles that are superuser, CREATEROLE, REPLICATION or BYPASSRLS.
    /// Intended only for break-glass grants.
    #[serde(default)]
    pub allow_privileged_role: bool,
}

// ---------------------------------------------------------------------------
// Session, limits, drain, audit, logging, propagation
// ---------------------------------------------------------------------------

/// How the startup `user` parameter is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserSemantics {
    /// An entitled role name selects that role; the identity's own username,
    /// subject or `*` selects the default role; anything else is denied.
    #[default]
    Auto,
    /// `user` must be an entitled role name.
    Role,
    /// `user` is ignored; the default role is always used.
    Identity,
}

/// Session lifetime settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionConfig {
    /// Startup `user` semantics.
    pub user_semantics: UserSemantics,
    /// Behaviour when the token expires.
    pub on_token_expiry: TokenExpiryAction,
    /// Grace period after `exp`.
    #[serde(with = "duration")]
    pub token_expiry_grace: Duration,
    /// Hard cap on session lifetime.
    #[serde(with = "duration")]
    pub max_lifetime: Duration,
    /// Close sessions idle (outside a transaction) for this long.
    #[serde(with = "duration")]
    pub idle_timeout: Duration,
    /// Close sessions idle inside a transaction for this long.
    #[serde(with = "duration")]
    pub idle_in_transaction_timeout: Duration,
    /// Time allowed from TCP accept to completed authentication.
    #[serde(with = "duration")]
    pub auth_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            user_semantics: UserSemantics::Auto,
            on_token_expiry: TokenExpiryAction::TerminateWhenIdle,
            token_expiry_grace: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(12 * 3600),
            idle_timeout: Duration::from_secs(3600),
            idle_in_transaction_timeout: Duration::from_secs(600),
            auth_timeout: Duration::from_secs(10),
        }
    }
}

/// Resource limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Maximum concurrent client connections (per replica).
    pub max_client_connections: u32,
    /// Maximum connections that have not finished authentication.
    pub max_pending_auth: u32,
    /// Maximum startup packet size in bytes.
    pub max_startup_packet_bytes: usize,
    /// Maximum password / SASL message size in bytes (tokens can be large).
    pub max_auth_message_bytes: usize,
    /// Failed authentications allowed per client IP per minute (0 = unlimited).
    pub auth_failures_per_ip_per_minute: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_client_connections: 10_000,
            max_pending_auth: 1_000,
            max_startup_packet_bytes: 10_000,
            max_auth_message_bytes: 16 * 1024,
            auth_failures_per_ip_per_minute: 30,
        }
    }
}

/// Graceful shutdown settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DrainConfig {
    /// Keep accepting connections this long after SIGTERM.
    #[serde(with = "duration")]
    pub accept_grace: Duration,
    /// Let session-mode sessions finish for this long before terminating them at idle.
    #[serde(with = "duration")]
    pub session_timeout: Duration,
    /// After this, remaining sessions are closed even mid-transaction.
    #[serde(with = "duration")]
    pub hard_timeout: Duration,
}

impl Default for DrainConfig {
    fn default() -> Self {
        DrainConfig {
            accept_grace: Duration::from_secs(5),
            session_timeout: Duration::from_secs(60),
            hard_timeout: Duration::from_secs(90),
        }
    }
}

/// Audit logging.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// Write audit events to stdout as JSON lines.
    pub stdout: bool,
    /// Also write audit events to this file (JSON lines).
    pub file: Option<PathBuf>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            stdout: true,
            file: None,
        }
    }
}

/// Process logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// Filter, in `tracing` env-filter syntax (overridden by `PGBEARER_LOG`).
    pub level: String,
    /// Output format.
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level: "info".into(),
            format: LogFormat::Json,
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// JSON lines.
    #[default]
    Json,
    /// Human-readable.
    Pretty,
}

/// Identity propagation to PostgreSQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PropagationConfig {
    /// Set `pgbearer.sub`, `pgbearer.username`, `pgbearer.session_id` GUCs.
    pub set_gucs: bool,
    /// Append ` [pgbearer:<username>]` to `application_name`.
    pub application_name_suffix: bool,
}

impl Default for PropagationConfig {
    fn default() -> Self {
        PropagationConfig {
            set_gucs: true,
            application_name_suffix: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_pg_port() -> u16 {
    5432
}

fn default_cluster_domain() -> String {
    "cluster.local".into()
}

fn default_cert_reload_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_leeway() -> Duration {
    Duration::from_secs(60)
}

fn default_algorithms() -> Vec<JwtAlgorithm> {
    vec![
        JwtAlgorithm::RS256,
        JwtAlgorithm::PS256,
        JwtAlgorithm::ES256,
        JwtAlgorithm::EdDSA,
    ]
}

#[cfg(test)]
mod tests;
