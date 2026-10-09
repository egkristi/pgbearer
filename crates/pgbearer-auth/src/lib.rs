//! Token validation for pgbearer (ARCHITECTURE.md §8).
//!
//! Pipeline for [`TokenValidator::validate`]:
//!
//! 1. Size check (`max_token_bytes`), then require a compact JWS (three
//!    base64url segments). Anything else → [`AuthError::Malformed`].
//! 2. Decode the header *without* trusting it: `alg` must be in the
//!    provider's allow-list (never `none` or HS*), `kid` should be present.
//! 3. Decode the payload *without* verifying, read `iss`, and select the
//!    provider whose effective issuer equals `iss` **exactly**. Unknown
//!    issuer → [`AuthError::UnknownIssuer`] with no network call.
//! 4. Look up the key by `kid` in that provider's JWKS cache. Unknown `kid` →
//!    one rate-limited, single-flight refresh (at most once per
//!    `jwks.min_refresh_interval`), then retry; still unknown →
//!    [`AuthError::UnknownKey`]. Keys never come from token headers
//!    (`jku`, `x5u`, `jwk` are ignored).
//! 5. Verify the signature and the claims: `iss` (exact), `aud` (any of the
//!    configured audiences), `exp` (required), `nbf` and `iat` if present, all
//!    with `leeway`; optional `typ` check; `tid` in `tenants` (Entra);
//!    `required_scopes` ⊆ scopes for delegated tokens (tokens without any
//!    scope claim, i.e. app-only tokens, skip the scope check);
//!    `allowed_client_ids`.
//! 6. Map claims to an [`Identity`] with the provider's effective claim names
//!    (dotted paths allowed; string or array values; scopes split on spaces).
//!    `kind` is `Workload` for Entra `idtyp=app`, Kubernetes and GitHub
//!    Actions tokens, `Human` for tokens with a `scp`/`scope` claim and a user
//!    subject, else `Unknown`. Entra groups overage (`_claim_names.groups` or
//!    `hasgroups`) sets `groups_overage`.
//!
//! JWKS cache (§8.3): initial discovery + fetch in [`TokenValidator::start`];
//! background refresh at `max(Cache-Control max-age, min_refresh_interval)`
//! capped at `jwks.max_age`; on refresh failure keep the last good set for up
//! to `jwks.max_stale` and never replace a good set with an empty one. Keys
//! with `use` other than `sig` are ignored; `alg`, if present on the key,
//! must match the token header. Readiness: every provider with
//! `required: true` has a usable key set.
//!
//! HTTP: `reqwest` with rustls, `jwks.http_timeout`, optional extra CA
//! (`ca_file`) and bearer token (`bearer_token_file`, re-read on each request).
//!
//! Metrics: `pgbearer_auth_attempts_total`, `pgbearer_auth_duration_seconds`,
//! `pgbearer_jwks_refresh_total`, `pgbearer_jwks_age_seconds`.

pub mod oauthbearer;

use std::sync::Arc;

use pgbearer_config::IdentityProviderConfig;
use pgbearer_core::Identity;
use pgbearer_telemetry::Metrics;
use tokio_util::sync::CancellationToken;

/// Why a token was rejected. `reason_code` is a stable metric label.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// Not a JWT, bad base64/JSON, or too large.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// `iss` does not match any configured provider.
    #[error("unknown issuer {0:?}")]
    UnknownIssuer(String),
    /// The algorithm is not allowed for this provider.
    #[error("algorithm {0} not allowed")]
    DisallowedAlgorithm(String),
    /// No key with this `kid` (after a refresh attempt).
    #[error("no signing key {kid:?} for provider {provider}")]
    UnknownKey {
        /// Provider name.
        provider: String,
        /// Key id from the token header.
        kid: String,
    },
    /// The provider has no keys loaded (IdP unreachable since startup).
    #[error("signing keys for provider {0} are not available")]
    KeysUnavailable(String),
    /// Signature verification failed.
    #[error("invalid signature")]
    BadSignature,
    /// `exp` is in the past (beyond leeway).
    #[error("token expired")]
    Expired,
    /// `nbf` is in the future (beyond leeway).
    #[error("token not yet valid")]
    NotYetValid,
    /// `aud` does not contain an accepted audience.
    #[error("audience not accepted")]
    BadAudience,
    /// A required claim is missing or has the wrong type.
    #[error("missing or invalid claim {0}")]
    MissingClaim(String),
    /// Tenant not allowed.
    #[error("tenant {0:?} not allowed")]
    TenantNotAllowed(String),
    /// Required scope missing.
    #[error("required scope {0:?} missing")]
    MissingScope(String),
    /// Client id not allowed.
    #[error("client {0:?} not allowed")]
    ClientNotAllowed(String),
    /// `typ` header mismatch.
    #[error("unexpected token type {0:?}")]
    BadType(String),
}

impl AuthError {
    /// Stable, low-cardinality reason code for metrics and audit.
    pub fn reason_code(&self) -> &'static str {
        match self {
            AuthError::Malformed(_) => "malformed",
            AuthError::UnknownIssuer(_) => "unknown_issuer",
            AuthError::DisallowedAlgorithm(_) => "disallowed_algorithm",
            AuthError::UnknownKey { .. } => "unknown_key",
            AuthError::KeysUnavailable(_) => "keys_unavailable",
            AuthError::BadSignature => "bad_signature",
            AuthError::Expired => "expired",
            AuthError::NotYetValid => "not_yet_valid",
            AuthError::BadAudience => "bad_audience",
            AuthError::MissingClaim(_) => "missing_claim",
            AuthError::TenantNotAllowed(_) => "tenant_not_allowed",
            AuthError::MissingScope(_) => "missing_scope",
            AuthError::ClientNotAllowed(_) => "client_not_allowed",
            AuthError::BadType(_) => "bad_type",
        }
    }
}

/// Status of one provider, for `/readyz` and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStatus {
    /// Provider name.
    pub name: String,
    /// Whether readiness depends on this provider.
    pub required: bool,
    /// Number of usable signing keys.
    pub keys: usize,
    /// Seconds since the key set was last fetched successfully.
    pub age_seconds: Option<u64>,
    /// Last refresh error, if the last attempt failed.
    pub last_error: Option<String>,
}

/// Validates access tokens against the configured identity providers.
pub struct TokenValidator {
    _private: (),
}

impl TokenValidator {
    /// Build from provider configs. Performs no network I/O.
    /// `max_token_bytes` is `limits.max_auth_message_bytes`.
    pub fn new(
        providers: &[IdentityProviderConfig],
        max_token_bytes: usize,
        metrics: Arc<Metrics>,
    ) -> Result<TokenValidator, AuthError> {
        let _ = (providers, max_token_bytes, metrics);
        todo!("pgbearer-auth: TokenValidator::new")
    }

    /// Fetch discovery documents and key sets for all providers concurrently
    /// (failures are logged and recorded, not returned), then spawn background
    /// refresh tasks that stop when `shutdown` is cancelled.
    pub async fn start(self: &Arc<Self>, shutdown: CancellationToken) {
        let _ = shutdown;
        todo!("pgbearer-auth: TokenValidator::start")
    }

    /// True when every required provider has a usable key set.
    pub fn is_ready(&self) -> bool {
        todo!("pgbearer-auth: TokenValidator::is_ready")
    }

    /// Per-provider status.
    pub fn status(&self) -> Vec<ProviderStatus> {
        todo!("pgbearer-auth: TokenValidator::status")
    }

    /// Validate a token and map it to an identity. See the crate docs for the
    /// exact pipeline. Records metrics for every attempt.
    pub async fn validate(&self, token: &str) -> Result<Identity, AuthError> {
        let _ = token;
        todo!("pgbearer-auth: TokenValidator::validate")
    }

    /// Validate without network access, using only the current key sets
    /// (used by `pgbearerctl explain --verify` and tests).
    pub fn validate_offline(&self, token: &str) -> Result<Identity, AuthError> {
        let _ = token;
        todo!("pgbearer-auth: TokenValidator::validate_offline")
    }

    /// Map an *unverified* claim set to an identity for a named provider,
    /// applying claim mapping but no signature or claim validation. For
    /// `pgbearerctl explain` only; never use on the connection path.
    pub fn map_claims_unverified(
        &self,
        provider: &str,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Identity, AuthError> {
        let _ = (provider, claims);
        todo!("pgbearer-auth: TokenValidator::map_claims_unverified")
    }

    /// For OAUTHBEARER listeners: `(openid-configuration URL, scope)` to send in
    /// the discovery response for `provider`.
    pub fn oauthbearer_discovery(&self, provider: &str) -> Option<(String, String)> {
        let _ = provider;
        todo!("pgbearer-auth: TokenValidator::oauthbearer_discovery")
    }
}
