//! Token validation for pgbearer (ARCHITECTURE.md §8).
//!
//! Pipeline for [`TokenValidator::validate`]:
//!
//! 1. Size check (`max_token_bytes`), then require a compact JWS (three
//!    base64url segments). Anything else → [`AuthError::Malformed`].
//! 2. Decode the header *without* trusting it: `alg` must be an asymmetric
//!    algorithm (never `none` or HS*) and, once the provider is known, in the
//!    provider's allow-list; `kid` should be present. Headers with `crit` are
//!    rejected (no JWS extensions are understood).
//! 3. Decode the payload *without* verifying, read `iss`, and select the
//!    provider whose effective issuer equals `iss` **exactly**. Unknown
//!    issuer → [`AuthError::UnknownIssuer`] with no network call. A `kid` in
//!    the provider's `revoked_key_ids` → [`AuthError::RevokedKey`], also
//!    without a network call.
//! 4. Look up the key by `kid` in that provider's JWKS cache (revoked keys
//!    are never loaded into it). Unknown `kid` →
//!    one rate-limited, single-flight refresh (at most once per
//!    `jwks.min_refresh_interval`), then retry; still unknown →
//!    [`AuthError::UnknownKey`]. A token without `kid` is accepted only when
//!    the provider's key set has exactly one key. If the key pins an `alg`, it
//!    must equal the header's. Keys never come from token headers (`jku`,
//!    `x5u`, `jwk`, `x5c` are ignored).
//! 5. Verify the signature and the claims: `iss` (exact), `aud` (any of the
//!    configured audiences), `exp` (required), `nbf` and `iat` if present, all
//!    with `leeway`; the token lifetime (`exp - iat`, or `exp - now` without
//!    `iat`) at most `max_token_lifetime` + `leeway`, else
//!    [`AuthError::TokenLifetime`]; optional `typ` check (case-insensitive, an
//!    `application/` prefix is ignored); `required_claims` present and not
//!    `null`; tenant in `tenants`; `allowed_client_ids` (checked against
//!    `azp`, `appid` or `client_id`). For `type: entra`, a token with a
//!    `nonce` claim (an ID token) is rejected, and the token must match
//!    exactly one enabled token profile (`delegated`: non-empty `scp`,
//!    `idtyp` absent or `user`; `application`: `idtyp=app`, no `scp`,
//!    non-empty `roles`), else [`AuthError::TokenProfile`]. Finally
//!    `required_scopes` ⊆ scopes, for every token except Entra application
//!    tokens and tokens from `kubernetes` and `github-actions` providers,
//!    which carry no scopes.
//! 6. Map claims to an [`Identity`] with the provider's effective claim names
//!    (dotted paths allowed, but a claim whose literal name matches wins;
//!    string or array values; scopes split on whitespace). `kind` is
//!    `Workload` for Kubernetes, GitHub Actions and Entra application tokens,
//!    `Human` for Entra delegated tokens, the configured `identity_kind` for
//!    `type: oidc`, else `Unknown`. `key_id` is the `kid` of the verifying
//!    key. Groups overage (`_claim_names.groups` or `hasgroups`) sets
//!    `groups_overage`.
//!
//! JWKS cache (§8.3): initial discovery + fetch in [`TokenValidator::start`];
//! background refresh at `max_age`, sooner when `Cache-Control: max-age` is
//! smaller but never below `min_refresh_interval`, with exponential backoff
//! after failures; on refresh failure keep the last good set for up to
//! `jwks.max_stale` and never replace a good set with an empty one. The
//! discovery document's `issuer` must equal the configured issuer (mix-up
//! protection); a configured `jwks_uri` skips discovery. Keys with `use`
//! other than `sig`, symmetric keys and keys for unsupported curves are
//! ignored. Readiness: every provider with `required: true` has a usable key
//! set.
//!
//! HTTP: `reqwest` with rustls, `jwks.http_timeout`, https only (unless
//! `insecure_allow_http`), responses capped at 1 MiB, optional extra CA
//! (`ca_file`) and bearer token (`bearer_token_file`, re-read on each
//! request). Redirects are followed only within the same origin (scheme,
//! host and port), at most 5 hops, so a redirect can neither leak the bearer
//! token to another host nor substitute another host's keys.
//!
//! Metrics: `pgbearer_auth_attempts_total`, `pgbearer_auth_duration_seconds`,
//! `pgbearer_jwks_refresh_total`, `pgbearer_jwks_age_seconds`.
//!
//! With the `testing` Cargo feature, `testing::MockIssuer` provides an
//! in-process OpenID Connect provider for tests.

mod claims;
mod jwks;
mod jwt;
pub mod oauthbearer;
mod provider;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::Validation;
use pgbearer_config::IdentityProviderConfig;
use pgbearer_core::Identity;
use pgbearer_telemetry::{Metrics, ProviderLabels};
use tokio_util::sync::CancellationToken;

use crate::jwks::{KeyLookup, VerifyKey};
use crate::jwt::{UnverifiedToken, alg_name, map_jwt_error, numeric_date, sanitize};
use crate::provider::Provider;

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
        /// Key id from the token header (empty if the token has none).
        kid: String,
    },
    /// The provider has no keys loaded (IdP unreachable since startup), or
    /// its keys are older than `jwks.max_stale` and refreshes are failing.
    /// [`TokenValidator::new`] also uses this variant for an unusable provider
    /// configuration, with the reason in parentheses after the name.
    #[error("signing keys for provider {0} are not available")]
    KeysUnavailable(String),
    /// Signature verification failed.
    #[error("invalid signature")]
    BadSignature,
    /// `exp` is in the past (beyond leeway).
    #[error("token expired")]
    Expired,
    /// `nbf` (or `iat`) is in the future (beyond leeway).
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
    /// The token does not match an enabled token profile (Entra ID), or is an
    /// ID token.
    #[error("token profile not accepted: {0}")]
    TokenProfile(String),
    /// The token's lifetime is longer than `max_token_lifetime`.
    #[error("token lifetime of {lifetime_secs}s exceeds the maximum of {max_secs}s")]
    TokenLifetime {
        /// `exp - iat`, or `exp - now` for a token without `iat`.
        lifetime_secs: u64,
        /// `max_token_lifetime` in seconds.
        max_secs: u64,
    },
    /// The token was signed with a key listed in `revoked_key_ids`.
    #[error("signing key {0:?} is revoked")]
    RevokedKey(String),
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
            AuthError::TokenProfile(_) => "token_profile",
            AuthError::TokenLifetime { .. } => "token_lifetime",
            AuthError::RevokedKey(_) => "revoked_key",
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
///
/// Cheap to share as `Arc<TokenValidator>`; all methods take `&self`.
pub struct TokenValidator {
    providers: Vec<Arc<Provider>>,
    max_token_bytes: usize,
    metrics: Arc<Metrics>,
    started: AtomicBool,
}

impl std::fmt::Debug for TokenValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenValidator")
            .field("providers", &self.providers)
            .field("max_token_bytes", &self.max_token_bytes)
            .finish_non_exhaustive()
    }
}

/// Why the cached keys could not verify a token.
enum KeyMiss {
    /// A refresh might help (no keys, unknown `kid`).
    Refreshable(AuthError),
    /// A refresh would not help.
    Final(AuthError),
}

impl KeyMiss {
    fn into_error(self) -> AuthError {
        match self {
            KeyMiss::Refreshable(e) | KeyMiss::Final(e) => e,
        }
    }
}

/// A token whose provider has been selected, not yet verified.
struct Selected<'a> {
    token: &'a str,
    parsed: UnverifiedToken,
    provider: &'a Provider,
}

impl TokenValidator {
    /// Build from provider configs. Performs no network I/O (`ca_file` is
    /// read here, so a bad CA bundle fails early).
    /// `max_token_bytes` is `limits.max_auth_message_bytes`.
    ///
    /// Fails with [`AuthError::KeysUnavailable`] (naming the provider and the
    /// problem) when a provider cannot work: no issuer, a non-https URL
    /// without `insecure_allow_http`, no audiences or algorithms, an
    /// unreadable `ca_file`, a `leeway` above 24 h, or duplicate provider
    /// names or issuers.
    pub fn new(
        providers: &[IdentityProviderConfig],
        max_token_bytes: usize,
        metrics: Arc<Metrics>,
    ) -> Result<TokenValidator, AuthError> {
        // jsonwebtoken picks its crypto backend from crate features; install
        // aws-lc-rs explicitly so a feature mix elsewhere in the build can
        // never leave the process without one (which would panic).
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
        );
        let mut built: Vec<Arc<Provider>> = Vec::with_capacity(providers.len());
        for cfg in providers {
            let config_error = |problem: String| {
                AuthError::KeysUnavailable(format!(
                    "{} (invalid configuration: {problem})",
                    cfg.name
                ))
            };
            if built.iter().any(|p| p.name() == cfg.name) {
                return Err(config_error("duplicate provider name".into()));
            }
            let provider = Provider::from_config(cfg, metrics.clone()).map_err(config_error)?;
            if let Some(other) = built
                .iter()
                .find(|p| p.rules.issuer == provider.rules.issuer)
            {
                return Err(config_error(format!(
                    "issuer {:?} is also used by provider {}",
                    provider.rules.issuer,
                    other.name()
                )));
            }
            built.push(Arc::new(provider));
        }
        Ok(TokenValidator {
            providers: built,
            max_token_bytes,
            metrics,
            started: AtomicBool::new(false),
        })
    }

    /// Fetch discovery documents and key sets for all providers concurrently
    /// (failures are logged and recorded, not returned), then spawn background
    /// refresh tasks that stop when `shutdown` is cancelled.
    ///
    /// Must be called within a Tokio runtime. Calling it more than once is a
    /// no-op (logged).
    pub async fn start(self: &Arc<Self>, shutdown: CancellationToken) {
        if self.started.swap(true, Ordering::AcqRel) {
            tracing::warn!("TokenValidator::start called more than once; ignoring");
            return;
        }
        let mut initial = tokio::task::JoinSet::new();
        for (index, provider) in self.providers.iter().enumerate() {
            let provider = provider.clone();
            initial.spawn(async move { (index, provider.refresh_scheduled().await) });
        }
        let mut failures = vec![0u32; self.providers.len()];
        loop {
            let next = tokio::select! {
                _ = shutdown.cancelled() => {
                    initial.abort_all();
                    return;
                }
                next = initial.join_next() => next,
            };
            match next {
                None => break,
                Some(Ok((index, result))) => {
                    if let Some(provider) = self.providers.get(index) {
                        match result {
                            Ok(keys) => tracing::info!(
                                provider = %provider.name(),
                                keys,
                                "loaded signing keys"
                            ),
                            Err(_) => {
                                if let Some(f) = failures.get_mut(index) {
                                    *f = 1;
                                }
                                // The error itself was logged by the refresh.
                                tracing::warn!(
                                    provider = %provider.name(),
                                    required = provider.required,
                                    "signing keys not available yet; retrying in the background"
                                );
                            }
                        }
                    }
                }
                Some(Err(e)) => tracing::error!(error = %e, "initial JWKS fetch task failed"),
            }
        }
        for (provider, failures) in self.providers.iter().zip(failures) {
            tokio::spawn(provider.clone().run_background(shutdown.clone(), failures));
        }
    }

    /// Fetch discovery documents and key sets for all providers once, now,
    /// without starting background tasks. Returns the number of usable keys
    /// per provider, or the error. Subject to the same serialisation as
    /// background refreshes (but not to `min_refresh_interval`). Intended for
    /// tools such as `pgbearerctl`.
    pub async fn refresh_all(&self) -> Vec<(String, Result<usize, String>)> {
        let mut out = Vec::with_capacity(self.providers.len());
        let mut tasks = tokio::task::JoinSet::new();
        for (index, provider) in self.providers.iter().enumerate() {
            let provider = provider.clone();
            tasks.spawn(async move { (index, provider.refresh_scheduled().await) });
        }
        let mut results: Vec<Option<Result<usize, String>>> = vec![None; self.providers.len()];
        while let Some(joined) = tasks.join_next().await {
            if let Ok((index, result)) = joined
                && let Some(slot) = results.get_mut(index)
            {
                *slot = Some(result);
            }
        }
        for (provider, result) in self.providers.iter().zip(results) {
            out.push((
                provider.name().to_string(),
                result.unwrap_or_else(|| Err("refresh task failed".into())),
            ));
        }
        out
    }

    /// Install a key set for `provider` from a JWKS document (no network),
    /// replacing the current one. Returns the number of usable keys. Intended
    /// for offline tools (`pgbearerctl explain --verify` with a saved JWKS)
    /// and tests.
    pub fn load_jwks(&self, provider: &str, jwks_json: &[u8]) -> Result<usize, AuthError> {
        let p = self
            .provider_by_name(provider)
            .ok_or_else(|| AuthError::UnknownIssuer(sanitize(provider)))?;
        p.install_jwks(jwks_json)
            .map_err(|e| AuthError::KeysUnavailable(format!("{provider} ({e})")))
    }

    /// True when every required provider has a usable key set.
    pub fn is_ready(&self) -> bool {
        self.providers
            .iter()
            .filter(|p| p.required)
            .all(|p| p.usable_keys().is_some())
    }

    /// Per-provider status.
    pub fn status(&self) -> Vec<ProviderStatus> {
        self.providers
            .iter()
            .map(|p| {
                p.update_age_gauge();
                ProviderStatus {
                    name: p.name().to_string(),
                    required: p.required,
                    keys: p.usable_keys().map_or(0, |k| k.keys.len()),
                    age_seconds: p.age().map(|a| a.as_secs()),
                    last_error: p.last_error(),
                }
            })
            .collect()
    }

    /// Validate a token and map it to an identity. See the crate docs for the
    /// exact pipeline. Records metrics for every attempt.
    pub async fn validate(&self, token: &str) -> Result<Identity, AuthError> {
        let started = Instant::now();
        let (provider, result) = match self.select(token) {
            Err((provider, e)) => (provider, Err(e)),
            Ok(selected) => {
                let result = match self.verify_with_cache(&selected) {
                    Err(KeyMiss::Refreshable(_)) => {
                        selected.provider.refresh_on_demand().await;
                        self.verify_with_cache(&selected)
                            .map_err(KeyMiss::into_error)
                    }
                    other => other.map_err(KeyMiss::into_error),
                };
                (Some(selected.provider), result)
            }
        };
        self.record(provider, &result, started.elapsed());
        if let Err(e) = &result {
            tracing::debug!(
                provider = provider.map_or("unknown", |p| p.name()),
                reason = e.reason_code(),
                error = %e,
                "token rejected"
            );
        }
        result
    }

    /// Validate without network access, using only the current key sets
    /// (used by `pgbearerctl explain --verify` and tests). Does not record
    /// metrics.
    pub fn validate_offline(&self, token: &str) -> Result<Identity, AuthError> {
        let selected = self.select(token).map_err(|(_, e)| e)?;
        self.verify_with_cache(&selected)
            .map_err(KeyMiss::into_error)
    }

    /// Map an *unverified* claim set to an identity for a named provider,
    /// applying claim mapping but no signature or claim validation. For
    /// `pgbearerctl explain` only; never use on the connection path.
    ///
    /// An unknown provider name is reported as [`AuthError::UnknownIssuer`].
    /// A missing `exp` maps to the Unix epoch.
    pub fn map_claims_unverified(
        &self,
        provider: &str,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Identity, AuthError> {
        let p = self
            .provider_by_name(provider)
            .ok_or_else(|| AuthError::UnknownIssuer(sanitize(provider)))?;
        claims::map_identity(&p.rules, claims, false)
    }

    /// For OAUTHBEARER listeners: `(openid-configuration URL, scope)` to send in
    /// the discovery response for `provider`. The URL is the configured
    /// `discovery_url`, or the issuer + `/.well-known/openid-configuration`.
    /// `None` if the provider is unknown or has no `oauthbearer` settings.
    pub fn oauthbearer_discovery(&self, provider: &str) -> Option<(String, String)> {
        let p = self.provider_by_name(provider)?;
        let scope = p.oauthbearer_scope.clone()?;
        Some((p.openid_configuration_url.clone(), scope))
    }

    fn provider_by_name(&self, name: &str) -> Option<&Provider> {
        self.providers
            .iter()
            .map(AsRef::as_ref)
            .find(|p| p.name() == name)
    }

    /// Steps 1–3: size, structure, header, issuer selection, alg allow-list.
    /// On error, also returns the provider if it was already selected.
    fn select<'a>(
        &'a self,
        token: &'a str,
    ) -> Result<Selected<'a>, (Option<&'a Provider>, AuthError)> {
        if token.len() > self.max_token_bytes {
            return Err((
                None,
                AuthError::Malformed(format!(
                    "token is {} bytes, more than the limit of {}",
                    token.len(),
                    self.max_token_bytes
                )),
            ));
        }
        let token = token.trim_ascii();
        let parsed = jwt::parse_unverified(token).map_err(|e| (None, e))?;
        let issuer = match parsed.claims.get("iss") {
            Some(serde_json::Value::String(iss)) => iss,
            _ => return Err((None, AuthError::MissingClaim("iss".into()))),
        };
        let provider = self
            .providers
            .iter()
            .map(AsRef::as_ref)
            .find(|p| p.rules.issuer == *issuer)
            .ok_or_else(|| (None, AuthError::UnknownIssuer(sanitize(issuer))))?;
        if !provider.algorithms.contains(&parsed.alg) {
            return Err((
                Some(provider),
                AuthError::DisallowedAlgorithm(alg_name(parsed.alg).into()),
            ));
        }
        if let Some(kid) = parsed.kid.as_deref()
            && provider.is_revoked(kid)
        {
            return Err((Some(provider), AuthError::RevokedKey(sanitize(kid))));
        }
        Ok(Selected {
            token,
            parsed,
            provider,
        })
    }

    /// Steps 4–6 against the current key set.
    fn verify_with_cache(&self, s: &Selected<'_>) -> Result<Identity, KeyMiss> {
        let p = s.provider;
        let unavailable = || AuthError::KeysUnavailable(p.name().to_string());
        let Some(keys) = p.usable_keys() else {
            return Err(KeyMiss::Refreshable(unavailable()));
        };
        let kid = s.parsed.kid.as_deref();
        match keys.find(kid, s.parsed.alg) {
            KeyLookup::Found(key) => self.verify(s, key).map_err(KeyMiss::Final),
            KeyLookup::Empty => Err(KeyMiss::Refreshable(unavailable())),
            KeyLookup::UnknownKid => Err(KeyMiss::Refreshable(AuthError::UnknownKey {
                provider: p.name().to_string(),
                kid: sanitize(kid.unwrap_or_default()),
            })),
            KeyLookup::Ambiguous => Err(KeyMiss::Final(AuthError::UnknownKey {
                provider: p.name().to_string(),
                kid: String::new(),
            })),
            KeyLookup::AlgMismatch => Err(KeyMiss::Final(AuthError::DisallowedAlgorithm(
                alg_name(s.parsed.alg).into(),
            ))),
        }
    }

    /// Step 5–6: signature and claim validation, constraints, mapping.
    fn verify(&self, s: &Selected<'_>, key: &VerifyKey) -> Result<Identity, AuthError> {
        let p = s.provider;
        let alg = s.parsed.alg;
        let mut validation = Validation::new(alg);
        validation.algorithms = vec![alg];
        validation.set_issuer(&[p.rules.issuer.as_str()]);
        validation.set_audience(&p.audiences);
        validation.leeway = p.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let data = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            s.token,
            &key.key,
            &validation,
        )
        .map_err(|e| map_jwt_error(&e, alg, &p.rules.issuer))?;
        let claims = data.claims;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let iat = match claims.get("iat") {
            None => None,
            Some(iat) => {
                let iat = numeric_date(iat).ok_or_else(|| AuthError::MissingClaim("iat".into()))?;
                if iat > now.saturating_add(p.leeway_secs) {
                    return Err(AuthError::NotYetValid);
                }
                Some(iat)
            }
        };
        let exp = claims
            .get("exp")
            .and_then(numeric_date)
            .ok_or_else(|| AuthError::MissingClaim("exp".into()))?;
        let lifetime_secs = exp.saturating_sub(iat.unwrap_or(now));
        if lifetime_secs > p.max_token_lifetime_secs.saturating_add(p.leeway_secs) {
            return Err(AuthError::TokenLifetime {
                lifetime_secs,
                max_secs: p.max_token_lifetime_secs,
            });
        }
        claims::check_constraints(&p.rules, s.parsed.typ.as_deref(), &claims)?;
        let mut identity = claims::map_identity(&p.rules, claims, true)?;
        identity.key_id = key.kid.clone();
        Ok(identity)
    }

    fn record(
        &self,
        provider: Option<&Provider>,
        result: &Result<Identity, AuthError>,
        elapsed: Duration,
    ) {
        let label = provider.map_or("unknown", Provider::name);
        match result {
            Ok(_) => self.metrics.auth_attempt(label, true, "ok"),
            Err(e) => self.metrics.auth_attempt(label, false, e.reason_code()),
        }
        self.metrics
            .auth_duration
            .get_or_create(&ProviderLabels {
                provider: label.to_string(),
            })
            .observe(elapsed.as_secs_f64());
    }
}
