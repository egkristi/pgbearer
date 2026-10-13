//! One configured identity provider at runtime: HTTP client, discovery,
//! JWKS cache and refresh scheduling (ARCHITECTURE.md §8.3).
//!
//! Refresh rules:
//!
//! * All fetches for a provider are serialised by `gate` (a tokio mutex), so
//!   there is never more than one request in flight per provider.
//! * On-demand refreshes (unknown `kid`, no keys) are single-flight: a caller
//!   that waited while another fetch ran does not fetch again. They are also
//!   rate-limited to one per `jwks.min_refresh_interval`, so random `kid`
//!   values cannot turn pgbearer into a JWKS-fetch amplifier.
//! * Scheduled refreshes run from [`Provider::run_background`]: every
//!   `jwks.max_age` (sooner if `Cache-Control: max-age` says so, but never
//!   below `min_refresh_interval`), with exponential backoff after failures.
//! * A failed or empty fetch never replaces a good key set. A key set older
//!   than `jwks.max_stale` whose last refresh failed is no longer used.
//! * Keys listed in `revoked_key_ids` are dropped from every fetched or
//!   installed key set, so they can verify no token, with or without `kid`.
//! * Redirects are followed only to the same origin, at most
//!   [`MAX_REDIRECTS`] times.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use jsonwebtoken::Algorithm;
use pgbearer_config::{IdentityProviderConfig, IdpType, JwksConfig, JwtAlgorithm};
use pgbearer_telemetry::{Metrics, ProviderLabels, ProviderResultLabels};
use reqwest::Url;
use reqwest::header::{ACCEPT, CACHE_CONTROL};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::claims::ClaimRules;
use crate::jwks::{KeySet, ParsedJwks, parse_cache_control, parse_jwks};

/// Maximum size of a discovery or JWKS response body.
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Most redirects followed for one discovery or JWKS request.
pub(crate) const MAX_REDIRECTS: usize = 5;
/// Largest accepted `leeway`; larger values are a configuration error.
pub(crate) const MAX_LEEWAY: Duration = Duration::from_secs(24 * 3600);
/// Shortest delay between scheduled refreshes (guards against busy loops).
const MIN_DELAY: Duration = Duration::from_millis(50);
/// First retry delay after a failed scheduled refresh; doubles per failure.
const RETRY_BASE: Duration = Duration::from_secs(1);
/// Longest retry delay after failures.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);
/// How often the background task updates `pgbearer_jwks_age_seconds`.
const AGE_GAUGE_INTERVAL: Duration = Duration::from_secs(15);
/// Longest delay between scheduled refreshes, whatever `jwks.max_age` says.
const MAX_SCHEDULE_DELAY: Duration = Duration::from_secs(7 * 24 * 3600);

/// Mutable bookkeeping, guarded by a std mutex (never held across `.await`).
#[derive(Debug, Default)]
struct FetchState {
    last_error: Option<String>,
    discovered_jwks_uri: Option<Url>,
}

/// Single-flight gate state, guarded by the tokio mutex.
#[derive(Debug, Default)]
struct Gate {
    last_on_demand: Option<Instant>,
}

/// A configured identity provider.
pub(crate) struct Provider {
    /// Claim rules (name, issuer, claim names, constraints).
    pub(crate) rules: ClaimRules,
    /// Accepted audiences.
    pub(crate) audiences: Vec<String>,
    /// Allowed signature algorithms (asymmetric only).
    pub(crate) algorithms: Vec<Algorithm>,
    /// Clock-skew leeway in seconds.
    pub(crate) leeway_secs: u64,
    /// Longest accepted token lifetime in seconds.
    pub(crate) max_token_lifetime_secs: u64,
    /// Key ids that must not verify tokens.
    revoked_key_ids: Vec<String>,
    /// Whether readiness depends on this provider.
    pub(crate) required: bool,
    /// Scope for OAUTHBEARER discovery, if configured.
    pub(crate) oauthbearer_scope: Option<String>,
    /// URL of the discovery document advertised to OAUTHBEARER clients.
    pub(crate) openid_configuration_url: String,
    jwks_cfg: JwksConfig,
    discovery_url: Url,
    configured_jwks_uri: Option<Url>,
    allow_http: bool,
    bearer_token_file: Option<PathBuf>,
    http: reqwest::Client,
    keys: ArcSwap<KeySet>,
    gate: tokio::sync::Mutex<Gate>,
    /// Incremented after every completed fetch attempt (success or failure).
    fetches: AtomicU64,
    state: Mutex<FetchState>,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.rules.name)
            .field("issuer", &self.rules.issuer)
            .field("keys", &self.keys.load().keys.len())
            .finish_non_exhaustive()
    }
}

fn check_scheme(url: &Url, allow_http: bool, what: &str) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => Err(format!(
            "{what} {url} must use https (insecure_allow_http is for tests only)"
        )),
        other => Err(format!("{what} {url} has unsupported scheme {other:?}")),
    }
}

fn parse_url(value: &str, allow_http: bool, what: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|e| format!("{what} {value:?} is not a valid URL: {e}"))?;
    check_scheme(&url, allow_http, what)?;
    Ok(url)
}

/// The redirect policy for discovery and JWKS requests: same origin
/// (scheme, host, port) as the original request, at most [`MAX_REDIRECTS`]
/// hops. A cross-origin redirect could send the bearer token to another host
/// or substitute another host's keys.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let same_origin = attempt
            .previous()
            .first()
            .is_some_and(|first| first.origin() == attempt.url().origin());
        if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if same_origin {
            attempt.follow()
        } else {
            attempt.error("redirect to another origin refused")
        }
    })
}

fn map_algorithm(a: JwtAlgorithm) -> Algorithm {
    match a {
        JwtAlgorithm::RS256 => Algorithm::RS256,
        JwtAlgorithm::RS384 => Algorithm::RS384,
        JwtAlgorithm::RS512 => Algorithm::RS512,
        JwtAlgorithm::PS256 => Algorithm::PS256,
        JwtAlgorithm::PS384 => Algorithm::PS384,
        JwtAlgorithm::PS512 => Algorithm::PS512,
        JwtAlgorithm::ES256 => Algorithm::ES256,
        JwtAlgorithm::ES384 => Algorithm::ES384,
        JwtAlgorithm::EdDSA => Algorithm::EdDSA,
    }
}

/// Render an error and its sources on one line.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = s.source();
    }
    out
}

/// Delay until the next scheduled refresh after a success: `max_age`, or the
/// `Cache-Control` max-age when smaller (but never below
/// `min_refresh_interval`).
pub(crate) fn refresh_delay(cfg: &JwksConfig, cache_max_age: Option<Duration>) -> Duration {
    let delay = match cache_max_age {
        Some(hint) if hint < cfg.max_age => hint.max(cfg.min_refresh_interval).min(cfg.max_age),
        _ => cfg.max_age,
    };
    delay.clamp(MIN_DELAY, MAX_SCHEDULE_DELAY)
}

/// Delay before retrying after `failures` consecutive failed refreshes:
/// 1 s, 2 s, 4 s, … capped at `min(max_age, 5 min)`.
pub(crate) fn retry_delay(cfg: &JwksConfig, failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(20);
    let delay = RETRY_BASE.saturating_mul(1u32 << exponent);
    delay.min(cfg.max_age.min(MAX_RETRY_DELAY)).max(MIN_DELAY)
}

/// Up to ~10 % of `d`, derived from the clock, so replicas do not refresh in
/// lockstep. Not cryptographic; it only spreads load.
fn jitter(d: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.subsec_nanos())
        .unwrap_or(0);
    d.mul_f64(f64::from(nanos % 1000) / 10_000.0)
}

impl Provider {
    /// Build a provider from its configuration. Reads `ca_file`; performs no
    /// network I/O.
    pub(crate) fn from_config(
        cfg: &IdentityProviderConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Provider, String> {
        if cfg.name.trim().is_empty() {
            return Err("name must not be empty".into());
        }
        let allow_http = cfg.insecure_allow_http;
        let issuer = cfg
            .effective_issuer()
            .ok_or_else(|| format!("issuer is required for type {:?}", cfg.kind))?;
        parse_url(&issuer, allow_http, "issuer")?;
        let openid_configuration_url = match &cfg.discovery_url {
            Some(u) => u.clone(),
            None => format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ),
        };
        let discovery_url = parse_url(&openid_configuration_url, allow_http, "discovery_url")?;
        let configured_jwks_uri = cfg
            .jwks_uri
            .as_deref()
            .map(|u| parse_url(u, allow_http, "jwks_uri"))
            .transpose()?;
        if cfg.audiences.is_empty() || cfg.audiences.iter().any(|a| a.trim().is_empty()) {
            return Err("at least one non-empty audience is required".into());
        }
        let mut algorithms: Vec<Algorithm> = Vec::new();
        for a in cfg.algorithms.iter().copied().map(map_algorithm) {
            if !algorithms.contains(&a) {
                algorithms.push(a);
            }
        }
        if algorithms.is_empty() {
            return Err("algorithms must not be empty".into());
        }
        if cfg.leeway > MAX_LEEWAY {
            return Err(format!(
                "leeway {:?} is larger than the maximum of {:?}",
                cfg.leeway, MAX_LEEWAY
            ));
        }
        if cfg.jwks.http_timeout.is_zero() {
            return Err("jwks.http_timeout must be greater than zero".into());
        }
        if cfg.kind == IdpType::Entra && cfg.tenants.is_empty() {
            return Err("type entra requires tenants (the allowed tid values)".into());
        }
        let max_token_lifetime = cfg.effective_max_token_lifetime();
        if max_token_lifetime.is_zero() {
            return Err("max_token_lifetime must be greater than zero".into());
        }

        let mut builder = reqwest::Client::builder()
            .timeout(cfg.jwks.http_timeout)
            .connect_timeout(cfg.jwks.http_timeout)
            .user_agent(concat!("pgbearer/", env!("CARGO_PKG_VERSION")))
            .redirect(redirect_policy())
            .https_only(!allow_http)
            .tls_version_min(reqwest::tls::Version::TLS_1_2);
        if let Some(path) = &cfg.ca_file {
            let pem = std::fs::read(path)
                .map_err(|e| format!("cannot read ca_file {}: {e}", path.display()))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                format!(
                    "ca_file {} is not a PEM certificate bundle: {}",
                    path.display(),
                    error_chain(&e)
                )
            })?;
            if certs.is_empty() {
                return Err(format!(
                    "ca_file {} contains no certificates",
                    path.display()
                ));
            }
            builder = builder.tls_certs_merge(certs);
        }
        let http = builder
            .build()
            .map_err(|e| format!("cannot build HTTP client: {}", error_chain(&e)))?;

        Ok(Provider {
            rules: ClaimRules::from_config(cfg, issuer),
            audiences: cfg.audiences.clone(),
            algorithms,
            leeway_secs: cfg.leeway.as_secs(),
            max_token_lifetime_secs: max_token_lifetime.as_secs(),
            revoked_key_ids: cfg.revoked_key_ids.clone(),
            required: cfg.required,
            oauthbearer_scope: cfg.oauthbearer.as_ref().map(|o| o.scope.clone()),
            openid_configuration_url,
            jwks_cfg: cfg.jwks.clone(),
            discovery_url,
            configured_jwks_uri,
            allow_http,
            bearer_token_file: cfg.bearer_token_file.clone(),
            http,
            keys: ArcSwap::from_pointee(KeySet::default()),
            gate: tokio::sync::Mutex::new(Gate::default()),
            fetches: AtomicU64::new(0),
            state: Mutex::new(FetchState::default()),
            metrics,
        })
    }

    /// Provider name.
    pub(crate) fn name(&self) -> &str {
        &self.rules.name
    }

    /// Whether `kid` is listed in `revoked_key_ids`.
    pub(crate) fn is_revoked(&self, kid: &str) -> bool {
        self.revoked_key_ids.iter().any(|r| r == kid)
    }

    /// Drop revoked keys from a parsed key set, recording them as skipped.
    fn drop_revoked(&self, parsed: &mut ParsedJwks) {
        if self.revoked_key_ids.is_empty() {
            return;
        }
        let mut revoked = Vec::new();
        parsed.keys.retain(|k| match k.kid.as_deref() {
            Some(kid) if self.is_revoked(kid) => {
                revoked.push(format!("key {kid:?} is revoked (revoked_key_ids)"));
                false
            }
            _ => true,
        });
        parsed.skipped.extend(revoked);
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FetchState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The last refresh error, if the last attempt failed.
    pub(crate) fn last_error(&self) -> Option<String> {
        self.state().last_error.clone()
    }

    /// The current key set if it may be used: non-empty, and not older than
    /// `max_stale` while refreshes are failing.
    pub(crate) fn usable_keys(&self) -> Option<Arc<KeySet>> {
        let keys = self.keys.load_full();
        if keys.keys.is_empty() {
            return None;
        }
        let too_old = keys
            .fetched_at
            .is_some_and(|t| t.elapsed() > self.jwks_cfg.max_stale);
        if too_old && self.last_error().is_some() {
            return None;
        }
        Some(keys)
    }

    /// Seconds since the key set was last fetched successfully.
    pub(crate) fn age(&self) -> Option<Duration> {
        self.keys.load().fetched_at.map(|t| t.elapsed())
    }

    /// Update `pgbearer_jwks_age_seconds` for this provider.
    pub(crate) fn update_age_gauge(&self) {
        if let Some(age) = self.age() {
            self.metrics
                .jwks_age_seconds
                .get_or_create(&ProviderLabels {
                    provider: self.rules.name.clone(),
                })
                .set(age.as_secs_f64());
        }
    }

    /// Install a key set parsed from a JWKS document (no network).
    pub(crate) fn install_jwks(&self, body: &[u8]) -> Result<usize, String> {
        let mut parsed = parse_jwks(body)?;
        self.drop_revoked(&mut parsed);
        if parsed.keys.is_empty() {
            return Err(format!(
                "JWKS contains no usable signing keys ({} skipped: {})",
                parsed.skipped.len(),
                parsed.skipped.join("; ")
            ));
        }
        let count = parsed.keys.len();
        self.keys.store(Arc::new(KeySet {
            keys: parsed.keys,
            fetched_at: Some(Instant::now()),
            cache_max_age: None,
        }));
        self.state().last_error = None;
        self.update_age_gauge();
        Ok(count)
    }

    /// HTTP GET with the provider's client, optional bearer token, status
    /// check and response size cap. Returns the body and the
    /// `Cache-Control` max-age.
    async fn get(&self, url: &Url) -> Result<(Vec<u8>, Option<Duration>), String> {
        check_scheme(url, self.allow_http, "URL")?;
        let mut request = self
            .http
            .get(url.clone())
            .header(ACCEPT, "application/json");
        if let Some(path) = &self.bearer_token_file {
            let token = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| format!("cannot read bearer_token_file {}: {e}", path.display()))?;
            let token = token.trim();
            if token.is_empty() {
                return Err(format!("bearer_token_file {} is empty", path.display()));
            }
            request = request.bearer_auth(token);
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| format!("GET {url} failed: {}", error_chain(&e)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("GET {url} returned HTTP {status}"));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
        {
            return Err(format!(
                "GET {url}: response is larger than {MAX_RESPONSE_BYTES} bytes"
            ));
        }
        let cache_max_age = parse_cache_control(
            response
                .headers()
                .get_all(CACHE_CONTROL)
                .iter()
                .filter_map(|v| v.to_str().ok()),
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            format!(
                "GET {url}: reading the response failed: {}",
                error_chain(&e)
            )
        })? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(format!(
                    "GET {url}: response is larger than {MAX_RESPONSE_BYTES} bytes"
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((body, cache_max_age))
    }

    /// Fetch the discovery document and return its `jwks_uri`. The document's
    /// `issuer` must equal the configured issuer exactly (mix-up protection).
    async fn discover(&self) -> Result<Url, String> {
        let (body, _) = self.get(&self.discovery_url).await?;
        let doc: Value = serde_json::from_slice(&body).map_err(|e| {
            format!(
                "discovery document {} is not valid JSON: {e}",
                self.discovery_url
            )
        })?;
        let issuer = doc
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("discovery document {} has no issuer", self.discovery_url))?;
        if issuer != self.rules.issuer {
            return Err(format!(
                "discovery document {} names issuer {:?}, but the configured issuer is {:?}",
                self.discovery_url,
                crate::jwt::sanitize(issuer),
                self.rules.issuer
            ));
        }
        let jwks_uri = doc
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("discovery document {} has no jwks_uri", self.discovery_url))?;
        parse_url(jwks_uri, self.allow_http, "jwks_uri from discovery")
    }

    /// Resolve the JWKS URL, fetch and parse the key set.
    async fn fetch_keys(&self) -> Result<KeySet, String> {
        let (jwks_uri, discovered) = match &self.configured_jwks_uri {
            Some(u) => (u.clone(), false),
            None => {
                let cached = self.state().discovered_jwks_uri.clone();
                match cached {
                    Some(u) => (u, true),
                    None => {
                        let u = self.discover().await?;
                        self.state().discovered_jwks_uri = Some(u.clone());
                        (u, true)
                    }
                }
            }
        };
        let fetched = self.get(&jwks_uri).await.and_then(|(body, cache_max_age)| {
            let mut parsed = parse_jwks(&body).map_err(|e| format!("{jwks_uri}: {e}"))?;
            self.drop_revoked(&mut parsed);
            if parsed.keys.is_empty() {
                return Err(format!(
                    "JWKS at {jwks_uri} contains no usable signing keys ({} skipped{}{})",
                    parsed.skipped.len(),
                    if parsed.skipped.is_empty() { "" } else { ": " },
                    parsed.skipped.join("; ")
                ));
            }
            if !parsed.skipped.is_empty() {
                tracing::debug!(
                    provider = %self.rules.name,
                    skipped = ?parsed.skipped,
                    "ignored unusable JWKS entries"
                );
            }
            Ok(KeySet {
                keys: parsed.keys,
                fetched_at: Some(Instant::now()),
                cache_max_age,
            })
        });
        if fetched.is_err() && discovered {
            // The discovery document may have changed; look it up again next time.
            self.state().discovered_jwks_uri = None;
        }
        fetched
    }

    /// One fetch attempt; stores the result and records metrics. Callers
    /// must hold `gate`.
    async fn fetch_and_store(&self) -> Result<usize, String> {
        let result = self.fetch_keys().await;
        let outcome = match result {
            Ok(set) => {
                let count = set.keys.len();
                self.keys.store(Arc::new(set));
                self.state().last_error = None;
                tracing::debug!(provider = %self.rules.name, keys = count, "JWKS refreshed");
                Ok(count)
            }
            Err(e) => {
                tracing::warn!(provider = %self.rules.name, error = %e, "JWKS refresh failed");
                self.state().last_error = Some(e.clone());
                Err(e)
            }
        };
        self.fetches.fetch_add(1, Ordering::AcqRel);
        self.metrics
            .jwks_refresh
            .get_or_create(&ProviderResultLabels {
                provider: self.rules.name.clone(),
                result: if outcome.is_ok() {
                    "success"
                } else {
                    "failure"
                }
                .into(),
            })
            .inc();
        self.update_age_gauge();
        outcome
    }

    /// A scheduled (startup or background) refresh. Not rate-limited, but
    /// serialised with all other fetches.
    pub(crate) async fn refresh_scheduled(&self) -> Result<usize, String> {
        let _gate = self.gate.lock().await;
        self.fetch_and_store().await
    }

    /// An on-demand refresh (unknown `kid` or no keys): single-flight and at
    /// most once per `min_refresh_interval`.
    pub(crate) async fn refresh_on_demand(&self) {
        let seen = self.fetches.load(Ordering::Acquire);
        let mut gate = self.gate.lock().await;
        if self.fetches.load(Ordering::Acquire) != seen {
            // Another fetch completed while we waited; use its result.
            return;
        }
        if let Some(last) = gate.last_on_demand
            && last.elapsed() < self.jwks_cfg.min_refresh_interval
        {
            tracing::debug!(
                provider = %self.rules.name,
                "JWKS refresh skipped: rate limited by jwks.min_refresh_interval"
            );
            return;
        }
        gate.last_on_demand = Some(Instant::now());
        let _ = self.fetch_and_store().await;
    }

    /// Background refresh loop; returns when `shutdown` is cancelled.
    /// `failures` is the number of consecutive failed attempts so far.
    pub(crate) async fn run_background(
        self: Arc<Self>,
        shutdown: CancellationToken,
        failures: u32,
    ) {
        let mut failures = failures;
        loop {
            let delay = if failures > 0 {
                retry_delay(&self.jwks_cfg, failures)
            } else {
                refresh_delay(&self.jwks_cfg, self.keys.load().cache_max_age)
            };
            let delay = delay.saturating_add(jitter(delay));
            let start = Instant::now();
            // `delay` is bounded (≤ 1.1 × MAX_SCHEDULE_DELAY), so this cannot
            // overflow in practice; fall back to an immediate refresh if it did.
            let deadline = start.checked_add(delay).unwrap_or(start);
            loop {
                self.update_age_gauge();
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let step = (deadline - now).min(AGE_GAUGE_INTERVAL);
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(step) => {}
                }
            }
            let result = tokio::select! {
                _ = shutdown.cancelled() => return,
                r = self.refresh_scheduled() => r,
            };
            failures = match result {
                Ok(_) => 0,
                Err(_) => failures.saturating_add(1),
            };
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;

    fn cfg(min: u64, max_age: u64) -> JwksConfig {
        JwksConfig {
            min_refresh_interval: Duration::from_secs(min),
            max_age: Duration::from_secs(max_age),
            ..JwksConfig::default()
        }
    }

    #[test]
    fn refresh_delay_honours_cache_control_within_bounds() {
        let c = cfg(30, 3600);
        assert_eq!(refresh_delay(&c, None), Duration::from_secs(3600));
        assert_eq!(
            refresh_delay(&c, Some(Duration::from_secs(600))),
            Duration::from_secs(600)
        );
        // Not below min_refresh_interval.
        assert_eq!(
            refresh_delay(&c, Some(Duration::from_secs(5))),
            Duration::from_secs(30)
        );
        assert_eq!(
            refresh_delay(&c, Some(Duration::ZERO)),
            Duration::from_secs(30)
        );
        // Larger hints are capped at max_age.
        assert_eq!(
            refresh_delay(&c, Some(Duration::from_secs(86_400))),
            Duration::from_secs(3600)
        );
        // Degenerate configs never produce a busy loop.
        assert_eq!(refresh_delay(&cfg(0, 0), Some(Duration::ZERO)), MIN_DELAY);
    }

    #[test]
    fn retry_delay_backs_off_exponentially() {
        let c = cfg(30, 3600);
        assert_eq!(retry_delay(&c, 1), Duration::from_secs(1));
        assert_eq!(retry_delay(&c, 2), Duration::from_secs(2));
        assert_eq!(retry_delay(&c, 4), Duration::from_secs(8));
        assert_eq!(retry_delay(&c, 30), MAX_RETRY_DELAY);
        assert_eq!(retry_delay(&c, u32::MAX), MAX_RETRY_DELAY);
        // Capped at max_age.
        assert_eq!(retry_delay(&cfg(0, 3), 10), Duration::from_secs(3));
        assert_eq!(retry_delay(&cfg(0, 0), 10), MIN_DELAY);
    }

    #[test]
    fn jitter_is_small() {
        let d = Duration::from_secs(100);
        assert!(jitter(d) <= Duration::from_secs(10));
    }

    #[test]
    fn url_checks() {
        assert!(parse_url("https://idp.example.com", false, "issuer").is_ok());
        assert!(parse_url("http://idp.example.com", true, "issuer").is_ok());
        let e = parse_url("http://idp.example.com", false, "issuer").unwrap_err();
        assert!(e.contains("must use https"), "{e}");
        assert!(parse_url("ftp://idp.example.com", true, "issuer").is_err());
        assert!(parse_url("not a url", true, "issuer").is_err());
    }
}
