//! An in-process mock OpenID Connect identity provider for tests
//! (Cargo feature `testing`).
//!
//! [`MockIssuer`] runs a small HTTP server on `127.0.0.1` with an ephemeral
//! port that serves:
//!
//! * `GET /.well-known/openid-configuration`: a discovery document whose
//!   `issuer` is [`MockIssuer::issuer_url`] and whose `jwks_uri` is
//!   [`MockIssuer::jwks_url`];
//! * `GET /jwks`: the public keys.
//!
//! It holds an ECDSA P-256 key (`ES256`, generated at start and on
//! [`MockIssuer::rotate_key`], published with `"alg": "ES256"`) and a fixed
//! RSA-2048 key (published without `alg`, as Entra ID does, so `RS256` and
//! `PS256` both verify), and mints signed tokens with [`MockIssuer::mint`] and
//! [`MockIssuer::mint_with`]. Outages, slow responses, issuer mix-ups and odd
//! key sets can be simulated, and request counters let tests check how often
//! pgbearer fetched keys.
//!
//! The issuer URL is `http://…`, so a provider config that points at it needs
//! `insecure_allow_http: true`; [`MockIssuer::provider_config`] builds one.
//!
//! ```no_run
//! # async fn demo() {
//! use std::sync::Arc;
//! use pgbearer_auth::TokenValidator;
//! use pgbearer_auth::testing::MockIssuer;
//! use serde_json::json;
//!
//! let idp = MockIssuer::start().await;
//! let validator = Arc::new(
//!     TokenValidator::new(&[idp.provider_config("test")], 16 * 1024,
//!                         pgbearer_telemetry::Metrics::new()).unwrap(),
//! );
//! validator.start(tokio_util::sync::CancellationToken::new()).await;
//! let token = idp.mint(json!({"sub": "alice", "aud": "pgbearer"}));
//! let identity = validator.validate(&token).await.unwrap();
//! assert_eq!(identity.subject, "alice");
//! # }
//! ```
//!
//! The RSA key is a **test-only** key committed to the repository
//! (`src/testdata/mock-issuer-rsa.TEST-ONLY.pem`); it protects nothing.
//!
//! The server stops when the [`MockIssuer`] is dropped. Its helpers panic on
//! internal failures (they are for tests only).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey};
use pgbearer_config::{ClaimMapping, IdentityProviderConfig, IdpType, JwksConfig, JwtAlgorithm};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::jwt::{alg_name, parse_asymmetric_alg};

/// The audience used by [`MockIssuer::provider_config`].
pub const DEFAULT_AUDIENCE: &str = "pgbearer";

/// Lifetime of minted tokens when the claims set no `exp`.
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

/// The committed, test-only RSA key (with an explanatory label before the PEM).
const RSA_FIXTURE: &str = include_str!("testdata/mock-issuer-rsa.TEST-ONLY.pem");

/// Which mock key signs a token.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MockKeyType {
    /// The current ECDSA P-256 key (`ES256`). Changes on
    /// [`MockIssuer::rotate_key`].
    #[default]
    Ec,
    /// The fixed RSA-2048 key (`RS256` by default; `PS*`/`RS*` via
    /// [`MintOptions::alg`]).
    Rsa,
}

/// The `kid` header of a minted token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum KidHeader {
    /// The signing key's id (default).
    #[default]
    Key,
    /// No `kid` header.
    Omit,
    /// This value.
    Custom(String),
}

/// Options for [`MockIssuer::mint_with`].
///
/// The default signs with the current EC key using `ES256`, sets `kid` and
/// `typ: "JWT"`, and fills in `iss`, `iat` and `exp`.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    /// Signing key.
    pub key: MockKeyType,
    /// The header `alg`. `None` uses the key's default (`ES256` / `RS256`).
    ///
    /// * An asymmetric algorithm compatible with the key (for example
    ///   `PS256` with the RSA key) signs with that algorithm.
    /// * `HS256`/`HS384`/`HS512` sign with HMAC using
    ///   [`MintOptions::hmac_secret`] (default: the signing key's public JWK
    ///   as JSON, the classic algorithm-confusion attack).
    /// * `none` (any case) produces an empty signature.
    /// * Anything else is written to the header as is, while the token is
    ///   signed with the key's default algorithm (a header/key mismatch).
    pub alg: Option<String>,
    /// The `kid` header.
    pub kid: KidHeader,
    /// Extra header fields, applied last. A JSON `null` removes a field (for
    /// example `"typ": null`).
    pub header: Map<String, Value>,
    /// Do not fill in `iss`, `iat` and `exp`, and keep `null` claims.
    pub no_defaults: bool,
    /// HMAC secret for `HS*` algorithms.
    pub hmac_secret: Option<Vec<u8>>,
}

impl MintOptions {
    /// Sign with the RSA key (`RS256`).
    pub fn rsa() -> MintOptions {
        MintOptions {
            key: MockKeyType::Rsa,
            ..MintOptions::default()
        }
    }

    /// Set the header `alg` (see [`MintOptions::alg`]).
    pub fn alg(mut self, alg: &str) -> MintOptions {
        self.alg = Some(alg.to_string());
        self
    }

    /// Set a custom `kid`.
    pub fn kid(mut self, kid: &str) -> MintOptions {
        self.kid = KidHeader::Custom(kid.to_string());
        self
    }

    /// Omit the `kid` header.
    pub fn without_kid(mut self) -> MintOptions {
        self.kid = KidHeader::Omit;
        self
    }

    /// Set (or, with `Value::Null`, remove) a header field.
    pub fn header(mut self, name: &str, value: Value) -> MintOptions {
        self.header.insert(name.to_string(), value);
        self
    }

    /// Do not fill in default claims.
    pub fn without_defaults(mut self) -> MintOptions {
        self.no_defaults = true;
        self
    }
}

/// A signing key and its public JWK.
struct MockKey {
    kid: String,
    alg: Algorithm,
    encoding: EncodingKey,
    jwk: Value,
}

impl MockKey {
    fn new(kid: String, alg: Algorithm, encoding: EncodingKey) -> MockKey {
        let mut jwk = match Jwk::from_encoding_key(&encoding, alg)
            .map_err(|e| e.to_string())
            .and_then(|j| serde_json::to_value(j).map_err(|e| e.to_string()))
        {
            Ok(v) => v,
            Err(e) => panic!("MockIssuer: cannot build the public JWK: {e}"),
        };
        jwk["kid"] = json!(kid);
        jwk["use"] = json!("sig");
        if alg.family() == jsonwebtoken::AlgorithmFamily::Rsa {
            // Like Entra ID, publish RSA keys without "alg" so that both
            // RS256 and PS256 tokens verify against them.
            if let Some(obj) = jwk.as_object_mut() {
                obj.remove("alg");
            }
        } else {
            jwk["alg"] = json!(alg_name(alg));
        }
        MockKey {
            kid,
            alg,
            encoding,
            jwk,
        }
    }

    fn generate_ec(kid: String) -> MockKey {
        let pair = match rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256) {
            Ok(p) => p,
            Err(e) => panic!("MockIssuer: cannot generate an EC key: {e}"),
        };
        MockKey::new(
            kid,
            Algorithm::ES256,
            EncodingKey::from_ec_der(&pair.serialize_der()),
        )
    }

    fn fixture_rsa() -> MockKey {
        let pem = RSA_FIXTURE
            .find("-----BEGIN")
            .map_or(RSA_FIXTURE, |i| &RSA_FIXTURE[i..]);
        let encoding = match EncodingKey::from_rsa_pem(pem.as_bytes()) {
            Ok(k) => k,
            Err(e) => panic!("MockIssuer: cannot load the RSA test key: {e}"),
        };
        MockKey::new("rsa-1".into(), Algorithm::RS256, encoding)
    }
}

/// Mutable mock state.
struct Inner {
    ec: MockKey,
    rsa: MockKey,
    rotations: u32,
    available: bool,
    discovery_issuer: Option<String>,
    cache_control: Option<String>,
    jwks_delay: Duration,
    publish_rsa: bool,
    extra_jwks: Vec<Value>,
    jwks_body: Option<String>,
    last_authorization: Option<String>,
}

struct Shared {
    issuer: String,
    inner: Mutex<Inner>,
    jwks_requests: AtomicUsize,
    discovery_requests: AtomicUsize,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn jwks_document(&self) -> Value {
        let inner = self.lock();
        let mut keys = vec![inner.ec.jwk.clone()];
        if inner.publish_rsa {
            keys.push(inner.rsa.jwk.clone());
        }
        keys.extend(inner.extra_jwks.iter().cloned());
        json!({ "keys": keys })
    }
}

/// A running mock identity provider. See the [module docs](self).
pub struct MockIssuer {
    addr: SocketAddr,
    shared: Arc<Shared>,
    shutdown: CancellationToken,
}

impl std::fmt::Debug for MockIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockIssuer")
            .field("issuer", &self.shared.issuer)
            .finish_non_exhaustive()
    }
}

impl Drop for MockIssuer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn record_authorization(shared: &Shared, headers: &HeaderMap) {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    shared.lock().last_authorization = value;
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "identity provider unavailable",
    )
        .into_response()
}

fn json_response(body: String, cache_control: Option<&str>) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(cc) = cache_control
        && let Ok(v) = HeaderValue::from_str(cc)
    {
        headers.insert(CACHE_CONTROL, v);
    }
    response
}

async fn discovery_handler(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    shared.discovery_requests.fetch_add(1, Ordering::SeqCst);
    record_authorization(&shared, &headers);
    let (available, issuer) = {
        let inner = shared.lock();
        (
            inner.available,
            inner
                .discovery_issuer
                .clone()
                .unwrap_or_else(|| shared.issuer.clone()),
        )
    };
    if !available {
        return unavailable();
    }
    let base = &shared.issuer;
    let doc = json!({
        "issuer": issuer,
        "jwks_uri": format!("{base}/jwks"),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "device_authorization_endpoint": format!("{base}/device"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256", "RS256", "PS256"],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
    });
    json_response(doc.to_string(), None)
}

async fn jwks_handler(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    shared.jwks_requests.fetch_add(1, Ordering::SeqCst);
    record_authorization(&shared, &headers);
    let delay = shared.lock().jwks_delay;
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let (available, body, cache_control) = {
        let inner = shared.lock();
        (
            inner.available,
            inner.jwks_body.clone(),
            inner.cache_control.clone(),
        )
    };
    if !available {
        return unavailable();
    }
    let body = body.unwrap_or_else(|| shared.jwks_document().to_string());
    json_response(body, cache_control.as_deref())
}

impl MockIssuer {
    /// Start a mock issuer on `127.0.0.1` with an ephemeral port.
    ///
    /// # Panics
    ///
    /// If the listener cannot be bound (see [`MockIssuer::try_start`]).
    pub async fn start() -> MockIssuer {
        match MockIssuer::try_start().await {
            Ok(m) => m,
            Err(e) => panic!("MockIssuer: cannot start: {e}"),
        }
    }

    /// Like [`MockIssuer::start`], returning bind errors.
    pub async fn try_start() -> std::io::Result<MockIssuer> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            issuer: format!("http://{addr}"),
            inner: Mutex::new(Inner {
                ec: MockKey::generate_ec("ec-1".into()),
                rsa: MockKey::fixture_rsa(),
                rotations: 1,
                available: true,
                discovery_issuer: None,
                cache_control: None,
                jwks_delay: Duration::ZERO,
                publish_rsa: true,
                extra_jwks: Vec::new(),
                jwks_body: None,
                last_authorization: None,
            }),
            jwks_requests: AtomicUsize::new(0),
            discovery_requests: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .route("/jwks", get(jwks_handler))
            .with_state(shared.clone());
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move { stop.cancelled().await })
                .await;
        });
        Ok(MockIssuer {
            addr,
            shared,
            shutdown,
        })
    }

    /// The issuer URL, `http://127.0.0.1:<port>` (no trailing slash). Minted
    /// tokens use it as `iss` by default.
    pub fn issuer_url(&self) -> String {
        self.shared.issuer.clone()
    }

    /// The server's socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `<issuer>/.well-known/openid-configuration`.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.shared.issuer)
    }

    /// `<issuer>/jwks`.
    pub fn jwks_url(&self) -> String {
        format!("{}/jwks", self.shared.issuer)
    }

    /// A provider config for this issuer: type `oidc`, audience
    /// [`DEFAULT_AUDIENCE`], `insecure_allow_http: true`, `required: true`,
    /// default algorithms, leeway (60 s) and JWKS settings. Adjust the fields
    /// as needed (for example `jwks.min_refresh_interval`).
    pub fn provider_config(&self, name: &str) -> IdentityProviderConfig {
        IdentityProviderConfig {
            name: name.to_string(),
            kind: IdpType::Oidc,
            issuer: Some(self.issuer_url()),
            audiences: vec![DEFAULT_AUDIENCE.to_string()],
            discovery_url: None,
            jwks_uri: None,
            ca_file: None,
            bearer_token_file: None,
            algorithms: vec![
                JwtAlgorithm::RS256,
                JwtAlgorithm::PS256,
                JwtAlgorithm::ES256,
                JwtAlgorithm::EdDSA,
            ],
            leeway: Duration::from_secs(60),
            required: true,
            claims: ClaimMapping::default(),
            tenants: Vec::new(),
            required_scopes: Vec::new(),
            required_claims: Vec::new(),
            allowed_client_ids: Vec::new(),
            expected_typ: None,
            jwks: JwksConfig::default(),
            insecure_allow_http: true,
            oauthbearer: None,
        }
    }

    /// Mint a token signed with the current EC key (`ES256`, `kid` set,
    /// `typ: "JWT"`). If `claims` is an object, `iss` (this issuer), `iat`
    /// (now) and `exp` (now + 1 h) are added when absent, and claims set to
    /// `null` are removed (for example `"exp": null` mints a token without
    /// `exp`). Nothing else is added; in particular set `aud` yourself.
    pub fn mint(&self, claims: Value) -> String {
        self.mint_with(claims, &MintOptions::default())
    }

    /// Mint a token with explicit options; see [`MintOptions`].
    ///
    /// # Panics
    ///
    /// If signing fails (only with an `alg` that cannot sign with the key).
    pub fn mint_with(&self, claims: Value, options: &MintOptions) -> String {
        let claims = if options.no_defaults {
            claims
        } else {
            self.with_default_claims(claims)
        };
        let inner = self.shared.lock();
        let key = match options.key {
            MockKeyType::Ec => &inner.ec,
            MockKeyType::Rsa => &inner.rsa,
        };
        let header_alg = options
            .alg
            .clone()
            .unwrap_or_else(|| alg_name(key.alg).to_string());

        let mut header = Map::new();
        header.insert("alg".into(), json!(header_alg));
        header.insert("typ".into(), json!("JWT"));
        match &options.kid {
            KidHeader::Key => {
                header.insert("kid".into(), json!(key.kid));
            }
            KidHeader::Omit => {}
            KidHeader::Custom(kid) => {
                header.insert("kid".into(), json!(kid));
            }
        }
        for (name, value) in &options.header {
            if value.is_null() {
                header.remove(name);
            } else {
                header.insert(name.clone(), value.clone());
            }
        }

        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(Value::Object(header).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let hmac = match header_alg.as_str() {
            "HS256" => Some(Algorithm::HS256),
            "HS384" => Some(Algorithm::HS384),
            "HS512" => Some(Algorithm::HS512),
            _ => None,
        };
        let signature = if header_alg.eq_ignore_ascii_case("none") {
            Ok(String::new())
        } else if let Some(alg) = hmac {
            let secret = options
                .hmac_secret
                .clone()
                .unwrap_or_else(|| key.jwk.to_string().into_bytes());
            jsonwebtoken::crypto::sign(message.as_bytes(), &EncodingKey::from_secret(&secret), alg)
        } else {
            let alg = parse_asymmetric_alg(&header_alg)
                .filter(|a| a.family() == key.alg.family() && compatible_ec(*a, key.alg))
                .unwrap_or(key.alg);
            jsonwebtoken::crypto::sign(message.as_bytes(), &key.encoding, alg)
        };
        match signature {
            Ok(sig) => format!("{message}.{sig}"),
            Err(e) => panic!("MockIssuer: cannot sign a token: {e}"),
        }
    }

    fn with_default_claims(&self, claims: Value) -> Value {
        let Value::Object(mut map) = claims else {
            return claims;
        };
        let now = now_secs();
        map.entry("iss")
            .or_insert_with(|| json!(self.shared.issuer));
        map.entry("iat").or_insert_with(|| json!(now));
        map.entry("exp")
            .or_insert_with(|| json!(now + DEFAULT_TOKEN_LIFETIME.as_secs()));
        map.retain(|_, v| !v.is_null());
        Value::Object(map)
    }

    /// The `kid` of the current EC key.
    pub fn current_kid(&self) -> String {
        self.shared.lock().ec.kid.clone()
    }

    /// The `kid` of the RSA key.
    pub fn rsa_kid(&self) -> String {
        self.shared.lock().rsa.kid.clone()
    }

    /// Replace the EC key with a new one (new `kid`, `ec-2`, `ec-3`, …) and
    /// return the new `kid`. The old key is no longer published, so tokens it
    /// signed stop validating once pgbearer refreshes its key set.
    pub fn rotate_key(&self) -> String {
        let mut inner = self.shared.lock();
        inner.rotations += 1;
        let kid = format!("ec-{}", inner.rotations);
        inner.ec = MockKey::generate_ec(kid.clone());
        kid
    }

    /// Simulate an outage: while `false`, both endpoints return HTTP 503.
    pub fn set_available(&self, available: bool) {
        self.shared.lock().available = available;
    }

    /// Serve a different `issuer` in the discovery document (to test mix-up
    /// protection); `None` restores the real one.
    pub fn set_discovery_issuer(&self, issuer: Option<String>) {
        self.shared.lock().discovery_issuer = issuer;
    }

    /// Send this `Cache-Control` header with the JWKS; `None` sends none.
    pub fn set_cache_control(&self, value: Option<String>) {
        self.shared.lock().cache_control = value;
    }

    /// Delay every JWKS response (to test timeouts and single-flight
    /// refreshes). The request is counted when it arrives.
    pub fn set_jwks_delay(&self, delay: Duration) {
        self.shared.lock().jwks_delay = delay;
    }

    /// Whether the RSA key is published in the JWKS (default `true`). With
    /// `false` the set has exactly one key (plus any extra JWKs).
    pub fn set_publish_rsa(&self, publish: bool) {
        self.shared.lock().publish_rsa = publish;
    }

    /// Additional raw JWK objects appended to the published key set (for
    /// example encryption or symmetric keys that must be ignored).
    pub fn set_extra_jwks(&self, keys: Vec<Value>) {
        self.shared.lock().extra_jwks = keys;
    }

    /// Serve this exact body from `/jwks` instead of the key set (for
    /// example `{"keys":[]}` or garbage); `None` restores normal behaviour.
    pub fn set_jwks_body(&self, body: Option<String>) {
        self.shared.lock().jwks_body = body;
    }

    /// The JWKS document as currently published (ignores
    /// [`MockIssuer::set_jwks_body`]). Useful with
    /// [`crate::TokenValidator::load_jwks`].
    pub fn jwks(&self) -> Value {
        self.shared.jwks_document()
    }

    /// Number of `/jwks` requests received.
    pub fn jwks_request_count(&self) -> usize {
        self.shared.jwks_requests.load(Ordering::SeqCst)
    }

    /// Number of discovery requests received.
    pub fn discovery_request_count(&self) -> usize {
        self.shared.discovery_requests.load(Ordering::SeqCst)
    }

    /// The `Authorization` header of the most recent request, if any.
    pub fn last_authorization(&self) -> Option<String> {
        self.shared.lock().last_authorization.clone()
    }
}

/// ES256 and ES384 share a family but need different curves; the mock EC key
/// is P-256, so only ES256 can really sign with it.
fn compatible_ec(requested: Algorithm, key_alg: Algorithm) -> bool {
    !matches!(
        (requested, key_alg),
        (Algorithm::ES384, Algorithm::ES256) | (Algorithm::ES256, Algorithm::ES384)
    )
}
