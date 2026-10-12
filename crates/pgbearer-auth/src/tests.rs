//! End-to-end tests of [`TokenValidator`] against [`MockIssuer`].

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pgbearer_config::{IdentityProviderConfig, IdpType, JwtAlgorithm, OauthBearerConfig};
use pgbearer_core::IdentityKind;
use pgbearer_telemetry::Metrics;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::testing::{MintOptions, MockIssuer};
use crate::{AuthError, TokenValidator};

const MAX_TOKEN: usize = 16 * 1024;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn build(cfgs: &[IdentityProviderConfig]) -> (Arc<TokenValidator>, Arc<Metrics>) {
    let metrics = Metrics::new();
    let v = TokenValidator::new(cfgs, MAX_TOKEN, metrics.clone()).unwrap();
    (Arc::new(v), metrics)
}

/// A started validator; the background tasks stop when the guard drops.
struct Started {
    v: Arc<TokenValidator>,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
}

impl Drop for Started {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn start(cfgs: &[IdentityProviderConfig]) -> Started {
    let (v, metrics) = build(cfgs);
    let shutdown = CancellationToken::new();
    v.start(shutdown.clone()).await;
    Started {
        v,
        metrics,
        shutdown,
    }
}

async fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

fn user_claims(sub: &str) -> Value {
    json!({"sub": sub, "aud": "pgbearer"})
}

fn new_err(cfgs: &[IdentityProviderConfig]) -> String {
    match TokenValidator::new(cfgs, MAX_TOKEN, Metrics::new()) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected TokenValidator::new to fail"),
    }
}

// ---------------------------------------------------------------------------
// Valid tokens and identity mapping per provider type
// ---------------------------------------------------------------------------

#[tokio::test]
async fn es256_token_maps_oidc_identity() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("oidc")]).await;
    assert!(s.v.is_ready());
    let exp = now() + 600;
    let token = idp.mint(json!({
        "sub": "user-1", "aud": "pgbearer", "exp": exp,
        "preferred_username": "alice@example.com", "groups": ["g1", "g2"],
        "roles": "reader", "scope": "openid db.connect", "azp": "cli", "jti": "tok-1",
        "custom": {"nested": true}
    }));
    let id = s.v.validate(&token).await.unwrap();
    assert_eq!(id.provider, "oidc");
    assert_eq!(id.issuer, idp.issuer_url());
    assert_eq!(id.subject, "user-1");
    assert_eq!(id.username.as_deref(), Some("alice@example.com"));
    assert_eq!(id.groups, ["g1", "g2"].map(String::from).into());
    assert_eq!(id.roles, ["reader".to_string()].into());
    assert_eq!(id.scopes, ["db.connect", "openid"].map(String::from).into());
    assert_eq!(id.client_id.as_deref(), Some("cli"));
    assert_eq!(id.kind, IdentityKind::Human);
    assert_eq!(id.token_id.as_deref(), Some("tok-1"));
    assert_eq!(id.expires_at, UNIX_EPOCH + Duration::from_secs(exp));
    assert!(!id.groups_overage);
    assert_eq!(id.claim("custom.nested"), Some(&json!(true)));
    assert_eq!(id.tenant, None);
}

#[tokio::test]
async fn rs256_and_ps256_tokens_validate() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("oidc")]).await;
    let rs = idp.mint_with(user_claims("rsa-user"), &MintOptions::rsa());
    assert_eq!(s.v.validate(&rs).await.unwrap().subject, "rsa-user");
    let ps = idp.mint_with(user_claims("pss-user"), &MintOptions::rsa().alg("PS256"));
    assert_eq!(s.v.validate(&ps).await.unwrap().subject, "pss-user");
}

#[tokio::test]
async fn entra_user_and_app_tokens() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("entra");
    cfg.kind = IdpType::Entra;
    cfg.tenants = vec!["tenant-1".into()];
    cfg.required_scopes = vec!["Database.Connect".into()];
    let s = start(&[cfg]).await;

    let user = idp.mint(json!({
        "aud": "pgbearer", "oid": "oid-1", "sub": "pairwise", "tid": "tenant-1",
        "scp": "Database.Connect", "roles": ["Orders.Reader"], "idtyp": "user",
        "preferred_username": "alice@contoso.com", "azp": "cli-app", "uti": "uti-1",
        "groups": ["grp-1"]
    }));
    let id = s.v.validate(&user).await.unwrap();
    assert_eq!(id.subject, "oid-1");
    assert_eq!(id.tenant.as_deref(), Some("tenant-1"));
    assert_eq!(id.kind, IdentityKind::Human);
    assert_eq!(id.scopes, ["Database.Connect".to_string()].into());
    assert_eq!(id.roles, ["Orders.Reader".to_string()].into());
    assert_eq!(id.groups, ["grp-1".to_string()].into());
    assert_eq!(id.client_id.as_deref(), Some("cli-app"));
    assert_eq!(id.token_id.as_deref(), Some("uti-1"));

    // App-only token: no scp, idtyp=app → workload, exempt from required_scopes.
    let app = idp.mint(json!({
        "aud": "pgbearer", "oid": "sp-1", "sub": "sp-1", "tid": "tenant-1",
        "roles": ["Orders.Owner"], "idtyp": "app", "appid": "app-client"
    }));
    let id = s.v.validate(&app).await.unwrap();
    assert_eq!(id.subject, "sp-1");
    assert_eq!(id.kind, IdentityKind::Workload);
    assert_eq!(id.client_id.as_deref(), Some("app-client"));
    assert!(id.scopes.is_empty());

    // A token without scp that does not say it is app-only must carry the scope.
    let no_scope = idp.mint(json!({"aud": "pgbearer", "oid": "x", "tid": "tenant-1"}));
    assert_eq!(
        s.v.validate(&no_scope).await.unwrap_err(),
        AuthError::MissingScope("Database.Connect".into())
    );
}

#[tokio::test]
async fn kubernetes_preset_is_workload_and_scope_exempt() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("k8s");
    cfg.kind = IdpType::Kubernetes;
    cfg.required_scopes = vec!["ignored".into()];
    let s = start(&[cfg]).await;
    let token = idp.mint(json!({
        "aud": "pgbearer", "sub": "system:serviceaccount:orders:api",
        "kubernetes.io": {"namespace": "orders", "serviceaccount": {"name": "api"}}
    }));
    let id = s.v.validate(&token).await.unwrap();
    assert_eq!(id.subject, "system:serviceaccount:orders:api");
    assert_eq!(
        id.username.as_deref(),
        Some("system:serviceaccount:orders:api")
    );
    assert_eq!(id.kind, IdentityKind::Workload);
    assert_eq!(id.claim("kubernetes.io.namespace"), None); // literal key with a dot
    assert_eq!(id.claim("/kubernetes.io/namespace"), Some(&json!("orders")));
    assert_eq!(id.claims["kubernetes.io"]["namespace"], "orders");
}

#[tokio::test]
async fn github_actions_preset() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("gha");
    cfg.kind = IdpType::GithubActions;
    cfg.tenants = vec!["1001".into()];
    let s = start(&[cfg]).await;
    let token = idp.mint(json!({
        "aud": "pgbearer", "sub": "repo:my-org/app:environment:prod",
        "repository": "my-org/app", "repository_owner": "my-org",
        "repository_owner_id": "1001", "environment": "prod"
    }));
    let id = s.v.validate(&token).await.unwrap();
    assert_eq!(id.subject, "repo:my-org/app:environment:prod");
    assert_eq!(id.username.as_deref(), Some("my-org/app"));
    assert_eq!(id.tenant.as_deref(), Some("1001"));
    assert_eq!(id.kind, IdentityKind::Workload);
    let other = idp.mint(json!({
        "aud": "pgbearer", "sub": "repo:evil/app:ref:refs/heads/main",
        "repository": "evil/app", "repository_owner": "evil", "repository_owner_id": "2002"
    }));
    assert_eq!(
        s.v.validate(&other).await.unwrap_err(),
        AuthError::TenantNotAllowed("2002".into())
    );
}

#[tokio::test]
async fn eddsa_tokens_validate_with_a_loaded_key_set() {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let x = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        pair.public_key_raw(),
    );
    let idp = MockIssuer::start().await;
    let (v, _) = build(&[idp.provider_config("ed")]);
    let jwks =
        json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "ed-1", "use": "sig"}]});
    assert_eq!(v.load_jwks("ed", jwks.to_string().as_bytes()).unwrap(), 1);
    let header = json!({"alg": "EdDSA", "kid": "ed-1", "typ": "JWT"});
    let claims =
        json!({"iss": idp.issuer_url(), "aud": "pgbearer", "sub": "ed-user", "exp": now() + 60});
    let b64 = |v: &Value| {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            v.to_string(),
        )
    };
    let message = format!("{}.{}", b64(&header), b64(&claims));
    let key = jsonwebtoken::EncodingKey::from_ed_der(&pair.serialize_der());
    let sig = jsonwebtoken::crypto::sign(message.as_bytes(), &key, jsonwebtoken::Algorithm::EdDSA)
        .unwrap();
    let token = format!("{message}.{sig}");
    assert_eq!(v.validate_offline(&token).unwrap().subject, "ed-user");
    assert_eq!(idp.jwks_request_count(), 0);
}

// ---------------------------------------------------------------------------
// Time-based claims
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_and_not_yet_valid_tokens() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let expired = idp.mint(json!({"sub": "a", "aud": "pgbearer", "exp": now() - 3600}));
    assert_eq!(
        s.v.validate(&expired).await.unwrap_err(),
        AuthError::Expired
    );
    let future = idp.mint(json!({"sub": "a", "aud": "pgbearer", "nbf": now() + 3600}));
    assert_eq!(
        s.v.validate(&future).await.unwrap_err(),
        AuthError::NotYetValid
    );
    let issued_in_future = idp.mint(json!({"sub": "a", "aud": "pgbearer", "iat": now() + 3600}));
    assert_eq!(
        s.v.validate(&issued_in_future).await.unwrap_err(),
        AuthError::NotYetValid
    );
    let bad_iat = idp.mint(json!({"sub": "a", "aud": "pgbearer", "iat": "yesterday"}));
    assert_eq!(
        s.v.validate(&bad_iat).await.unwrap_err(),
        AuthError::MissingClaim("iat".into())
    );
    let no_exp = idp.mint(json!({"sub": "a", "aud": "pgbearer", "exp": null}));
    assert_eq!(
        s.v.validate(&no_exp).await.unwrap_err(),
        AuthError::MissingClaim("exp".into())
    );
    let string_exp = idp.mint(json!({"sub": "a", "aud": "pgbearer", "exp": "never"}));
    assert_eq!(
        s.v.validate(&string_exp).await.unwrap_err(),
        AuthError::MissingClaim("exp".into())
    );
}

#[tokio::test]
async fn leeway_applies_to_exp_nbf_and_iat() {
    let idp = MockIssuer::start().await;
    let mut lenient = idp.provider_config("p");
    lenient.leeway = Duration::from_secs(120);
    let s = start(&[lenient]).await;
    let just_expired = idp.mint(json!({"sub": "a", "aud": "pgbearer", "exp": now() - 30}));
    let almost_valid =
        idp.mint(json!({"sub": "a", "aud": "pgbearer", "nbf": now() + 30, "iat": now() + 30}));
    assert!(s.v.validate(&just_expired).await.is_ok());
    assert!(s.v.validate(&almost_valid).await.is_ok());
    drop(s);

    let mut strict = idp.provider_config("p");
    strict.leeway = Duration::ZERO;
    let s = start(&[strict]).await;
    assert_eq!(
        s.v.validate(&just_expired).await.unwrap_err(),
        AuthError::Expired
    );
    assert_eq!(
        s.v.validate(&almost_valid).await.unwrap_err(),
        AuthError::NotYetValid
    );
}

// ---------------------------------------------------------------------------
// Audience and issuer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audience_checks() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.audiences = vec!["pgbearer".into(), "api://pgbearer".into()];
    let s = start(&[cfg]).await;
    let wrong = idp.mint(json!({"sub": "a", "aud": "other-service"}));
    assert_eq!(
        s.v.validate(&wrong).await.unwrap_err(),
        AuthError::BadAudience
    );
    let list = idp.mint(json!({"sub": "a", "aud": ["other", "api://pgbearer"]}));
    assert!(s.v.validate(&list).await.is_ok());
    let empty_list = idp.mint(json!({"sub": "a", "aud": []}));
    assert_eq!(
        s.v.validate(&empty_list).await.unwrap_err(),
        AuthError::BadAudience
    );
    let missing = idp.mint(json!({"sub": "a"}));
    assert_eq!(
        s.v.validate(&missing).await.unwrap_err(),
        AuthError::MissingClaim("aud".into())
    );
    let number = idp.mint(json!({"sub": "a", "aud": 5}));
    assert_eq!(
        s.v.validate(&number).await.unwrap_err(),
        AuthError::MissingClaim("aud".into())
    );
}

#[tokio::test]
async fn unknown_issuer_makes_no_network_request() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let (jwks, discovery) = (idp.jwks_request_count(), idp.discovery_request_count());
    for iss in [
        "https://evil.example.com".to_string(),
        format!("{}/", idp.issuer_url()),
        format!("{}/extra", idp.issuer_url()),
        idp.issuer_url().to_uppercase(),
        String::new(),
    ] {
        let token = idp.mint(json!({"sub": "a", "aud": "pgbearer", "iss": iss}));
        assert!(
            matches!(s.v.validate(&token).await, Err(AuthError::UnknownIssuer(_))),
            "{iss}"
        );
    }
    for iss in [json!(null), json!(5), json!([idp.issuer_url()])] {
        let token = idp.mint_with(
            json!({"sub": "a", "aud": "pgbearer", "iss": iss, "exp": now() + 60}),
            &MintOptions::default().without_defaults(),
        );
        assert_eq!(
            s.v.validate(&token).await.unwrap_err(),
            AuthError::MissingClaim("iss".into())
        );
    }
    assert_eq!(idp.jwks_request_count(), jwks);
    assert_eq!(idp.discovery_request_count(), discovery);
}

#[tokio::test]
async fn multiple_providers_route_by_issuer() {
    let a = MockIssuer::start().await;
    let b = MockIssuer::start().await;
    let s = start(&[a.provider_config("a"), b.provider_config("b")]).await;
    let ta = a.mint(user_claims("from-a"));
    let tb = b.mint(user_claims("from-b"));
    assert_eq!(s.v.validate(&ta).await.unwrap().provider, "a");
    assert_eq!(s.v.validate(&tb).await.unwrap().provider, "b");
    // A token from b claiming to be from a fails: b's key is not in a's set.
    let forged = b.mint(json!({"sub": "x", "aud": "pgbearer", "iss": a.issuer_url()}));
    assert!(matches!(
        s.v.validate(&forged).await,
        Err(AuthError::BadSignature | AuthError::UnknownKey { .. })
    ));
}

// ---------------------------------------------------------------------------
// Algorithms, keys and signatures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alg_none_hmac_and_mismatches_are_rejected() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.algorithms = vec![JwtAlgorithm::ES256, JwtAlgorithm::PS256];
    let s = start(&[cfg]).await;
    let claims = user_claims("a");
    let none = idp.mint_with(claims.clone(), &MintOptions::default().alg("none"));
    assert_eq!(
        s.v.validate(&none).await.unwrap_err(),
        AuthError::DisallowedAlgorithm("none".into())
    );
    // HMAC signed with the public key (algorithm confusion).
    for alg in ["HS256", "HS384", "HS512"] {
        let t = idp.mint_with(claims.clone(), &MintOptions::default().alg(alg));
        assert_eq!(
            s.v.validate(&t).await.unwrap_err(),
            AuthError::DisallowedAlgorithm(alg.into())
        );
    }
    // RS256 is not in this provider's allow-list.
    let rs = idp.mint_with(claims.clone(), &MintOptions::rsa());
    assert_eq!(
        s.v.validate(&rs).await.unwrap_err(),
        AuthError::DisallowedAlgorithm("RS256".into())
    );
    // Header says PS256 but names the EC key: the key's alg (ES256) wins.
    let mismatch = idp.mint_with(claims.clone(), &MintOptions::default().alg("PS256"));
    assert_eq!(
        s.v.validate(&mismatch).await.unwrap_err(),
        AuthError::DisallowedAlgorithm("PS256".into())
    );
    // ES384 header with a P-256 key (ES384 not allowed here either).
    let es384 = idp.mint_with(claims, &MintOptions::default().alg("ES384"));
    assert_eq!(
        s.v.validate(&es384).await.unwrap_err(),
        AuthError::DisallowedAlgorithm("ES384".into())
    );
}

#[tokio::test]
async fn alg_mismatch_with_key_without_alg() {
    let idp = MockIssuer::start().await;
    idp.set_publish_rsa(false);
    // Publish the RSA key without "alg" under a known kid; an ES256 header for
    // it must be rejected by key type.
    let mut rsa_jwk = MockIssuer::start().await.jwks()["keys"][1].clone();
    rsa_jwk.as_object_mut().unwrap().remove("alg");
    rsa_jwk["kid"] = json!("rsa-noalg");
    idp.set_extra_jwks(vec![rsa_jwk]);
    let s = start(&[idp.provider_config("p")]).await;
    let t = idp.mint_with(user_claims("a"), &MintOptions::default().kid("rsa-noalg"));
    assert_eq!(
        s.v.validate(&t).await.unwrap_err(),
        AuthError::DisallowedAlgorithm("ES256".into())
    );
}

#[tokio::test]
async fn bad_signatures_are_rejected() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let token = idp.mint(user_claims("a"));
    let parts: Vec<&str> = token.split('.').collect();
    // Swap in a different payload under the original signature.
    let other = idp.mint(user_claims("admin"));
    let other_payload = other.split('.').nth(1).unwrap();
    let tampered = format!("{}.{}.{}", parts[0], other_payload, parts[2]);
    assert_eq!(
        s.v.validate(&tampered).await.unwrap_err(),
        AuthError::BadSignature
    );
    // Truncated signature (still valid base64url).
    let truncated = format!("{}.{}.{}", parts[0], parts[1], &parts[2][..12]);
    assert_eq!(
        s.v.validate(&truncated).await.unwrap_err(),
        AuthError::BadSignature
    );
    // A signature that is not valid base64url (non-zero trailing bits). The
    // final character is fixed: a random prefix ends in zero trailing bits
    // one time in 16, which would make this case flaky.
    let bad_b64 = format!("{}.{}.{}B", parts[0], parts[1], &parts[2][..9]);
    assert!(matches!(
        s.v.validate(&bad_b64).await,
        Err(AuthError::Malformed(_))
    ));
    // Signed by a different key under a known kid.
    let rogue = MockIssuer::start().await;
    let forged = rogue.mint_with(
        json!({"sub": "a", "aud": "pgbearer", "iss": idp.issuer_url()}),
        &MintOptions::default().kid(&idp.current_kid()),
    );
    assert_eq!(
        s.v.validate(&forged).await.unwrap_err(),
        AuthError::BadSignature
    );
}

#[tokio::test]
async fn tokens_without_kid_need_a_single_key() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    // Two keys published (EC + RSA): ambiguous.
    let t = idp.mint_with(user_claims("a"), &MintOptions::default().without_kid());
    assert_eq!(
        s.v.validate(&t).await.unwrap_err(),
        AuthError::UnknownKey {
            provider: "p".into(),
            kid: String::new()
        }
    );
    drop(s);
    idp.set_publish_rsa(false);
    let s = start(&[idp.provider_config("p")]).await;
    assert_eq!(s.v.validate(&t).await.unwrap().subject, "a");
}

#[tokio::test]
async fn token_headers_never_supply_keys() {
    let idp = MockIssuer::start().await;
    let attacker = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let jwk = attacker.jwks()["keys"][0].clone();
    let token = attacker.mint_with(
        json!({"sub": "a", "aud": "pgbearer", "iss": idp.issuer_url()}),
        &MintOptions::default()
            .kid("attacker-kid")
            .header("jku", json!(attacker.jwks_url()))
            .header("x5u", json!(attacker.jwks_url()))
            .header("jwk", jwk),
    );
    assert!(matches!(
        s.v.validate(&token).await,
        Err(AuthError::UnknownKey { .. })
    ));
    assert_eq!(attacker.jwks_request_count(), 0);
    assert_eq!(attacker.discovery_request_count(), 0);
}

#[tokio::test]
async fn crit_and_odd_headers_are_rejected() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let crit = idp.mint_with(
        user_claims("a"),
        &MintOptions::default()
            .header("crit", json!(["b64"]))
            .header("b64", json!(false)),
    );
    assert!(matches!(
        s.v.validate(&crit).await,
        Err(AuthError::Malformed(_))
    ));
    let numeric_kid = idp.mint_with(
        user_claims("a"),
        &MintOptions::default().header("kid", json!(7)),
    );
    assert!(matches!(
        s.v.validate(&numeric_kid).await,
        Err(AuthError::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// JWKS cache: refresh, rate limiting, rotation, outages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_kid_triggers_exactly_one_refresh_per_interval() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.min_refresh_interval = Duration::from_secs(60);
    let s = start(&[cfg]).await;
    assert_eq!(idp.discovery_request_count(), 1);
    assert_eq!(idp.jwks_request_count(), 1);
    for i in 0..10 {
        let t = idp.mint_with(
            user_claims("a"),
            &MintOptions::default().kid(&format!("random-{i}")),
        );
        assert_eq!(
            s.v.validate(&t).await.unwrap_err(),
            AuthError::UnknownKey {
                provider: "p".into(),
                kid: format!("random-{i}")
            }
        );
    }
    assert_eq!(
        idp.jwks_request_count(),
        2,
        "one refresh for ten unknown kids"
    );
    // Known keys still work and cause no fetches.
    assert!(s.v.validate(&idp.mint(user_claims("a"))).await.is_ok());
    assert_eq!(idp.jwks_request_count(), 2);
    // The discovery result is cached.
    assert_eq!(idp.discovery_request_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_unknown_kids_share_one_refresh() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.min_refresh_interval = Duration::ZERO;
    let s = start(&[cfg]).await;
    assert_eq!(idp.jwks_request_count(), 1);
    idp.set_jwks_delay(Duration::from_millis(300));
    let new_kid = idp.rotate_key();
    let token = idp.mint(user_claims("a"));
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let v = s.v.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move { v.validate(&token).await }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap().subject, "a");
    }
    assert_eq!(
        idp.jwks_request_count(),
        2,
        "all waiters must share one fetch of {new_kid}"
    );
}

#[tokio::test]
async fn key_rotation_is_picked_up() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.min_refresh_interval = Duration::from_millis(100);
    let s = start(&[cfg]).await;
    let old = idp.mint(user_claims("old"));
    assert!(s.v.validate(&old).await.is_ok());
    let new_kid = idp.rotate_key();
    assert_eq!(new_kid, "ec-2");
    let new = idp.mint(user_claims("new"));
    assert_eq!(s.v.validate(&new).await.unwrap().subject, "new");
    assert_eq!(idp.jwks_request_count(), 2);
    // The old key is gone from the refreshed set.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(matches!(
        s.v.validate(&old).await,
        Err(AuthError::UnknownKey { .. })
    ));
}

#[tokio::test]
async fn idp_outage_keeps_old_keys_and_readiness() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.max_age = Duration::from_millis(100);
    cfg.jwks.min_refresh_interval = Duration::from_millis(50);
    let s = start(&[cfg]).await;
    let token = idp.mint(user_claims("a"));
    idp.set_available(false);
    // After a failed JWKS fetch the provider re-runs discovery, so count both.
    let requests = || idp.jwks_request_count() + idp.discovery_request_count();
    let before = requests();
    assert!(
        wait_until(Duration::from_secs(5), || requests() >= before + 3).await,
        "background refresh should keep retrying"
    );
    let status = s.v.status();
    assert!(
        status[0]
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("503"),
        "{status:?}"
    );
    assert_eq!(status[0].keys, 2);
    assert!(s.v.is_ready());
    assert_eq!(s.v.validate(&token).await.unwrap().subject, "a");
    // New keys cannot be fetched during the outage.
    idp.rotate_key();
    let new = idp.mint(user_claims("b"));
    assert!(matches!(
        s.v.validate(&new).await,
        Err(AuthError::UnknownKey { .. })
    ));
    let text = s.metrics.encode();
    assert!(
        text.contains("pgbearer_jwks_refresh_total{provider=\"p\",result=\"failure\"}"),
        "{text}"
    );
    // Recovery.
    idp.set_available(true);
    assert!(
        wait_until(Duration::from_secs(5), || s.v.status()[0]
            .last_error
            .is_none())
        .await
    );
    assert_eq!(s.v.validate(&new).await.unwrap().subject, "b");
}

#[tokio::test]
async fn keys_expire_after_max_stale_while_refresh_fails() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.max_age = Duration::from_millis(100);
    cfg.jwks.min_refresh_interval = Duration::from_millis(50);
    cfg.jwks.max_stale = Duration::from_millis(400);
    let s = start(&[cfg]).await;
    let token = idp.mint(user_claims("a"));
    idp.set_available(false);
    assert!(wait_until(Duration::from_secs(5), || !s.v.is_ready()).await);
    assert_eq!(
        s.v.validate(&token).await.unwrap_err(),
        AuthError::KeysUnavailable("p".into())
    );
    assert_eq!(s.v.status()[0].keys, 0);
    idp.set_available(true);
    assert!(wait_until(Duration::from_secs(5), || s.v.is_ready()).await);
    assert!(s.v.validate(&token).await.is_ok());
}

#[tokio::test]
async fn discovery_issuer_mismatch_fails() {
    let idp = MockIssuer::start().await;
    idp.set_discovery_issuer(Some("https://evil.example.com".into()));
    let s = start(&[idp.provider_config("p")]).await;
    assert!(!s.v.is_ready());
    let status = s.v.status();
    let err = status[0].last_error.clone().unwrap();
    assert!(err.contains("https://evil.example.com"), "{err}");
    assert!(err.contains("configured issuer"), "{err}");
    assert_eq!(
        idp.jwks_request_count(),
        0,
        "jwks_uri of a mismatched document is not used"
    );
    assert_eq!(
        s.v.validate(&idp.mint(user_claims("a"))).await.unwrap_err(),
        AuthError::KeysUnavailable("p".into())
    );
}

#[tokio::test]
async fn configured_jwks_uri_skips_discovery() {
    let idp = MockIssuer::start().await;
    idp.set_discovery_issuer(Some("https://would-fail.example.com".into()));
    let mut cfg = idp.provider_config("p");
    cfg.jwks_uri = Some(idp.jwks_url());
    let s = start(&[cfg]).await;
    assert!(s.v.is_ready());
    assert_eq!(idp.discovery_request_count(), 0);
    assert!(s.v.validate(&idp.mint(user_claims("a"))).await.is_ok());
}

#[tokio::test]
async fn explicit_discovery_url_is_used() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.discovery_url = Some(idp.discovery_url());
    cfg.oauthbearer = Some(OauthBearerConfig { scope: "db".into() });
    let s = start(&[cfg]).await;
    assert!(s.v.is_ready());
    assert_eq!(
        s.v.oauthbearer_discovery("p"),
        Some((idp.discovery_url(), "db".into()))
    );
}

#[tokio::test]
async fn empty_or_invalid_jwks_never_replaces_good_keys() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.min_refresh_interval = Duration::ZERO;
    let s = start(&[cfg]).await;
    let token = idp.mint(user_claims("a"));
    for body in [
        r#"{"keys":[]}"#.to_string(),
        "garbage".to_string(),
        json!({"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "x"}]}).to_string(),
    ] {
        idp.set_jwks_body(Some(body.clone()));
        let unknown = idp.mint_with(user_claims("a"), &MintOptions::default().kid("unknown"));
        assert!(s.v.validate(&unknown).await.is_err());
        assert!(s.v.status()[0].last_error.is_some(), "{body}");
        assert_eq!(s.v.status()[0].keys, 2);
        assert!(s.v.is_ready());
        assert!(s.v.validate(&token).await.is_ok(), "{body}");
    }
}

#[tokio::test]
async fn unusable_jwks_entries_are_ignored() {
    let idp = MockIssuer::start().await;
    idp.set_extra_jwks(vec![
        json!({"kty": "RSA", "use": "enc", "kid": "enc", "n": "AQAB", "e": "AQAB"}),
        json!({"kty": "oct", "k": "c2VjcmV0", "kid": "sym"}),
        json!({"kty": "EC", "crv": "P-521", "kid": "p521", "x": "AA", "y": "AA"}),
        json!("junk"),
    ]);
    let s = start(&[idp.provider_config("p")]).await;
    assert_eq!(s.v.status()[0].keys, 2);
    assert!(s.v.validate(&idp.mint(user_claims("a"))).await.is_ok());
    // A token naming the symmetric key cannot use it.
    let t = idp.mint_with(
        user_claims("a"),
        &MintOptions::default().alg("HS256").kid("sym"),
    );
    assert_eq!(
        s.v.validate(&t).await.unwrap_err(),
        AuthError::DisallowedAlgorithm("HS256".into())
    );
}

#[tokio::test]
async fn oversized_jwks_response_is_rejected() {
    let idp = MockIssuer::start().await;
    idp.set_jwks_body(Some(format!(
        "{{\"keys\":[],\"pad\":\"{}\"}}",
        "x".repeat(2 * 1024 * 1024)
    )));
    let s = start(&[idp.provider_config("p")]).await;
    assert!(!s.v.is_ready());
    let err = s.v.status()[0].last_error.clone().unwrap();
    assert!(err.contains("larger than"), "{err}");
}

#[tokio::test]
async fn slow_idp_times_out() {
    let idp = MockIssuer::start().await;
    idp.set_jwks_delay(Duration::from_secs(3));
    let mut cfg = idp.provider_config("p");
    cfg.jwks.http_timeout = Duration::from_millis(200);
    let started = Instant::now();
    let s = start(&[cfg]).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!s.v.is_ready());
    assert!(s.v.status()[0].last_error.is_some());
}

#[tokio::test]
async fn cache_control_shortens_the_refresh_interval() {
    let idp = MockIssuer::start().await;
    idp.set_cache_control(Some("public, max-age=0".into()));
    let mut cfg = idp.provider_config("p");
    cfg.jwks.max_age = Duration::from_secs(3600);
    cfg.jwks.min_refresh_interval = Duration::from_millis(100);
    let _s = start(&[cfg]).await;
    assert!(
        wait_until(Duration::from_secs(5), || idp.jwks_request_count() >= 4).await,
        "refreshes should follow max(Cache-Control max-age, min_refresh_interval)"
    );
}

#[tokio::test]
async fn shutdown_stops_background_refresh() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.jwks.max_age = Duration::from_millis(60);
    cfg.jwks.min_refresh_interval = Duration::from_millis(10);
    let s = start(&[cfg]).await;
    assert!(wait_until(Duration::from_secs(5), || idp.jwks_request_count() >= 3).await);
    s.shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let count = idp.jwks_request_count();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(idp.jwks_request_count(), count);
}

#[tokio::test]
async fn start_twice_is_a_no_op() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    s.v.start(s.shutdown.clone()).await;
    assert_eq!(idp.jwks_request_count(), 1);
}

// ---------------------------------------------------------------------------
// Readiness and status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn readiness_depends_on_required_providers() {
    let up = MockIssuer::start().await;
    let down = MockIssuer::start().await;
    down.set_available(false);
    let mut optional = down.provider_config("optional");
    optional.required = false;
    let s = start(&[up.provider_config("up"), optional]).await;
    assert!(s.v.is_ready());
    let status = s.v.status();
    assert_eq!(status.len(), 2);
    assert_eq!(status[0].name, "up");
    assert!(status[0].required);
    assert_eq!(status[0].keys, 2);
    assert!(status[0].age_seconds.is_some());
    assert_eq!(status[0].last_error, None);
    assert_eq!(status[1].name, "optional");
    assert!(!status[1].required);
    assert_eq!(status[1].keys, 0);
    assert_eq!(status[1].age_seconds, None);
    assert!(status[1].last_error.is_some());
    drop(s);

    let mut required_down = down.provider_config("down");
    required_down.jwks.min_refresh_interval = Duration::ZERO;
    let s = start(&[up.provider_config("up"), required_down]).await;
    assert!(!s.v.is_ready());
    // A token arriving while no keys are loaded triggers an on-demand refresh.
    down.set_available(true);
    assert!(s.v.validate(&down.mint(user_claims("a"))).await.is_ok());
    assert!(s.v.is_ready());
}

#[tokio::test]
async fn readiness_recovers_through_background_retries() {
    let idp = MockIssuer::start().await;
    idp.set_available(false);
    let s = start(&[idp.provider_config("p")]).await;
    assert!(!s.v.is_ready());
    idp.set_available(true);
    assert!(
        wait_until(Duration::from_secs(8), || s.v.is_ready()).await,
        "the background task retries with backoff starting at 1 s"
    );
}

#[tokio::test]
async fn not_ready_before_start() {
    let idp = MockIssuer::start().await;
    let (v, _) = build(&[idp.provider_config("p")]);
    assert!(!v.is_ready());
    let (empty, _) = build(&[]);
    assert!(empty.is_ready());
}

// ---------------------------------------------------------------------------
// Claim constraints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_scopes() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.required_scopes = vec!["db.connect".into(), "openid".into()];
    let s = start(&[cfg]).await;
    let ok = idp.mint(json!({"sub": "a", "aud": "pgbearer", "scope": "openid db.connect"}));
    assert!(s.v.validate(&ok).await.is_ok());
    let missing = idp.mint(json!({"sub": "a", "aud": "pgbearer", "scope": "openid"}));
    assert_eq!(
        s.v.validate(&missing).await.unwrap_err(),
        AuthError::MissingScope("db.connect".into())
    );
    let none = idp.mint(json!({"sub": "a", "aud": "pgbearer"}));
    assert_eq!(
        s.v.validate(&none).await.unwrap_err(),
        AuthError::MissingScope("db.connect".into())
    );
}

#[tokio::test]
async fn tenant_allow_list() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("entra");
    cfg.kind = IdpType::Entra;
    cfg.tenants = vec!["t-allowed".into()];
    let s = start(&[cfg]).await;
    let ok = idp.mint(json!({"aud": "pgbearer", "oid": "o", "tid": "t-allowed", "scp": "x"}));
    assert!(s.v.validate(&ok).await.is_ok());
    let other = idp.mint(json!({"aud": "pgbearer", "oid": "o", "tid": "t-other", "scp": "x"}));
    assert_eq!(
        s.v.validate(&other).await.unwrap_err(),
        AuthError::TenantNotAllowed("t-other".into())
    );
    let missing = idp.mint(json!({"aud": "pgbearer", "oid": "o", "scp": "x"}));
    assert_eq!(
        s.v.validate(&missing).await.unwrap_err(),
        AuthError::MissingClaim("tid".into())
    );
}

#[tokio::test]
async fn client_id_allow_list() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.allowed_client_ids = vec!["good-client".into()];
    let s = start(&[cfg]).await;
    for claim in ["azp", "appid", "client_id"] {
        let ok = idp.mint(json!({"sub": "a", "aud": "pgbearer", claim: "good-client"}));
        assert!(s.v.validate(&ok).await.is_ok(), "{claim}");
        let bad = idp.mint(json!({"sub": "a", "aud": "pgbearer", claim: "bad-client"}));
        assert_eq!(
            s.v.validate(&bad).await.unwrap_err(),
            AuthError::ClientNotAllowed("bad-client".into()),
            "{claim}"
        );
    }
    let none = idp.mint(user_claims("a"));
    assert_eq!(
        s.v.validate(&none).await.unwrap_err(),
        AuthError::MissingClaim("azp".into())
    );
}

#[tokio::test]
async fn expected_typ() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("p");
    cfg.expected_typ = Some("at+jwt".into());
    let s = start(&[cfg]).await;
    for typ in ["at+jwt", "AT+JWT", "application/at+jwt"] {
        let t = idp.mint_with(
            user_claims("a"),
            &MintOptions::default().header("typ", json!(typ)),
        );
        assert!(s.v.validate(&t).await.is_ok(), "{typ}");
    }
    let jwt = idp.mint(user_claims("a"));
    assert_eq!(
        s.v.validate(&jwt).await.unwrap_err(),
        AuthError::BadType("JWT".into())
    );
    let none = idp.mint_with(
        user_claims("a"),
        &MintOptions::default().header("typ", Value::Null),
    );
    assert_eq!(
        s.v.validate(&none).await.unwrap_err(),
        AuthError::BadType(String::new())
    );
}

#[tokio::test]
async fn groups_overage_flag() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("entra");
    cfg.kind = IdpType::Entra;
    cfg.tenants = vec!["t".into()];
    let s = start(&[cfg]).await;
    let base = json!({"aud": "pgbearer", "oid": "o", "tid": "t", "scp": "x"});
    let with = |extra: Value| {
        let mut c = base.clone();
        c.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        idp.mint(c)
    };
    let overage = with(json!({"_claim_names": {"groups": "src1"},
        "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/v1.0/users/o/getMemberObjects"}}}));
    let id = s.v.validate(&overage).await.unwrap();
    assert!(id.groups_overage);
    assert!(id.groups.is_empty());
    assert!(
        s.v.validate(&with(json!({"hasgroups": true})))
            .await
            .unwrap()
            .groups_overage
    );
    assert!(
        !s.v.validate(&with(json!({"groups": ["g"]})))
            .await
            .unwrap()
            .groups_overage
    );
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversize_token_is_rejected() {
    let idp = MockIssuer::start().await;
    let metrics = Metrics::new();
    let v = TokenValidator::new(&[idp.provider_config("p")], 100, metrics).unwrap();
    let token = idp.mint(user_claims("a"));
    assert!(token.len() > 100);
    let err = v.validate(&token).await.unwrap_err();
    assert!(
        matches!(err, AuthError::Malformed(ref m) if m.contains("limit")),
        "{err}"
    );
}

#[tokio::test]
async fn malformed_tokens_are_rejected_without_network() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let (jwks, discovery) = (idp.jwks_request_count(), idp.discovery_request_count());
    let valid = idp.mint(user_claims("a"));
    let parts: Vec<&str> = valid.split('.').collect();
    let cases = vec![
        String::new(),
        "   ".into(),
        "garbage".into(),
        "not.a.jwt".into(),
        format!("{}.{}", parts[0], parts[1]),
        format!("{valid}.extra"),
        format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[2], parts[2]
        ),
        format!("{}!.{}.{}", parts[0], parts[1], parts[2]),
        format!("{}.{}=.{}", parts[0], parts[1], parts[2]),
        format!("bm90IGpzb24.{}.{}", parts[1], parts[2]),
        format!("{}.bm90IGpzb24.{}", parts[0], parts[2]),
        format!("{}.WzEsMl0.{}", parts[0], parts[2]),
        format!("{}..{}", parts[0], parts[2]),
        "\u{1F600}.\u{1F600}.\u{1F600}".into(),
        "Bearer ".to_string() + &valid,
    ];
    for case in cases {
        let err = s.v.validate(&case).await.unwrap_err();
        assert!(matches!(err, AuthError::Malformed(_)), "{case:?}: {err:?}");
    }
    assert_eq!(idp.jwks_request_count(), jwks);
    assert_eq!(idp.discovery_request_count(), discovery);
    // Surrounding whitespace (for example a trailing newline) is tolerated.
    assert!(s.v.validate(&format!("{valid}\n")).await.is_ok());
}

// ---------------------------------------------------------------------------
// HTTP options
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bearer_token_file_is_sent_and_reread() {
    let idp = MockIssuer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "first-token\n").unwrap();
    let mut cfg = idp.provider_config("p");
    cfg.bearer_token_file = Some(path.clone());
    cfg.jwks.min_refresh_interval = Duration::ZERO;
    let s = start(&[cfg]).await;
    assert!(s.v.is_ready());
    assert_eq!(
        idp.last_authorization().as_deref(),
        Some("Bearer first-token")
    );
    std::fs::write(&path, "second-token").unwrap();
    let unknown = idp.mint_with(user_claims("a"), &MintOptions::default().kid("nope"));
    let _ = s.v.validate(&unknown).await;
    assert_eq!(
        idp.last_authorization().as_deref(),
        Some("Bearer second-token")
    );
    // An unreadable token file fails the refresh (and keeps the keys).
    std::fs::remove_file(&path).unwrap();
    let _ = s.v.validate(&unknown).await;
    let err = s.v.status()[0].last_error.clone().unwrap();
    assert!(err.contains("bearer_token_file"), "{err}");
    assert!(s.v.is_ready());
}

#[tokio::test]
async fn ca_file_problems_fail_construction() {
    let idp = MockIssuer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = idp.provider_config("p");
    cfg.ca_file = Some(dir.path().join("missing.pem"));
    assert!(new_err(&[cfg.clone()]).contains("cannot read ca_file"));
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "no certificates here").unwrap();
    cfg.ca_file = Some(empty);
    assert!(new_err(&[cfg.clone()]).contains("no certificates"));
    // A valid CA bundle is accepted.
    let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let good = dir.path().join("ca.pem");
    std::fs::write(&good, ca.cert.pem()).unwrap();
    cfg.ca_file = Some(good);
    assert!(TokenValidator::new(&[cfg], MAX_TOKEN, Metrics::new()).is_ok());
}

#[tokio::test]
async fn configuration_errors() {
    let idp = MockIssuer::start().await;
    let base = idp.provider_config("p");

    let mut c = base.clone();
    c.insecure_allow_http = false;
    let e = new_err(&[c]);
    assert!(e.contains("must use https"), "{e}");
    assert!(e.contains("provider p"), "{e}");

    let mut c = base.clone();
    c.issuer = None;
    assert!(new_err(&[c]).contains("issuer is required"));

    let mut c = base.clone();
    c.audiences = vec![];
    assert!(new_err(&[c]).contains("audience"));

    let mut c = base.clone();
    c.algorithms = vec![];
    assert!(new_err(&[c]).contains("algorithms"));

    let mut c = base.clone();
    c.leeway = Duration::from_secs(10 * 24 * 3600);
    assert!(new_err(&[c]).contains("leeway"));

    let mut c = base.clone();
    c.jwks_uri = Some("ftp://example.com/jwks".into());
    assert!(new_err(&[c]).contains("jwks_uri"));

    let mut other = base.clone();
    other.issuer = Some("https://other.example.com".into());
    assert!(new_err(&[base.clone(), other.clone()]).contains("duplicate provider name"));
    let mut dup_issuer = base.clone();
    dup_issuer.name = "q".into();
    assert!(new_err(&[base.clone(), dup_issuer]).contains("also used by provider p"));

    let mut entra = base.clone();
    entra.kind = IdpType::Entra;
    assert!(new_err(&[entra]).contains("tenants"));

    // Kubernetes and GitHub Actions have default (https) issuers.
    let mut k8s = base.clone();
    k8s.kind = IdpType::Kubernetes;
    k8s.issuer = None;
    k8s.insecure_allow_http = false;
    assert!(TokenValidator::new(&[k8s], MAX_TOKEN, Metrics::new()).is_ok());
}

// ---------------------------------------------------------------------------
// Offline APIs, OAUTHBEARER settings, metrics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validate_offline_never_fetches() {
    let idp = MockIssuer::start().await;
    let (v, metrics) = build(&[idp.provider_config("p")]);
    let token = idp.mint(user_claims("a"));
    assert_eq!(
        v.validate_offline(&token).unwrap_err(),
        AuthError::KeysUnavailable("p".into())
    );
    let n = v.load_jwks("p", idp.jwks().to_string().as_bytes()).unwrap();
    assert_eq!(n, 2);
    assert!(v.is_ready());
    assert_eq!(v.validate_offline(&token).unwrap().subject, "a");
    let unknown = idp.mint_with(user_claims("a"), &MintOptions::default().kid("x"));
    assert!(matches!(
        v.validate_offline(&unknown),
        Err(AuthError::UnknownKey { .. })
    ));
    assert_eq!(idp.jwks_request_count(), 0);
    assert_eq!(idp.discovery_request_count(), 0);
    assert!(!metrics.encode().contains("pgbearer_auth_attempts_total{"));
    // load_jwks errors.
    assert!(matches!(
        v.load_jwks("p", b"{\"keys\":[]}"),
        Err(AuthError::KeysUnavailable(_))
    ));
    assert!(matches!(
        v.load_jwks("nope", b"{}"),
        Err(AuthError::UnknownIssuer(_))
    ));
}

#[tokio::test]
async fn refresh_all_fetches_without_background_tasks() {
    let idp = MockIssuer::start().await;
    let down = MockIssuer::start().await;
    down.set_available(false);
    let (v, _) = build(&[idp.provider_config("up"), down.provider_config("down")]);
    let results = v.refresh_all().await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, "up");
    assert_eq!(results[0].1, Ok(2));
    assert_eq!(results[1].0, "down");
    assert!(results[1].1.is_err());
    assert_eq!(idp.jwks_request_count(), 1);
}

#[tokio::test]
async fn map_claims_unverified_applies_mapping_only() {
    let idp = MockIssuer::start().await;
    let mut cfg = idp.provider_config("entra");
    cfg.kind = IdpType::Entra;
    cfg.tenants = vec!["t".into()];
    let (v, _) = build(&[cfg]);
    let claims = json!({"oid": "o", "tid": "other-tenant", "scp": "a b", "aud": "wrong"});
    let id = v
        .map_claims_unverified("entra", claims.as_object().unwrap().clone())
        .unwrap();
    assert_eq!(id.subject, "o");
    assert_eq!(id.tenant.as_deref(), Some("other-tenant"));
    assert_eq!(id.scopes.len(), 2);
    assert_eq!(id.expires_at, UNIX_EPOCH);
    assert!(matches!(
        v.map_claims_unverified("missing", serde_json::Map::new()),
        Err(AuthError::UnknownIssuer(_))
    ));
    assert_eq!(
        v.map_claims_unverified("entra", serde_json::Map::new()),
        Err(AuthError::MissingClaim("oid".into()))
    );
}

#[tokio::test]
async fn oauthbearer_discovery_settings() {
    let idp = MockIssuer::start().await;
    let mut with = idp.provider_config("with");
    with.oauthbearer = Some(OauthBearerConfig {
        scope: "api://pgbearer/Database.Connect".into(),
    });
    let mut trailing = MockIssuer::start().await.provider_config("trailing");
    let trailing_issuer = format!("{}/", trailing.issuer.clone().unwrap());
    trailing.issuer = Some(trailing_issuer.clone());
    trailing.oauthbearer = Some(OauthBearerConfig { scope: "s".into() });
    let other = MockIssuer::start().await;
    let (v, _) = build(&[with, trailing, other.provider_config("without")]);
    assert_eq!(
        v.oauthbearer_discovery("with"),
        Some((
            format!("{}/.well-known/openid-configuration", idp.issuer_url()),
            "api://pgbearer/Database.Connect".into()
        ))
    );
    assert_eq!(
        v.oauthbearer_discovery("trailing"),
        Some((
            format!("{}.well-known/openid-configuration", trailing_issuer),
            "s".into()
        ))
    );
    assert_eq!(v.oauthbearer_discovery("without"), None);
    assert_eq!(v.oauthbearer_discovery("unknown"), None);
}

#[tokio::test]
async fn metrics_are_recorded_for_every_attempt() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    s.v.validate(&idp.mint(user_claims("a"))).await.unwrap();
    let _ =
        s.v.validate(&idp.mint(json!({"sub": "a", "aud": "x"})))
            .await;
    let _ =
        s.v.validate(&idp.mint(json!({"sub": "a", "aud": "pgbearer", "iss": "https://nope"})))
            .await;
    let _ = s.v.validate("garbage").await;
    let text = s.metrics.encode();
    for expected in [
        "pgbearer_auth_attempts_total{provider=\"p\",result=\"success\",reason=\"ok\"} 1",
        "pgbearer_auth_attempts_total{provider=\"p\",result=\"failure\",reason=\"bad_audience\"} 1",
        "pgbearer_auth_attempts_total{provider=\"unknown\",result=\"failure\",reason=\"unknown_issuer\"} 1",
        "pgbearer_auth_attempts_total{provider=\"unknown\",result=\"failure\",reason=\"malformed\"} 1",
        "pgbearer_auth_duration_seconds_count{provider=\"p\"} 2",
        "pgbearer_auth_duration_seconds_count{provider=\"unknown\"} 2",
        "pgbearer_jwks_refresh_total{provider=\"p\",result=\"success\"} 1",
        "pgbearer_jwks_age_seconds{provider=\"p\"}",
    ] {
        assert!(text.contains(expected), "missing {expected}\n{text}");
    }
}

#[test]
fn validator_and_futures_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}
    fn assert_send<T: Send>(_: &T) {}
    let (v, _) = build(&[]);
    assert_send_sync(&*v);
    let validate = v.validate("token");
    assert_send(&validate);
    let start = v.start(CancellationToken::new());
    assert_send(&start);
    let refresh = v.refresh_all();
    assert_send(&refresh);
}

#[test]
fn construction_needs_no_runtime_or_network() {
    let cfg = IdentityProviderConfig {
        name: "entra".into(),
        kind: IdpType::Entra,
        issuer: Some("https://login.microsoftonline.com/tenant-id/v2.0".into()),
        audiences: vec!["api://pgbearer".into()],
        discovery_url: None,
        jwks_uri: None,
        ca_file: None,
        bearer_token_file: None,
        algorithms: vec![JwtAlgorithm::RS256],
        leeway: Duration::from_secs(60),
        required: true,
        claims: Default::default(),
        tenants: vec!["tenant-id".into()],
        required_scopes: vec!["Database.Connect".into()],
        allowed_client_ids: vec![],
        expected_typ: None,
        jwks: Default::default(),
        insecure_allow_http: false,
        oauthbearer: Some(OauthBearerConfig {
            scope: "api://pgbearer/Database.Connect".into(),
        }),
    };
    let v = TokenValidator::new(&[cfg], MAX_TOKEN, Metrics::new()).unwrap();
    assert!(!v.is_ready());
    assert_eq!(
        v.oauthbearer_discovery("entra"),
        Some((
            "https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration"
                .into(),
            "api://pgbearer/Database.Connect".into()
        ))
    );
    assert!(format!("{v:?}").contains("entra"));
}

#[test]
fn error_reason_codes_and_messages() {
    let cases = [
        (AuthError::Malformed("x".into()), "malformed"),
        (AuthError::UnknownIssuer("x".into()), "unknown_issuer"),
        (
            AuthError::DisallowedAlgorithm("x".into()),
            "disallowed_algorithm",
        ),
        (
            AuthError::UnknownKey {
                provider: "p".into(),
                kid: "k".into(),
            },
            "unknown_key",
        ),
        (AuthError::KeysUnavailable("p".into()), "keys_unavailable"),
        (AuthError::BadSignature, "bad_signature"),
        (AuthError::Expired, "expired"),
        (AuthError::NotYetValid, "not_yet_valid"),
        (AuthError::BadAudience, "bad_audience"),
        (AuthError::MissingClaim("x".into()), "missing_claim"),
        (
            AuthError::TenantNotAllowed("x".into()),
            "tenant_not_allowed",
        ),
        (AuthError::MissingScope("x".into()), "missing_scope"),
        (
            AuthError::ClientNotAllowed("x".into()),
            "client_not_allowed",
        ),
        (AuthError::BadType("x".into()), "bad_type"),
    ];
    for (err, code) in cases {
        assert_eq!(err.reason_code(), code);
        assert!(!err.to_string().is_empty());
    }
}

#[tokio::test]
async fn attacker_controlled_text_is_sanitised_in_errors() {
    let idp = MockIssuer::start().await;
    let s = start(&[idp.provider_config("p")]).await;
    let iss = format!("https://evil\n{}", "x".repeat(500));
    let t = idp.mint(json!({"sub": "a", "aud": "pgbearer", "iss": iss}));
    match s.v.validate(&t).await.unwrap_err() {
        AuthError::UnknownIssuer(shown) => {
            assert!(!shown.contains('\n'));
            assert!(shown.chars().count() <= 65);
        }
        other => panic!("{other:?}"),
    }
}

mod fuzz {
    use super::*;
    use proptest::prelude::*;

    fn validator_with_keys() -> (Arc<TokenValidator>, String, String) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let idp = MockIssuer::start().await;
            let (v, _) = build(&[idp.provider_config("p")]);
            v.load_jwks("p", idp.jwks().to_string().as_bytes()).unwrap();
            (v, idp.issuer_url(), idp.mint(user_claims("a")))
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn validate_offline_never_panics(input in ".{0,400}") {
            let (v, _, _) = validator_with_keys();
            let _ = v.validate_offline(&input);
        }

        #[test]
        fn mutated_tokens_never_validate_or_panic(index in 0usize..2000, byte in any::<u8>()) {
            let (v, _, token) = validator_with_keys();
            let mut bytes = token.into_bytes();
            let i = index % bytes.len();
            prop_assume!(bytes[i] != byte);
            bytes[i] = byte;
            if let Ok(mutated) = String::from_utf8(bytes) {
                // Changing any byte must never yield a valid identity, except
                // when the change is invisible to base64url decoding (the
                // unused low bits of the last character of a segment).
                if let Ok(id) = v.validate_offline(&mutated) {
                    prop_assert_eq!(id.subject, "a");
                }
            }
        }

        #[test]
        fn arbitrary_claims_never_panic(
            sub in proptest::option::of(".{0,10}"),
            aud in prop_oneof![Just(json!("pgbearer")), Just(json!(["pgbearer"])), Just(json!(1)), Just(json!(null))],
            exp in prop_oneof![Just(json!(4_000_000_000u64)), Just(json!(-1)), Just(json!(1.5e300)), Just(json!("x"))],
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let idp = MockIssuer::start().await;
                let (v, _) = build(&[idp.provider_config("p")]);
                v.load_jwks("p", idp.jwks().to_string().as_bytes()).unwrap();
                let mut claims = json!({"aud": aud, "exp": exp, "iss": idp.issuer_url()});
                if let Some(s) = sub {
                    claims["sub"] = json!(s);
                }
                let token = idp.mint_with(claims, &MintOptions::default().without_defaults());
                let _ = v.validate_offline(&token);
            });
        }
    }
}
