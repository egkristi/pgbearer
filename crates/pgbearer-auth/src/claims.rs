//! Claim constraints (tenant, client, Entra token profiles, scopes, `typ`)
//! and the mapping from a claim set to an [`Identity`] (ARCHITECTURE.md §8.2,
//! §8.5, §15.2).

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use pgbearer_config::{EffectiveClaims, IdentityProviderConfig, IdpType, TokenProfile};
use pgbearer_core::{Identity, IdentityKind};
use serde_json::{Map, Value};

use crate::AuthError;
use crate::jwt::{numeric_date, sanitize};

/// Fallback claims for the OAuth client id, after the configured one.
const CLIENT_ID_CLAIMS: [&str; 3] = ["azp", "appid", "client_id"];

/// The per-provider rules for claim checks and identity mapping.
#[derive(Debug, Clone)]
pub(crate) struct ClaimRules {
    /// Provider name.
    pub(crate) name: String,
    /// Effective issuer URL.
    pub(crate) issuer: String,
    /// Provider type.
    pub(crate) kind: IdpType,
    /// Effective claim names.
    pub(crate) claims: EffectiveClaims,
    /// Allowed tenants (empty: any).
    pub(crate) tenants: Vec<String>,
    /// Scopes required in delegated tokens.
    pub(crate) required_scopes: Vec<String>,
    /// Allowed OAuth client ids (empty: any).
    pub(crate) allowed_client_ids: Vec<String>,
    /// Required header `typ`.
    pub(crate) expected_typ: Option<String>,
    /// Claims every token must carry.
    pub(crate) required_claims: Vec<String>,
    /// Accepted Entra token profiles (empty for other types).
    pub(crate) token_profiles: Vec<TokenProfile>,
    /// Declared kind of every token (`type: oidc` only).
    pub(crate) identity_kind: Option<IdentityKind>,
}

impl ClaimRules {
    /// Rules from a provider config, with `issuer` already resolved.
    pub(crate) fn from_config(cfg: &IdentityProviderConfig, issuer: String) -> ClaimRules {
        ClaimRules {
            name: cfg.name.clone(),
            issuer,
            kind: cfg.kind,
            claims: cfg.effective_claims(),
            tenants: cfg.tenants.clone(),
            required_scopes: cfg.required_scopes.clone(),
            allowed_client_ids: cfg.allowed_client_ids.clone(),
            required_claims: cfg.required_claims.clone(),
            expected_typ: cfg.expected_typ.clone(),
            token_profiles: cfg.effective_token_profiles(),
            identity_kind: cfg.identity_kind,
        }
    }

    fn tenant_claim(&self) -> &str {
        self.claims.tenant.as_deref().unwrap_or("tid")
    }
}

/// Look up a claim by name with the shared rules of
/// [`pgbearer_core::lookup_claim`] (literal name, then dotted path; a leading
/// `/` makes it a JSON Pointer), so claim mapping and policy always agree.
pub(crate) fn lookup<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    pgbearer_core::lookup_claim(claims, path)
}

/// A claim as a non-empty string (numbers are converted to strings).
fn string_claim(claims: &Map<String, Value>, path: &str) -> Option<String> {
    match lookup(claims, path)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A string-or-array claim as a set. Non-string array elements are ignored.
/// With `split`, every string is also split on whitespace (OAuth scopes).
fn string_set(value: Option<&Value>, split: bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut add = |s: &str| {
        if split {
            out.extend(s.split_whitespace().map(str::to_string));
        } else if !s.is_empty() {
            out.insert(s.to_string());
        }
    };
    match value {
        Some(Value::String(s)) => add(s),
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).for_each(add),
        _ => {}
    }
    out
}

fn scopes(rules: &ClaimRules, claims: &Map<String, Value>) -> BTreeSet<String> {
    match rules.claims.scopes.as_deref() {
        Some(c) => string_set(lookup(claims, c), true),
        None => BTreeSet::new(),
    }
}

/// The OAuth client id: the configured claim, then `azp`, `appid`, `client_id`.
fn client_id(rules: &ClaimRules, claims: &Map<String, Value>) -> Option<String> {
    rules
        .claims
        .client_id
        .as_deref()
        .into_iter()
        .chain(CLIENT_ID_CLAIMS)
        .find_map(|c| string_claim(claims, c))
}

/// The Entra token profile a claim set has, if any (see
/// [`TokenProfile`]). Uses Entra's own claim names (`scp`, `idtyp`, `roles`),
/// whatever the claim mapping says, because they describe the token's shape.
fn entra_profile(claims: &Map<String, Value>) -> Option<TokenProfile> {
    let present = |name: &str| claims.get(name).is_some_and(|v| !v.is_null());
    let idtyp = match claims.get("idtyp") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        // A malformed idtyp matches no profile.
        Some(_) => return None,
    };
    let has_scopes = !string_set(claims.get("scp"), true).is_empty();
    let has_roles = !string_set(claims.get("roles"), false).is_empty();
    match idtyp {
        None | Some("user") if has_scopes => Some(TokenProfile::Delegated),
        Some("app") if !present("scp") && has_roles => Some(TokenProfile::Application),
        _ => None,
    }
}

/// Whether `required_scopes` applies to this token.
fn scopes_enforced(rules: &ClaimRules, claims: &Map<String, Value>) -> bool {
    match rules.kind {
        IdpType::Kubernetes | IdpType::GithubActions => false,
        IdpType::Entra => entra_profile(claims) != Some(TokenProfile::Application),
        IdpType::Oidc => true,
    }
}

/// Entra only: reject ID tokens and tokens that match no enabled profile.
fn check_entra_profile(rules: &ClaimRules, claims: &Map<String, Value>) -> Result<(), AuthError> {
    if claims.contains_key("nonce") {
        return Err(AuthError::TokenProfile(
            "ID tokens are not accepted (the token has a nonce claim)".into(),
        ));
    }
    match entra_profile(claims) {
        Some(profile) if rules.token_profiles.contains(&profile) => Ok(()),
        Some(profile) => Err(AuthError::TokenProfile(format!(
            "the {} token profile is not enabled for this provider",
            profile.as_str()
        ))),
        None => Err(AuthError::TokenProfile(
            "the token matches no enabled token profile (delegated: scp, and idtyp absent or \
             user; application: idtyp=app, no scp, and roles)"
                .into(),
        )),
    }
}

/// `typ` comparison: case-insensitive, ignoring an `application/` prefix
/// (RFC 7515 §4.1.9).
fn typ_matches(expected: &str, actual: &str) -> bool {
    fn strip(s: &str) -> &str {
        match s.get(..12) {
            Some(prefix) if prefix.eq_ignore_ascii_case("application/") => &s[12..],
            _ => s,
        }
    }
    strip(expected).eq_ignore_ascii_case(strip(actual))
}

/// Check the provider's constraints on a *verified* token: `typ`, required
/// claims, tenant, client id, Entra token profiles and required scopes.
pub(crate) fn check_constraints(
    rules: &ClaimRules,
    typ: Option<&str>,
    claims: &Map<String, Value>,
) -> Result<(), AuthError> {
    if let Some(expected) = &rules.expected_typ {
        let actual = typ.unwrap_or("");
        if !typ_matches(expected, actual) {
            return Err(AuthError::BadType(sanitize(actual)));
        }
    }
    if let Some(missing) = rules
        .required_claims
        .iter()
        .find(|name| lookup(claims, name).is_none_or(Value::is_null))
    {
        return Err(AuthError::MissingClaim(sanitize(missing)));
    }
    if !rules.tenants.is_empty() {
        let claim = rules.tenant_claim();
        let tenant =
            string_claim(claims, claim).ok_or_else(|| AuthError::MissingClaim(claim.into()))?;
        if !rules.tenants.contains(&tenant) {
            return Err(AuthError::TenantNotAllowed(sanitize(&tenant)));
        }
    }
    if !rules.allowed_client_ids.is_empty() {
        let client = client_id(rules, claims).ok_or_else(|| {
            AuthError::MissingClaim(
                rules
                    .claims
                    .client_id
                    .clone()
                    .unwrap_or_else(|| "azp".into()),
            )
        })?;
        if !rules.allowed_client_ids.contains(&client) {
            return Err(AuthError::ClientNotAllowed(sanitize(&client)));
        }
    }
    if rules.kind == IdpType::Entra {
        check_entra_profile(rules, claims)?;
    }
    if !rules.required_scopes.is_empty() && scopes_enforced(rules, claims) {
        let have = scopes(rules, claims);
        if let Some(missing) = rules.required_scopes.iter().find(|s| !have.contains(*s)) {
            return Err(AuthError::MissingScope(missing.clone()));
        }
    }
    Ok(())
}

fn identity_kind(rules: &ClaimRules, claims: &Map<String, Value>) -> IdentityKind {
    match rules.kind {
        IdpType::Kubernetes | IdpType::GithubActions => IdentityKind::Workload,
        IdpType::Entra => match entra_profile(claims) {
            Some(TokenProfile::Delegated) => IdentityKind::Human,
            Some(TokenProfile::Application) => IdentityKind::Workload,
            None => IdentityKind::Unknown,
        },
        // A scope claim says nothing reliable about who holds the token.
        IdpType::Oidc => rules.identity_kind.unwrap_or_default(),
    }
}

/// Groups overage (§8.5): `_claim_names` names the groups claim (OIDC
/// distributed claims, used by Entra ID), or `hasgroups` is true.
fn groups_overage(rules: &ClaimRules, claims: &Map<String, Value>) -> bool {
    let groups_claim = rules.claims.groups.as_deref().unwrap_or("groups");
    let top = groups_claim.split('.').next().unwrap_or(groups_claim);
    let distributed = claims
        .get("_claim_names")
        .and_then(Value::as_object)
        .is_some_and(|names| {
            names.contains_key("groups")
                || names.contains_key(groups_claim)
                || names.contains_key(top)
        });
    let hasgroups = match claims.get("hasgroups") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    distributed || hasgroups
}

/// Map a claim set to an identity. With `require_exp`, a missing or invalid
/// `exp` is an error; otherwise it maps to the Unix epoch.
pub(crate) fn map_identity(
    rules: &ClaimRules,
    claims: Map<String, Value>,
    require_exp: bool,
) -> Result<Identity, AuthError> {
    let c = &rules.claims;
    let subject = string_claim(&claims, &c.subject)
        .ok_or_else(|| AuthError::MissingClaim(c.subject.clone()))?;
    let username = c.username.as_deref().and_then(|n| string_claim(&claims, n));
    let tenant = c.tenant.as_deref().and_then(|n| string_claim(&claims, n));
    let groups = c
        .groups
        .as_deref()
        .map(|n| string_set(lookup(&claims, n), false))
        .unwrap_or_default();
    let roles = c
        .roles
        .as_deref()
        .map(|n| string_set(lookup(&claims, n), false))
        .unwrap_or_default();
    let scopes = scopes(rules, &claims);
    let client_id = client_id(rules, &claims);
    let kind = identity_kind(rules, &claims);
    let expires_at = match claims
        .get("exp")
        .and_then(numeric_date)
        .and_then(|exp| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp)))
    {
        Some(t) => t,
        None if require_exp => return Err(AuthError::MissingClaim("exp".into())),
        None => SystemTime::UNIX_EPOCH,
    };
    let token_id = string_claim(&claims, "jti").or_else(|| string_claim(&claims, "uti"));
    let groups_overage = groups_overage(rules, &claims);
    Ok(Identity {
        provider: rules.name.clone(),
        issuer: rules.issuer.clone(),
        subject,
        username,
        tenant,
        groups,
        roles,
        scopes,
        client_id,
        kind,
        expires_at,
        token_id,
        key_id: None,
        groups_overage,
        claims,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn rules(kind: IdpType) -> ClaimRules {
        ClaimRules {
            name: "p".into(),
            issuer: "https://issuer".into(),
            kind,
            claims: EffectiveClaims::defaults_for(kind),
            tenants: vec![],
            required_scopes: vec![],
            allowed_client_ids: vec![],
            expected_typ: None,
            required_claims: vec![],
            token_profiles: match kind {
                IdpType::Entra => vec![TokenProfile::Delegated, TokenProfile::Application],
                _ => vec![],
            },
            identity_kind: None,
        }
    }

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn dotted_paths_and_literal_names() {
        let c = obj(json!({
            "realm_access": {"roles": ["a", "b"]},
            "https://example.com/roles": ["x"],
            "a.b": "literal",
            "a": {"b": "nested"},
        }));
        assert_eq!(lookup(&c, "realm_access.roles"), Some(&json!(["a", "b"])));
        assert_eq!(lookup(&c, "https://example.com/roles"), Some(&json!(["x"])));
        assert_eq!(lookup(&c, "a.b"), Some(&json!("literal")));
        assert_eq!(lookup(&c, "realm_access.missing"), None);
        assert_eq!(lookup(&c, "realm_access.roles.deeper"), None);
        assert_eq!(lookup(&c, "missing"), None);
        assert_eq!(lookup(&c, ""), None);
        assert_eq!(lookup(&c, "."), None);
    }

    #[test]
    fn string_sets() {
        assert_eq!(
            string_set(Some(&json!("openid  db.connect\tx")), true),
            ["db.connect", "openid", "x"].map(String::from).into()
        );
        assert_eq!(
            string_set(Some(&json!(["a b", "c", 5, null, ""])), false),
            ["a b", "c"].map(String::from).into()
        );
        assert_eq!(
            string_set(Some(&json!(["a b", "c"])), true),
            ["a", "b", "c"].map(String::from).into()
        );
        assert!(string_set(Some(&json!({"a": 1})), false).is_empty());
        assert!(string_set(Some(&json!("")), false).is_empty());
        assert!(string_set(None, false).is_empty());
    }

    #[test]
    fn maps_oidc_identity() {
        let r = rules(IdpType::Oidc);
        let id = map_identity(
            &r,
            obj(json!({
                "sub": "u1", "preferred_username": "alice", "groups": "g1",
                "roles": ["r1", "r2"], "scope": "openid db", "azp": "cli",
                "exp": 2_000_000_000u64, "jti": "j1"
            })),
            true,
        )
        .unwrap();
        assert_eq!(id.provider, "p");
        assert_eq!(id.issuer, "https://issuer");
        assert_eq!(id.subject, "u1");
        assert_eq!(id.username.as_deref(), Some("alice"));
        assert_eq!(id.groups, ["g1".to_string()].into());
        assert_eq!(id.roles.len(), 2);
        assert_eq!(id.scopes, ["db", "openid"].map(String::from).into());
        assert_eq!(id.client_id.as_deref(), Some("cli"));
        // A scope claim does not make a generic OIDC token a human's.
        assert_eq!(id.kind, IdentityKind::Unknown);
        assert_eq!(id.token_id.as_deref(), Some("j1"));
        assert_eq!(id.key_id, None);
        assert_eq!(
            id.expires_at,
            SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
        );
        assert!(!id.groups_overage);
        assert_eq!(id.claims["sub"], "u1");
    }

    #[test]
    fn subject_is_required_and_exp_optional_when_unverified() {
        let r = rules(IdpType::Oidc);
        assert_eq!(
            map_identity(&r, obj(json!({"exp": 1})), true).unwrap_err(),
            AuthError::MissingClaim("sub".into())
        );
        assert_eq!(
            map_identity(&r, obj(json!({"sub": ""})), false).unwrap_err(),
            AuthError::MissingClaim("sub".into())
        );
        assert_eq!(
            map_identity(&r, obj(json!({"sub": "x"})), true).unwrap_err(),
            AuthError::MissingClaim("exp".into())
        );
        let id = map_identity(&r, obj(json!({"sub": 42})), false).unwrap();
        assert_eq!(id.subject, "42");
        assert_eq!(id.expires_at, SystemTime::UNIX_EPOCH);
        assert_eq!(id.kind, IdentityKind::Unknown);
        // An exp that cannot be represented is invalid, never a panic.
        assert!(map_identity(&r, obj(json!({"sub": "x", "exp": u64::MAX})), true).is_err());
    }

    #[test]
    fn oidc_identity_kind_is_declared() {
        let mut r = rules(IdpType::Oidc);
        for kind in [IdentityKind::Human, IdentityKind::Workload] {
            r.identity_kind = Some(kind);
            let id = map_identity(&r, obj(json!({"sub": "u", "exp": 1})), true).unwrap();
            assert_eq!(id.kind, kind);
        }
    }

    #[test]
    fn entra_kinds_and_client_ids() {
        let r = rules(IdpType::Entra);
        let app = map_identity(
            &r,
            obj(
                json!({"oid": "o1", "sub": "s", "idtyp": "app", "roles": ["Db.Connect"],
                        "appid": "app-1", "tid": "t", "exp": 1}),
            ),
            true,
        )
        .unwrap();
        assert_eq!(app.subject, "o1");
        assert_eq!(app.kind, IdentityKind::Workload);
        assert_eq!(app.client_id.as_deref(), Some("app-1"));
        assert_eq!(app.tenant.as_deref(), Some("t"));
        let user = map_identity(
            &r,
            obj(json!({"oid": "o2", "scp": "Database.Connect", "uti": "u", "exp": 1})),
            true,
        )
        .unwrap();
        assert_eq!(user.kind, IdentityKind::Human);
        assert_eq!(user.token_id.as_deref(), Some("u"));
        let explicit_user = map_identity(
            &r,
            obj(json!({"oid": "o3", "idtyp": "user", "scp": "x", "exp": 1})),
            true,
        )
        .unwrap();
        assert_eq!(explicit_user.kind, IdentityKind::Human);
        // Shapes that match no profile have no kind (and fail validation).
        for claims in [
            json!({"oid": "o4", "exp": 1}),
            json!({"oid": "o5", "idtyp": "user", "exp": 1}),
            json!({"oid": "o6", "idtyp": "app", "exp": 1}),
        ] {
            let id = map_identity(&r, obj(claims), true).unwrap();
            assert_eq!(id.kind, IdentityKind::Unknown);
        }
    }

    #[test]
    fn entra_profile_classification() {
        use TokenProfile::{Application as A, Delegated as D};
        let cases: Vec<(Value, Option<TokenProfile>)> = vec![
            (json!({"scp": "Database.Connect"}), Some(D)),
            (json!({"scp": "a b", "idtyp": "user"}), Some(D)),
            (json!({"scp": ["a"]}), Some(D)),
            (json!({"scp": "  "}), None),
            (json!({"scp": ""}), None),
            (json!({"scp": "a", "idtyp": "app"}), None),
            (json!({"scp": "a", "idtyp": "device"}), None),
            (json!({"scp": "a", "idtyp": 1}), None),
            (json!({"idtyp": "app", "roles": ["R"]}), Some(A)),
            (json!({"idtyp": "app", "roles": "R"}), Some(A)),
            (json!({"idtyp": "app", "roles": []}), None),
            (json!({"idtyp": "app"}), None),
            (json!({"idtyp": "app", "roles": ["R"], "scp": ""}), None),
            (
                json!({"idtyp": "app", "roles": ["R"], "scp": null}),
                Some(A),
            ),
            // Without idtyp an app token cannot be told from a broken one.
            (json!({"roles": ["R"]}), None),
            (json!({"idtyp": null, "scp": "a"}), Some(D)),
            (json!({}), None),
        ];
        for (claims, expected) in cases {
            assert_eq!(entra_profile(&obj(claims.clone())), expected, "{claims}");
        }
    }

    #[test]
    fn entra_profiles_are_enforced() {
        let mut r = rules(IdpType::Entra);
        r.required_scopes = vec!["Database.Connect".into()];
        let delegated = obj(json!({"scp": "Database.Connect"}));
        let application = obj(json!({"idtyp": "app", "roles": ["R"]}));
        assert_eq!(check_constraints(&r, None, &delegated), Ok(()));
        assert_eq!(check_constraints(&r, None, &application), Ok(()));
        let profile_error = |r: &ClaimRules, c: &Map<String, Value>| {
            matches!(
                check_constraints(r, None, c),
                Err(AuthError::TokenProfile(_))
            )
        };
        assert!(profile_error(&r, &obj(json!({"roles": ["R"]}))));
        assert!(profile_error(&r, &obj(json!({"idtyp": "user"}))));
        // ID tokens are refused even when they would otherwise match.
        assert!(profile_error(
            &r,
            &obj(json!({"scp": "Database.Connect", "nonce": "n"}))
        ));
        r.token_profiles = vec![TokenProfile::Delegated];
        assert_eq!(check_constraints(&r, None, &delegated), Ok(()));
        assert_eq!(
            check_constraints(&r, None, &application),
            Err(AuthError::TokenProfile(
                "the application token profile is not enabled for this provider".into()
            ))
        );
        r.token_profiles = vec![TokenProfile::Application];
        assert!(profile_error(&r, &delegated));
        assert_eq!(check_constraints(&r, None, &application), Ok(()));
    }

    #[test]
    fn workload_presets() {
        let k = map_identity(
            &rules(IdpType::Kubernetes),
            obj(json!({"sub": "system:serviceaccount:ns:app", "exp": 1})),
            true,
        )
        .unwrap();
        assert_eq!(k.kind, IdentityKind::Workload);
        assert_eq!(k.username.as_deref(), Some("system:serviceaccount:ns:app"));
        let g = map_identity(
            &rules(IdpType::GithubActions),
            obj(
                json!({"sub": "repo:org/r:environment:prod", "repository": "org/r",
                        "repository_owner": "org", "repository_owner_id": "4242", "exp": 1}),
            ),
            true,
        )
        .unwrap();
        assert_eq!(g.kind, IdentityKind::Workload);
        assert_eq!(g.username.as_deref(), Some("org/r"));
        // The tenant is the immutable owner ID, not the renamable owner name.
        assert_eq!(g.tenant.as_deref(), Some("4242"));
        assert!(g.scopes.is_empty());
    }

    #[test]
    fn groups_overage_detection() {
        let r = rules(IdpType::Entra);
        let base = |extra: Value| {
            let mut c = obj(json!({"oid": "o", "exp": 1}));
            c.extend(obj(extra));
            map_identity(&r, c, true).unwrap().groups_overage
        };
        assert!(base(json!({"_claim_names": {"groups": "src1"}})));
        assert!(base(json!({"hasgroups": true})));
        assert!(base(json!({"hasgroups": "true"})));
        assert!(!base(json!({"hasgroups": false})));
        assert!(!base(json!({"_claim_names": {"other": "src1"}})));
        assert!(!base(json!({"_claim_names": "groups"})));
        assert!(!base(json!({"groups": ["g"]})));
    }

    #[test]
    fn typ_comparison() {
        assert!(typ_matches("at+jwt", "at+jwt"));
        assert!(typ_matches("at+jwt", "AT+JWT"));
        assert!(typ_matches("at+jwt", "application/at+jwt"));
        assert!(typ_matches("application/AT+JWT", "at+jwt"));
        assert!(!typ_matches("at+jwt", "JWT"));
        assert!(!typ_matches("at+jwt", ""));
        assert!(!typ_matches("at+jwt", "application/"));
        // Multi-byte characters near the prefix boundary must not panic.
        assert!(!typ_matches("at+jwt", "ééééééé"));
    }

    #[test]
    fn constraint_checks() {
        let mut r = rules(IdpType::Entra);
        r.tenants = vec!["t1".into()];
        r.allowed_client_ids = vec!["c1".into()];
        r.required_scopes = vec!["Database.Connect".into()];
        r.expected_typ = Some("JWT".into());
        let ok = obj(json!({"tid": "t1", "azp": "c1", "scp": "Database.Connect other"}));
        assert_eq!(check_constraints(&r, Some("jwt"), &ok), Ok(()));
        assert_eq!(
            check_constraints(&r, Some("at+jwt"), &ok),
            Err(AuthError::BadType("at+jwt".into()))
        );
        assert_eq!(
            check_constraints(&r, None, &ok),
            Err(AuthError::BadType(String::new()))
        );
        let c = |v: Value| check_constraints(&r, Some("JWT"), &obj(v));
        assert_eq!(
            c(json!({"azp": "c1", "scp": "Database.Connect"})),
            Err(AuthError::MissingClaim("tid".into()))
        );
        assert_eq!(
            c(json!({"tid": "t2", "azp": "c1", "scp": "Database.Connect"})),
            Err(AuthError::TenantNotAllowed("t2".into()))
        );
        assert_eq!(
            c(json!({"tid": "t1", "scp": "Database.Connect"})),
            Err(AuthError::MissingClaim("azp".into()))
        );
        assert_eq!(
            c(json!({"tid": "t1", "appid": "c2", "scp": "Database.Connect"})),
            Err(AuthError::ClientNotAllowed("c2".into()))
        );
        assert_eq!(
            c(json!({"tid": "t1", "appid": "c1", "scp": "Database.Connect"})),
            Ok(())
        );
        assert_eq!(
            c(json!({"tid": "t1", "azp": "c1", "scp": "Other"})),
            Err(AuthError::MissingScope("Database.Connect".into()))
        );
        // A token without any scope claim matches no profile.
        assert!(matches!(
            c(json!({"tid": "t1", "azp": "c1"})),
            Err(AuthError::TokenProfile(_))
        ));
        // Entra app-only tokens are exempt from required_scopes.
        assert_eq!(
            c(json!({"tid": "t1", "azp": "c1", "idtyp": "app", "roles": ["R"]})),
            Ok(())
        );
    }

    #[test]
    fn scope_exemptions_by_provider_type() {
        for kind in [IdpType::Kubernetes, IdpType::GithubActions] {
            let mut r = rules(kind);
            r.required_scopes = vec!["x".into()];
            assert_eq!(check_constraints(&r, None, &obj(json!({}))), Ok(()));
        }
        let mut r = rules(IdpType::Oidc);
        r.required_scopes = vec!["x".into()];
        // `idtyp` means nothing for generic OIDC providers.
        assert_eq!(
            check_constraints(&r, None, &obj(json!({"idtyp": "app"}))),
            Err(AuthError::MissingScope("x".into()))
        );
        assert_eq!(
            check_constraints(&r, None, &obj(json!({"scope": ["y", "x"]}))),
            Ok(())
        );
    }

    #[test]
    fn required_claims_must_be_present() {
        let mut r = rules(IdpType::Oidc);
        r.required_claims = vec!["acct".into(), "/kubernetes.io/pod/uid".into()];
        let ok = obj(json!({"acct": 0, "kubernetes.io": {"pod": {"uid": "u"}}}));
        assert_eq!(check_constraints(&r, None, &ok), Ok(()));
        assert_eq!(
            check_constraints(
                &r,
                None,
                &obj(json!({"kubernetes.io": {"pod": {"uid": "u"}}}))
            ),
            Err(AuthError::MissingClaim("acct".into()))
        );
        assert_eq!(
            check_constraints(&r, None, &obj(json!({"acct": null, "kubernetes.io": {}}))),
            Err(AuthError::MissingClaim("acct".into()))
        );
        assert_eq!(
            check_constraints(&r, None, &obj(json!({"acct": 1}))),
            Err(AuthError::MissingClaim("/kubernetes.io/pod/uid".into()))
        );
    }

    #[test]
    fn github_tenant_uses_repository_owner_id() {
        let mut r = rules(IdpType::GithubActions);
        r.tenants = vec!["4242".into()];
        assert_eq!(
            check_constraints(
                &r,
                None,
                &obj(json!({"repository_owner": "my-org", "repository_owner_id": "4242"}))
            ),
            Ok(())
        );
        // A renamed or re-registered owner name does not help.
        assert_eq!(
            check_constraints(
                &r,
                None,
                &obj(json!({"repository_owner": "4242", "repository_owner_id": "666"}))
            ),
            Err(AuthError::TenantNotAllowed("666".into()))
        );
    }

    #[test]
    fn custom_claim_mapping() {
        let mut r = rules(IdpType::Oidc);
        r.claims.subject = "user.id".into();
        r.claims.roles = Some("realm_access.roles".into());
        r.claims.groups = Some("https://example.com/groups".into());
        let id = map_identity(
            &r,
            obj(
                json!({"user": {"id": "nested"}, "realm_access": {"roles": ["admin"]},
                        "https://example.com/groups": ["g"], "exp": 1}),
            ),
            true,
        )
        .unwrap();
        assert_eq!(id.subject, "nested");
        assert_eq!(id.roles, ["admin".to_string()].into());
        assert_eq!(id.groups, ["g".to_string()].into());
    }

    proptest! {
        #[test]
        fn mapping_arbitrary_claims_never_panics(
            sub in proptest::option::of(".{0,10}"),
            scope in ".{0,30}",
            path in "[a-z.]{0,10}",
        ) {
            let mut r = rules(IdpType::Entra);
            r.claims.groups = Some(path.clone());
            r.required_scopes = vec!["a".into()];
            r.tenants = vec!["t".into()];
            let mut c = obj(json!({"scp": scope, "exp": 5, "tid": "t"}));
            if let Some(s) = sub {
                c.insert("oid".into(), json!(s));
            }
            let _ = check_constraints(&r, None, &c);
            let _ = map_identity(&r, c, true);
        }
    }
}
