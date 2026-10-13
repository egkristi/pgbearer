//! Property tests: order independence, monotonicity under unknown data, and
//! the algebra of [`Truth`].

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

use pgbearer_config::{
    ClaimPredicate, Config, DenyRule, DenyTermination, Grant, GrantRule, IdpType, Predicate,
    UnknownHandling, UserSemantics,
};
use pgbearer_core::{Identity, IdentityKind, PoolMode, RoleRisk, TokenExpiryAction};
use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use serde_json::{Map, Value, json};

use crate::{ConnectRequest, Decision, Denied, PolicyEngine, Truth};

const BASE: &str = r#"
apiVersion: pgbearer/v1alpha1
kind: ProxyConfig
listeners:
  - name: l1
    address: "127.0.0.1:6432"
    insecure_allow_plaintext_auth: true
  - name: l2
    address: "127.0.0.1:6433"
    insecure_allow_plaintext_auth: true
identity_providers:
  - name: idp
    issuer: "https://idp.example.com"
    audiences: ["pgbearer"]
  - name: k8s
    type: kubernetes
    audiences: ["pgbearer"]
backends:
  - name: b1
    static: { host: "127.0.0.1", port: 5432 }
    tls: { mode: disable }
    login:
      method: password
      roles:
        r1: { password_file: /run/secrets/r1 }
        r2: { password_file: /run/secrets/r2 }
        r3: { password_file: /run/secrets/r3 }
  - name: b2
    static: { host: "127.0.0.1", port: 5433 }
    tls: { mode: disable }
    login:
      method: password
      roles:
        r1: { password_file: /run/secrets/r1 }
        r2: { password_file: /run/secrets/r2 }
        r3: { password_file: /run/secrets/r3 }
experimental:
  transaction_pooling: true
"#;

static BASE_CONFIG: LazyLock<Config> = LazyLock::new(|| Config::from_yaml_str(BASE).unwrap());

const ROLES: &[&str] = &["r1", "r2", "r3"];
const BACKENDS: &[&str] = &["b1", "b2"];
const LISTENERS: &[&str] = &["l1", "l2"];
const GROUPS: &[&str] = &["g1", "g2", "g3"];
const APP_ROLES: &[&str] = &["a1", "a2"];
const SCOPES: &[&str] = &["s1", "s2"];
const TENANTS: &[&str] = &["t1", "t2"];
const CLIENTS: &[&str] = &["c1", "c2"];
const SUBJECTS: &[&str] = &["alice", "bob", "svc-1"];
const USERNAMES: &[&str] = &["alice@x", "bob@x"];
const CLAIM_NAMES: &[&str] = &["acct", "env", "tags", "/nested/x"];

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn strings(items: &'static [&'static str]) -> impl Strategy<Value = Vec<String>> {
    subsequence(items, 0..=items.len())
        .prop_map(|v| v.into_iter().map(String::from).collect::<Vec<_>>())
}

/// Usually empty (no condition), sometimes a subset.
fn sparse(items: &'static [&'static str]) -> impl Strategy<Value = Vec<String>> {
    prop_oneof![8 => Just(Vec::new()), 1 => strings(items)]
}

fn maybe<S: Strategy>(s: S) -> impl Strategy<Value = Option<S::Value>> {
    proptest::option::weighted(0.12, s)
}

/// A grant setting: often set, so that merges are exercised.
fn setting<S: Strategy>(s: S) -> impl Strategy<Value = Option<S::Value>> {
    proptest::option::weighted(0.5, s)
}

/// A claim the identity usually has.
fn present<S: Strategy>(s: S) -> impl Strategy<Value = Option<S::Value>> {
    proptest::option::weighted(0.7, s)
}

fn owned(items: &'static [&'static str]) -> impl Strategy<Value = String> {
    select(items).prop_map(String::from)
}

fn kind() -> impl Strategy<Value = IdentityKind> {
    select(
        &[
            IdentityKind::Human,
            IdentityKind::Workload,
            IdentityKind::Unknown,
        ][..],
    )
}

fn claim_value() -> impl Strategy<Value = Value> {
    select(vec![
        json!(0),
        json!(1),
        json!("1"),
        json!("prod"),
        json!("dev"),
        json!("a"),
    ])
}

fn claim_predicate() -> impl Strategy<Value = ClaimPredicate> {
    (
        owned(CLAIM_NAMES),
        maybe(claim_value()),
        maybe(claim_value()),
        prop_oneof![2 => Just(Vec::new()), 1 => prop::collection::vec(claim_value(), 1..3)],
        maybe(any::<bool>()),
    )
        .prop_map(|(name, equals, contains, any_of, exists)| ClaimPredicate {
            name,
            equals,
            contains,
            any_of,
            exists,
        })
}

/// Half the predicates only name an issuer (or nothing); the others combine
/// sparse conditions of every kind.
fn predicate() -> impl Strategy<Value = Predicate> {
    let simple =
        proptest::option::weighted(0.8, Just("idp".to_owned())).prop_map(|issuer| Predicate {
            issuer,
            ..Predicate::default()
        });
    prop_oneof![1 => simple, 1 => full_predicate()]
}

fn full_predicate() -> impl Strategy<Value = Predicate> {
    let identity_part = (
        proptest::option::weighted(
            0.5,
            prop_oneof![6 => Just("idp".to_owned()), 1 => Just("k8s".to_owned())],
        ),
        maybe(owned(&["alice", "bob", "svc-*", "*", "al*"])),
        sparse(&["alice", "bob", "svc-*"]),
        maybe(owned(&["alice@x", "bob@*", "*"])),
        maybe(kind()),
        sparse(TENANTS),
        sparse(CLIENTS),
    );
    let attribute_part = (
        sparse(APP_ROLES),
        sparse(APP_ROLES),
        sparse(GROUPS),
        sparse(GROUPS),
        sparse(SCOPES),
        prop_oneof![6 => Just(Vec::new()), 1 => prop::collection::vec(claim_predicate(), 1..3)],
        sparse(&["10.0.0.0/8", "192.168.0.0/16", "::ffff:10.0.0.0/104"]),
        sparse(LISTENERS),
    );
    (identity_part, attribute_part).prop_map(
        |(
            (issuer, subject, subjects, username, kind, tenants, client_ids),
            (roles_any, roles_all, groups_any, groups_all, scopes_any, claims, cidrs, listeners),
        )| Predicate {
            issuer,
            subject,
            subjects,
            username,
            roles_any,
            roles_all,
            groups_any,
            groups_all,
            scopes_any,
            tenants,
            client_ids,
            kind,
            claims,
            source_cidrs: cidrs.iter().filter_map(|c| c.parse().ok()).collect(),
            listeners,
        },
    )
}

/// Mostly the first backend, so that grants and requests often meet.
fn backend() -> impl Strategy<Value = String> {
    prop_oneof![3 => Just(BACKENDS[0].to_owned()), 1 => Just(BACKENDS[1].to_owned())]
}

fn grant() -> impl Strategy<Value = Grant> {
    (
        backend(),
        subsequence(&["d1", "d2", "*"][..], 1..=3),
        subsequence(ROLES, 1..=ROLES.len()),
        proptest::option::weighted(0.6, any::<prop::sample::Index>()),
        setting(select(&[PoolMode::Session, PoolMode::Transaction][..])),
        setting(1u32..5),
        setting((1u64..60).prop_map(|m| Duration::from_secs(m * 60))),
        setting(select(
            &[
                TokenExpiryAction::Terminate,
                TokenExpiryAction::TerminateWhenIdle,
            ][..],
        )),
        subsequence(RoleRisk::ALL.to_vec(), 0..=3),
        proptest::bool::weighted(0.2),
    )
        .prop_map(
            |(
                backend,
                databases,
                roles,
                default,
                pool_mode,
                max_sessions,
                lifetime,
                expiry,
                risks,
                allow_privileged_role,
            )| {
                let pg_roles: Vec<String> = roles.into_iter().map(String::from).collect();
                Grant {
                    backend,
                    databases: databases.into_iter().map(String::from).collect(),
                    default_pg_role: default.map(|i| i.get(&pg_roles).clone()),
                    pg_roles,
                    pool_mode,
                    max_sessions_per_identity_per_replica: max_sessions,
                    session_max_lifetime: lifetime,
                    on_token_expiry: expiry,
                    acknowledged_role_risks: risks.into_iter().collect(),
                    allow_privileged_role,
                }
            },
        )
}

fn grants() -> impl Strategy<Value = Vec<GrantRule>> {
    prop::collection::vec((predicate(), grant()), 0..8).prop_map(|rules| {
        rules
            .into_iter()
            .enumerate()
            .map(|(i, (when, grant))| GrantRule {
                name: format!("grant{i}"),
                when,
                grant,
            })
            .collect()
    })
}

fn deny_rules() -> impl Strategy<Value = Vec<DenyRule>> {
    let rule = (
        predicate(),
        select(&[UnknownHandling::Deny, UnknownHandling::Ignore][..]),
        select(&[DenyTermination::AtSafePoint, DenyTermination::Immediate][..]),
        owned(&["bob", "svc-2", "carol"]),
    );
    prop::collection::vec(rule, 0..3).prop_map(|rules| {
        rules
            .into_iter()
            .enumerate()
            .map(|(i, (mut when, on_unknown, terminate, subject))| {
                // Deny rules that match nearly everything would make almost
                // every case a denial; give unscoped rules a subject.
                if when.subject.is_none() {
                    when.subject = Some(subject);
                }
                DenyRule {
                    name: format!("deny{i}"),
                    when,
                    on_unknown,
                    terminate,
                }
            })
            .collect()
    })
}

fn identity() -> impl Strategy<Value = Identity> {
    let names = (
        prop_oneof![6 => Just("idp"), 1 => Just("k8s"), 1 => Just("ghost")],
        owned(SUBJECTS),
        proptest::option::weighted(0.8, owned(USERNAMES)),
        proptest::option::weighted(0.8, owned(TENANTS)),
        proptest::option::weighted(0.8, owned(CLIENTS)),
        prop_oneof![3 => Just(IdentityKind::Human), 2 => Just(IdentityKind::Workload), 1 => Just(IdentityKind::Unknown)],
    );
    let sets = (
        strings(GROUPS),
        strings(APP_ROLES),
        strings(SCOPES),
        proptest::bool::weighted(0.2),
        present(claim_value()),
        present(claim_value()),
        present(strings(&["a", "prod", "1"])),
        present(claim_value()),
    );
    (names, sets).prop_map(
        |(
            (provider, subject, username, tenant, client_id, kind),
            (groups, roles, scopes, groups_overage, acct, env, tags, nested),
        )| {
            let mut claims = Map::new();
            if let Some(v) = acct {
                claims.insert("acct".into(), v);
            }
            if let Some(v) = env {
                claims.insert("env".into(), v);
            }
            if let Some(v) = tags {
                claims.insert("tags".into(), json!(v));
            }
            if let Some(v) = nested {
                claims.insert("nested".into(), json!({ "x": v }));
            }
            Identity {
                provider: provider.into(),
                issuer: format!("https://{provider}.example.com"),
                subject,
                username,
                tenant,
                client_id,
                groups: groups.into_iter().collect(),
                roles: roles.into_iter().collect(),
                scopes: scopes.into_iter().collect(),
                kind,
                expires_at: SystemTime::UNIX_EPOCH,
                token_id: None,
                groups_overage,
                claims,
            }
        },
    )
}

/// Requested user, database, backend, listener, client address.
#[derive(Debug, Clone)]
struct Request {
    user: String,
    database: String,
    backend: String,
    listener: String,
    client_ip: IpAddr,
}

impl Request {
    fn bind<'a>(&'a self, identity: &'a Identity) -> ConnectRequest<'a> {
        ConnectRequest {
            identity,
            requested_user: &self.user,
            database: &self.database,
            backend: &self.backend,
            listener: &self.listener,
            client_ip: self.client_ip,
        }
    }
}

fn request() -> impl Strategy<Value = Request> {
    (
        owned(&["", "r1", "r2", "r3", "*", "alice", "alice@x", "nobody"]),
        owned(&["d1", "d2", "d3"]),
        backend(),
        owned(LISTENERS),
        owned(&["10.1.2.3", "192.168.1.1", "::ffff:10.1.2.3", "2001:db8::1"]),
    )
        .prop_map(|(user, database, backend, listener, ip)| Request {
            user,
            database,
            backend,
            listener,
            client_ip: ip.parse().unwrap_or(IpAddr::from([127, 0, 0, 1])),
        })
}

fn semantics() -> impl Strategy<Value = UserSemantics> {
    select(
        &[
            UserSemantics::Auto,
            UserSemantics::Role,
            UserSemantics::Identity,
        ][..],
    )
}

fn truth() -> impl Strategy<Value = Truth> {
    select(&[Truth::True, Truth::False, Truth::Unknown][..])
}

/// A list together with a permutation of it.
fn permuted<T: Clone + std::fmt::Debug>(
    s: impl Strategy<Value = Vec<T>>,
) -> impl Strategy<Value = (Vec<T>, Vec<T>)> {
    s.prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn config_for(grants: Vec<GrantRule>, deny: Vec<DenyRule>, semantics: UserSemantics) -> Config {
    let mut config = BASE_CONFIG.clone();
    config.policies = grants;
    config.deny = deny;
    config.session.user_semantics = semantics;
    config
}

/// A decision with order-dependent parts normalised: matched grants and
/// session limits sorted; for a deny rule only the fact that one fired.
#[derive(Debug, PartialEq)]
enum Normalized {
    Allow { allowed: Box<crate::Allowed> },
    DenyRule,
    Deny(Denied),
}

fn normalize(decision: Decision) -> Normalized {
    match decision {
        Decision::Allow(mut a) => {
            a.matched_grants.sort();
            Normalized::Allow {
                allowed: Box::new(a),
            }
        }
        Decision::Deny(d) if d.deny_rule.is_some() => Normalized::DenyRule,
        Decision::Deny(d) => Normalized::Deny(d),
    }
}

/// Ways of making data unknown.
#[derive(Debug, Clone, Copy)]
enum Unknowable {
    GroupsOverage,
    Username,
    Tenant,
    ClientId,
    Kind,
    Claim(&'static str),
    ProviderUnmapped,
    ProviderUnconfigured,
}

fn unknowable() -> impl Strategy<Value = Unknowable> {
    prop_oneof![
        Just(Unknowable::GroupsOverage),
        Just(Unknowable::Username),
        Just(Unknowable::Tenant),
        Just(Unknowable::ClientId),
        Just(Unknowable::Kind),
        select(&["acct", "env", "tags", "nested"][..]).prop_map(Unknowable::Claim),
        Just(Unknowable::ProviderUnmapped),
        Just(Unknowable::ProviderUnconfigured),
    ]
}

impl Unknowable {
    /// Rewrite rules so that the transformation only turns conditions
    /// unknown: `exists` tests absence (a fact, never unknown) and `kind:
    /// unknown` matches identities of unknown kind, so removing a claim or
    /// forgetting the kind would change those conditions from false to true.
    fn sanitize(&self, predicate: &mut Predicate) {
        match *self {
            Unknowable::Claim(_) => {
                for c in &mut predicate.claims {
                    c.exists = None;
                }
            }
            Unknowable::Kind if predicate.kind == Some(IdentityKind::Unknown) => {
                predicate.kind = None;
            }
            _ => {}
        }
    }

    fn apply(&self, identity: &mut Identity, config: &mut Config) {
        match *self {
            Unknowable::GroupsOverage => identity.groups_overage = true,
            Unknowable::Username => identity.username = None,
            Unknowable::Tenant => identity.tenant = None,
            Unknowable::ClientId => identity.client_id = None,
            Unknowable::Kind => identity.kind = IdentityKind::Unknown,
            Unknowable::Claim(name) => {
                identity.claims.remove(name);
            }
            Unknowable::ProviderUnmapped => {
                for p in &mut config.identity_providers {
                    if p.name == identity.provider {
                        p.kind = IdpType::Kubernetes;
                        p.claims = Default::default();
                    }
                }
            }
            Unknowable::ProviderUnconfigured => config
                .identity_providers
                .retain(|p| p.name != identity.provider),
        }
    }
}

/// Grants that cover the request and whose predicate is `True`.
fn candidate_names(engine: &PolicyEngine, req: &ConnectRequest<'_>) -> BTreeSet<String> {
    engine
        .explain(req)
        .grants
        .into_iter()
        .filter(|t| t.predicate.truth == Truth::True && t.target_matches == Some(true))
        .map(|t| t.name)
        .collect()
}

fn roles_of(config: &Config, grants: &BTreeSet<String>) -> BTreeSet<String> {
    config
        .policies
        .iter()
        .filter(|g| grants.contains(&g.name))
        .flat_map(|g| g.grant.pg_roles.iter().cloned())
        .collect()
}

fn is_default_role_denial(d: &Denied) -> bool {
    d.reason.starts_with("conflicting default roles")
        || d.reason.starts_with("ambiguous default role")
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Permuting `policies` and `deny` changes neither allow/deny, nor the
    /// role, nor any merged setting; only the named deny rule and the order
    /// of `matched_grants` may differ.
    #[test]
    fn decisions_do_not_depend_on_rule_order(
        (grants, shuffled_grants) in permuted(grants()),
        (deny, shuffled_deny) in permuted(deny_rules()),
        semantics in semantics(),
        identity in identity(),
        request in request(),
    ) {
        let original = config_for(grants, deny, semantics);
        let shuffled = config_for(shuffled_grants, shuffled_deny, semantics);
        let a = PolicyEngine::from_config(&original);
        let b = PolicyEngine::from_config(&shuffled);
        let req = request.bind(&identity);

        let decision = a.evaluate(&req);
        prop_assert_eq!(&a.explain(&req).decision, &decision);
        prop_assert_eq!(normalize(decision), normalize(b.evaluate(&req)));

        let names = |e: &PolicyEngine| -> BTreeSet<String> {
            e.entitlements(&identity, &request.listener, request.client_ip)
                .into_iter()
                .map(|e| e.grant)
                .collect()
        };
        prop_assert_eq!(names(&a), names(&b));
        prop_assert_eq!(
            a.matching_deny_rule(&identity, &request.listener, request.client_ip).is_some(),
            b.matching_deny_rule(&identity, &request.listener, request.client_ip).is_some()
        );
    }

    /// Making data unknown never bypasses a deny rule (with the default
    /// `on_unknown: deny`), never adds a grant, and never yields a role the
    /// identity was not entitled to with complete data. A request that names
    /// a role is never turned from Deny into Allow; with the default role,
    /// the only possible change is that fewer matching grants resolve a
    /// conflicting or ambiguous default (a role that was already entitled).
    #[test]
    fn unknown_data_never_widens_access(
        grants in grants(),
        deny in deny_rules(),
        semantics in semantics(),
        identity in identity(),
        request in request(),
        changes in prop::collection::vec(unknowable(), 1..4),
    ) {
        let mut grants = grants;
        let mut deny = deny;
        for change in &changes {
            for g in &mut grants {
                change.sanitize(&mut g.when);
            }
            for d in &mut deny {
                change.sanitize(&mut d.when);
            }
        }
        for d in &mut deny {
            d.on_unknown = UnknownHandling::Deny;
        }
        let known_config = config_for(grants, deny, semantics);
        let mut unknown_config = known_config.clone();
        let mut unknown_identity = identity.clone();
        for change in &changes {
            change.apply(&mut unknown_identity, &mut unknown_config);
        }

        let known = PolicyEngine::from_config(&known_config);
        let unknown = PolicyEngine::from_config(&unknown_config);
        let known_req = request.bind(&identity);
        let unknown_req = request.bind(&unknown_identity);
        let before = known.evaluate(&known_req);
        let after = unknown.evaluate(&unknown_req);

        // Deny rules are never bypassed.
        if let Decision::Deny(d) = &before && d.deny_rule.is_some() {
            prop_assert!(
                matches!(&after, Decision::Deny(d) if d.deny_rule.is_some()),
                "deny rule bypassed: {:?} -> {:?}", before, after
            );
        }
        let (listener, ip) = (&request.listener, request.client_ip);
        if known.matching_deny_rule(&identity, listener, ip).is_some() {
            prop_assert!(unknown.matching_deny_rule(&unknown_identity, listener, ip).is_some());
        }

        // Grants are never added.
        let known_candidates = candidate_names(&known, &known_req);
        prop_assert!(candidate_names(&unknown, &unknown_req).is_subset(&known_candidates));
        let entitled = |e: &PolicyEngine, id: &Identity| -> BTreeSet<String> {
            e.entitlements(id, listener, ip).into_iter().map(|e| e.grant).collect()
        };
        prop_assert!(entitled(&unknown, &unknown_identity).is_subset(&entitled(&known, &identity)));

        if let Decision::Allow(a) = &after {
            // Only roles and grants that were entitled with complete data.
            let entitled_roles = roles_of(&known_config, &known_candidates);
            prop_assert!(entitled_roles.contains(&a.pg_role), "{:?} -> {:?}", before, after);
            prop_assert!(a.matched_grants.iter().all(|g| known_candidates.contains(g)));
            match &before {
                Decision::Allow(b) => {
                    if ROLES.contains(&request.user.as_str()) && semantics != UserSemantics::Identity {
                        prop_assert_eq!(&a.pg_role, &b.pg_role);
                    }
                }
                Decision::Deny(d) => {
                    prop_assert!(
                        is_default_role_denial(d),
                        "unknown data turned a denial into an allow: {:?} -> {:?}", before, after
                    );
                }
            }
        }
        // A request that names a role is never turned from Deny into Allow.
        if ROLES.contains(&request.user.as_str()) && semantics != UserSemantics::Identity {
            prop_assert!(before.is_allow() || !after.is_allow());
        }
    }

    /// Conjunction is commutative and associative; `False` dominates, `True`
    /// is the identity.
    #[test]
    fn truth_conjunction_algebra(a in truth(), b in truth(), c in truth()) {
        prop_assert_eq!(a.and(b), b.and(a));
        prop_assert_eq!(a.and(b).and(c), a.and(b.and(c)));
        prop_assert_eq!(a.and(Truth::False), Truth::False);
        prop_assert_eq!(a.and(Truth::True), a);
        prop_assert_eq!(a.and(a), a);
        if a == Truth::Unknown && b != Truth::False {
            prop_assert_eq!(a.and(b), Truth::Unknown);
        }
    }
}
