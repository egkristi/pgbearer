//! Table and scenario tests for predicates, claim conditions and the engine.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use pgbearer_config::{
    ClaimPredicate, Config, DenyTermination, IdentityProviderConfig, Predicate, UserSemantics,
};
use pgbearer_core::{Identity, IdentityKind, PoolMode, RoleRisk, TokenExpiryAction};
use serde_json::{Value, json};

use crate::{
    Allowed, ConnectRequest, Decision, Denied, Entitlement, PolicyEngine, SessionLimit, Truth,
    claim_truth, evaluate_predicate,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE: &str = r#"
apiVersion: pgbearer/v1alpha1
kind: ProxyConfig
listeners:
  - name: pg
    address: "127.0.0.1:6432"
    insecure_allow_plaintext_auth: true
  - name: internal
    address: "127.0.0.1:6433"
    insecure_allow_plaintext_auth: true
identity_providers:
  - name: idp
    issuer: "https://idp.example.com/realms/main"
    audiences: ["pgbearer"]
  - name: k8s
    type: kubernetes
    audiences: ["pgbearer"]
backends:
  - name: db
    static: { host: "127.0.0.1", port: 5432 }
    tls: { mode: disable }
    login:
      method: password
      roles:
        ro: { password_file: /run/secrets/ro }
        rw: { password_file: /run/secrets/rw }
        owner: { password_file: /run/secrets/owner }
  - name: other
    static: { host: "127.0.0.1", port: 5433 }
    tls: { mode: disable }
    login:
      method: password
      roles:
        ro: { password_file: /run/secrets/other_ro }
        owner: { password_file: /run/secrets/other_owner }
experimental:
  transaction_pooling: true
"#;

const EXAMPLE: &str = include_str!("../../../deploy/examples/pgbearer.yaml");

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));

fn base_config() -> Config {
    Config::from_yaml_str(BASE).unwrap()
}

fn config(policies: Value, deny: Value) -> Config {
    let mut c = base_config();
    c.policies = serde_json::from_value(policies).unwrap();
    c.deny = serde_json::from_value(deny).unwrap();
    c
}

/// An engine from a configuration that must pass validation.
fn engine(policies: Value, deny: Value) -> PolicyEngine {
    let c = config(policies, deny);
    if let Err(e) = c.validate() {
        panic!("test configuration must be valid: {e}");
    }
    PolicyEngine::from_config(&c)
}

fn engine_with(policies: Value, deny: Value, semantics: UserSemantics) -> PolicyEngine {
    let mut c = config(policies, deny);
    c.session.user_semantics = semantics;
    c.validate().unwrap();
    PolicyEngine::from_config(&c)
}

/// An engine from a configuration that validation would reject.
fn engine_unchecked(policies: Value, deny: Value) -> PolicyEngine {
    PolicyEngine::from_config(&config(policies, deny))
}

fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.into_iter().map(String::from).collect()
}

fn claims(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().unwrap()
}

fn alice() -> Identity {
    Identity {
        provider: "idp".into(),
        issuer: "https://idp.example.com/realms/main".into(),
        subject: "sub-alice".into(),
        username: Some("alice@example.com".into()),
        tenant: Some("t1".into()),
        groups: set(["readers", "staff"]),
        roles: set(["Orders.Analyst"]),
        scopes: set(["db.connect"]),
        client_id: Some("cli".into()),
        kind: IdentityKind::Human,
        expires_at: SystemTime::UNIX_EPOCH,
        token_id: None,
        groups_overage: false,
        claims: claims(json!({"acct": 0, "env": "prod", "tags": ["a", "b"]})),
    }
}

fn workload() -> Identity {
    Identity {
        provider: "k8s".into(),
        issuer: "https://kubernetes.default.svc.cluster.local".into(),
        subject: "system:serviceaccount:orders:api".into(),
        username: Some("system:serviceaccount:orders:api".into()),
        tenant: None,
        groups: BTreeSet::new(),
        roles: BTreeSet::new(),
        scopes: BTreeSet::new(),
        client_id: None,
        kind: IdentityKind::Workload,
        expires_at: SystemTime::UNIX_EPOCH,
        token_id: None,
        groups_overage: false,
        claims: claims(json!({"kubernetes.io": {"namespace": "orders"}})),
    }
}

fn request<'a>(
    identity: &'a Identity,
    user: &'a str,
    backend: &'a str,
    database: &'a str,
) -> ConnectRequest<'a> {
    ConnectRequest {
        identity,
        requested_user: user,
        database,
        backend,
        listener: "pg",
        client_ip: IP,
    }
}

fn allowed(decision: Decision) -> Allowed {
    match decision {
        Decision::Allow(a) => a,
        Decision::Deny(d) => panic!("expected Allow, got Deny: {}", d.reason),
    }
}

fn denied(decision: Decision) -> Denied {
    match decision {
        Decision::Deny(d) => d,
        Decision::Allow(a) => panic!("expected Deny, got Allow as {:?}", a.pg_role),
    }
}

/// A grant rule for `db` with one role as default.
fn simple_grant(name: &str, when: Value, databases: Value, role: &str) -> Value {
    json!({
        "name": name,
        "when": when,
        "grant": {
            "backend": "db",
            "databases": databases,
            "pg_roles": [role],
            "default_pg_role": role,
        }
    })
}

// ---------------------------------------------------------------------------
// Truth
// ---------------------------------------------------------------------------

#[test]
fn truth_conjunction_table() {
    use Truth::{False as F, True as T, Unknown as U};
    let table = [
        (T, T, T),
        (T, U, U),
        (T, F, F),
        (U, T, U),
        (U, U, U),
        (U, F, F),
        (F, T, F),
        (F, U, F),
        (F, F, F),
    ];
    for (a, b, expected) in table {
        assert_eq!(a.and(b), expected, "{a:?} and {b:?}");
    }
    assert_eq!(Truth::from_bool(true), T);
    assert_eq!(Truth::from_bool(false), F);
}

// ---------------------------------------------------------------------------
// Predicate conditions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Provider {
    Idp,
    K8s,
    Missing,
}

struct Case {
    name: &'static str,
    when: Value,
    expect: Truth,
    identity: fn(&mut Identity),
    provider: Provider,
    client_ip: IpAddr,
    unknown: &'static [&'static str],
}

fn case(name: &'static str, when: Value, expect: Truth) -> Case {
    Case {
        name,
        when,
        expect,
        identity: |_| {},
        provider: Provider::Idp,
        client_ip: IP,
        unknown: &[],
    }
}

impl Case {
    fn identity(mut self, f: fn(&mut Identity)) -> Case {
        self.identity = f;
        self
    }
    fn provider(mut self, p: Provider) -> Case {
        self.provider = p;
        self
    }
    fn ip(mut self, ip: &str) -> Case {
        self.client_ip = ip.parse().unwrap();
        self
    }
    fn unknown(mut self, unknown: &'static [&'static str]) -> Case {
        self.unknown = unknown;
        self
    }
}

fn overage(i: &mut Identity) {
    i.groups_overage = true;
}

fn everything_unknown(i: &mut Identity) {
    i.kind = IdentityKind::Unknown;
    i.username = None;
    i.tenant = None;
    i.client_id = None;
    i.groups_overage = true;
    i.claims.clear();
}

#[test]
fn predicate_conditions_table() {
    use Provider::{K8s, Missing};
    use Truth::{False as F, True as T, Unknown as U};
    let cases =
        vec![
        // issuer: never unknown, even for an unconfigured provider.
        case("issuer matches", json!({"issuer": "idp"}), T),
        case("issuer differs", json!({"issuer": "k8s"}), F),
        case("issuer, provider missing", json!({"issuer": "idp"}), T).provider(Missing),
        // kind
        case("kind equal", json!({"kind": "human"}), T),
        case("kind differs", json!({"kind": "workload"}), F),
        case("kind of identity unknown", json!({"kind": "human"}), U)
            .identity(|i| i.kind = IdentityKind::Unknown)
            .unknown(&["kind (identity kind unknown)"]),
        case("kind unknown matches unknown", json!({"kind": "unknown"}), T)
            .identity(|i| i.kind = IdentityKind::Unknown),
        case("kind unknown vs human", json!({"kind": "unknown"}), F),
        // subject / subjects
        case("subject exact", json!({"subject": "sub-alice"}), T),
        case("subject exact is not a prefix", json!({"subject": "sub-al"}), F),
        case("subject case-sensitive", json!({"subject": "SUB-alice"}), F),
        case("subject prefix", json!({"subject": "sub-*"}), T),
        case("subject prefix miss", json!({"subject": "svc-*"}), F),
        case("subject star alone", json!({"subject": "*"}), T),
        case("inner star is literal", json!({"subject": "sub*alice"}), F),
        case("inner star matches itself", json!({"subject": "sub*alice"}), T)
            .identity(|i| i.subject = "sub*alice".into()),
        case("only the last star is special", json!({"subject": "sub-alice**"}), F),
        case("double star is a prefix ending in star", json!({"subject": "sub-**"}), T)
            .identity(|i| i.subject = "sub-*x".into()),
        case("subjects any", json!({"subjects": ["bob", "sub-*"]}), T),
        case("subjects none", json!({"subjects": ["bob", "carol"]}), F),
        case("subjects empty is no condition", json!({"subjects": []}), T),
        case(
            "subject and subjects both apply",
            json!({"subject": "sub-*", "subjects": ["bob"]}),
            F,
        ),
        // username
        case("username prefix", json!({"username": "alice@*"}), T),
        case("username differs", json!({"username": "bob@example.com"}), F),
        case("username absent", json!({"username": "alice@*"}), U)
            .identity(|i| i.username = None)
            .unknown(&["username (absent)"]),
        // roles
        case("roles_any hit", json!({"roles_any": ["x", "Orders.Analyst"]}), T),
        case("roles_any miss", json!({"roles_any": ["x"]}), F),
        case("roles_all subset", json!({"roles_all": ["Orders.Analyst"]}), T),
        case("roles_all missing one", json!({"roles_all": ["Orders.Analyst", "x"]}), F),
        case("roles_any unmapped", json!({"roles_any": ["x"]}), U)
            .provider(K8s)
            .unknown(&["roles (identity provider \"k8s\" maps no roles)"]),
        case("roles_all unmapped", json!({"roles_all": ["x"]}), U)
            .provider(K8s)
            .unknown(&["roles (identity provider \"k8s\" maps no roles)"]),
        case("roles, provider missing", json!({"roles_all": ["Orders.Analyst"]}), U)
            .provider(Missing)
            .unknown(&["roles (identity provider \"idp\" is not configured)"]),
        // groups
        case("groups_any hit", json!({"groups_any": ["admins", "readers"]}), T),
        case("groups_any miss", json!({"groups_any": ["admins"]}), F),
        case("groups_all subset", json!({"groups_all": ["readers", "staff"]}), T),
        case("groups_all missing one", json!({"groups_all": ["readers", "admins"]}), F),
        case("groups_any overage", json!({"groups_any": ["readers"]}), U)
            .identity(overage)
            .unknown(&["groups (groups overage)"]),
        case("groups_any overage, miss", json!({"groups_any": ["admins"]}), U)
            .identity(overage)
            .unknown(&["groups (groups overage)"]),
        case(
            "groups_any and groups_all overage, reported once",
            json!({"groups_any": ["readers"], "groups_all": ["staff"]}),
            U,
        )
        .identity(overage)
        .unknown(&["groups (groups overage)"]),
        case("groups unmapped", json!({"groups_any": ["readers"]}), U)
            .provider(K8s)
            .unknown(&["groups (identity provider \"k8s\" maps no groups)"]),
        case("groups, provider missing", json!({"groups_all": ["readers"]}), U)
            .provider(Missing)
            .unknown(&["groups (identity provider \"idp\" is not configured)"]),
        // scopes
        case("scopes hit", json!({"scopes_any": ["db.connect"]}), T),
        case("scopes miss", json!({"scopes_any": ["db.admin"]}), F),
        case("scopes unmapped", json!({"scopes_any": ["db.connect"]}), U)
            .provider(K8s)
            .unknown(&["scopes (identity provider \"k8s\" maps no scopes)"]),
        case("scopes, provider missing", json!({"scopes_any": ["db.connect"]}), U)
            .provider(Missing)
            .unknown(&["scopes (identity provider \"idp\" is not configured)"]),
        // tenants and client ids
        case("tenant member", json!({"tenants": ["t0", "t1"]}), T),
        case("tenant not member", json!({"tenants": ["t2"]}), F),
        case("tenant absent", json!({"tenants": ["t1"]}), U)
            .identity(|i| i.tenant = None)
            .unknown(&["tenant (absent)"]),
        case("client member", json!({"client_ids": ["cli"]}), T),
        case("client not member", json!({"client_ids": ["other"]}), F),
        case("client absent", json!({"client_ids": ["cli"]}), U)
            .identity(|i| i.client_id = None)
            .unknown(&["client_id (absent)"]),
        // claims
        case("claim equals", json!({"claims": [{"name": "acct", "equals": 0}]}), T),
        case("claim differs", json!({"claims": [{"name": "acct", "equals": 1}]}), F),
        case("claim absent", json!({"claims": [{"name": "missing", "equals": 1}]}), U)
            .unknown(&["claim missing (absent)"]),
        case(
            "claim absence checked",
            json!({"claims": [{"name": "missing", "exists": false}]}),
            T,
        ),
        case(
            "every claim condition must hold",
            json!({"claims": [{"name": "acct", "equals": 0}, {"name": "env", "equals": "dev"}]}),
            F,
        ),
        // source networks
        case(
            "cidr hit",
            json!({"source_cidrs": ["192.168.0.0/16", "10.0.0.0/8"]}),
            T,
        ),
        case("cidr miss", json!({"source_cidrs": ["192.168.0.0/16"]}), F),
        case(
            "v4-mapped client in a v4 network",
            json!({"source_cidrs": ["10.0.0.0/8"]}),
            T,
        )
        .ip("::ffff:10.1.2.3"),
        case(
            "v4 client in a v4-mapped network",
            json!({"source_cidrs": ["::ffff:10.0.0.0/104"]}),
            T,
        ),
        case("v6 client", json!({"source_cidrs": ["2001:db8::/32"]}), T).ip("2001:db8::1"),
        case("v6 client miss", json!({"source_cidrs": ["10.0.0.0/8"]}), F).ip("2001:db8::1"),
        // listeners
        case("listener hit", json!({"listeners": ["internal", "pg"]}), T),
        case("listener miss", json!({"listeners": ["internal"]}), F),
        // conjunction
        case("empty predicate", json!({}), T),
        case(
            "empty lists are not conditions",
            json!({
                "subjects": [], "roles_any": [], "roles_all": [], "groups_any": [],
                "groups_all": [], "scopes_any": [], "tenants": [], "client_ids": [],
                "claims": [], "source_cidrs": [], "listeners": []
            }),
            T,
        )
        .provider(Missing)
        .identity(everything_unknown),
        case(
            "true and unknown is unknown",
            json!({"issuer": "idp", "groups_any": ["readers"]}),
            U,
        )
        .identity(overage)
        .unknown(&["groups (groups overage)"]),
        case(
            "false dominates; unknowns are still reported",
            json!({"issuer": "k8s", "username": "alice@*", "groups_any": ["readers"]}),
            F,
        )
        .identity(|i| {
            i.username = None;
            i.groups_overage = true;
        })
        .unknown(&["username (absent)", "groups (groups overage)"]),
        case(
            "every unknown condition is reported, in order",
            json!({
                "kind": "human", "username": "a*", "roles_any": ["x"], "groups_any": ["readers"],
                "scopes_any": ["s"], "tenants": ["t1"], "client_ids": ["cli"],
                "claims": [{"name": "nope", "contains": "x"}],
                "listeners": ["pg"], "source_cidrs": ["10.0.0.0/8"], "subject": "sub-*"
            }),
            U,
        )
        .provider(Missing)
        .identity(everything_unknown)
        .unknown(&[
            "kind (identity kind unknown)",
            "username (absent)",
            "roles (identity provider \"idp\" is not configured)",
            "groups (identity provider \"idp\" is not configured)",
            "scopes (identity provider \"idp\" is not configured)",
            "tenant (absent)",
            "client_id (absent)",
            "claim nope (absent)",
        ]),
    ];

    let base = base_config();
    for c in cases {
        let predicate: Predicate = serde_json::from_value(c.when.clone()).unwrap();
        let mut identity = alice();
        (c.identity)(&mut identity);
        let provider: Option<&IdentityProviderConfig> = match c.provider {
            Provider::Idp => base.identity_provider("idp"),
            Provider::K8s => base.identity_provider("k8s"),
            Provider::Missing => None,
        };
        let result = evaluate_predicate(&predicate, &identity, provider, "pg", c.client_ip);
        assert_eq!(result.truth, c.expect, "case {:?}: {:?}", c.name, result);
        assert_eq!(result.unknown, c.unknown, "case {:?}", c.name);
    }
}

// ---------------------------------------------------------------------------
// Claim conditions
// ---------------------------------------------------------------------------

#[test]
fn claim_truth_table() {
    use Truth::{False as F, True as T, Unknown as U};
    let token = json!({
        "acct": 1,
        "repository_id": "123456789",
        "ratio": 1.5,
        "neg": -5,
        "big": 18_446_744_073_709_551_615_u64,
        "flag": true,
        "env": "prod",
        "groups": ["a", "b"],
        "ids": [1, 2],
        "obj": {"a": 1, "b": [1, "2"]},
        "event_name": "push",
        "realm_access": {"roles": ["admin", "user"]},
        "https://example.com/roles": ["admin"],
        "kubernetes.io": {"namespace": "orders", "serviceaccount": {"name": "api"}},
        "a/b": {"c~d": "escaped"},
        "list": [{"v": "first"}, {"v": "second"}],
        "nothing": null,
    });
    let cases: Vec<(&str, Value, Truth)> = vec![
        // exists: never unknown
        ("exists present", json!({"name": "acct", "exists": true}), T),
        ("exists absent", json!({"name": "nope", "exists": true}), F),
        (
            "not exists absent",
            json!({"name": "nope", "exists": false}),
            T,
        ),
        (
            "not exists present",
            json!({"name": "acct", "exists": false}),
            F,
        ),
        // equals
        ("equals number", json!({"name": "acct", "equals": 1}), T),
        (
            "equals float form",
            json!({"name": "acct", "equals": 1.0}),
            T,
        ),
        (
            "equals other number",
            json!({"name": "acct", "equals": 2}),
            F,
        ),
        (
            "number claim equals string",
            json!({"name": "acct", "equals": "1"}),
            T,
        ),
        (
            "leading zero is not equal",
            json!({"name": "acct", "equals": "01"}),
            F,
        ),
        (
            "string claim equals number",
            json!({"name": "repository_id", "equals": 123_456_789}),
            T,
        ),
        (
            "string claim equals string",
            json!({"name": "repository_id", "equals": "123456789"}),
            T,
        ),
        (
            "string claim, other number",
            json!({"name": "repository_id", "equals": 12_345_678}),
            F,
        ),
        (
            "float claim equals string",
            json!({"name": "ratio", "equals": "1.5"}),
            T,
        ),
        (
            "negative claim equals string",
            json!({"name": "neg", "equals": "-5"}),
            T,
        ),
        (
            "u64::MAX equals string",
            json!({"name": "big", "equals": "18446744073709551615"}),
            T,
        ),
        (
            "bool is not a string",
            json!({"name": "flag", "equals": "true"}),
            F,
        ),
        (
            "bool equals bool",
            json!({"name": "flag", "equals": true}),
            T,
        ),
        ("string equals", json!({"name": "env", "equals": "prod"}), T),
        (
            "string case-sensitive",
            json!({"name": "env", "equals": "PROD"}),
            F,
        ),
        (
            "objects compare recursively",
            json!({"name": "obj", "equals": {"b": ["1", 2], "a": "1"}}),
            T,
        ),
        (
            "arrays are ordered",
            json!({"name": "groups", "equals": ["b", "a"]}),
            F,
        ),
        // contains
        (
            "array contains",
            json!({"name": "groups", "contains": "a"}),
            T,
        ),
        ("array lacks", json!({"name": "groups", "contains": "c"}), F),
        (
            "array contains number as string",
            json!({"name": "ids", "contains": "2"}),
            T,
        ),
        (
            "single-valued string",
            json!({"name": "env", "contains": "prod"}),
            T,
        ),
        (
            "no substring match",
            json!({"name": "env", "contains": "pro"}),
            F,
        ),
        (
            "number claim is not a container",
            json!({"name": "acct", "contains": 1}),
            F,
        ),
        // any_of
        (
            "any_of miss",
            json!({"name": "event_name", "any_of": ["pull_request", "pull_request_target"]}),
            F,
        ),
        (
            "any_of hit",
            json!({"name": "event_name", "any_of": ["x", "push"]}),
            T,
        ),
        (
            "any_of loose equality",
            json!({"name": "acct", "any_of": ["2", "1"]}),
            T,
        ),
        // absent claims make value conditions unknown
        ("absent equals", json!({"name": "nope", "equals": 1}), U),
        (
            "absent contains",
            json!({"name": "nope", "contains": "a"}),
            U,
        ),
        ("absent any_of", json!({"name": "nope", "any_of": ["a"]}), U),
        (
            "not exists and equals on absent claim",
            json!({"name": "nope", "exists": false, "equals": 1}),
            U,
        ),
        (
            "exists and equals on absent claim: false dominates",
            json!({"name": "nope", "exists": true, "equals": 1}),
            F,
        ),
        (
            "exists and equals on present claim",
            json!({"name": "acct", "exists": true, "equals": 1}),
            T,
        ),
        (
            "all sub-conditions must hold",
            json!({"name": "groups", "contains": "a", "any_of": [["a"]]}),
            F,
        ),
        // names: dotted paths, literal names with dots and slashes, JSON Pointers
        (
            "dotted path",
            json!({"name": "realm_access.roles", "contains": "admin"}),
            T,
        ),
        (
            "literal URL name",
            json!({"name": "https://example.com/roles", "contains": "admin"}),
            T,
        ),
        (
            "pointer into dotted name",
            json!({"name": "/kubernetes.io/serviceaccount/name", "equals": "api"}),
            T,
        ),
        (
            "pointer escapes",
            json!({"name": "/a~1b/c~0d", "equals": "escaped"}),
            T,
        ),
        (
            "pointer array index",
            json!({"name": "/list/1/v", "equals": "second"}),
            T,
        ),
        (
            "pointer to missing member",
            json!({"name": "/kubernetes.io/missing", "equals": "x"}),
            U,
        ),
        (
            "pointer to missing member, absence",
            json!({"name": "/kubernetes.io/missing", "exists": false}),
            T,
        ),
        (
            "dotted path does not descend into dotted names",
            json!({"name": "kubernetes.io.namespace", "exists": true}),
            F,
        ),
        // a JSON null claim is absent, as for required_claims
        ("null exists", json!({"name": "nothing", "exists": true}), F),
        (
            "null not exists",
            json!({"name": "nothing", "exists": false}),
            T,
        ),
        ("null equals", json!({"name": "nothing", "equals": "x"}), U),
        (
            "null any_of",
            json!({"name": "nothing", "any_of": ["x"]}),
            U,
        ),
    ];
    let mut identity = alice();
    identity.claims = claims(token);
    for (name, predicate, expected) in cases {
        let predicate: ClaimPredicate = serde_json::from_value(predicate).unwrap();
        assert_eq!(
            claim_truth(&identity, &predicate),
            expected,
            "case {name:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Deny rules
// ---------------------------------------------------------------------------

fn readers_grant() -> Value {
    json!([simple_grant(
        "readers",
        json!({"issuer": "idp"}),
        json!(["*"]),
        "ro"
    )])
}

#[test]
fn deny_rule_fires_on_true() {
    let e = engine(
        readers_grant(),
        json!([{"name": "block-staff", "when": {"groups_any": ["staff"]}}]),
    );
    let id = alice();
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert_eq!(d.deny_rule.as_deref(), Some("block-staff"));
    assert_eq!(d.terminate, Some(DenyTermination::AtSafePoint));
    assert!(!d.due_to_unknown);
    assert_eq!(d.reason, "deny rule \"block-staff\" matched");
}

#[test]
fn deny_rule_fires_on_unknown_by_default() {
    let deny = json!([{
        "name": "block-admins",
        "when": {"issuer": "idp", "groups_any": ["admins"]},
        "terminate": "immediate"
    }]);
    let e = engine(readers_grant(), deny);
    let mut id = alice();
    assert!(e.evaluate(&request(&id, "", "db", "orders")).is_allow());

    id.groups_overage = true;
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert_eq!(d.deny_rule.as_deref(), Some("block-admins"));
    assert_eq!(d.terminate, Some(DenyTermination::Immediate));
    assert!(d.due_to_unknown);
    assert_eq!(
        d.reason,
        "deny rule \"block-admins\" fired on unknown data: groups (groups overage)"
    );
}

#[test]
fn deny_rule_with_on_unknown_ignore_fires_only_on_true() {
    let deny = json!([{
        "name": "block-admins",
        "when": {"issuer": "idp", "groups_any": ["admins"]},
        "on_unknown": "ignore"
    }]);
    let e = engine(readers_grant(), deny);
    let mut id = alice();
    id.groups_overage = true;
    assert!(e.evaluate(&request(&id, "", "db", "orders")).is_allow());

    id.groups_overage = false;
    id.groups.insert("admins".into());
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert_eq!(d.deny_rule.as_deref(), Some("block-admins"));
    assert!(!d.due_to_unknown);
}

#[test]
fn deny_rule_fires_on_unknown_for_unmapped_and_unconfigured_providers() {
    // Deny rules may omit the issuer; for a provider that maps no roles (or
    // is not configured) the condition is unknown, so the rule fires.
    let e = engine(
        json!([simple_grant(
            "api",
            json!({"issuer": "k8s", "subject": "system:serviceaccount:orders:*"}),
            json!(["*"]),
            "rw"
        )]),
        json!([{"name": "no-break-glass", "when": {"roles_any": ["BreakGlass"]}}]),
    );
    let mut id = workload();
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert_eq!(d.deny_rule.as_deref(), Some("no-break-glass"));
    assert!(d.due_to_unknown);
    assert!(
        d.reason
            .contains("roles (identity provider \"k8s\" maps no roles)"),
        "{}",
        d.reason
    );

    id.provider = "ghost".into();
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert!(
        d.reason
            .contains("roles (identity provider \"ghost\" is not configured)"),
        "{}",
        d.reason
    );
}

#[test]
fn deny_rules_take_precedence_and_the_first_in_order_is_named() {
    let deny = json!([
        {"name": "first-false", "when": {"issuer": "k8s"}},
        {"name": "second", "when": {"claims": [{"name": "env", "equals": "prod"}]}},
        {"name": "third", "when": {"issuer": "idp"}, "terminate": "immediate"},
    ]);
    let e = engine(readers_grant(), deny);
    let id = alice();
    let d = denied(e.evaluate(&request(&id, "ro", "db", "orders")));
    assert_eq!(d.deny_rule.as_deref(), Some("second"));
    assert_eq!(d.terminate, Some(DenyTermination::AtSafePoint));
    assert_eq!(
        e.matching_deny_rule(&id, "pg", IP).as_deref(),
        Some("second")
    );
}

#[test]
fn matching_deny_rule_respects_unknown_handling() {
    let deny = json!([
        {"name": "ignore-unknown", "when": {"tenants": ["t9"]}, "on_unknown": "ignore"},
        {"name": "deny-unknown", "when": {"client_ids": ["evil"]}},
    ]);
    let e = engine(readers_grant(), deny);
    let mut id = alice();
    assert_eq!(e.matching_deny_rule(&id, "pg", IP), None);
    id.tenant = None;
    assert_eq!(e.matching_deny_rule(&id, "pg", IP), None);
    id.client_id = None;
    assert_eq!(
        e.matching_deny_rule(&id, "pg", IP).as_deref(),
        Some("deny-unknown")
    );
    id.tenant = Some("t9".into());
    assert_eq!(
        e.matching_deny_rule(&id, "pg", IP).as_deref(),
        Some("ignore-unknown")
    );
}

// ---------------------------------------------------------------------------
// Grants and candidates
// ---------------------------------------------------------------------------

#[test]
fn grants_never_match_on_unknown() {
    let policies = json!([
        simple_grant(
            "by-group",
            json!({"issuer": "idp", "groups_any": ["readers"]}),
            json!(["*"]),
            "ro"
        ),
        simple_grant(
            "by-name",
            json!({"issuer": "idp", "username": "alice@*"}),
            json!(["*"]),
            "ro"
        ),
        simple_grant(
            "by-claim",
            json!({"issuer": "idp", "claims": [{"name": "env", "equals": "prod"}]}),
            json!(["*"]),
            "ro"
        ),
        simple_grant(
            "by-kind",
            json!({"issuer": "idp", "kind": "human"}),
            json!(["*"]),
            "ro"
        ),
        simple_grant(
            "by-tenant",
            json!({"issuer": "idp", "tenants": ["t1"]}),
            json!(["*"]),
            "ro"
        ),
        simple_grant(
            "by-client",
            json!({"issuer": "idp", "client_ids": ["cli"]}),
            json!(["*"]),
            "ro"
        ),
    ]);
    let e = engine(policies, json!([]));
    let req_for = |id: &Identity| e.evaluate(&request(id, "", "db", "orders"));

    let base = alice();
    let a = allowed(req_for(&base));
    assert_eq!(a.matched_grants.len(), 6);

    let mut id = base.clone();
    everything_unknown(&mut id);
    let d = denied(req_for(&id));
    assert!(d.due_to_unknown);
    assert_eq!(d.deny_rule, None);
    assert_eq!(
        d.reason,
        "no grant matches backend \"db\", database \"orders\"; grants skipped because of \
         unknown data: \"by-claim\" (claim env (absent)), \"by-client\" (client_id (absent)), \
         \"by-group\" (groups (groups overage)), \"by-kind\" (kind (identity kind unknown)), \
         \"by-name\" (username (absent)), \"by-tenant\" (tenant (absent))"
    );

    // One unknown condition removes exactly that grant.
    let mut id = base.clone();
    id.groups_overage = true;
    let a = allowed(req_for(&id));
    assert!(!a.matched_grants.contains(&"by-group".to_string()));
    assert_eq!(a.matched_grants.len(), 5);
}

#[test]
fn grants_for_unmapped_or_unconfigured_providers_do_not_match() {
    // Validation rejects a roles condition for a provider that maps no roles;
    // the engine still treats it as unknown.
    let e = engine_unchecked(
        json!([simple_grant(
            "k8s-roles",
            json!({"issuer": "k8s", "roles_any": ["x"]}),
            json!(["*"]),
            "rw"
        )]),
        json!([]),
    );
    let mut id = workload();
    id.roles.insert("x".into());
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert!(d.due_to_unknown);
    assert!(
        d.reason
            .contains("\"k8s-roles\" (roles (identity provider \"k8s\" maps no roles))")
    );

    let e = engine(
        json!([simple_grant(
            "readers",
            json!({"issuer": "idp", "groups_any": ["readers"]}),
            json!(["*"]),
            "ro"
        )]),
        json!([]),
    );
    let mut id = alice();
    id.provider = "ghost".into();
    id.issuer = "https://ghost.example.com".into();
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    // The issuer condition is false, so the grant is not even unknown.
    assert!(!d.due_to_unknown);
    assert_eq!(
        d.reason,
        "no grant matches backend \"db\", database \"orders\""
    );
}

#[test]
fn unknown_grants_that_do_not_cover_the_request_are_not_reported() {
    let e = engine(
        json!([simple_grant(
            "reports",
            json!({"issuer": "idp", "groups_any": ["readers"]}),
            json!(["reports"]),
            "ro"
        ),]),
        json!([]),
    );
    let mut id = alice();
    id.groups_overage = true;
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert!(!d.due_to_unknown);
    assert_eq!(
        d.reason,
        "no grant matches backend \"db\", database \"orders\""
    );
}

#[test]
fn candidates_are_filtered_by_backend_and_database() {
    let policies = json!([
        {"name": "db-orders", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["ro"]}},
        {"name": "db-any", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["rw"]}},
        {"name": "other-any", "when": {"issuer": "idp"},
         "grant": {"backend": "other", "databases": ["*"], "pg_roles": ["owner"]}},
    ]);
    let e = engine(policies, json!([]));
    let id = alice();
    let role = |user: &str, backend: &str, database: &str| match e
        .evaluate(&request(&id, user, backend, database))
    {
        Decision::Allow(a) => Ok((a.pg_role, a.matched_grants)),
        Decision::Deny(d) => Err(d.reason),
    };

    assert_eq!(
        role("ro", "db", "orders"),
        Ok(("ro".into(), vec!["db-orders".into()]))
    );
    assert_eq!(
        role("rw", "db", "orders"),
        Ok(("rw".into(), vec!["db-any".into()]))
    );
    // `*` covers any database, `orders` only itself.
    assert_eq!(
        role("rw", "db", "reports"),
        Ok(("rw".into(), vec!["db-any".into()]))
    );
    assert!(role("ro", "db", "reports").is_err());
    // Roles from other backends never apply.
    let err = role("owner", "db", "orders").unwrap_err();
    assert_eq!(
        err,
        "requested user \"owner\" is not an entitled role for backend \"db\", database \"orders\" \
         (entitled roles: \"ro\", \"rw\"), nor the identity's username or subject, nor \"*\""
    );
    assert_eq!(
        role("owner", "other", "orders"),
        Ok(("owner".into(), vec!["other-any".into()]))
    );
    assert!(role("ro", "other", "orders").is_err());
    // A database literally named `*` is only covered by `*`.
    assert!(role("rw", "db", "*").is_ok());
    assert!(role("ro", "db", "*").is_err());
    // Unknown backend.
    assert_eq!(
        role("ro", "nope", "orders"),
        Err("no grant matches backend \"nope\", database \"orders\"".into())
    );
}

#[test]
fn entitlements_from_one_grant_never_combine_with_another_target() {
    // Grant A gives (orders, ro); grant B gives (reports, owner). The
    // identity must not get (orders, owner).
    let policies = json!([
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["ro"]}},
        {"name": "b", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["reports"], "pg_roles": ["owner"]}},
    ]);
    let e = engine(policies, json!([]));
    let id = alice();
    assert!(
        !e.evaluate(&request(&id, "owner", "db", "orders"))
            .is_allow()
    );
    assert!(!e.evaluate(&request(&id, "ro", "db", "reports")).is_allow());
    let a = allowed(e.evaluate(&request(&id, "ro", "db", "orders")));
    assert_eq!(a.matched_grants, ["a"]);
    let a = allowed(e.evaluate(&request(&id, "owner", "db", "reports")));
    assert_eq!(a.matched_grants, ["b"]);
    // The default role is computed per target as well.
    assert_eq!(
        allowed(e.evaluate(&request(&id, "", "db", "orders"))).pg_role,
        "ro"
    );
    assert_eq!(
        allowed(e.evaluate(&request(&id, "", "db", "reports"))).pg_role,
        "owner"
    );

    // Same across backends.
    let policies = json!([
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["ro"]}},
        {"name": "b", "when": {"issuer": "idp"},
         "grant": {"backend": "other", "databases": ["orders"], "pg_roles": ["owner"]}},
    ]);
    let e = engine(policies, json!([]));
    assert!(
        !e.evaluate(&request(&id, "owner", "db", "orders"))
            .is_allow()
    );
    assert!(
        !e.evaluate(&request(&id, "ro", "other", "orders"))
            .is_allow()
    );
}

// ---------------------------------------------------------------------------
// Role selection
// ---------------------------------------------------------------------------

fn two_role_grant() -> Value {
    json!([{
        "name": "app",
        "when": {"issuer": "idp"},
        "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro", "rw"], "default_pg_role": "ro"}
    }])
}

fn selected(e: &PolicyEngine, id: &Identity, user: &str) -> Result<String, String> {
    match e.evaluate(&request(id, user, "db", "orders")) {
        Decision::Allow(a) => Ok(a.pg_role),
        Decision::Deny(d) => Err(d.reason),
    }
}

#[test]
fn user_semantics_auto() {
    let e = engine_with(two_role_grant(), json!([]), UserSemantics::Auto);
    assert_eq!(e.user_semantics(), UserSemantics::Auto);
    let mut id = alice();
    assert_eq!(selected(&e, &id, "rw").as_deref(), Ok("rw"));
    assert_eq!(selected(&e, &id, "ro").as_deref(), Ok("ro"));
    assert_eq!(selected(&e, &id, "alice@example.com").as_deref(), Ok("ro"));
    assert_eq!(selected(&e, &id, "sub-alice").as_deref(), Ok("ro"));
    assert_eq!(selected(&e, &id, "*").as_deref(), Ok("ro"));
    assert_eq!(selected(&e, &id, "").as_deref(), Ok("ro"));
    let err = selected(&e, &id, "postgres").unwrap_err();
    assert!(
        err.starts_with("requested user \"postgres\" is not an entitled role"),
        "{err}"
    );
    assert!(err.contains("(entitled roles: \"ro\", \"rw\")"), "{err}");
    // Role names are case-sensitive.
    assert!(selected(&e, &id, "RW").is_err());

    // Without a username, an empty user still selects the default role.
    id.username = None;
    assert_eq!(selected(&e, &id, "").as_deref(), Ok("ro"));
    assert!(selected(&e, &id, "alice@example.com").is_err());

    // An entitled role name wins over the identity's own name.
    id.username = Some("rw".into());
    assert_eq!(selected(&e, &id, "rw").as_deref(), Ok("rw"));
    assert_eq!(selected(&e, &id, "").as_deref(), Ok("rw"));
}

#[test]
fn user_semantics_role() {
    let e = engine_with(two_role_grant(), json!([]), UserSemantics::Role);
    assert_eq!(e.user_semantics(), UserSemantics::Role);
    let id = alice();
    assert_eq!(selected(&e, &id, "rw").as_deref(), Ok("rw"));
    assert_eq!(selected(&e, &id, "ro").as_deref(), Ok("ro"));
    for user in ["alice@example.com", "sub-alice", "*", "", "postgres"] {
        let err = selected(&e, &id, user).unwrap_err();
        assert!(
            err.ends_with("; user_semantics: role requires a role name"),
            "{user:?}: {err}"
        );
    }
    assert!(selected(&e, &id, "").unwrap_err().starts_with(
        "requested user \"\" (taken as the identity's username \"alice@example.com\") \
             is not an entitled role"
    ));
}

#[test]
fn user_semantics_identity() {
    let e = engine_with(two_role_grant(), json!([]), UserSemantics::Identity);
    assert_eq!(e.user_semantics(), UserSemantics::Identity);
    let id = alice();
    for user in ["rw", "ro", "alice@example.com", "", "*", "postgres"] {
        assert_eq!(selected(&e, &id, user).as_deref(), Ok("ro"), "{user:?}");
    }
}

#[test]
fn default_role_single() {
    // One grant sets a default; another adds a role without one.
    let policies = json!([
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "default_pg_role": "ro"}},
        {"name": "b", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["rw"]}},
        {"name": "c", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["ro", "owner"], "default_pg_role": "ro"}},
    ]);
    let e = engine(policies, json!([]));
    let a = allowed(e.evaluate(&request(&alice(), "", "db", "orders")));
    assert_eq!(a.pg_role, "ro");
    assert_eq!(a.matched_grants, ["a", "c"]);
}

#[test]
fn default_role_conflict_is_a_deny() {
    let policies = json!([
        simple_grant("readers", json!({"issuer": "idp"}), json!(["*"]), "ro"),
        simple_grant(
            "writers",
            json!({"issuer": "idp", "groups_any": ["staff"]}),
            json!(["orders"]),
            "rw"
        ),
    ]);
    for semantics in [UserSemantics::Auto, UserSemantics::Identity] {
        let e = engine_with(policies.clone(), json!([]), semantics);
        let d = denied(e.evaluate(&request(&alice(), "", "db", "orders")));
        assert_eq!(
            d.reason,
            "conflicting default roles \"ro\" (grants \"readers\"), \"rw\" (grants \"writers\"); \
             name a role as the user"
        );
        assert!(!d.due_to_unknown);
    }
    let e = engine(policies, json!([]));
    let id = alice();
    // Naming a role resolves the conflict.
    assert_eq!(selected(&e, &id, "rw").as_deref(), Ok("rw"));
    assert_eq!(selected(&e, &id, "ro").as_deref(), Ok("ro"));
    // Where only one grant applies, there is no conflict.
    assert_eq!(
        allowed(e.evaluate(&request(&id, "", "db", "reports"))).pg_role,
        "ro"
    );
}

#[test]
fn default_role_from_a_single_role_without_defaults() {
    let policies = json!([
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"]}},
        {"name": "b", "when": {"issuer": "idp", "groups_any": ["staff"]},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"]}},
    ]);
    let e = engine(policies, json!([]));
    let a = allowed(e.evaluate(&request(&alice(), "", "db", "orders")));
    assert_eq!(a.pg_role, "ro");
    assert_eq!(a.matched_grants, ["a", "b"]);
}

#[test]
fn default_role_ambiguous_is_a_deny() {
    let policies = json!([
        {"name": "b", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["rw"]}},
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"]}},
    ]);
    let e = engine(policies, json!([]));
    let id = alice();
    let d = denied(e.evaluate(&request(&id, "", "db", "orders")));
    assert_eq!(
        d.reason,
        "ambiguous default role: matching grants \"a\", \"b\" entitle roles \"ro\", \"rw\" and \
         none sets default_pg_role; name a role as the user"
    );
    assert_eq!(selected(&e, &id, "rw").as_deref(), Ok("rw"));
}

#[test]
fn default_role_outside_pg_roles_is_denied_without_panicking() {
    // Validation rejects this; the engine must still not panic.
    let e = engine_unchecked(
        json!([{"name": "broken", "when": {"issuer": "idp"},
                "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "default_pg_role": "rw"}}]),
        json!([]),
    );
    let d = denied(e.evaluate(&request(&alice(), "", "db", "orders")));
    assert_eq!(
        d.reason,
        "default role \"rw\" is not in the pg_roles of any matching grant (\"broken\")"
    );
    assert_eq!(selected(&e, &alice(), "ro").as_deref(), Ok("ro"));
}

#[test]
fn reasons_mention_unknown_grants_for_role_denials_too() {
    let policies = json!([
        simple_grant("readers", json!({"issuer": "idp"}), json!(["*"]), "ro"),
        simple_grant(
            "admins",
            json!({"issuer": "idp", "groups_any": ["admins"]}),
            json!(["*"]),
            "owner"
        ),
    ]);
    let e = engine(policies, json!([]));
    let mut id = alice();
    id.groups_overage = true;
    let d = denied(e.evaluate(&request(&id, "owner", "db", "orders")));
    assert!(d.due_to_unknown);
    assert!(
        d.reason.ends_with(
            "; grants skipped because of unknown data: \"admins\" (groups (groups overage))"
        ),
        "{}",
        d.reason
    );
    // The role from the known grant is still available.
    assert_eq!(selected(&e, &id, "").as_deref(), Ok("ro"));
}

// ---------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------

#[test]
fn settings_merge_independently_of_order() {
    let a = json!({"name": "a", "when": {"issuer": "idp"},
        "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "default_pg_role": "ro",
                  "max_sessions_per_identity_per_replica": 5, "session_max_lifetime": "30m",
                  "on_token_expiry": "terminate_when_idle", "pool_mode": "transaction",
                  "acknowledged_role_risks": ["read_all"]}});
    let b = json!({"name": "b", "when": {"issuer": "idp", "groups_any": ["staff"]},
        "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["ro", "rw"],
                  "max_sessions_per_identity_per_replica": 2, "session_max_lifetime": "10m",
                  "on_token_expiry": "terminate", "pool_mode": "session",
                  "acknowledged_role_risks": ["read_all"]}});
    let c = json!({"name": "c", "when": {"issuer": "idp"},
        "grant": {"backend": "db", "databases": ["orders"], "pg_roles": ["ro"],
                  "acknowledged_role_risks": ["read_all"]}});
    // Contributes nothing: a different role.
    let d = json!({"name": "d", "when": {"issuer": "idp"},
        "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["owner"],
                  "max_sessions_per_identity_per_replica": 1, "session_max_lifetime": "1m"}});
    let orders = [
        json!([a.clone(), b.clone(), c.clone(), d.clone()]),
        json!([d.clone(), c.clone(), b.clone(), a.clone()]),
        json!([b, d, a, c]),
    ];
    for policies in orders {
        let e = engine(policies, json!([]));
        let mut got = allowed(e.evaluate(&request(&alice(), "ro", "db", "orders")));
        got.matched_grants.sort();
        assert_eq!(
            got,
            Allowed {
                backend: "db".into(),
                database: "orders".into(),
                pg_role: "ro".into(),
                matched_grants: vec!["a".into(), "b".into(), "c".into()],
                pool_mode: Some(PoolMode::Session),
                pool_mode_conflict: true,
                session_limits: vec![
                    SessionLimit {
                        grant: "a".into(),
                        max_sessions_per_replica: 5
                    },
                    SessionLimit {
                        grant: "b".into(),
                        max_sessions_per_replica: 2
                    },
                ],
                session_max_lifetime: Some(Duration::from_secs(600)),
                on_token_expiry: Some(TokenExpiryAction::Terminate),
                acknowledged_role_risks: [RoleRisk::ReadAll].into_iter().collect(),
            }
        );
    }
}

#[test]
fn matched_grants_in_configuration_order_limits_by_name() {
    let policies = json!([
        {"name": "z", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "max_sessions_per_identity_per_replica": 3}},
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "max_sessions_per_identity_per_replica": 4}},
    ]);
    let a = allowed(engine(policies, json!([])).evaluate(&request(&alice(), "", "db", "x")));
    assert_eq!(a.matched_grants, ["z", "a"]);
    assert_eq!(a.session_limits[0].grant, "a");
    assert_eq!(a.session_limits[0].max_sessions_per_replica, 4);
    assert_eq!(a.session_limits[1].grant, "z");
    assert_eq!(a.session_limits[1].max_sessions_per_replica, 3);
}

#[test]
fn pool_mode_merge() {
    let grant = |name: &str, mode: Value| {
        json!({"name": name, "when": {"issuer": "idp"},
               "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "pool_mode": mode}})
    };
    let cases = [
        (json!([grant("a", Value::Null)]), None, false),
        (
            json!([grant("a", json!("transaction")), grant("b", Value::Null)]),
            Some(PoolMode::Transaction),
            false,
        ),
        (
            json!([grant("a", json!("session")), grant("b", Value::Null)]),
            Some(PoolMode::Session),
            false,
        ),
        (
            json!([
                grant("a", json!("transaction")),
                grant("b", json!("session"))
            ]),
            Some(PoolMode::Session),
            true,
        ),
        (
            json!([
                grant("a", json!("transaction")),
                grant("b", json!("transaction"))
            ]),
            Some(PoolMode::Transaction),
            false,
        ),
    ];
    for (policies, mode, conflict) in cases {
        let a = allowed(engine(policies.clone(), json!([])).evaluate(&request(
            &alice(),
            "",
            "db",
            "x",
        )));
        assert_eq!(
            (a.pool_mode, a.pool_mode_conflict),
            (mode, conflict),
            "{policies}"
        );
    }
}

#[test]
fn unset_settings_merge_to_none() {
    let a = allowed(engine(readers_grant(), json!([])).evaluate(&request(&alice(), "", "db", "x")));
    assert_eq!(a.pool_mode, None);
    assert!(!a.pool_mode_conflict);
    assert!(a.session_limits.is_empty());
    assert_eq!(a.session_max_lifetime, None);
    assert_eq!(a.on_token_expiry, None);
    assert!(a.acknowledged_role_risks.is_empty());
}

#[test]
fn token_expiry_terminate_when_idle_only() {
    let policies = json!([
        {"name": "a", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"], "on_token_expiry": "terminate_when_idle"}},
        {"name": "b", "when": {"issuer": "idp"},
         "grant": {"backend": "db", "databases": ["*"], "pg_roles": ["ro"]}},
    ]);
    let a = allowed(engine(policies, json!([])).evaluate(&request(&alice(), "", "db", "x")));
    assert_eq!(
        a.on_token_expiry,
        Some(TokenExpiryAction::TerminateWhenIdle)
    );
}

#[test]
fn role_risks_are_intersected_including_the_deprecated_flag() {
    let grant = |name: &str, extra: Value| {
        let mut g = json!({"backend": "db", "databases": ["*"], "pg_roles": ["owner"]});
        for (k, v) in extra.as_object().unwrap() {
            g[k.as_str()] = v.clone();
        }
        json!({"name": name, "when": {"issuer": "idp"}, "grant": g})
    };
    let all: BTreeSet<RoleRisk> = RoleRisk::ALL.into_iter().collect();
    let all_names: Vec<&str> = RoleRisk::ALL.iter().map(|r| r.as_str()).collect();

    // Validated: the deprecated flag equals acknowledging every risk.
    let e = engine(
        json!([
            grant("a", json!({"allow_privileged_role": true})),
            grant("b", json!({"acknowledged_role_risks": all_names})),
        ]),
        json!([]),
    );
    let a = allowed(e.evaluate(&request(&alice(), "owner", "db", "x")));
    assert_eq!(a.acknowledged_role_risks, all);

    // Unvalidated: differing sets intersect.
    let e = engine_unchecked(
        json!([
            grant("a", json!({"allow_privileged_role": true})),
            grant(
                "b",
                json!({"acknowledged_role_risks": ["database_owner", "createdb"]})
            ),
            grant(
                "c",
                json!({"acknowledged_role_risks": ["database_owner", "superuser"]})
            ),
        ]),
        json!([]),
    );
    let a = allowed(e.evaluate(&request(&alice(), "owner", "db", "x")));
    assert_eq!(
        a.acknowledged_role_risks,
        [RoleRisk::DatabaseOwner].into_iter().collect()
    );

    // A grant that acknowledges nothing empties the intersection.
    let e = engine_unchecked(
        json!([
            grant("a", json!({"allow_privileged_role": true})),
            grant("b", json!({})),
        ]),
        json!([]),
    );
    let a = allowed(e.evaluate(&request(&alice(), "owner", "db", "x")));
    assert!(a.acknowledged_role_risks.is_empty());
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

#[test]
fn explain_traces_every_rule() {
    let policies = json!([
        simple_grant("readers", json!({"issuer": "idp"}), json!(["orders"]), "ro"),
        simple_grant(
            "reporting",
            json!({"issuer": "idp"}),
            json!(["reports"]),
            "ro"
        ),
        simple_grant(
            "admins",
            json!({"issuer": "idp", "groups_any": ["admins"]}),
            json!(["*"]),
            "owner"
        ),
        simple_grant("api", json!({"issuer": "k8s"}), json!(["*"]), "rw"),
    ]);
    let deny = json!([
        {"name": "no-workloads", "when": {"kind": "workload"}},
        {"name": "no-guests", "when": {"claims": [{"name": "acct", "equals": 1}]}},
        {"name": "never", "when": {"listeners": ["internal"]}},
    ]);
    let e = engine(policies, deny);
    let mut id = alice();
    id.groups_overage = true;
    let req = request(&id, "", "db", "orders");
    let x = e.explain(&req);
    assert_eq!(x.decision, e.evaluate(&req));
    assert_eq!(allowed(x.decision.clone()).matched_grants, ["readers"]);

    let deny_traces: Vec<_> = x
        .deny_rules
        .iter()
        .map(|t| (t.name.as_str(), t.predicate.truth, t.target_matches))
        .collect();
    assert_eq!(
        deny_traces,
        [
            ("no-workloads", Truth::False, None),
            ("no-guests", Truth::False, None),
            ("never", Truth::False, None),
        ]
    );
    let grant_traces: Vec<_> = x
        .grants
        .iter()
        .map(|t| (t.name.as_str(), t.predicate.truth, t.target_matches))
        .collect();
    assert_eq!(
        grant_traces,
        [
            ("readers", Truth::True, Some(true)),
            ("reporting", Truth::True, Some(false)),
            ("admins", Truth::Unknown, Some(true)),
            ("api", Truth::False, Some(true)),
        ]
    );
    assert_eq!(x.grants[2].predicate.unknown, ["groups (groups overage)"]);

    // When a deny rule fires, every rule is still traced.
    id.claims.remove("acct");
    let req = request(&id, "", "db", "orders");
    let x = e.explain(&req);
    assert_eq!(x.decision, e.evaluate(&req));
    let d = denied(x.decision.clone());
    assert_eq!(d.deny_rule.as_deref(), Some("no-guests"));
    assert!(d.due_to_unknown);
    assert_eq!(x.deny_rules.len(), 3);
    assert_eq!(x.deny_rules[1].predicate.truth, Truth::Unknown);
    assert_eq!(x.deny_rules[1].predicate.unknown, ["claim acct (absent)"]);
    assert_eq!(x.grants.len(), 4);
}

#[test]
fn entitlements_list_true_grants_regardless_of_target() {
    let policies = json!([
        {"name": "readers", "when": {"issuer": "idp", "listeners": ["pg"]},
         "grant": {"backend": "db", "databases": ["orders", "reports"], "pg_roles": ["ro", "rw"], "default_pg_role": "ro"}},
        simple_grant("admins", json!({"issuer": "idp", "groups_any": ["admins"]}), json!(["*"]), "owner"),
        {"name": "elsewhere", "when": {"issuer": "idp", "source_cidrs": ["10.0.0.0/8"]},
         "grant": {"backend": "other", "databases": ["*"], "pg_roles": ["owner"]}},
        simple_grant("api", json!({"issuer": "k8s"}), json!(["*"]), "rw"),
    ]);
    let e = engine(policies, json!([]));
    let mut id = alice();
    id.groups_overage = true;
    let got = e.entitlements(&id, "pg", IP);
    assert_eq!(
        got,
        [
            Entitlement {
                grant: "readers".into(),
                backend: "db".into(),
                databases: vec!["orders".into(), "reports".into()],
                pg_roles: vec!["ro".into(), "rw".into()],
                default_pg_role: Some("ro".into()),
            },
            Entitlement {
                grant: "elsewhere".into(),
                backend: "other".into(),
                databases: vec!["*".into()],
                pg_roles: vec!["owner".into()],
                default_pg_role: None,
            },
        ]
    );
    let names: Vec<String> = e
        .entitlements(&id, "internal", "192.168.1.1".parse().unwrap())
        .into_iter()
        .map(|e| e.grant)
        .collect();
    assert!(names.is_empty(), "{names:?}");
}

#[test]
fn empty_policy_denies() {
    let e = engine(json!([]), json!([]));
    let d = denied(e.evaluate(&request(&alice(), "", "db", "orders")));
    assert_eq!(
        d.reason,
        "no grant matches backend \"db\", database \"orders\""
    );
    assert!(!d.due_to_unknown);
    assert_eq!(d.terminate, None);
    assert!(e.entitlements(&alice(), "pg", IP).is_empty());
    assert_eq!(e.matching_deny_rule(&alice(), "pg", IP), None);
}

// ---------------------------------------------------------------------------
// The shipped example
// ---------------------------------------------------------------------------

fn example_identity(provider: &str, subject: &str, token: Value) -> Identity {
    Identity {
        provider: provider.into(),
        issuer: String::new(),
        subject: subject.into(),
        username: None,
        tenant: None,
        groups: BTreeSet::new(),
        roles: BTreeSet::new(),
        scopes: BTreeSet::new(),
        client_id: None,
        kind: IdentityKind::Workload,
        expires_at: SystemTime::UNIX_EPOCH,
        token_id: None,
        groups_overage: false,
        claims: claims(token),
    }
}

#[test]
fn example_configuration_decisions() {
    let config = Config::from_yaml_str(EXAMPLE).unwrap();
    let e = PolicyEngine::from_config(&config);
    let orders = |id: &Identity| e.evaluate(&request(id, "", "orders", "orders"));

    // Entra analyst.
    let mut analyst = example_identity("entra", "oid-1", json!({"acct": 0}));
    analyst.kind = IdentityKind::Human;
    analyst.username = Some("ann@example.com".into());
    analyst.roles = set(["Orders.Analyst"]);
    let a = allowed(orders(&analyst));
    assert_eq!(a.pg_role, "orders_readonly");
    assert_eq!(
        a.session_limits,
        [SessionLimit {
            grant: "orders-analysts".into(),
            max_sessions_per_replica: 5
        }]
    );
    // Guests are denied; a token without "acct" is denied on unknown data.
    analyst.claims = claims(json!({"acct": 1}));
    assert_eq!(
        denied(orders(&analyst)).deny_rule.as_deref(),
        Some("no-guests")
    );
    analyst.claims.clear();
    let d = denied(orders(&analyst));
    assert_eq!(d.deny_rule.as_deref(), Some("no-guests"));
    assert!(d.due_to_unknown);

    // GitHub Actions migrations: repository_id may be written as a number.
    let token = json!({
        "repository_id": "123456789",
        "ref": "refs/heads/main",
        "job_workflow_ref": "acme/orders/.github/workflows/migrate.yml@refs/heads/main",
        "event_name": "push",
    });
    let mut ci = example_identity("github", "repo:acme/orders:environment:production", token);
    let a = allowed(orders(&ci));
    assert_eq!(a.pg_role, "orders_owner");
    assert_eq!(a.session_max_lifetime, Some(Duration::from_secs(1800)));
    ci.claims.insert("repository_id".into(), json!(123_456_789));
    assert!(orders(&ci).is_allow());
    ci.claims.insert("event_name".into(), json!("pull_request"));
    assert_eq!(
        denied(orders(&ci)).deny_rule.as_deref(),
        Some("no-pull-request-workflows")
    );
    ci.claims.insert("event_name".into(), json!("push"));
    ci.claims.remove("job_workflow_ref");
    let d = denied(orders(&ci));
    assert!(d.due_to_unknown);
    assert!(
        d.reason
            .contains("\"orders-migrations\" (claim job_workflow_ref (absent))")
    );

    // Kubernetes workload.
    let api = example_identity("k8s", "system:serviceaccount:orders:orders-api", json!({}));
    assert_eq!(allowed(orders(&api)).pg_role, "orders_app");
    let other = example_identity("k8s", "system:serviceaccount:orders:other", json!({}));
    assert!(!orders(&other).is_allow());
}
