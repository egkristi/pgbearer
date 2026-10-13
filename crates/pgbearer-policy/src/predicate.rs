//! Three-valued evaluation of `when` predicates and claim conditions.
//!
//! A configured [`Predicate`] is compiled once into a [`CompiledPredicate`]
//! (patterns split into exact names and prefixes, networks normalised).
//! Evaluation compares strings and walks small sets; it allocates only to
//! describe conditions that are `Unknown`, and it never panics.

use std::fmt::{self, Write as _};
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};
use pgbearer_config::{ClaimPredicate, IdentityKind, IdentityProviderConfig, Predicate};
use pgbearer_core::Identity;
use serde_json::{Number, Value};

use crate::{PredicateResult, Truth};

/// Depth beyond which two JSON values are never considered equal. Token
/// claims are parsed by `serde_json`, whose recursion limit (128) keeps real
/// values below this; the guard only bounds the stack for unusual inputs.
const MAX_JSON_DEPTH: usize = 128;

/// What an identity provider maps: the attributes whose absence makes
/// `roles_*`, `groups_*` and `scopes_any` conditions `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderInfo {
    name: String,
    maps_groups: bool,
    maps_roles: bool,
    maps_scopes: bool,
}

impl ProviderInfo {
    /// Derive from a provider's effective claim mapping.
    pub(crate) fn from_config(provider: &IdentityProviderConfig) -> ProviderInfo {
        let claims = provider.effective_claims();
        ProviderInfo {
            name: provider.name.clone(),
            maps_groups: claims.groups.is_some(),
            maps_roles: claims.roles.is_some(),
            maps_scopes: claims.scopes.is_some(),
        }
    }

    fn maps(&self, attribute: Attribute) -> bool {
        match attribute {
            Attribute::Groups => self.maps_groups,
            Attribute::Roles => self.maps_roles,
            Attribute::Scopes => self.maps_scopes,
        }
    }
}

/// A provider-dependent identity attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attribute {
    Groups,
    Roles,
    Scopes,
}

impl Attribute {
    fn name(self) -> &'static str {
        match self {
            Attribute::Groups => "groups",
            Attribute::Roles => "roles",
            Attribute::Scopes => "scopes",
        }
    }
}

/// Everything a predicate is evaluated against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EvalCtx<'a> {
    identity: &'a Identity,
    /// The identity's provider, or `None` if it is not configured.
    provider: Option<&'a ProviderInfo>,
    listener: &'a str,
    client_ip: IpAddr,
}

impl<'a> EvalCtx<'a> {
    pub(crate) fn new(
        identity: &'a Identity,
        provider: Option<&'a ProviderInfo>,
        listener: &'a str,
        client_ip: IpAddr,
    ) -> EvalCtx<'a> {
        EvalCtx {
            identity,
            provider,
            listener,
            client_ip,
        }
    }

    /// Why a condition on `attribute` cannot be decided, if it cannot.
    fn attribute_gap(&self, attribute: Attribute) -> Option<String> {
        let what = attribute.name();
        match self.provider {
            None => Some(format!(
                "{what} (identity provider {:?} is not configured)",
                self.identity.provider
            )),
            Some(p) if !p.maps(attribute) => Some(format!(
                "{what} (identity provider {:?} maps no {what})",
                p.name
            )),
            Some(_) if attribute == Attribute::Groups && self.identity.groups_overage => {
                Some("groups (groups overage)".to_owned())
            }
            Some(_) => None,
        }
    }
}

/// A subject or username pattern: exact, or a prefix when the configured
/// pattern ends with `*` (only a trailing `*` is special; `*` alone matches
/// anything).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    Exact(String),
    Prefix(String),
}

impl Pattern {
    fn new(pattern: &str) -> Pattern {
        match pattern.strip_suffix('*') {
            Some(prefix) => Pattern::Prefix(prefix.to_owned()),
            None => Pattern::Exact(pattern.to_owned()),
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Pattern::Exact(exact) => exact == value,
            Pattern::Prefix(prefix) => value.starts_with(prefix.as_str()),
        }
    }
}

/// A `source_cidrs` entry. A client address matches when the network as
/// written contains it, or when both are compared in canonical form
/// (IPv4-mapped IPv6 `::ffff:a.b.c.d` as IPv4), so `10.0.0.0/8` also covers
/// a client seen as `::ffff:10.1.2.3` on a dual-stack socket.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Network {
    as_written: IpNet,
    canonical: IpNet,
}

impl Network {
    fn new(net: IpNet) -> Network {
        Network {
            as_written: net,
            canonical: canonical_net(net),
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.as_written.contains(&ip) || self.canonical.contains(&ip.to_canonical())
    }
}

/// Express a network inside `::ffff:0:0/96` as the IPv4 network it maps.
fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.network().to_ipv4_mapped()
        && let Ok(v4net) = Ipv4Net::new(v4, v6.prefix_len() - 96)
    {
        return IpNet::V4(v4net);
    }
    net
}

/// A predicate compiled for evaluation. Unset options are `None` and empty
/// lists are empty; neither is a condition.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompiledPredicate {
    issuer: Option<String>,
    kind: Option<IdentityKind>,
    subject: Option<Pattern>,
    subjects: Vec<Pattern>,
    username: Option<Pattern>,
    roles_any: Vec<String>,
    roles_all: Vec<String>,
    groups_any: Vec<String>,
    groups_all: Vec<String>,
    scopes_any: Vec<String>,
    tenants: Vec<String>,
    client_ids: Vec<String>,
    claims: Vec<ClaimPredicate>,
    source_cidrs: Vec<Network>,
    listeners: Vec<String>,
}

impl CompiledPredicate {
    pub(crate) fn compile(p: &Predicate) -> CompiledPredicate {
        CompiledPredicate {
            issuer: p.issuer.clone(),
            kind: p.kind,
            subject: p.subject.as_deref().map(Pattern::new),
            subjects: p.subjects.iter().map(|s| Pattern::new(s)).collect(),
            username: p.username.as_deref().map(Pattern::new),
            roles_any: p.roles_any.clone(),
            roles_all: p.roles_all.clone(),
            groups_any: p.groups_any.clone(),
            groups_all: p.groups_all.clone(),
            scopes_any: p.scopes_any.clone(),
            tenants: p.tenants.clone(),
            client_ids: p.client_ids.clone(),
            claims: p.claims.clone(),
            source_cidrs: p.source_cidrs.iter().copied().map(Network::new).collect(),
            listeners: p.listeners.clone(),
        }
    }

    /// Evaluate every set condition (no short-circuit, so that every
    /// `Unknown` condition is reported even when another one is `False`).
    pub(crate) fn eval(&self, ctx: &EvalCtx<'_>) -> PredicateResult {
        let id = ctx.identity;
        let mut acc = Accumulator::default();

        if let Some(issuer) = &self.issuer {
            acc.check(id.provider == *issuer);
        }
        if let Some(kind) = self.kind {
            if kind != IdentityKind::Unknown && id.kind == IdentityKind::Unknown {
                acc.unknown("kind (identity kind unknown)".to_owned());
            } else {
                acc.check(kind == id.kind);
            }
        }
        if let Some(pattern) = &self.subject {
            acc.check(pattern.matches(&id.subject));
        }
        if !self.subjects.is_empty() {
            acc.check(self.subjects.iter().any(|p| p.matches(&id.subject)));
        }
        if let Some(pattern) = &self.username {
            match id.username.as_deref() {
                None => acc.unknown("username (absent)".to_owned()),
                Some(username) => acc.check(pattern.matches(username)),
            }
        }

        let set_conditions = [
            (
                Attribute::Roles,
                &self.roles_any,
                &id.roles,
                Quantifier::Any,
            ),
            (
                Attribute::Roles,
                &self.roles_all,
                &id.roles,
                Quantifier::All,
            ),
            (
                Attribute::Groups,
                &self.groups_any,
                &id.groups,
                Quantifier::Any,
            ),
            (
                Attribute::Groups,
                &self.groups_all,
                &id.groups,
                Quantifier::All,
            ),
            (
                Attribute::Scopes,
                &self.scopes_any,
                &id.scopes,
                Quantifier::Any,
            ),
        ];
        for (attribute, wanted, have, quantifier) in set_conditions {
            if wanted.is_empty() {
                continue;
            }
            match ctx.attribute_gap(attribute) {
                Some(why) => acc.unknown(why),
                None => acc.check(match quantifier {
                    Quantifier::Any => wanted.iter().any(|w| have.contains(w)),
                    Quantifier::All => wanted.iter().all(|w| have.contains(w)),
                }),
            }
        }

        membership(&mut acc, &self.tenants, id.tenant.as_deref(), "tenant");
        membership(
            &mut acc,
            &self.client_ids,
            id.client_id.as_deref(),
            "client_id",
        );

        for claim in &self.claims {
            match claim_truth(id, claim) {
                Truth::Unknown => acc.unknown(format!("claim {} (absent)", claim.name)),
                truth => acc.add(truth),
            }
        }

        if !self.source_cidrs.is_empty() {
            acc.check(self.source_cidrs.iter().any(|n| n.contains(ctx.client_ip)));
        }
        if !self.listeners.is_empty() {
            acc.check(self.listeners.iter().any(|l| l == ctx.listener));
        }

        acc.finish()
    }
}

#[derive(Debug, Clone, Copy)]
enum Quantifier {
    Any,
    All,
}

/// `tenants` / `client_ids`: `Unknown` when the identity has no value.
fn membership(acc: &mut Accumulator, allowed: &[String], value: Option<&str>, what: &str) {
    if allowed.is_empty() {
        return;
    }
    match value {
        None => acc.unknown(format!("{what} (absent)")),
        Some(v) => acc.check(allowed.iter().any(|a| a == v)),
    }
}

/// Three-valued conjunction plus the descriptions of `Unknown` conditions.
#[derive(Debug)]
struct Accumulator {
    truth: Truth,
    unknown: Vec<String>,
}

impl Default for Accumulator {
    fn default() -> Self {
        Accumulator {
            truth: Truth::True,
            unknown: Vec::new(),
        }
    }
}

impl Accumulator {
    fn add(&mut self, truth: Truth) {
        self.truth = self.truth.and(truth);
    }

    fn check(&mut self, holds: bool) {
        self.add(Truth::from_bool(holds));
    }

    fn unknown(&mut self, description: String) {
        self.add(Truth::Unknown);
        if !self.unknown.contains(&description) {
            self.unknown.push(description);
        }
    }

    fn finish(self) -> PredicateResult {
        PredicateResult {
            truth: self.truth,
            unknown: self.unknown,
        }
    }
}

/// See [`crate::claim_truth`].
pub(crate) fn claim_truth(identity: &Identity, p: &ClaimPredicate) -> Truth {
    // A JSON `null` claim counts as absent, as it does for `required_claims`.
    let value = identity.claim(&p.name).filter(|v| !v.is_null());
    let mut truth = Truth::True;
    if let Some(want_present) = p.exists {
        truth = truth.and(Truth::from_bool(value.is_some() == want_present));
    }
    let has_value_conditions = p.equals.is_some() || p.contains.is_some() || !p.any_of.is_empty();
    let Some(value) = value else {
        return if has_value_conditions {
            truth.and(Truth::Unknown)
        } else {
            truth
        };
    };
    if let Some(expected) = &p.equals {
        truth = truth.and(Truth::from_bool(claim_eq(value, expected)));
    }
    if let Some(needle) = &p.contains {
        truth = truth.and(Truth::from_bool(claim_contains(value, needle)));
    }
    if !p.any_of.is_empty() {
        truth = truth.and(Truth::from_bool(
            p.any_of.iter().any(|candidate| claim_eq(value, candidate)),
        ));
    }
    truth
}

/// `contains`: an array with an element equal to `needle`, or a string
/// (single-valued claim) equal to it. Other claim types never contain.
fn claim_contains(claim: &Value, needle: &Value) -> bool {
    match claim {
        Value::Array(items) => items.iter().any(|item| claim_eq(item, needle)),
        Value::String(_) => claim_eq(claim, needle),
        _ => false,
    }
}

/// Claim equality: JSON equality with numbers compared by mathematical value
/// (`1 == 1.0`), and a string equal to a number when the number's decimal
/// form equals the string (`"123" == 123`, but `"0123" != 123`). Applies
/// recursively inside arrays (ordered) and objects.
pub(crate) fn claim_eq(a: &Value, b: &Value) -> bool {
    claim_eq_at(a, b, 0)
}

fn claim_eq_at(a: &Value, b: &Value, depth: usize) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => number_eq(x, y),
        (Value::String(s), Value::Number(n)) | (Value::Number(n), Value::String(s)) => {
            number_text_eq(n, s)
        }
        (Value::Array(x), Value::Array(y)) => {
            depth < MAX_JSON_DEPTH
                && x.len() == y.len()
                && x.iter().zip(y).all(|(p, q)| claim_eq_at(p, q, depth + 1))
        }
        (Value::Object(x), Value::Object(y)) => {
            depth < MAX_JSON_DEPTH
                && x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| claim_eq_at(v, w, depth + 1)))
        }
        _ => false,
    }
}

/// Whether the decimal form of `n` (as `serde_json` prints it) is `text`,
/// compared without allocating.
fn number_text_eq(n: &Number, text: &str) -> bool {
    struct Compare<'a> {
        rest: &'a str,
    }
    impl fmt::Write for Compare<'_> {
        fn write_str(&mut self, chunk: &str) -> fmt::Result {
            match self.rest.strip_prefix(chunk) {
                Some(rest) => {
                    self.rest = rest;
                    Ok(())
                }
                None => Err(fmt::Error),
            }
        }
    }
    let mut compare = Compare { rest: text };
    write!(compare, "{n}").is_ok() && compare.rest.is_empty()
}

/// Numbers by mathematical value, exactly (no rounding of large integers
/// through `f64`).
fn number_eq(a: &Number, b: &Number) -> bool {
    match (exact_int(a), exact_int(b)) {
        (Some(x), Some(y)) => x == y,
        (Some(i), None) => float_equals_int(b, i),
        (None, Some(i)) => float_equals_int(a, i),
        (None, None) => match (a.as_f64(), b.as_f64()) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
    }
}

fn exact_int(n: &Number) -> Option<i128> {
    n.as_i64()
        .map(i128::from)
        .or_else(|| n.as_u64().map(i128::from))
}

/// Whether the float `f` is exactly the integer `i` (which fits in i64 or u64).
fn float_equals_int(f: &Number, i: i128) -> bool {
    /// 2^64: every integer that fits in i64 or u64 is smaller in magnitude.
    const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;
    let Some(f) = f.as_f64() else {
        return false;
    };
    if !f.is_finite() || f.fract() != 0.0 || f.abs() >= TWO_POW_64 {
        return false;
    }
    // `f` is integral with |f| < 2^64, so the conversion is exact.
    f as i128 == i
}
