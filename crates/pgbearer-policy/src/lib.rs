//! Access policy for pgbearer (ARCHITECTURE.md §9.1).
//!
//! The engine is pure (no I/O), deterministic, and cheap to rebuild on every
//! configuration reload. All string comparisons are exact and case-sensitive.
//!
//! # Three-valued conditions
//!
//! Every predicate condition evaluates to [`Truth::True`], [`Truth::False`] or
//! [`Truth::Unknown`]. *Unknown* means the data the condition needs is not
//! available, so the condition can neither be confirmed nor ruled out. A
//! predicate is the conjunction of its set conditions: `False` if any
//! condition is `False`, otherwise `Unknown` if any is `Unknown`, otherwise
//! `True`. A predicate with no conditions is `True`.
//!
//! * **Grants match only on `True`.** Unknown data never grants access.
//! * **Deny rules fire on `True` or `Unknown`**, unless the rule sets
//!   `on_unknown: ignore` (then only on `True`). Unknown data never bypasses a
//!   deny.
//!
//! Per condition (identity = the validated [`Identity`], provider = the
//! `identity_providers` entry whose `name` equals `identity.provider`; if no
//! such provider exists in the configuration, every provider-dependent
//! condition below is `Unknown`):
//!
//! | Condition | Unknown when | Otherwise |
//! |---|---|---|
//! | `issuer` | never | `identity.provider == issuer` |
//! | `kind` | predicate kind ≠ `unknown` and `identity.kind == Unknown` | equality |
//! | `subject`, `subjects` | never | exact, or prefix when the pattern ends with `*` (only a trailing `*` is special); `subjects` = any of them |
//! | `username` | `identity.username` is `None` | same matching as `subject` |
//! | `roles_any`, `roles_all` | the provider maps no roles (`effective_claims().roles` is `None`) | non-empty intersection / subset |
//! | `groups_any`, `groups_all` | `identity.groups_overage`, or the provider maps no groups | non-empty intersection / subset |
//! | `scopes_any` | the provider maps no scopes | non-empty intersection |
//! | `tenants` | `identity.tenant` is `None` | membership |
//! | `client_ids` | `identity.client_id` is `None` | membership |
//! | `claims[i]` | see [`claim_truth`] | see [`claim_truth`] |
//! | `source_cidrs` | never | client IP in any network |
//! | `listeners` | never | listener name in the list |
//!
//! Empty list conditions (`subjects: []`, `roles_any: []`, …) and unset
//! options are not conditions at all.
//!
//! # Evaluation of a [`ConnectRequest`]
//!
//! 1. **Deny rules**, in configuration order. The first rule that fires
//!    decides: `Deny` with `deny_rule` set, `terminate` copied from the rule,
//!    and a reason naming the rule (and, when it fired on `Unknown`, which
//!    data was unknown).
//! 2. **Candidate grants**: grants whose predicate is `True`, whose
//!    `grant.backend` equals the request's backend, and whose
//!    `grant.databases` contains the requested database or `*`. Grants whose
//!    predicate is `Unknown` are not candidates, but are remembered for the
//!    denial reason. No candidates → `Deny` ("no grant matches …", naming
//!    grants skipped because of unknown data, if any).
//! 3. **Role selection** by [`UserSemantics`]. An empty `requested_user` is
//!    treated like the identity's username.
//!    * `auto`: if `requested_user` is a role in any candidate's `pg_roles`,
//!      use it. Otherwise, if it equals the identity's `username`, its
//!      `subject`, or `*`, use the default role. Otherwise deny ("requested
//!      user … is not an entitled role").
//!    * `role`: `requested_user` must be a role in a candidate's `pg_roles`,
//!      else deny.
//!    * `identity`: ignore `requested_user`; use the default role.
//!
//!    **Default role:** the distinct `default_pg_role` values set by the
//!    candidates. Exactly one → that role. More than one → deny ("conflicting
//!    default roles …; name a role as the user"). None → if the union of the
//!    candidates' `pg_roles` has exactly one role, that role; otherwise deny
//!    ("ambiguous default role; name a role as the user").
//! 4. **Result.** The *contributing grants* are the candidates whose
//!    `pg_roles` contain the selected role. Their settings merge
//!    **independently of their order**:
//!    * `matched_grants`: the contributing grant names, in configuration order.
//!    * `session_limits`: one entry per contributing grant that sets
//!      `max_sessions_per_identity_per_replica` (every one is enforced),
//!      sorted by grant name.
//!    * `session_max_lifetime`: the minimum of the values set (or `None`).
//!    * `on_token_expiry`: the strictest of the values set (or `None`); see
//!      [`TokenExpiryAction::strictest`].
//!    * `pool_mode`: `None` if no contributing grant sets one; `Session` if
//!      any sets `Session` (and `pool_mode_conflict` is true when another
//!      sets `Transaction`); otherwise `Transaction`.
//!    * `acknowledged_role_risks`: the intersection of the contributing
//!      grants' [`Grant::effective_role_risks`] (validation already requires
//!      them to be equal for the same backend and role).
//!
//! Decisions are invariant under any permutation of `policies` and `deny`
//! except for which deny rule is named when several fire and the order of
//! `matched_grants`; property tests check this.
//!
//! [`Grant::effective_role_risks`]: pgbearer_config::Grant::effective_role_risks

mod engine;
mod predicate;

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod proptests;
#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use pgbearer_config::{ClaimPredicate, Config, DenyTermination, Predicate, UserSemantics};
use pgbearer_core::{Identity, PoolMode, RoleRisk, TokenExpiryAction};

/// A three-valued truth value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Truth {
    /// The condition holds.
    True,
    /// The condition does not hold.
    False,
    /// The data needed to decide is not available.
    Unknown,
}

impl Truth {
    /// Conjunction: `False` dominates, then `Unknown`, then `True`.
    pub fn and(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::False, _) | (_, Truth::False) => Truth::False,
            (Truth::Unknown, _) | (_, Truth::Unknown) => Truth::Unknown,
            (Truth::True, Truth::True) => Truth::True,
        }
    }

    /// `True` for `true`, `False` for `false`.
    pub fn from_bool(value: bool) -> Truth {
        if value { Truth::True } else { Truth::False }
    }
}

/// The result of evaluating one predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateResult {
    /// The overall truth value.
    pub truth: Truth,
    /// Human-readable descriptions of the conditions that were `Unknown`, for
    /// example `"groups (groups overage)"` or `"claim acct (absent)"`. Also
    /// filled when the overall result is `False` because another condition
    /// failed.
    pub unknown: Vec<String>,
}

/// Input to a policy decision.
#[derive(Debug, Clone, Copy)]
pub struct ConnectRequest<'a> {
    /// The validated identity.
    pub identity: &'a Identity,
    /// Startup `user` parameter (may be empty).
    pub requested_user: &'a str,
    /// Startup `database` parameter.
    pub database: &'a str,
    /// Backend selected by routing.
    pub backend: &'a str,
    /// Listener name.
    pub listener: &'a str,
    /// Client IP address (from the TCP peer, or from a trusted PROXY header).
    pub client_ip: IpAddr,
}

/// A per-identity session limit from one contributing grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLimit {
    /// Grant name (sessions are counted per issuer, subject and grant).
    pub grant: String,
    /// Maximum concurrent sessions per identity on one replica.
    pub max_sessions_per_replica: u32,
}

/// An allowed connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    /// Backend name.
    pub backend: String,
    /// Database.
    pub database: String,
    /// PostgreSQL role to log in as.
    pub pg_role: String,
    /// All contributing grants, in configuration order.
    pub matched_grants: Vec<String>,
    /// Pool mode override (`None`: the backend's default applies).
    pub pool_mode: Option<PoolMode>,
    /// True when contributing grants set different pool modes (resolved to
    /// session mode; recorded in the audit event).
    pub pool_mode_conflict: bool,
    /// Every contributing per-identity session limit.
    pub session_limits: Vec<SessionLimit>,
    /// Shortest session lifetime override among contributing grants.
    pub session_max_lifetime: Option<Duration>,
    /// Strictest token-expiry override among contributing grants.
    pub on_token_expiry: Option<TokenExpiryAction>,
    /// Role risks acknowledged by every contributing grant.
    pub acknowledged_role_risks: BTreeSet<RoleRisk>,
}

/// A denied connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// Precise internal reason (audit only; never sent to the client).
    pub reason: String,
    /// Name of the deny rule that fired, if any.
    pub deny_rule: Option<String>,
    /// For a deny rule: how active sessions it newly matches are ended.
    pub terminate: Option<DenyTermination>,
    /// True when the decision depended on unknown data (a deny rule fired on
    /// `Unknown`, or grants were skipped because of unknown data).
    pub due_to_unknown: bool,
}

/// A policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed.
    Allow(Allowed),
    /// Denied.
    Deny(Denied),
}

impl Decision {
    /// True for [`Decision::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
}

/// One role an identity may use (for `pgbearerctl explain`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlement {
    /// Grant name.
    pub grant: String,
    /// Backend.
    pub backend: String,
    /// Databases.
    pub databases: Vec<String>,
    /// Roles.
    pub pg_roles: Vec<String>,
    /// Default role.
    pub default_pg_role: Option<String>,
}

/// How one rule evaluated (for `pgbearerctl explain`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTrace {
    /// Rule name.
    pub name: String,
    /// Predicate result.
    pub predicate: PredicateResult,
    /// For grants: whether backend and database matched the request.
    pub target_matches: Option<bool>,
}

/// A decision with the evaluation of every rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The decision [`PolicyEngine::evaluate`] would return.
    pub decision: Decision,
    /// Deny rules, in configuration order.
    pub deny_rules: Vec<RuleTrace>,
    /// Grants, in configuration order.
    pub grants: Vec<RuleTrace>,
}

/// The compiled policy.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    inner: engine::Engine,
}

impl PolicyEngine {
    /// Build from a validated configuration (`policies`, `deny`,
    /// `identity_providers` for claim mappings, `session.user_semantics`).
    pub fn from_config(config: &Config) -> PolicyEngine {
        PolicyEngine {
            inner: engine::Engine::new(config),
        }
    }

    /// Decide a connection request.
    pub fn evaluate(&self, req: &ConnectRequest<'_>) -> Decision {
        self.inner.evaluate(req)
    }

    /// Decide a request and report how every rule evaluated.
    pub fn explain(&self, req: &ConnectRequest<'_>) -> Explanation {
        self.inner.explain(req)
    }

    /// Grants whose predicate is `True` for the identity on the given
    /// listener and client IP, ignoring backend and database (diagnostics).
    pub fn entitlements(
        &self,
        identity: &Identity,
        listener: &str,
        client_ip: IpAddr,
    ) -> Vec<Entitlement> {
        self.inner.entitlements(identity, listener, client_ip)
    }

    /// Name of the first deny rule that fires for the identity (on `True`, or
    /// on `Unknown` unless the rule ignores unknown data), if any.
    pub fn matching_deny_rule(
        &self,
        identity: &Identity,
        listener: &str,
        client_ip: IpAddr,
    ) -> Option<String> {
        self.inner.matching_deny_rule(identity, listener, client_ip)
    }

    /// The configured user semantics.
    pub fn user_semantics(&self) -> UserSemantics {
        self.inner.user_semantics()
    }
}

/// Evaluate a predicate against an identity and connection. `provider` is
/// the identity's provider configuration, or `None` if it is not configured
/// (then provider-dependent conditions are `Unknown`).
pub fn evaluate_predicate(
    predicate: &Predicate,
    identity: &Identity,
    provider: Option<&pgbearer_config::IdentityProviderConfig>,
    listener: &str,
    client_ip: IpAddr,
) -> PredicateResult {
    let provider = provider.map(predicate::ProviderInfo::from_config);
    let ctx = predicate::EvalCtx::new(identity, provider.as_ref(), listener, client_ip);
    predicate::CompiledPredicate::compile(predicate).eval(&ctx)
}

/// Evaluate one claim condition. The claim is looked up with
/// [`Identity::claim`] (literal name, dotted path, or JSON Pointer).
///
/// * `exists: true/false`: presence or absence; never `Unknown`.
/// * When the claim is **absent** (missing, or JSON `null`), `equals`,
///   `contains` and `any_of` are `Unknown`.
/// * `equals`: JSON equality, except that a string and a number compare
///   equal when the number's decimal form equals the string (claims such as
///   GitHub's `repository_id` are strings that look like numbers, and YAML
///   authors may write either).
/// * `contains`: the claim is an array containing the value (same equality),
///   or a string equal to it (a single-valued claim).
/// * `any_of`: the claim equals one of the values (same equality).
///
/// All set sub-conditions must hold (three-valued conjunction).
pub fn claim_truth(identity: &Identity, predicate: &ClaimPredicate) -> Truth {
    predicate::claim_truth(identity, predicate)
}
