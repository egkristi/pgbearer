//! Access policy for pgbearer (ARCHITECTURE.md §9).
//!
//! Evaluation of a [`ConnectRequest`] (all string comparisons are exact and
//! case-sensitive):
//!
//! 1. **Deny rules** are checked first. If any deny rule's predicate matches,
//!    the result is `Deny` naming that rule.
//! 2. **Candidate grants**: grants whose predicate matches the identity and
//!    connection, whose `backend` equals the request's backend, and whose
//!    `databases` contains the requested database or `*`. Order is config order.
//!    No candidates → `Deny("no grant matches …")`.
//! 3. **Role selection** by [`UserSemantics`]:
//!    * `auto`: if `requested_user` is a role in any candidate's `pg_roles`,
//!      use it. Otherwise, if `requested_user` equals the identity's
//!      `username`, its `subject`, or `*`, use the default role (below).
//!      Otherwise deny ("requested user … is not an entitled role").
//!    * `role`: `requested_user` must be an entitled role, else deny.
//!    * `identity`: ignore `requested_user`; use the default role.
//!
//!    Default role: the `default_pg_role` of the first candidate that sets one;
//!    if none sets one and the union of candidate roles has exactly one role,
//!    that role; otherwise deny ("ambiguous default role; name a role as the
//!    user"). An empty `requested_user` is treated like the identity's username.
//! 4. **Result**: the *contributing grants* are the candidates whose
//!    `pg_roles` contain the selected role. `matched_grants` lists all of them
//!    in config order; per-grant settings (`pool_mode`,
//!    `max_connections_per_identity`, `session_max_lifetime`,
//!    `on_token_expiry`, `allow_privileged_role`) come from the **first**
//!    contributing grant that sets each one (`allow_privileged_role` is true
//!    only if the first contributing grant sets it).
//!
//! Predicate matching (all set conditions must hold):
//! * `issuer` = identity.provider; `kind` = identity.kind.
//! * `subject`/`subjects`/`username`: exact, or prefix match when the pattern
//!   ends with `*` (only a trailing `*` is special).
//! * `roles_any`/`groups_any`/`scopes_any`: non-empty intersection;
//!   `roles_all`/`groups_all`: subset. If the predicate has any group
//!   condition and the identity has `groups_overage`, the predicate does
//!   **not** match (fail closed) and the denial reason mentions the overage.
//! * `tenants`, `client_ids`: identity value present and in the list.
//! * `claims`: each [`ClaimPredicate`] on `identity.claim(name)`:
//!   `exists` (presence), `equals` (JSON equality), `contains` (array contains
//!   the value, or string equals it), `any_of` (equals one of). All set
//!   sub-conditions must hold.
//! * `source_cidrs`: client IP in any network; `listeners`: listener name in list.
//!
//! The engine is pure (no I/O) and cheap to rebuild on config reload.

use std::net::IpAddr;
use std::time::Duration;

use pgbearer_config::{ClaimPredicate, Config, UserSemantics};
use pgbearer_core::{Identity, PoolMode, TokenExpiryAction};

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
    /// Client IP address.
    pub client_ip: IpAddr,
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
    /// All contributing grants, in config order.
    pub matched_grants: Vec<String>,
    /// Pool mode override.
    pub pool_mode: Option<PoolMode>,
    /// Per-identity connection limit.
    pub max_connections_per_identity: Option<u32>,
    /// Session lifetime override.
    pub session_max_lifetime: Option<Duration>,
    /// Token-expiry behaviour override.
    pub on_token_expiry: Option<TokenExpiryAction>,
    /// Whether privileged roles are allowed.
    pub allow_privileged_role: bool,
}

/// A denied connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// Precise internal reason (audit only; never sent to the client).
    pub reason: String,
    /// Name of the deny rule that matched, if any.
    pub deny_rule: Option<String>,
}

/// A policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed.
    Allow(Allowed),
    /// Denied.
    Deny(Denied),
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

/// The compiled policy.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    _private: (),
}

impl PolicyEngine {
    /// Build from a validated config (`policies`, `deny`, `session.user_semantics`).
    pub fn from_config(config: &Config) -> PolicyEngine {
        let _ = config;
        todo!("pgbearer-policy: PolicyEngine::from_config")
    }

    /// Decide a connection request.
    pub fn evaluate(&self, req: &ConnectRequest<'_>) -> Decision {
        let _ = req;
        todo!("pgbearer-policy: PolicyEngine::evaluate")
    }

    /// Grants whose predicate matches the identity for the given listener and
    /// client IP, ignoring backend and database (for diagnostics).
    pub fn entitlements(
        &self,
        identity: &Identity,
        listener: &str,
        client_ip: IpAddr,
    ) -> Vec<Entitlement> {
        let _ = (identity, listener, client_ip);
        todo!("pgbearer-policy: PolicyEngine::entitlements")
    }

    /// Name of the first deny rule matching the identity, if any (for diagnostics).
    pub fn matching_deny_rule(
        &self,
        identity: &Identity,
        listener: &str,
        client_ip: IpAddr,
    ) -> Option<String> {
        let _ = (identity, listener, client_ip);
        todo!("pgbearer-policy: PolicyEngine::matching_deny_rule")
    }

    /// The configured user semantics.
    pub fn user_semantics(&self) -> UserSemantics {
        todo!("pgbearer-policy: PolicyEngine::user_semantics")
    }
}

/// Evaluate one claim predicate against an identity (exposed for testing).
pub fn claim_matches(identity: &Identity, predicate: &ClaimPredicate) -> bool {
    let _ = (identity, predicate);
    todo!("pgbearer-policy: claim_matches")
}
