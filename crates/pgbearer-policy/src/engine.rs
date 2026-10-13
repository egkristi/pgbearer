//! Compiled policy: deny rules, candidate grants, role selection and the
//! order-independent merge of grant settings.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

use pgbearer_config::{Config, DenyTermination, Grant, UnknownHandling, UserSemantics};
use pgbearer_core::{Identity, PoolMode, RoleRisk, TokenExpiryAction};

use crate::predicate::{CompiledPredicate, EvalCtx, ProviderInfo};
use crate::{
    Allowed, ConnectRequest, Decision, Denied, Entitlement, Explanation, PredicateResult,
    RuleTrace, SessionLimit, Truth,
};

/// A grant rule, compiled.
#[derive(Debug, Clone)]
struct CompiledGrant {
    name: String,
    predicate: CompiledPredicate,
    grant: Grant,
    /// [`Grant::effective_role_risks`], computed once.
    role_risks: BTreeSet<RoleRisk>,
}

impl CompiledGrant {
    /// Whether the grant covers the routed backend and requested database.
    fn targets(&self, backend: &str, database: &str) -> bool {
        self.grant.backend == backend
            && self
                .grant
                .databases
                .iter()
                .any(|d| d == "*" || d == database)
    }

    /// The grant's spelling of `role`, if the grant entitles it.
    fn role(&self, role: &str) -> Option<&str> {
        self.grant
            .pg_roles
            .iter()
            .find(|r| *r == role)
            .map(String::as_str)
    }
}

/// A deny rule, compiled.
#[derive(Debug, Clone)]
struct CompiledDeny {
    name: String,
    predicate: CompiledPredicate,
    on_unknown: UnknownHandling,
    terminate: DenyTermination,
}

impl CompiledDeny {
    /// Deny rules fire on `True`, and on `Unknown` unless they ignore it.
    fn fires(&self, truth: Truth) -> bool {
        match truth {
            Truth::True => true,
            Truth::Unknown => self.on_unknown == UnknownHandling::Deny,
            Truth::False => false,
        }
    }
}

/// A grant that covers the request but whose predicate is `Unknown`.
#[derive(Debug)]
struct Skipped<'e> {
    name: &'e str,
    unknown: Vec<String>,
}

/// The compiled policy behind [`crate::PolicyEngine`].
#[derive(Debug, Clone)]
pub(crate) struct Engine {
    grants: Vec<CompiledGrant>,
    deny: Vec<CompiledDeny>,
    /// Identity providers by name (the first entry wins for a duplicate
    /// name, as in [`Config::identity_provider`]).
    providers: BTreeMap<String, ProviderInfo>,
    user_semantics: UserSemantics,
}

impl Engine {
    pub(crate) fn new(config: &Config) -> Engine {
        let mut providers = BTreeMap::new();
        for p in &config.identity_providers {
            providers
                .entry(p.name.clone())
                .or_insert_with(|| ProviderInfo::from_config(p));
        }
        Engine {
            grants: config
                .policies
                .iter()
                .map(|g| CompiledGrant {
                    name: g.name.clone(),
                    predicate: CompiledPredicate::compile(&g.when),
                    grant: g.grant.clone(),
                    role_risks: g.grant.effective_role_risks(),
                })
                .collect(),
            deny: config
                .deny
                .iter()
                .map(|d| CompiledDeny {
                    name: d.name.clone(),
                    predicate: CompiledPredicate::compile(&d.when),
                    on_unknown: d.on_unknown,
                    terminate: d.terminate,
                })
                .collect(),
            providers,
            user_semantics: config.session.user_semantics,
        }
    }

    pub(crate) fn user_semantics(&self) -> UserSemantics {
        self.user_semantics
    }

    fn ctx<'a>(&'a self, identity: &'a Identity, listener: &'a str, ip: IpAddr) -> EvalCtx<'a> {
        EvalCtx::new(
            identity,
            self.providers.get(&identity.provider),
            listener,
            ip,
        )
    }

    pub(crate) fn evaluate(&self, req: &ConnectRequest<'_>) -> Decision {
        self.run(req, false).decision
    }

    pub(crate) fn explain(&self, req: &ConnectRequest<'_>) -> Explanation {
        self.run(req, true)
    }

    pub(crate) fn entitlements(
        &self,
        identity: &Identity,
        listener: &str,
        client_ip: IpAddr,
    ) -> Vec<Entitlement> {
        let ctx = self.ctx(identity, listener, client_ip);
        self.grants
            .iter()
            .filter(|g| g.predicate.eval(&ctx).truth == Truth::True)
            .map(|g| Entitlement {
                grant: g.name.clone(),
                backend: g.grant.backend.clone(),
                databases: g.grant.databases.clone(),
                pg_roles: g.grant.pg_roles.clone(),
                default_pg_role: g.grant.default_pg_role.clone(),
            })
            .collect()
    }

    pub(crate) fn matching_deny_rule(
        &self,
        identity: &Identity,
        listener: &str,
        client_ip: IpAddr,
    ) -> Option<String> {
        let ctx = self.ctx(identity, listener, client_ip);
        self.deny
            .iter()
            .find(|rule| rule.fires(rule.predicate.eval(&ctx).truth))
            .map(|rule| rule.name.clone())
    }

    /// Decide a request. With `explain`, every rule is evaluated and traced;
    /// without it, evaluation stops at the first deny rule that fires and
    /// only grants that cover the backend and database are evaluated. The
    /// decision is the same either way.
    fn run(&self, req: &ConnectRequest<'_>, explain: bool) -> Explanation {
        let ctx = self.ctx(req.identity, req.listener, req.client_ip);

        // 1. Deny rules, in configuration order; the first that fires decides.
        let mut deny_traces = Vec::new();
        let mut fired: Option<(&CompiledDeny, PredicateResult)> = None;
        for rule in &self.deny {
            let result = rule.predicate.eval(&ctx);
            let fires = fired.is_none() && rule.fires(result.truth);
            if !explain {
                if fires {
                    fired = Some((rule, result));
                    break;
                }
                continue;
            }
            if fires {
                fired = Some((rule, result.clone()));
            }
            deny_traces.push(RuleTrace {
                name: rule.name.clone(),
                predicate: result,
                target_matches: None,
            });
        }

        // 2. Candidate grants (and grants skipped because of unknown data).
        let mut grant_traces = Vec::new();
        let mut candidates: Vec<&CompiledGrant> = Vec::new();
        let mut skipped: Vec<Skipped<'_>> = Vec::new();
        if explain || fired.is_none() {
            for grant in &self.grants {
                let target = grant.targets(req.backend, req.database);
                if !target && !explain {
                    continue;
                }
                let mut result = grant.predicate.eval(&ctx);
                if target {
                    match result.truth {
                        Truth::True => candidates.push(grant),
                        Truth::Unknown => skipped.push(Skipped {
                            name: &grant.name,
                            unknown: if explain {
                                result.unknown.clone()
                            } else {
                                std::mem::take(&mut result.unknown)
                            },
                        }),
                        Truth::False => {}
                    }
                }
                if explain {
                    grant_traces.push(RuleTrace {
                        name: grant.name.clone(),
                        predicate: result,
                        target_matches: Some(target),
                    });
                }
            }
        }

        let decision = match fired {
            Some((rule, result)) => deny_rule_decision(rule, result),
            None => self.decide_grants(req, &candidates, &skipped),
        };
        Explanation {
            decision,
            deny_rules: deny_traces,
            grants: grant_traces,
        }
    }

    /// Steps 2–4 once no deny rule fired.
    fn decide_grants(
        &self,
        req: &ConnectRequest<'_>,
        candidates: &[&CompiledGrant],
        skipped: &[Skipped<'_>],
    ) -> Decision {
        let deny = |reason: String| {
            Decision::Deny(Denied {
                reason: reason + &skipped_note(skipped),
                deny_rule: None,
                terminate: None,
                due_to_unknown: !skipped.is_empty(),
            })
        };
        if candidates.is_empty() {
            return deny(format!(
                "no grant matches backend {:?}, database {:?}",
                req.backend, req.database
            ));
        }
        let role = match self.select_role(req, candidates) {
            Ok(role) => role,
            Err(reason) => return deny(reason),
        };
        let contributing: Vec<&CompiledGrant> = candidates
            .iter()
            .copied()
            .filter(|g| g.role(role).is_some())
            .collect();
        if contributing.is_empty() {
            // Only reachable with an unvalidated configuration whose
            // default_pg_role is not one of the grant's pg_roles.
            return deny(format!(
                "default role {role:?} is not in the pg_roles of any matching grant ({})",
                quoted(grant_names(candidates))
            ));
        }
        Decision::Allow(merge(req, role, &contributing))
    }

    /// Step 3: role selection by user semantics.
    fn select_role<'g>(
        &self,
        req: &ConnectRequest<'_>,
        candidates: &[&'g CompiledGrant],
    ) -> Result<&'g str, String> {
        let identity = req.identity;
        let requested = if req.requested_user.is_empty() {
            identity.username.as_deref().unwrap_or("")
        } else {
            req.requested_user
        };
        let entitled = |name: &str| candidates.iter().find_map(|&g| g.role(name));
        let not_entitled = |suffix: &str| {
            let shown = if req.requested_user.is_empty() {
                format!("\"\" (taken as the identity's username {requested:?})")
            } else {
                format!("{requested:?}")
            };
            format!(
                "requested user {shown} is not an entitled role for backend {:?}, \
                 database {:?} (entitled roles: {}){suffix}",
                req.backend,
                req.database,
                quoted(entitled_roles(candidates))
            )
        };
        match self.user_semantics {
            UserSemantics::Identity => default_role(candidates),
            UserSemantics::Role => entitled(requested)
                .ok_or_else(|| not_entitled("; user_semantics: role requires a role name")),
            UserSemantics::Auto => {
                if let Some(role) = entitled(requested) {
                    return Ok(role);
                }
                let names_identity = req.requested_user.is_empty()
                    || identity.username.as_deref() == Some(requested)
                    || requested == identity.subject
                    || requested == "*";
                if names_identity {
                    default_role(candidates)
                } else {
                    Err(not_entitled(
                        ", nor the identity's username or subject, nor \"*\"",
                    ))
                }
            }
        }
    }
}

/// The decision for a deny rule that fired.
fn deny_rule_decision(rule: &CompiledDeny, result: PredicateResult) -> Decision {
    let due_to_unknown = result.truth == Truth::Unknown;
    let reason = if due_to_unknown {
        format!(
            "deny rule {:?} fired on unknown data: {}",
            rule.name,
            result.unknown.join(", ")
        )
    } else {
        format!("deny rule {:?} matched", rule.name)
    };
    Decision::Deny(Denied {
        reason,
        deny_rule: Some(rule.name.clone()),
        terminate: Some(rule.terminate),
        due_to_unknown,
    })
}

/// The default role among the candidates (see the crate documentation).
fn default_role<'g>(candidates: &[&'g CompiledGrant]) -> Result<&'g str, String> {
    let mut defaults: BTreeMap<&'g str, BTreeSet<&'g str>> = BTreeMap::new();
    for g in candidates {
        if let Some(role) = g.grant.default_pg_role.as_deref() {
            defaults.entry(role).or_default().insert(&g.name);
        }
    }
    let mut roles = defaults.keys().copied();
    match (roles.next(), roles.next()) {
        (Some(role), None) => Ok(role),
        (Some(_), Some(_)) => {
            let mut text = String::new();
            for (i, (role, grants)) in defaults.iter().enumerate() {
                if i > 0 {
                    text.push_str(", ");
                }
                let _ = write!(text, "{role:?} (grants {})", quoted(grants.iter().copied()));
            }
            Err(format!(
                "conflicting default roles {text}; name a role as the user"
            ))
        }
        (None, _) => {
            let all = entitled_roles(candidates);
            let mut iter = all.iter().copied();
            match (iter.next(), iter.next()) {
                (Some(role), None) => Ok(role),
                _ => Err(format!(
                    "ambiguous default role: matching grants {} entitle roles {} and none sets \
                     default_pg_role; name a role as the user",
                    quoted(grant_names(candidates)),
                    quoted(all.iter().copied())
                )),
            }
        }
    }
}

/// Step 4: merge the contributing grants' settings, independently of order.
fn merge(req: &ConnectRequest<'_>, role: &str, contributing: &[&CompiledGrant]) -> Allowed {
    let mut session_limits = Vec::new();
    let mut session_max_lifetime: Option<Duration> = None;
    let mut on_token_expiry: Option<TokenExpiryAction> = None;
    let (mut session_mode, mut transaction_mode) = (false, false);
    let mut role_risks: Option<BTreeSet<RoleRisk>> = None;
    for g in contributing {
        let grant = &g.grant;
        if let Some(max) = grant.max_sessions_per_identity_per_replica {
            session_limits.push(SessionLimit {
                grant: g.name.clone(),
                max_sessions_per_replica: max,
            });
        }
        if let Some(lifetime) = grant.session_max_lifetime {
            session_max_lifetime = Some(session_max_lifetime.map_or(lifetime, |l| l.min(lifetime)));
        }
        if let Some(action) = grant.on_token_expiry {
            on_token_expiry = Some(on_token_expiry.map_or(action, |a| a.strictest(action)));
        }
        match grant.pool_mode {
            Some(PoolMode::Session) => session_mode = true,
            Some(PoolMode::Transaction) => transaction_mode = true,
            None => {}
        }
        role_risks = Some(match role_risks {
            None => g.role_risks.clone(),
            Some(acc) => acc.intersection(&g.role_risks).copied().collect(),
        });
    }
    // Grant names are unique, so this order does not depend on `policies`.
    session_limits.sort_by(|a, b| a.grant.cmp(&b.grant));
    let pool_mode = if session_mode {
        Some(PoolMode::Session)
    } else if transaction_mode {
        Some(PoolMode::Transaction)
    } else {
        None
    };
    Allowed {
        backend: req.backend.to_owned(),
        database: req.database.to_owned(),
        pg_role: role.to_owned(),
        matched_grants: contributing.iter().map(|g| g.name.clone()).collect(),
        pool_mode,
        pool_mode_conflict: session_mode && transaction_mode,
        session_limits,
        session_max_lifetime,
        on_token_expiry,
        acknowledged_role_risks: role_risks.unwrap_or_default(),
    }
}

/// The union of the candidates' roles, sorted.
fn entitled_roles<'g>(candidates: &[&'g CompiledGrant]) -> BTreeSet<&'g str> {
    candidates
        .iter()
        .flat_map(|g| g.grant.pg_roles.iter().map(String::as_str))
        .collect()
}

/// Grant names, sorted (so that reasons do not depend on rule order).
fn grant_names<'g>(grants: &[&'g CompiledGrant]) -> BTreeSet<&'g str> {
    grants.iter().map(|g| g.name.as_str()).collect()
}

/// `; grants skipped because of unknown data: "a" (groups (groups overage)), …`
/// sorted by grant name, or empty.
fn skipped_note(skipped: &[Skipped<'_>]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<&Skipped<'_>> = skipped.iter().collect();
    sorted.sort_by_key(|s| s.name);
    let mut text = String::from("; grants skipped because of unknown data: ");
    for (i, s) in sorted.iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        let _ = write!(text, "{:?} ({})", s.name, s.unknown.join(", "));
    }
    text
}

/// `"a", "b"`, or `none`.
fn quoted<'s>(items: impl IntoIterator<Item = &'s str>) -> String {
    let mut text = String::new();
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        let _ = write!(text, "{item:?}");
    }
    if text.is_empty() {
        text.push_str("none");
    }
    text
}
