//! Semantic validation of a parsed [`Config`].

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    API_VERSION, BackendConfig, BackendTlsMode, ClientAuthMethod, Config, IdentityProviderConfig,
    IdpType, KIND, LoginMethod, Predicate,
};

/// Collect every validation problem in `config`.
pub(crate) fn validate(config: &Config) -> Vec<String> {
    let mut v = Validator::default();
    v.root(config);
    v.problems
}

#[derive(Default)]
struct Validator {
    problems: Vec<String>,
}

impl Validator {
    fn err(&mut self, msg: impl Into<String>) {
        self.problems.push(msg.into());
    }

    fn unique<'a>(&mut self, what: &str, names: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        for n in names {
            if n.trim().is_empty() {
                self.err(format!("{what}: name must not be empty"));
            } else if !seen.insert(n.to_string()) {
                self.err(format!("{what}: duplicate name {n:?}"));
            }
        }
        seen
    }

    fn root(&mut self, c: &Config) {
        if c.api_version != API_VERSION {
            self.err(format!(
                "apiVersion must be {API_VERSION:?}, found {:?}",
                c.api_version
            ));
        }
        if c.kind != KIND {
            self.err(format!("kind must be {KIND:?}, found {:?}", c.kind));
        }

        if c.listeners.is_empty() {
            self.err("listeners: at least one listener is required");
        }
        if c.identity_providers.is_empty() {
            self.err("identity_providers: at least one identity provider is required");
        }
        if c.backends.is_empty() {
            self.err("backends: at least one backend is required");
        }

        let listener_names = self.unique("listeners", c.listeners.iter().map(|l| l.name.as_str()));
        let idp_names = self.unique(
            "identity_providers",
            c.identity_providers.iter().map(|p| p.name.as_str()),
        );
        let backend_names = self.unique("backends", c.backends.iter().map(|b| b.name.as_str()));
        self.unique("policies", c.policies.iter().map(|g| g.name.as_str()));
        self.unique("deny", c.deny.iter().map(|d| d.name.as_str()));

        // Listeners
        let mut addresses = BTreeSet::new();
        for l in &c.listeners {
            let ctx = format!("listeners[{}]", l.name);
            if !addresses.insert(l.address) {
                self.err(format!(
                    "{ctx}: address {} is used by another listener",
                    l.address
                ));
            }
            if l.tls.is_none() && !l.insecure_allow_plaintext_auth {
                self.err(format!(
                    "{ctx}: tls is required (tokens must not cross the network in clear text); \
                     set insecure_allow_plaintext_auth: true only for local development"
                ));
            }
            if let Some(tls) = &l.tls
                && tls.reload_interval.is_zero()
            {
                self.err(format!(
                    "{ctx}: tls.reload_interval must be greater than zero"
                ));
            }
            match l.client_auth {
                ClientAuthMethod::Oauthbearer => match &l.oauthbearer_provider {
                    None => self.err(format!(
                        "{ctx}: client_auth: oauthbearer requires oauthbearer_provider"
                    )),
                    Some(p) => match c.identity_provider(p) {
                        None => self.err(format!(
                            "{ctx}: oauthbearer_provider {p:?} is not a configured identity provider"
                        )),
                        Some(idp) if idp.oauthbearer.is_none() => self.err(format!(
                            "{ctx}: identity provider {p:?} has no oauthbearer settings"
                        )),
                        Some(_) => {}
                    },
                },
                ClientAuthMethod::TokenPassword => {
                    if l.oauthbearer_provider.is_some() {
                        self.err(format!(
                            "{ctx}: oauthbearer_provider is only valid with client_auth: oauthbearer"
                        ));
                    }
                }
            }
        }

        // Identity providers
        let mut issuers: BTreeMap<String, String> = BTreeMap::new();
        for p in &c.identity_providers {
            self.idp(p);
            if let Some(iss) = p.effective_issuer()
                && let Some(other) = issuers.insert(iss.clone(), p.name.clone())
            {
                self.err(format!(
                    "identity_providers[{}]: issuer {iss:?} is also used by {other:?}; \
                     issuers must be unique because tokens are routed by their iss claim",
                    p.name
                ));
            }
        }

        // Backends
        for b in &c.backends {
            self.backend(b);
        }

        // Routes
        for (i, r) in c.routes.iter().enumerate() {
            let ctx = format!("routes[{i}]");
            if !backend_names.contains(&r.backend) {
                self.err(format!("{ctx}: unknown backend {:?}", r.backend));
            }
            for l in &r.matcher.listeners {
                if !listener_names.contains(l) {
                    self.err(format!("{ctx}: unknown listener {l:?}"));
                }
            }
            if let Some(sni) = &r.matcher.sni {
                let host = sni.strip_prefix("*.").unwrap_or(sni);
                if host.is_empty() || host.contains('*') {
                    self.err(format!(
                        "{ctx}: sni {sni:?} is invalid; only a leading \"*.\" wildcard is supported"
                    ));
                }
            }
            for d in &r.matcher.databases {
                if d.is_empty() {
                    self.err(format!("{ctx}: database names must not be empty"));
                }
            }
        }

        // Grants
        for g in &c.policies {
            let ctx = format!("policies[{}]", g.name);
            self.predicate(&ctx, &g.when, &idp_names, &listener_names);
            let grant = &g.grant;
            match c.backend(&grant.backend) {
                None => self.err(format!("{ctx}: unknown backend {:?}", grant.backend)),
                Some(b) => {
                    for role in &grant.pg_roles {
                        if b.login.credential_for(role).is_none() {
                            self.err(format!(
                                "{ctx}: backend {:?} has no login credential for role {role:?} \
                                 (add login.cert_file/key_file or login.roles.{role})",
                                b.name
                            ));
                        }
                    }
                }
            }
            if grant.databases.is_empty() {
                self.err(format!(
                    "{ctx}: grant.databases must not be empty (use [\"*\"] for any)"
                ));
            }
            if grant.pg_roles.is_empty() {
                self.err(format!("{ctx}: grant.pg_roles must not be empty"));
            }
            for role in &grant.pg_roles {
                check_identifier(self, &ctx, "pg_roles", role);
            }
            for db in &grant.databases {
                if db != "*" {
                    check_identifier(self, &ctx, "databases", db);
                }
            }
            if let Some(d) = &grant.default_pg_role
                && !grant.pg_roles.contains(d)
            {
                self.err(format!(
                    "{ctx}: default_pg_role {d:?} must be one of pg_roles {:?}",
                    grant.pg_roles
                ));
            }
            if grant.max_connections_per_identity == Some(0) {
                self.err(format!(
                    "{ctx}: max_connections_per_identity must be at least 1"
                ));
            }
            if grant.session_max_lifetime.is_some_and(|d| d.is_zero()) {
                self.err(format!(
                    "{ctx}: session_max_lifetime must be greater than zero"
                ));
            }
        }

        // Deny rules
        for d in &c.deny {
            let ctx = format!("deny[{}]", d.name);
            self.predicate(&ctx, &d.when, &idp_names, &listener_names);
        }

        // Session, limits, drain
        if c.session.auth_timeout.is_zero() {
            self.err("session.auth_timeout must be greater than zero");
        }
        if c.session.max_lifetime.is_zero() {
            self.err("session.max_lifetime must be greater than zero");
        }
        let l = &c.limits;
        if !(1024..=65_536).contains(&l.max_startup_packet_bytes) {
            self.err("limits.max_startup_packet_bytes must be between 1024 and 65536");
        }
        if !(1024..=1_048_576).contains(&l.max_auth_message_bytes) {
            self.err("limits.max_auth_message_bytes must be between 1024 and 1048576");
        }
        if l.max_client_connections == 0 {
            self.err("limits.max_client_connections must be at least 1");
        }
        if l.max_pending_auth == 0 {
            self.err("limits.max_pending_auth must be at least 1");
        }
        if c.drain.hard_timeout < c.drain.session_timeout {
            self.err("drain.hard_timeout must be at least drain.session_timeout");
        }
    }

    fn idp(&mut self, p: &IdentityProviderConfig) {
        let ctx = format!("identity_providers[{}]", p.name);
        match p.effective_issuer() {
            None => self.err(format!("{ctx}: issuer is required for type {:?}", p.kind)),
            Some(iss) => self.check_url(&ctx, "issuer", &iss, p.insecure_allow_http),
        }
        if let Some(u) = &p.discovery_url {
            self.check_url(&ctx, "discovery_url", u, p.insecure_allow_http);
        }
        if let Some(u) = &p.jwks_uri {
            self.check_url(&ctx, "jwks_uri", u, p.insecure_allow_http);
        }
        if p.audiences.is_empty() || p.audiences.iter().any(|a| a.trim().is_empty()) {
            self.err(format!(
                "{ctx}: at least one non-empty audience is required"
            ));
        }
        if p.algorithms.is_empty() {
            self.err(format!("{ctx}: algorithms must not be empty"));
        }
        if p.kind == IdpType::Entra {
            if p.tenants.is_empty() {
                self.err(format!(
                    "{ctx}: type entra requires tenants (the allowed tid values)"
                ));
            }
            if let Some(iss) = p.effective_issuer()
                && (iss.contains("/common/")
                    || iss.contains("/organizations/")
                    || iss.contains("/consumers/"))
            {
                self.err(format!(
                    "{ctx}: Entra issuer must be tenant-specific (https://login.microsoftonline.com/<tenant-id>/v2.0)"
                ));
            }
        }
        let j = &p.jwks;
        if j.min_refresh_interval.is_zero() || j.max_age.is_zero() || j.http_timeout.is_zero() {
            self.err(format!(
                "{ctx}: jwks.min_refresh_interval, max_age and http_timeout must be greater than zero"
            ));
        }
        if j.max_age < j.min_refresh_interval {
            self.err(format!(
                "{ctx}: jwks.max_age must be at least jwks.min_refresh_interval"
            ));
        }
        if let Some(ob) = &p.oauthbearer
            && ob.scope.trim().is_empty()
        {
            self.err(format!("{ctx}: oauthbearer.scope must not be empty"));
        }
    }

    fn check_url(&mut self, ctx: &str, field: &str, value: &str, allow_http: bool) {
        match url::Url::parse(value) {
            Err(e) => self.err(format!("{ctx}: {field} {value:?} is not a valid URL: {e}")),
            Ok(u) => match u.scheme() {
                "https" => {}
                "http" if allow_http => {}
                "http" => self.err(format!(
                    "{ctx}: {field} must use https (set insecure_allow_http: true only for tests)"
                )),
                s => self.err(format!("{ctx}: {field} has unsupported scheme {s:?}")),
            },
        }
    }

    fn backend(&mut self, b: &BackendConfig) {
        let ctx = format!("backends[{}]", b.name);
        match (&b.static_endpoint, &b.cnpg) {
            (Some(_), Some(_)) => self.err(format!(
                "{ctx}: set exactly one of static and cnpg, not both"
            )),
            (None, None) => self.err(format!("{ctx}: one of static or cnpg is required")),
            (Some(s), None) => {
                if s.host.trim().is_empty() {
                    self.err(format!("{ctx}: static.host must not be empty"));
                }
                if s.port == 0 {
                    self.err(format!("{ctx}: static.port must not be 0"));
                }
            }
            (None, Some(c)) => {
                if c.cluster.trim().is_empty() || c.namespace.trim().is_empty() {
                    self.err(format!(
                        "{ctx}: cnpg.cluster and cnpg.namespace are required"
                    ));
                }
                if c.port == 0 {
                    self.err(format!("{ctx}: cnpg.port must not be 0"));
                }
            }
        }
        if b.tls.mode == BackendTlsMode::Disable && b.login.method == LoginMethod::Cert {
            self.err(format!(
                "{ctx}: login.method cert requires TLS (tls.mode must not be disable)"
            ));
        }
        let login = &b.login;
        if login.cert_file.is_some() != login.key_file.is_some() {
            self.err(format!(
                "{ctx}: login.cert_file and login.key_file must be set together"
            ));
        }
        if login.method == LoginMethod::Password && login.cert_file.is_some() {
            self.err(format!(
                "{ctx}: login.cert_file is only used with method cert; per-role certificates go in login.roles"
            ));
        }
        for (role, rc) in &login.roles {
            let rctx = format!("{ctx}: login.roles.{role}");
            if rc.cert_file.is_some() != rc.key_file.is_some() {
                self.err(format!(
                    "{rctx}: cert_file and key_file must be set together"
                ));
            }
            if rc.password_file.is_some() && rc.cert_file.is_some() {
                self.err(format!(
                    "{rctx}: set either password_file or cert_file/key_file, not both"
                ));
            }
            if rc.password_file.is_none() && rc.cert_file.is_none() {
                self.err(format!("{rctx}: needs password_file or cert_file/key_file"));
            }
            if rc.cert_file.is_some() && b.tls.mode == BackendTlsMode::Disable {
                self.err(format!("{rctx}: certificate login requires TLS"));
            }
        }
        let p = &b.pool;
        if p.max_connections == 0 || p.max_backend_connections == 0 {
            self.err(format!(
                "{ctx}: pool.max_connections and pool.max_backend_connections must be at least 1"
            ));
        }
        if p.max_connections > p.max_backend_connections {
            self.err(format!(
                "{ctx}: pool.max_connections ({}) must not exceed pool.max_backend_connections ({})",
                p.max_connections, p.max_backend_connections
            ));
        }
        if p.acquire_timeout.is_zero() || p.connect_timeout.is_zero() {
            self.err(format!(
                "{ctx}: pool.acquire_timeout and pool.connect_timeout must be greater than zero"
            ));
        }
        if p.reset_query.trim().is_empty() {
            self.err(format!("{ctx}: pool.reset_query must not be empty"));
        }
    }

    fn predicate(
        &mut self,
        ctx: &str,
        p: &Predicate,
        idp_names: &BTreeSet<String>,
        listener_names: &BTreeSet<String>,
    ) {
        if let Some(i) = &p.issuer
            && !idp_names.contains(i)
        {
            self.err(format!(
                "{ctx}: when.issuer {i:?} is not a configured identity provider"
            ));
        }
        for l in &p.listeners {
            if !listener_names.contains(l) {
                self.err(format!(
                    "{ctx}: when.listeners contains unknown listener {l:?}"
                ));
            }
        }
        for c in &p.claims {
            if c.name.trim().is_empty() {
                self.err(format!("{ctx}: when.claims entries need a name"));
            }
            if c.equals.is_none()
                && c.contains.is_none()
                && c.any_of.is_empty()
                && c.exists.is_none()
            {
                self.err(format!(
                    "{ctx}: when.claims[{}] needs one of equals, contains, any_of or exists",
                    c.name
                ));
            }
        }
    }
}

/// PostgreSQL identifiers used in startup packets: non-empty, no NUL, at most 63 bytes.
fn check_identifier(v: &mut Validator, ctx: &str, field: &str, value: &str) {
    if value.is_empty() || value.contains('\0') || value.len() > 63 {
        v.err(format!(
            "{ctx}: {field} entry {value:?} is not a valid PostgreSQL identifier (1-63 bytes, no NUL)"
        ));
    }
}
