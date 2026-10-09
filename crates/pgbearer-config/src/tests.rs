use super::*;

const EXAMPLE: &str = include_str!("../../../deploy/examples/pgbearer.yaml");

fn minimal() -> String {
    r#"
apiVersion: pgbearer/v1alpha1
kind: ProxyConfig
listeners:
  - name: pg
    address: "127.0.0.1:6432"
    insecure_allow_plaintext_auth: true
identity_providers:
  - name: idp
    issuer: "https://idp.example.com/realms/main"
    audiences: ["pgbearer"]
backends:
  - name: db
    static: { host: "127.0.0.1", port: 5432 }
    tls: { mode: disable }
    login:
      method: password
      roles:
        app_ro: { password_file: /run/secrets/app_ro }
policies:
  - name: readers
    when: { issuer: idp, groups_any: ["readers"] }
    grant:
      backend: db
      databases: ["*"]
      pg_roles: ["app_ro"]
      default_pg_role: app_ro
"#
    .to_string()
}

fn problems(yaml: &str) -> Vec<String> {
    match Config::from_yaml_str(yaml) {
        Err(ConfigError::Invalid(p)) => p,
        Err(e) => panic!("expected validation error, got {e}"),
        Ok(_) => panic!("expected validation error, got Ok"),
    }
}

#[test]
fn example_config_is_valid() {
    let c = Config::from_yaml_str(EXAMPLE).expect("example config must be valid");
    assert_eq!(c.listeners.len(), 1);
    assert_eq!(c.identity_providers.len(), 3);
    let orders = c.backend("orders").expect("orders backend");
    assert_eq!(
        orders.host_port(),
        Some(("orders-db-rw.data.svc.cluster.local".to_string(), 5432))
    );
    assert_eq!(orders.pool.max_connections, 20);
    assert_eq!(orders.pool.acquire_timeout, Duration::from_secs(5));
    assert_eq!(c.session.token_expiry_grace, Duration::from_secs(300));
    let gh = c.identity_provider("github").expect("github idp");
    assert_eq!(
        gh.effective_issuer().as_deref(),
        Some("https://token.actions.githubusercontent.com")
    );
    let entra = c.identity_provider("entra").expect("entra idp");
    assert_eq!(entra.effective_claims().subject, "oid");
    assert_eq!(entra.effective_claims().scopes.as_deref(), Some("scp"));
    assert_eq!(c.deny[0].when.claims[0].equals, Some(serde_json::json!(1)));
}

#[test]
fn minimal_config_is_valid_and_defaults_apply() {
    let c = Config::from_yaml_str(&minimal()).expect("minimal config");
    assert_eq!(
        c.admin.address,
        Some(SocketAddr::from(([0, 0, 0, 0], 9090)))
    );
    assert_eq!(c.session.user_semantics, UserSemantics::Auto);
    assert_eq!(c.limits.max_auth_message_bytes, 16 * 1024);
    assert_eq!(c.backends[0].pool.mode, PoolMode::Session);
    assert_eq!(c.identity_providers[0].leeway, Duration::from_secs(60));
    assert_eq!(
        c.identity_providers[0].jwks.min_refresh_interval,
        Duration::from_secs(30)
    );
    assert!(c.propagation.set_gucs);
}

#[test]
fn unknown_fields_are_rejected() {
    let yaml = minimal().replace("kind: ProxyConfig", "kind: ProxyConfig\nlistenerz: []");
    assert!(matches!(
        Config::from_yaml_str(&yaml),
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn wrong_api_version_is_rejected() {
    let yaml = minimal().replace("pgbearer/v1alpha1", "pgbearer/v9");
    assert!(problems(&yaml).iter().any(|p| p.contains("apiVersion")));
}

#[test]
fn tls_required_unless_explicitly_insecure() {
    let yaml = minimal().replace("    insecure_allow_plaintext_auth: true\n", "");
    assert!(
        problems(&yaml)
            .iter()
            .any(|p| p.contains("tls is required"))
    );
}

#[test]
fn http_issuer_requires_opt_in() {
    let yaml = minimal().replace("https://idp.example.com", "http://idp.example.com");
    assert!(problems(&yaml).iter().any(|p| p.contains("must use https")));
    let yaml = yaml.replace(
        "    audiences: [\"pgbearer\"]",
        "    audiences: [\"pgbearer\"]\n    insecure_allow_http: true",
    );
    Config::from_yaml_str(&yaml).expect("http allowed with opt-in");
}

#[test]
fn grant_references_must_resolve() {
    let yaml = minimal()
        .replace(
            "backend: db\n      databases",
            "backend: nope\n      databases",
        )
        .replace("issuer: idp, groups_any", "issuer: missing, groups_any");
    let p = problems(&yaml);
    assert!(
        p.iter().any(|m| m.contains("unknown backend \"nope\"")),
        "{p:?}"
    );
    assert!(
        p.iter()
            .any(|m| m.contains("\"missing\" is not a configured identity provider")),
        "{p:?}"
    );
}

#[test]
fn roles_need_credentials() {
    let yaml = minimal().replace(
        "pg_roles: [\"app_ro\"]",
        "pg_roles: [\"app_ro\", \"admin\"]",
    );
    let p = problems(&yaml);
    assert!(
        p.iter()
            .any(|m| m.contains("no login credential for role \"admin\"")),
        "{p:?}"
    );
}

#[test]
fn default_role_must_be_granted() {
    let yaml = minimal().replace("default_pg_role: app_ro", "default_pg_role: other");
    assert!(
        problems(&yaml)
            .iter()
            .any(|p| p.contains("default_pg_role"))
    );
}

#[test]
fn entra_requires_tenants_and_specific_issuer() {
    let yaml = minimal().replace(
        "  - name: idp\n    issuer: \"https://idp.example.com/realms/main\"",
        "  - name: idp\n    type: entra\n    issuer: \"https://login.microsoftonline.com/common/v2.0\"",
    );
    let p = problems(&yaml);
    assert!(p.iter().any(|m| m.contains("requires tenants")), "{p:?}");
    assert!(p.iter().any(|m| m.contains("tenant-specific")), "{p:?}");
}

#[test]
fn backend_needs_exactly_one_endpoint() {
    let yaml = minimal().replace(
        "    static: { host: \"127.0.0.1\", port: 5432 }\n",
        "    static: { host: \"127.0.0.1\", port: 5432 }\n    cnpg: { cluster: c, namespace: n }\n",
    );
    assert!(
        problems(&yaml)
            .iter()
            .any(|p| p.contains("exactly one of static and cnpg"))
    );
}

#[test]
fn duplicate_names_are_reported() {
    let yaml = minimal().replace(
        "policies:\n",
        "policies:\n  - name: readers\n    grant: { backend: db, databases: [\"*\"], pg_roles: [\"app_ro\"] }\n",
    );
    assert!(
        problems(&yaml)
            .iter()
            .any(|p| p.contains("duplicate name \"readers\""))
    );
}

#[test]
fn claim_predicate_needs_a_condition() {
    let yaml = minimal().replace(
        "when: { issuer: idp, groups_any: [\"readers\"] }",
        "when: { issuer: idp, claims: [ { name: acct } ] }",
    );
    assert!(
        problems(&yaml)
            .iter()
            .any(|p| p.contains("needs one of equals"))
    );
}

#[test]
fn oauthbearer_listener_needs_provider() {
    let yaml = minimal().replace(
        "    insecure_allow_plaintext_auth: true",
        "    insecure_allow_plaintext_auth: true\n    client_auth: oauthbearer",
    );
    assert!(
        problems(&yaml)
            .iter()
            .any(|p| p.contains("requires oauthbearer_provider"))
    );
}

#[test]
fn credential_resolution_prefers_role_entries() {
    let login = BackendLoginConfig {
        method: LoginMethod::Cert,
        cert_file: Some("/a.crt".into()),
        key_file: Some("/a.key".into()),
        roles: BTreeMap::from([(
            "special".to_string(),
            RoleCredentialConfig {
                password_file: Some("/pw".into()),
                ..Default::default()
            },
        )]),
    };
    assert_eq!(
        login.credential_for("special"),
        Some(ResolvedCredential::Password {
            password_file: "/pw".into()
        })
    );
    assert_eq!(
        login.credential_for("anyone"),
        Some(ResolvedCredential::Cert {
            cert_file: "/a.crt".into(),
            key_file: "/a.key".into()
        })
    );
}

#[test]
fn cloudnativepg_example_values_config_is_valid() {
    #[derive(serde::Deserialize)]
    struct HelmValues {
        config: Config,
    }
    let text = include_str!("../../../deploy/examples/cloudnativepg/values.yaml");
    let values: HelmValues = serde_saphyr::from_str(text).expect("values.yaml parses");
    values.config.validate().expect("example config validates");
    let orders = values.config.backend("orders").expect("orders backend");
    assert_eq!(
        orders.tls_server_name().as_deref(),
        Some("orders-db-rw.data.svc.cluster.local")
    );
}
