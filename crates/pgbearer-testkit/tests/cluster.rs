//! Integration tests: start real throwaway clusters and log in over TLS with
//! a client certificate and with SCRAM. Skipped when PostgreSQL is not
//! installed (see `pgbearer_testkit::pg_available`).

#![allow(clippy::unwrap_used)]

use pgbearer_testkit::role_graph::{self, APP, BYPASS_ROLE, OWNER_ROLE, PLAIN, READER, SUPER_GRP};
use pgbearer_testkit::{CERT_USER, PgCluster, PgOptions, create_role_graph, require_pg};
use tokio_postgres::Client;

/// `(current_user, ssl, client_dn)` of the connection.
async fn whoami(client: &Client) -> (String, bool, Option<String>) {
    let row = client
        .query_one(
            "SELECT current_user::text, s.ssl, s.client_dn \
             FROM pg_catalog.pg_stat_ssl s WHERE s.pid = pg_catalog.pg_backend_pid()",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

async fn started() -> PgCluster {
    let cluster = PgCluster::start(PgOptions::default())
        .await
        .unwrap_or_else(|e| panic!("start cluster: {e}"));
    create_role_graph(&cluster.admin().await.unwrap())
        .await
        .unwrap_or_else(|e| panic!("create role graph: {e}\n{}", cluster.log_contents()));
    cluster
}

#[tokio::test]
async fn tls_client_certificate_and_scram_logins() {
    require_pg!();
    let cluster = started().await;
    assert!(
        cluster.version_num() >= 160_000,
        "{}",
        cluster.version_num()
    );
    assert_eq!(cluster.host(), "127.0.0.1");
    assert!(cluster.ca_cert_path().is_file());
    assert!(cluster.server_cert_path().is_file());
    assert!(cluster.server_key_path().is_file());

    // Client certificate CN=pgbearer, mapped to `plain` (member of
    // pgbearer_login); the server is verified against the generated CA for
    // 127.0.0.1 (IP SAN).
    let client = cluster
        .connect_tls(&cluster.tcp_config(PLAIN), Some(CERT_USER))
        .await
        .unwrap();
    let (user, ssl, dn) = whoami(&client).await;
    assert_eq!(user, PLAIN);
    assert!(ssl);
    assert_eq!(dn.as_deref(), Some("/CN=pgbearer"));

    // Same through the DNS name `localhost` (verify-full on the DNS SAN).
    let by_name = cluster.tcp_config_with_host(APP, "localhost");
    let client = cluster
        .connect_tls(&by_name, Some(CERT_USER))
        .await
        .unwrap();
    assert_eq!(whoami(&client).await.0, APP);

    // The server name is verified too (verify-full): a name outside the
    // certificate's SANs is rejected by the client.
    let err = cluster
        .connect_tls(
            &cluster.tcp_config_with_host(PLAIN, "not-localhost.invalid"),
            Some(CERT_USER),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("certificate"), "{err}");

    // A certificate with another CN is not mapped.
    let err = cluster
        .connect_tls(&cluster.tcp_config(PLAIN), Some("someone-else"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("certificate"), "{err}");

    // pgbearer_login members cannot log in over TLS without a certificate,
    // even with the right password.
    let mut no_cert = cluster.tcp_config(PLAIN);
    no_cert.password(role_graph::password(PLAIN));
    assert!(cluster.connect_tls(&no_cert, None).await.is_err());

    // SCRAM over TLS (channel binding available) for roles outside
    // pgbearer_login.
    for role in [READER, OWNER_ROLE] {
        let mut config = cluster.tcp_config(role);
        config.password(role_graph::password(role));
        let client = cluster.connect_tls(&config, None).await.unwrap();
        let (user, ssl, dn) = whoami(&client).await;
        assert_eq!(user, role);
        assert!(ssl);
        assert_eq!(dn, None);
    }

    // SCRAM over plain TCP, for every LOGIN role.
    for role in role_graph::LOGIN_ROLES {
        let mut config = cluster.tcp_config(role);
        config.password(role_graph::password(role));
        let client = cluster.connect_plain(&config).await.unwrap();
        let (user, ssl, _) = whoami(&client).await;
        assert_eq!(user, role);
        assert!(!ssl);
    }

    // A wrong password is rejected.
    let mut wrong = cluster.tcp_config(READER);
    wrong.password("not-the-password");
    assert!(cluster.connect_tls(&wrong, None).await.is_err());

    // Client certificate files can be minted for any CN.
    let (cert, key) = cluster.client_cert("some user/with odd chars").unwrap();
    assert!(cert.is_file() && key.is_file());

    assert!(cluster.log_contents().contains("connection authorized"));

    let addr = cluster.addr();
    let root = cluster.data_dir().parent().unwrap().to_path_buf();
    cluster.stop().await.unwrap();
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    assert!(!root.exists(), "temporary directory removed");
}

#[tokio::test]
async fn role_graph_escalation_paths_work() {
    require_pg!();
    let cluster = started().await;

    // `app` inherits nothing from super_grp but can SET ROLE to it.
    let app = cluster
        .connect_tls(&cluster.tcp_config(APP), Some(CERT_USER))
        .await
        .unwrap();
    let row = app
        .query_one(
            "SELECT pg_has_role($1, 'USAGE'), pg_has_role($1, 'SET'), \
                    pg_has_role($2, 'USAGE'), pg_has_role('pg_signal_backend', 'USAGE')",
            &[&SUPER_GRP, &BYPASS_ROLE],
        )
        .await
        .unwrap();
    let flags: (bool, bool, bool, bool) = (row.get(0), row.get(1), row.get(2), row.get(3));
    assert_eq!(flags, (false, true, false, true));
    app.batch_execute(&format!("SET ROLE {SUPER_GRP}"))
        .await
        .unwrap();
    let su: String = app
        .query_one("SELECT current_setting('is_superuser')", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(su, "on");
    app.batch_execute("RESET ROLE").await.unwrap();

    // The ADMIN option held by adm_holder lets `app` grant itself BYPASSRLS.
    app.batch_execute(&format!("GRANT {BYPASS_ROLE} TO {APP}"))
        .await
        .unwrap();
    app.batch_execute(&format!("SET ROLE {BYPASS_ROLE}"))
        .await
        .unwrap();
    let bypass: bool = app
        .query_one(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(bypass);

    // `plain` reaches nothing risky.
    let plain = cluster
        .connect_tls(&cluster.tcp_config(PLAIN), Some(CERT_USER))
        .await
        .unwrap();
    assert!(
        plain
            .batch_execute(&format!("SET ROLE {SUPER_GRP}"))
            .await
            .is_err()
    );

    // owner_role owns owner_db; reader can read everything.
    let admin = cluster.admin().await.unwrap();
    let owner: String = admin
        .query_one(
            "SELECT pg_get_userbyid(datdba)::text FROM pg_database WHERE datname = $1",
            &[&role_graph::OWNED_DATABASE],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(owner, OWNER_ROLE);
    let reads: bool = admin
        .query_one(
            "SELECT pg_has_role($1, 'pg_read_all_data', 'USAGE')",
            &[&READER],
        )
        .await
        .unwrap()
        .get(0);
    assert!(reads);
}

#[tokio::test]
async fn extra_options_are_applied() {
    require_pg!();
    let cluster = PgCluster::start(
        PgOptions::new()
            .conf("work_mem = '7MB'")
            // Placed before the defaults, so it wins over the scram rules.
            .hba("hostssl all trusted_tls 127.0.0.1/32 trust")
            .sql("CREATE ROLE trusted_tls LOGIN")
            .sql("CREATE DATABASE extra_db"),
    )
    .await
    .unwrap();

    let client = cluster
        .connect_tls(&cluster.tcp_config("trusted_tls"), None)
        .await
        .unwrap();
    let work_mem: String = client.query_one("SHOW work_mem", &[]).await.unwrap().get(0);
    assert_eq!(work_mem, "7MB");

    let mut config = cluster.admin_config();
    config.dbname("extra_db");
    let (db, conn) = config.connect(tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    db.simple_query("SELECT 1").await.unwrap();

    cluster.exec("CREATE TABLE t (x int)").await.unwrap();
    // Dropping without stop() stops the server too.
    let root = cluster.data_dir().parent().unwrap().to_path_buf();
    drop(cluster);
    assert!(!root.exists());
}
