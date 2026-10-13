//! A ready-made role graph for backend role-safety tests.
//!
//! [`create_role_graph`] creates these roles (PostgreSQL 16 membership
//! options):
//!
//! ```text
//! app (LOGIN) ── SET only ──▶ mid ── SET only ──▶ super_grp (SUPERUSER)
//!   │
//!   ├─ INHERIT only ──▶ adm_holder ── ADMIN only ──▶ rls_bypass (BYPASSRLS)
//!   ├─ pg_signal_backend
//!   └─ pgbearer_login
//!
//! plain (LOGIN) ──▶ pgbearer_login                       (no risks)
//! owner_role (LOGIN), owner of database owner_db
//! reader (LOGIN) ──▶ pg_read_all_data
//! ```
//!
//! So `app` can `SET ROLE super_grp` (superuser) although it inherits none
//! of its privileges, can `GRANT rls_bypass TO app` through the ADMIN option
//! held by `adm_holder`, and can signal other backends.
//!
//! Every LOGIN role gets the SCRAM password [`password`]`(role)`
//! (`pw-<role>`). With the cluster's `pg_hba.conf`, members of
//! `pgbearer_login` (`app`, `plain`) log in over TLS with a client
//! certificate whose CN is [`crate::CERT_USER`]; `owner_role` and `reader`
//! log in over TLS with SCRAM. Over plain TCP every LOGIN role uses SCRAM.

use tokio_postgres::Client;

use crate::{LOGIN_GROUP, TestkitError};

/// LOGIN role reaching SUPERUSER, BYPASSRLS (via ADMIN) and
/// `pg_signal_backend`; member of [`LOGIN_GROUP`].
pub const APP: &str = "app";
/// LOGIN role without any risky privileges; member of [`LOGIN_GROUP`].
pub const PLAIN: &str = "plain";
/// LOGIN role owning the database [`OWNED_DATABASE`].
pub const OWNER_ROLE: &str = "owner_role";
/// LOGIN role that is a member of `pg_read_all_data`.
pub const READER: &str = "reader";
/// NOLOGIN role between [`APP`] and [`SUPER_GRP`] (SET-only edges).
pub const MID: &str = "mid";
/// NOLOGIN SUPERUSER role reachable from [`APP`] with `SET ROLE` only.
pub const SUPER_GRP: &str = "super_grp";
/// NOLOGIN role holding ADMIN OPTION on [`BYPASS_ROLE`]; [`APP`] inherits
/// from it.
pub const ADM_HOLDER: &str = "adm_holder";
/// NOLOGIN BYPASSRLS role that [`APP`] can grant itself.
pub const BYPASS_ROLE: &str = "rls_bypass";
/// Database owned by [`OWNER_ROLE`].
pub const OWNED_DATABASE: &str = "owner_db";
/// Every LOGIN role of the graph.
pub const LOGIN_ROLES: [&str; 4] = [APP, PLAIN, OWNER_ROLE, READER];

/// The SCRAM password of a LOGIN role of the graph: `pw-<role>`.
pub fn password(role: &str) -> String {
    format!("pw-{role}")
}

/// Create the role graph described in the [module documentation](self)
/// through `client`, which must be connected as a superuser (for example
/// [`crate::PgCluster::admin`]). Creates [`LOGIN_GROUP`] when it does not
/// exist yet. Fails if any other role of the graph already exists.
pub async fn create_role_graph(client: &Client) -> Result<(), TestkitError> {
    let roles = format!(
        "DO $$ BEGIN \
           IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{LOGIN_GROUP}') THEN \
             CREATE ROLE {LOGIN_GROUP} NOLOGIN; \
           END IF; \
         END $$; \
         CREATE ROLE {SUPER_GRP} NOLOGIN SUPERUSER; \
         CREATE ROLE {MID} NOLOGIN; \
         CREATE ROLE {BYPASS_ROLE} NOLOGIN BYPASSRLS; \
         CREATE ROLE {ADM_HOLDER} NOLOGIN; \
         CREATE ROLE {APP} LOGIN PASSWORD '{app_pw}'; \
         CREATE ROLE {PLAIN} LOGIN PASSWORD '{plain_pw}'; \
         CREATE ROLE {OWNER_ROLE} LOGIN PASSWORD '{owner_pw}'; \
         CREATE ROLE {READER} LOGIN PASSWORD '{reader_pw}'; \
         GRANT {LOGIN_GROUP} TO {APP}, {PLAIN}; \
         GRANT {SUPER_GRP} TO {MID} WITH INHERIT FALSE, SET TRUE; \
         GRANT {MID} TO {APP} WITH INHERIT FALSE, SET TRUE; \
         GRANT {BYPASS_ROLE} TO {ADM_HOLDER} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; \
         GRANT {ADM_HOLDER} TO {APP} WITH INHERIT TRUE, SET FALSE; \
         GRANT pg_signal_backend TO {APP}; \
         GRANT pg_read_all_data TO {READER};",
        app_pw = password(APP),
        plain_pw = password(PLAIN),
        owner_pw = password(OWNER_ROLE),
        reader_pw = password(READER),
    );
    client.batch_execute(&roles).await?;
    // CREATE DATABASE cannot run inside the implicit transaction of a
    // multi-statement query.
    client
        .batch_execute(&format!(
            "CREATE DATABASE {OWNED_DATABASE} OWNER {OWNER_ROLE}"
        ))
        .await?;
    Ok(())
}
