# Local development

## Build and test

```bash
cargo build --workspace
cargo test --workspace            # unit tests + end-to-end tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

The end-to-end tests in `crates/pgbearer/tests` start a temporary PostgreSQL
cluster with `initdb`/`pg_ctl` and an in-process mock OIDC issuer. They look
for PostgreSQL binaries in `$PGBEARER_TEST_PG_BIN`, then in
`/usr/lib/postgresql/<version>/bin`, then on `PATH`. If none are found the
tests are skipped with a message.

## Run pgbearer against a local PostgreSQL

1. Start PostgreSQL and create a role with a password:

   ```sql
   CREATE ROLE app_ro LOGIN PASSWORD 'secret';
   GRANT pg_read_all_data TO app_ro;
   ```

2. Run an OIDC provider, for example Keycloak:

   ```bash
   docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
     -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.0 start-dev
   ```

   Create a realm `dev`, a client `pgbearer` with an audience mapper, and a user.

3. Write `pgbearer.yaml`:

   ```yaml
   apiVersion: pgbearer/v1alpha1
   kind: ProxyConfig
   listeners:
     - name: pg
       address: "127.0.0.1:6432"
       insecure_allow_plaintext_auth: true   # local development only
   identity_providers:
     - name: keycloak
       issuer: "http://localhost:8080/realms/dev"
       audiences: ["pgbearer"]
       insecure_allow_http: true             # local development only
   backends:
     - name: local
       static: { host: 127.0.0.1, port: 5432 }
       tls: { mode: disable }
       login:
         method: password
         roles:
           app_ro: { password_file: ./app_ro.password }
   policies:
     - name: everyone
       when: { issuer: keycloak }
       grant: { backend: local, databases: ["*"], pg_roles: ["app_ro"], default_pg_role: app_ro }
   logging: { format: pretty }
   ```

4. Run and connect:

   ```bash
   echo -n secret > app_ro.password
   cargo run -p pgbearer -- --config pgbearer.yaml
   TOKEN=$(curl -s -d grant_type=password -d client_id=pgbearer -d username=alice -d password=alice \
     http://localhost:8080/realms/dev/protocol/openid-connect/token | jq -r .access_token)
   PGPASSWORD=$TOKEN psql "host=127.0.0.1 port=6432 dbname=postgres user=app_ro"
   ```

`pgbearerctl explain --config pgbearer.yaml --token "$TOKEN"` shows how the
policy treats a token without connecting.
