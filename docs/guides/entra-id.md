# pgbearer with Microsoft Entra ID

This guide configures Entra ID so people (and Azure workloads) can connect to
PostgreSQL through pgbearer with Entra access tokens.

## 1. Register the API (`pgbearer`)

In the Entra admin center, under **App registrations**, create **pgbearer**:

1. **Expose an API**: set the Application ID URI to `api://pgbearer` (or
   `api://<client-id>` if your tenant policy requires it). Add a delegated
   scope `Database.Connect`.
2. **App roles**: create roles for access levels, for example
   `Orders.Analyst` and `Orders.Owner`, with allowed member types
   *Users/Groups* and *Applications*.
3. **Manifest**: set `api.requestedAccessTokenVersion` to `2`
   (`accessTokenAcceptedVersion` in the legacy manifest). v1 tokens have issuer
   `https://sts.windows.net/<tid>/` and will be rejected.
4. **Enterprise application → Properties**: set *Assignment required* to
   **Yes**, then assign users and groups to the app roles. Only assigned
   principals can get tokens at all.
5. Optional: under **Token configuration**, emit the groups claim for
   "Groups assigned to the application" (avoids the 200-group overage), and add
   the optional claim `acct` if you want to deny guests.

Note the **Application (client) ID**: with v2 tokens it is the `aud` claim.

## 2. Configure pgbearer

```yaml
identity_providers:
  - name: entra
    type: entra
    issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
    audiences: ["<pgbearer-api-client-id>"]
    tenants: ["<tenant-id>"]
    required_scopes: ["Database.Connect"]

policies:
  - name: orders-analysts
    when: { issuer: entra, roles_any: ["Orders.Analyst"] }
    grant:
      backend: orders
      databases: ["orders"]
      pg_roles: ["orders_readonly"]
      default_pg_role: orders_readonly

deny:
  - name: no-guests
    when:
      issuer: entra
      claims: [{ name: acct, equals: 1 }]
```

pgbearer uses `oid` as the subject (immutable) and `preferred_username` only
for display and audit. App-only tokens (`idtyp: app`) are classified as
workloads and are exempt from `required_scopes`, because they carry app
`roles` instead of scopes.

## 3. Connect as a person

**With the Azure CLI.** Under **Expose an API → Authorized client
applications**, add the Azure CLI client ID
`04b07795-8ddb-461a-bbee-02f9e1bf7b46` for the `Database.Connect` scope. Then:

```bash
export PGPASSWORD=$(az account get-access-token \
    --scope api://pgbearer/Database.Connect --query accessToken -o tsv)
psql "host=orders.db.example.com dbname=orders user=orders_readonly sslmode=verify-full"
```

**With pgbearerctl (device code).** Register a public client application
`pgbearer-cli`: enable *Allow public client flows*, and add the API permission
`api://pgbearer/Database.Connect` with admin consent. Then:

```bash
export PGPASSWORD=$(pgbearerctl token \
    --issuer https://login.microsoftonline.com/<tenant-id>/v2.0 \
    --client-id <pgbearer-cli-client-id> \
    --scope api://pgbearer/Database.Connect)
psql "host=orders.db.example.com dbname=orders user=orders_readonly sslmode=verify-full"
```

The `user` parameter selects one of your entitled roles. Use your UPN or `*`
to get the grant's default role.

## 4. Connect as a workload on AKS

Pods with Azure Workload Identity request a token for
`api://pgbearer/.default` with the client-credentials flow. The token carries
the app roles assigned to the managed identity or service principal, so grant
on `roles_any`. For workloads in the same Kubernetes cluster, the
`kubernetes` issuer type (projected ServiceAccount tokens) is simpler and
needs no Entra configuration.

## Token lifetime

Entra access tokens live 60–90 minutes. By default pgbearer closes a session
at its next idle point after the token expires plus 5 minutes of grace
(`session.on_token_expiry: terminate_when_idle`). Connection pools in
applications reconnect with a fresh token.
