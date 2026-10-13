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
5. Under **Token configuration**, add the optional access-token claim
   **`idtyp`**: it is how pgbearer recognises application (workload) tokens.
   Optionally emit the groups claim for "Groups assigned to the application"
   (avoids the 200-group overage), and add the optional claim `acct` if you
   want to deny guests.
6. Use a **separate** app registration for any public client (such as
   `pgbearer-cli`), so its ID tokens never carry the API's audience.

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
      kind: human
      claims: [{ name: acct, equals: 1 }]
```

pgbearer uses `oid` as the subject (immutable) and `preferred_username` only
for display and audit. Every token must match exactly one of the provider's
`token_profiles` (default: both):

* **`delegated`** (a signed-in user): a non-empty `scp` claim, and `idtyp`
  absent or `user`. `required_scopes` applies, so it must name the API's
  delegated permission (`Database.Connect`). Kind: human.
* **`application`** (client credentials, managed identities): `idtyp: app`,
  no `scp`, and at least one app role in `roles`. `required_scopes` does not
  apply. Kind: workload. An app-only token without `idtyp` matches neither
  profile and is rejected, so enable the optional claim before onboarding
  workloads.

Set `token_profiles: [delegated]` if workloads must not use this provider.
ID tokens (they carry a `nonce` claim) are always rejected, and tokens may live
at most `max_token_lifetime` (default 24 h).

Deny rules fail closed: a user token without `acct` matches `no-guests` (the
claim is unknown) unless the rule sets `on_unknown: ignore`, so enable the
optional claim first. `kind: human` keeps the rule away from app-only tokens,
which never carry `acct`. If the provider accepts only people
(`token_profiles: [delegated]`), you can instead list `acct` in
`required_claims`, so tokens without it are rejected at login with a clear
reason (this is what [the example configuration](../../deploy/examples/pgbearer.yaml)
does).

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
at its next idle point after the token expires plus 60 seconds of grace
(`session.on_token_expiry: terminate_when_idle`), and in any case 120 seconds
later (`token_expiry_hard_timeout`), even if the session never goes idle.
Connection pools in applications must obtain a fresh token for every new
physical connection (a password callback) and keep their maximum connection
lifetime shorter than the token lifetime.

Removing a user's app-role assignment in Entra does not change tokens already
issued: pgbearer validates tokens locally, so such a change takes effect when
the token expires (at most `max_token_lifetime`) plus the grace and hard
timeout. For immediate offboarding add a `deny` rule for the user's `oid`;
pgbearer then ends their sessions within `revocation.hard_timeout`
(60 seconds by default) after the configuration reaches the pods.
