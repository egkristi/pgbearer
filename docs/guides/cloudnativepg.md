# pgbearer with CloudNativePG

This guide puts pgbearer in front of a CloudNativePG (CNPG) cluster so people
and workloads log in with OIDC tokens and land in least-privilege roles. No
passwords are distributed.

The complete manifests are in
[`deploy/examples/cloudnativepg/`](../../deploy/examples/cloudnativepg/).

## How it fits together

```text
client --TLS + token--> pgbearer --TLS verify-full + client cert CN=pgbearer--> orders-db-rw
                         |                                                        |
                    policy: identity -> role                      pg_ident: pgbearer -> +pgbearer_login
```

* pgbearer holds **one** client certificate (`CN=pgbearer`) issued by the
  cluster's client CA.
* `pg_ident.conf` lets that certificate log in as any role that is a member of
  `pgbearer_login` (`+role` syntax, PostgreSQL 16+).
* The pgbearer policy decides which of those roles an identity gets.
* PostgreSQL GRANTs and RLS decide what the role may do.

## Prerequisites

* CloudNativePG 1.30+ (for `DatabaseRole`; 1.29+ for `podSelectorRefs`).
* cert-manager.
* PostgreSQL 16+ in the cluster image (pgbearer's supported baseline; also
  needed for `+role` in `pg_ident`).

## Steps

1. **Client CA and certificates.** `cluster.yaml` creates a cert-manager CA
   (`orders-db-client-ca`), the replication client certificate CNPG requires
   in user-provided CA mode, and pgbearer's client certificate
   (`pgbearer-orders-client`, `CN=pgbearer`).
2. **Cluster.** `spec.certificates.clientCASecret` points at the cert-manager
   CA. `pg_ident` and `pg_hba` allow certificate logins for
   `+pgbearer_login` only from pgbearer pods (`${podselector:pgbearer}`) and
   reject every other login attempt for those roles.
3. **Roles.** `DatabaseRole` resources create `pgbearer_login` (no login, no
   privileges) and the reachable roles `orders_readonly`, `orders_app` and
   `orders_owner`, which are members of it.
4. **pgbearer.** Install the Helm chart in the same namespace with
   `values.yaml`. It mounts the CNPG server CA (`orders-db-ca`, key `ca.crt`)
   for `verify-full` and the client certificate Secret.

```bash
kubectl apply -f deploy/examples/cloudnativepg/cluster.yaml
helm install pgbearer deploy/helm/pgbearer -n data -f deploy/examples/cloudnativepg/values.yaml
kubectl -n data rollout status deploy/pgbearer
```

## Things to know

* **What a role can reach matters, not just its attributes.** Membership can
  allow `SET ROLE` into a privileged role, inherited memberships carry
  privileges, and ADMIN OPTION lets a role grant itself another role. Keep
  `pgbearer_login` empty (no privileges, no ownership, member of nothing),
  never make privileged roles members of it, and avoid predefined roles such
  as `pg_read_all_data` or `pg_signal_backend` for mapped roles; grant
  schema-level privileges instead. pgbearer walks the reachable roles on every
  backend connection and refuses risky ones unless a grant lists them in
  `acknowledged_role_risks` (ARCHITECTURE §9.2). Writers of `Cluster` and
  `DatabaseRole` objects are superuser-equivalent.
* **Restrict the database column.** The example HBA line allows every
  database; use the database name (`hostssl orders +pgbearer_login …`) so a
  stolen gateway certificate cannot reach other databases.
* **Connection budget.** Set `max_connections` explicitly and size
  `pool.max_backend_connections` with the per-instance formula in
  ARCHITECTURE §10.3, counting the HPA maximum, rollout surge and draining
  pods. Set `client_connection_check_interval` (for example `10s`) so
  PostgreSQL stops work promptly when pgbearer closes a session.
* **The CNPG app secret stops working for these roles.** The `reject` rule
  blocks password logins for every member of `pgbearer_login`, including the
  bootstrap owner. Remove the `reject` line if some applications must keep
  using CNPG-generated passwords.
* **Different namespaces.** A namespaced cert-manager `Issuer` can only issue
  certificates in its own namespace. To run pgbearer elsewhere, use a
  `ClusterIssuer` and distribute the CA certificate to the cluster namespace
  (for example with trust-manager), or replicate the client certificate Secret.
  `podSelectorRefs` only works within the same namespace; use a CIDR or a
  NetworkPolicy instead.
* **Failover.** pgbearer connects to `orders-db-rw` and checks after every
  connect that it reached a primary. After a switchover, connections to the
  old primary fail and new ones go to the new primary. A client whose request
  was in flight gets `08007` ("outcome unknown"): its COMMIT may have
  completed, so applications should use idempotency keys or reconcile rather
  than blindly retry. Watching the `Cluster` resource to close old-primary
  sessions proactively is on the roadmap (PLAN.md Phase 4).
* **Certificate rotation is not revocation.** pgbearer reads client
  certificates from the mounted files on every new backend connection, so
  cert-manager renewals apply without restarts. A reissued Secret does not
  invalidate a stolen older certificate from the same CA: remove the role or
  HBA access, or rotate the CA, to revoke.
