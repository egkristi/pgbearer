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
* PostgreSQL 16+ in the cluster image (for `+role` in `pg_ident`). On 14–15,
  list the roles explicitly in `pg_ident` instead.

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

* **Membership is transitive.** Never grant a pgbearer-reachable role to a
  privileged role, and never make superuser, `CREATEROLE`, `REPLICATION` or
  `BYPASSRLS` roles members of `pgbearer_login`. pgbearer also checks this at
  login and refuses privileged roles unless a grant sets
  `allow_privileged_role: true`.
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
* **Failover.** pgbearer connects to `orders-db-rw`. After a switchover,
  connections to the old primary fail and new ones go to the new primary.
  Watching the `Cluster` resource to drain pools proactively is on the
  roadmap (PLAN.md Phase 4).
* **Certificate rotation.** pgbearer reads client certificates from the
  mounted files on every new backend connection, so cert-manager renewals
  apply without restarts.
