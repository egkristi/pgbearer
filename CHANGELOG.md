# Changelog

All notable changes to pgbearer are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are gated by evidence (see [PLAN.md](PLAN.md#6-release-gates)), not
dates.

## [Unreleased]

### Added

- Project plan, architecture and README; Apache-2.0 licence; project name
  `pgbearer` (formerly *pgproxy*).
- Cargo workspace (edition 2024) with twelve crates, workspace-wide lints
  (`unsafe_code` forbidden) and centralised dependency versions.
- `pgbearer-core`: identity model, SQLSTATE codes, session ids, and one claim
  lookup shared by token validation and policy (literal name, dotted path or
  RFC 6901 JSON Pointer).
- `pgbearer-config`: typed `pgbearer/v1alpha1` configuration with semantic
  validation that reports every problem at once.
- `pgbearer-telemetry`: Prometheus metrics registry and structured logging.
- `pgbearer-audit`: versioned audit event schema with JSON-lines, memory and
  null sinks.
- `pgbearer-wire`: PostgreSQL protocol codec covering startup packets
  (protocol 3.0 and 3.2), SSL/GSS/cancel requests, direct-TLS detection,
  PROXY protocol v2, streaming header-only framing and typed messages.
- `pgbearer-tls`: rustls listener TLS (SSLRequest and direct TLS with ALPN
  `postgresql`, SNI capture, coherent hot reload, expiry metric) and backend
  TLS (`verify-full`/`verify-ca`/`require`, client certificates,
  `tls-server-end-point` channel binding data).
- `pgbearer-auth`: OIDC discovery with exact issuer matching, a JWKS cache
  (single-flight, rate-limited, atomic replacement, bounded staleness), JWT
  validation, claim mapping with presets for OIDC, Entra ID, Kubernetes and
  GitHub Actions, and the SASL OAUTHBEARER server exchange.
- CI (format, Clippy, tests against PostgreSQL 16/17/18, cargo-deny,
  container build, Helm lint), distroless container image, Helm chart,
  CloudNativePG example and guides for CNPG, Entra ID and local development.
- Analysis of the external design audit of 9 October 2026
  ([docs/reviews/2026-10-09-audit-response.md](docs/reviews/2026-10-09-audit-response.md)).
- Security scanning: CodeQL (code scanning default setup), daily RustSec
  advisories, dependency review on pull requests, Trivy (dependencies,
  Dockerfile/Helm/Kubernetes misconfigurations, secrets, container image),
  zizmor, TruffleHog and OpenSSF Scorecard; Dependabot for crates, actions
  and container images. `SECURITY.md` describes private vulnerability
  reporting and the scans.
- `pgbearer-policy`: a three-valued policy engine. A claim condition on a
  missing (or `null`) claim is *unknown*: grants match only when every
  condition is true, and deny rules fail closed (they also fire on unknown)
  unless they set `on_unknown: ignore`. Deny rules choose how a live session
  ends (`terminate: at_safe_point` or `immediate`). Matching grants merge
  independently of their order: the shortest lifetime, the strictest token
  expiry action, every per-identity session limit, and `session` pool mode
  over `transaction`. `explain` and `entitlements` support diagnostics, and
  property tests check that decisions do not depend on rule order.
- Role risk classes (`superuser`, `createrole`, `replication`, `bypassrls`,
  `server_files`, `admin_option`, `predefined_admin`, `database_owner`,
  `createdb`, `read_all`). A grant must acknowledge the risky
  capabilities its PostgreSQL role can reach with `acknowledged_role_risks`;
  grants for the same backend and role must acknowledge the same set.
- `required_claims` on identity providers: a token without one of the listed
  claims, or with a `null` value, is rejected. The examples use it so that
  deny rules on optional claims never see an unknown value.
- Configuration for TCP keepalive and `TCP_USER_TIMEOUT` on client and backend
  connections, server-side keepalive and `client_connection_check_interval`
  (sent as backend startup parameters), `backends[].cancel_endpoint`,
  `pool.reuse` (rejected until Phase 3a), `revocation.hard_timeout` (60 s) and
  `session.token_expiry_hard_timeout` (120 s).
- Entra ID token profiles (`token_profiles`): a token must match exactly one
  enabled profile, `delegated` (user tokens with `scp`) or `application`
  (app-only tokens with `idtyp: app` and app roles). Each profile fixes the
  identity kind and whether `required_scopes` applies.
- `identity_kind` declares whether a generic OIDC provider's tokens belong to
  people or workloads.
- `max_token_lifetime` per identity provider (default 24 hours, 1 hour for
  GitHub Actions, at most 7 days) bounds how long a stolen token can be
  replayed, even when the IdP issues long-lived tokens.
- `revoked_key_ids` per identity provider: tokens signed with a listed key are
  rejected at once, even while the IdP still publishes it.
- `Identity.key_id` records the `kid` of the key that verified the token.
- Interface contracts, not yet implemented, for the backend pool (connect,
  role inspection, leases, generations, cancel targets) and the session
  building blocks (startup profile, relay state, cancel registry, admission
  control).

### Changed

- The roadmap now follows evidence gates G0–G5. The MVP is a 1:1 session
  identity gateway; connection reuse is opt-in and transaction mode is
  experimental. The supported PostgreSQL baseline is 16+.
- Client startup settings are forwarded in the backend StartupMessage instead
  of being replayed with `SET`; cancellation uses poison-and-discard with a
  pinned physical endpoint; policy evaluation is three-valued and
  order-independent; revocation and token expiry have hard deadlines
  (architecture revision after the audit).
- `token_expiry_grace` defaults to 60 seconds.
- `max_connections_per_identity` is now
  `max_sessions_per_identity_per_replica`, which names what it counts and
  where. `allow_privileged_role: true` is deprecated; it acknowledges every
  role risk.
- CloudNativePG backends verify the TLS server name
  `<cluster>-<service>.<namespace>.svc` by default.
- Identity kinds are attested, never guessed: a generic OIDC token is
  `unknown` unless the provider sets `identity_kind` (a `scope` claim no
  longer makes it `human`), and an Entra token's kind comes from its profile.
- The GitHub Actions preset uses the immutable `repository_owner_id` as the
  tenant.
- The Helm chart mounts the configuration as a directory so hot reload works,
  rolls pods only for restart-required sections, uses a PDB with
  `maxUnavailable: 1`, and paces rollouts with `minReadySeconds`.

### Fixed

- CI: cargo-deny rejected the internal path dependencies as wildcards
  ([#3](https://github.com/egkristi/pgbearer/issues/3)); rustdoc failed on a
  link to the feature-gated `testing::MockIssuer`
  ([#4](https://github.com/egkristi/pgbearer/issues/4)); clippy failed on
  unimplemented stubs, and the CI toolchain is now pinned with a non-blocking
  latest-stable job ([#5](https://github.com/egkristi/pgbearer/issues/5)).

- A cancelled or failed `FrameReader` body operation could be retried and
  write the same bytes twice; the reader is now poisoned instead.
- `encode_startup_message` silently truncated values at NUL bytes; it now
  rejects NUL, empty names and packets over 10 000 bytes.
- Claim names containing dots (`kubernetes.io`, URL-style names) could not be
  addressed in policy.

### Removed

- `on_token_expiry: ignore`: sessions always end after their token expires
  (`terminate_when_idle` with a hard deadline, or `terminate`).
- `pool.reset_query`: connection reset will only ever use `DISCARD ALL`.

### Security

- `pool_mode: transaction` requires `experimental.transaction_pooling`.
- Entra tokens with a `nonce` claim (ID tokens) are rejected, and an
  identity provider's audience may not also be one of its
  `allowed_client_ids` (the client's own ID tokens would carry it).
- Discovery and JWKS requests follow redirects only within the same origin,
  so a redirect can neither send the bearer token elsewhere nor substitute
  another host's keys.
- Deny rules fail closed on unknown claims. A grant, or a deny rule without
  `on_unknown: ignore`, that tests groups, roles or scopes on a provider that
  does not map them is a configuration error.
- PROXY protocol requires a `trusted_proxies` list, so clients cannot forge
  their source address.
- Grants must name an issuer; per-grant session lifetimes may only shorten
  the global maximum.
- Kubernetes identity providers reject the API server's own audience.
- `limits.max_startup_packet_bytes` is capped at PostgreSQL's 10 000 bytes.
- Examples no longer use `pg_read_all_data` or an unrestricted HBA database
  column, and stay within PostgreSQL's connection budget.
