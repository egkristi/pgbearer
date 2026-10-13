# Security policy

pgbearer is an authentication and authorization gateway, so we treat
security reports with priority.

## Supported versions

pgbearer has not had a release yet. Until `v1.0.0`, only the latest commit on
`main` and the most recent pre-release receive security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/egkristi/pgbearer/security/advisories/new)
for this repository. Include:

- the affected version or commit;
- a description of the issue and its impact (for example authentication
  bypass, privilege escalation, cross-session data exposure, denial of
  service);
- steps to reproduce, ideally with a minimal configuration and client
  commands;
- whether the issue is already public or known to others.

Never include real tokens, passwords, private keys or production data. Use
test tenants and generated credentials.

## What to expect

- Acknowledgement within 3 working days.
- An initial assessment (severity, affected versions) within 10 working days.
- We coordinate a fix and a disclosure date with you. The default embargo is
  90 days or until a fixed release is available, whichever comes first.
- Credit in the advisory and the changelog, unless you prefer otherwise.

## Scope

In scope: the `pgbearer` gateway, `pgbearerctl`, the Helm chart and the
container image published from this repository, and the documented example
configurations.

Out of scope: vulnerabilities in PostgreSQL, CloudNativePG, identity
providers or Kubernetes themselves (report those upstream), and findings that
require an attacker who already controls the gateway's configuration,
Kubernetes Secrets or the database administrator role (see the trust model in
[ARCHITECTURE.md §17](ARCHITECTURE.md#17-security-architecture) and the
[audit response](docs/reviews/2026-10-09-audit-response.md)).

## Automated scanning

Every push to `main`, every pull request and a daily schedule run:

| Scan | What it covers | Workflow |
|---|---|---|
| CodeQL | Rust source and the GitHub Actions workflows | repository code scanning (*default setup*) |
| cargo-deny | RustSec advisories, licences, banned crates (OpenSSL), sources | `ci.yml`, `security.yml` |
| Dependency review | New vulnerable dependencies in pull requests | `security.yml` |
| Trivy | `Cargo.lock` vulnerabilities, Dockerfile/Helm/Kubernetes misconfigurations, committed secrets, and the built container image | `security.yml` |
| zizmor | Workflow security (injection, permissions, credential persistence) | `security.yml` |
| TruffleHog | Verified secrets in the full git history | `security.yml` |
| OpenSSF Scorecard | Supply-chain practices | `scorecard.yml` |
| Dependabot | Version updates for Rust crates, GitHub Actions and the container base images | `dependabot.yml` |

Results appear under the repository's **Security** tab (code scanning).
CodeQL runs through GitHub's code scanning *default setup* (repository
settings; the *Extended* query suite is recommended), so there is no CodeQL
workflow file. Other repository settings that complement these files:
Dependabot alerts and security updates, secret scanning with push
protection, and private vulnerability reporting.

## Hardening guidance

The security-relevant defaults and their bounds (TLS requirements, token
lifetime caps, revocation deadlines, role reachability checks, PROXY protocol
trust) are documented in [ARCHITECTURE.md](ARCHITECTURE.md). Deployments that
change them should record why.
