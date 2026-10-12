# Response to the design audit of 9 October 2026

> Status: **analysis complete, decisions proposed** (12 October 2026).
> Subject: *pgbearer design review and audit — 9 October 2026* (external,
> findings F01–F22, appendices A–D).
> Repository state analysed: branch `claude/stoic-galileo-c8wu2s` at commit
> `eed172a` (about 16 400 lines of Rust, 284 passing tests).

This document records how pgbearer responds to the external audit: which
claims hold, where the audit is wrong or incomplete, what we found that it did
not, and what changes in the plan and the implementation. The audit is treated
as a set of claims to verify, not as instructions. Decisions marked
**proposed** are the maintainers' recommended defaults. They are implemented
unless the project owner overrides them (see [§8](#8-owner-decisions)).

## Contents

1. [Summary](#1-summary)
2. [Scope and method](#2-scope-and-method)
3. [Verdicts at a glance](#3-verdicts-at-a-glance)
4. [Findings in detail](#4-findings-in-detail)
5. [Issues the audit did not raise](#5-issues-the-audit-did-not-raise)
6. [Validation plan and release gates](#6-validation-plan-and-release-gates)
7. [Proposed ADRs (appendices C and D)](#7-proposed-adrs-appendices-c-and-d)
8. [Owner decisions](#8-owner-decisions)
9. [Consequences for the plan and the implementation](#9-consequences-for-the-plan-and-the-implementation)

---

## 1. Summary

**The audit is accurate and timely, and its central recommendation is
accepted.** pgbearer is first delivered as a 1:1 *session identity gateway*.
Connection reuse, transaction pooling, cross-replica cancellation and native
OAuth each follow behind their own evidence gate.

Every one of the 22 findings holds up against primary sources: PostgreSQL 18
source and documentation, libpq, the CloudNativePG 1.30 and Kubernetes
documentation, and the current code. None is rejected.

* **Valid as written: 13** (F02, F03, F07, F08, F09, F10, F11, F12, F14,
  F15, F16, F18, F19). Several need sharper remedies; see §4.
* **Valid, with a remedy that is insufficient: 1** (F01). The audit's fixes,
  fresh connections and `set_config`, do not restore startup defaults. Only
  forwarding the settings in the backend StartupMessage does.
* **Valid, but partly addressed by code written after the audited commit: 4**
  (F05, F06, F13, F17).
* **Valid, with a corrected claim: 2** (F04, F21). F04's "Cartesian
  expansion" concern is already prevented by the policy contract.
* **Partially accepted: 2** (F20, F22). We accept the sequencing and the
  provenance corrections. We do not accept merging the existing crates.

The audit reviewed commit `7023ed0`, which contained only documents. Since
then the configuration model, the wire codec, token validation, TLS,
telemetry and the audit event types have been implemented. The pool, session,
policy and server crates are still stubs, but their *documented contracts*
already encoded several of the designs the audit warns about:

* `SET` replay of startup settings;
* a 200 ms cancel delay;
* an attribute-only role check;
* first-wins policy merging;
* a silent fallback from transaction to session mode;
* a free-form reset query.

Those crates are next in the build order, so the fixes cost little now and a
great deal later.

The ten changes with the largest effect:

1. **Forward client startup settings in the backend StartupMessage.** Never
   replay them with `SET` (F01, plus a new list-quoting bug). The gateway's
   internal queries become fully schema-qualified.
2. **No backend reuse by default.** Reuse becomes opt-in and is keyed by
   generation, backend, database, role and startup profile (F01, F07). Under
   this default the cancel race (F02) and most of F07 do not arise in the
   pilot.
3. **An explicit relay-state predicate decides "safe point" and "reusable".**
   It replaces "the last ReadyForQuery was `I`". It tracks expected
   ReadyForQuery messages, an open extended-protocol batch, COPY state,
   partial frames and flushed writers (F12). This also matters in session
   mode, for idle timeout, drain and expiry.
4. **Cancel poisons the lease; a poisoned lease is discarded.** The physical
   endpoint is pinned through `inet_server_addr()` and `pg_backend_pid()`;
   there is no timer (F02, ADR-005).
5. **Role reachability, not role attributes.** A recursive SET/INHERIT/ADMIN
   walk classifies risks, which grants must acknowledge explicitly. It is
   re-checked with a TTL (F03).
6. **Bounded revocation and expiry.** Policy generations and re-evaluation
   of active sessions; hard deadlines (expiry grace 60 s plus 120 s, local
   revocation 60 s); cancel before forced close; deny rules that fail
   closed on unknown data; order-independent merging (F04, ADR-014).
7. **Phase-aware failure reporting.** "Outcome unknown" (`08007`) when a
   request is in flight, never `57P01`. TCP keepalives and server-side
   connection checks. Old-primary sessions are closed on failover (F14).
8. **Honest capacity.** Count limits are per replica and named that way; the
   examples stay within PostgreSQL's connection budget; buffers are lazy;
   rollouts are paced (F09, F19).
9. **Trust planes.** The PROXY header is accepted only from configured
   trusted proxies. Admin mutations move to a local Unix socket. Peers use
   mTLS. The ConfigMap is mounted as a directory so hot reload works (F08,
   F17, plus a new issue).
10. **Scope and baseline.** PostgreSQL 16+; transaction pooling is
    experimental behind a flag; the README stops advertising unbuilt
    features; release gates G0–G5 replace date-driven milestones (F11, F18,
    F20).

The analysis also found **45 issues the audit did not raise** (§5). Eight are
rated high, among them:

* the `SET` list-quoting bug for `search_path`;
* the commit hazard of an extended batch left open without Sync;
* deny rules that fail open on unknown claims;
* the Helm `subPath` mount that disables hot reload;
* forced termination that does not stop backend work;
* shipped examples that already exceed PostgreSQL's connection capacity;
* no TCP keepalive anywhere.

## 2. Scope and method

* **Baseline.** The audit's findings were re-evaluated against the current
  tree, not the documents-only commit it reviewed. Each finding records its
  *current state*.
* **Primary sources:**
  * PostgreSQL `REL_18_STABLE` source: `guc.c`, `guc_funcs.c`,
    `postinit.c`, `postgres.c`, `xact.c`, `plancache.c`, `pqcomm.h`;
  * the PostgreSQL 18 SGML documentation (protocol, client authentication,
    configuration, functions) and libpq (`fe-connect.c`, `fe-cancel.c`);
  * Npgsql source (startup parameters and reset behaviour);
  * CloudNativePG 1.30 documentation;
  * Kubernetes documentation (Deployments, DNS, ServiceAccount tokens).
* **Reproductions:**
  * The `FrameReader::copy_body` cancellation defect, using a scratch crate
    with a writer that accepts 3 bytes and then stalls.
  * The F03 privilege paths on a scratch PostgreSQL 16.15 cluster: SET-only
    chains to SUPERUSER, inherit-only BYPASSRLS, and ADMIN self-grant.
  * No repository files were changed for either.
* **Limits.**
  * No Entra ID tenant, AKS cluster or CNPG cluster was available. Entra and
    CNPG behaviour comes from vendor documentation.
  * Claims that could not be confirmed are marked *unverified*.
  * No performance measurement exists yet. All performance numbers remain
    goals.

## 3. Verdicts at a glance

Priorities follow the audit's convention: **P0** = settle before
implementing the affected boundary, **P1** = before a multi-user pilot,
**P2** = before beta/GA. "Ours" is the priority after analysis.

| ID | Topic | Audit | Verdict | Ours | State in the current tree | Main action |
|---|---|---|---|---|---|---|
| F01 | Startup settings and reset | P0 | Valid; remedy insufficient | P0 | Pool/session contracts use `SET` replay | Startup forwarding; profile filter; no reuse by default |
| F02 | Cancel ownership and endpoint | P0 | Valid | P0 | Contract still has a 200 ms delay; no physical endpoint | Poison-and-discard; endpoint pinning; ADR-005 |
| F03 | Effective privileges | P0 | Valid | P0 | Attribute-only check in the pool contract | Reachability query; acknowledged risks; TTL recheck |
| F04 | Revocation and expiry | P0 | Valid (one clause moot) | P0 | No generations, no hard deadlines; deny fails open | Re-evaluation, deadlines, three-valued deny, ADR-014 |
| F05 | Entra token classes | P0 | Valid; partly addressed | P0 | `idtyp`-based split exists; profiles implicit | Explicit token profiles; ID-token and audience rules |
| F06 | Token and key trust | P0 | Valid; mostly addressed | P1 | Exact issuer, https, caps, atomic swap and stale bound done | Max token lifetime, same-origin redirects, key purge |
| F07 | Pool generations and reload | P0 | Valid | P0 (subset) | Backend changes need a restart; not observable | Generation in the pool API; re-evaluation; purge |
| F08 | PROXY, peers, admin | P1 | Valid | P1 | `proxy_protocol: optional` in the example; no trust list | Trusted proxies; admin over a Unix socket; peer mTLS |
| F09 | Capacity and quotas | P1 | Valid; understated | P1 | Examples over budget at steady state | Per-instance formula; renames; chart check; pacing |
| F10 | Audit guarantees | P1 | Valid | P0 ids / P1 delivery | Ids missing; sink blocks the runtime | Lease and physical ids; async sink; delivery classes |
| F11 | Transaction semantics | P0 | Valid | P0 (gate) | Accepted by config, silently degraded | Experimental flag; identity-scoped; ADR-010 first |
| F12 | Relay progress and safe detach | P0 | Valid; understated | P0 | Contract uses the RFQ status only; `copy_body` defect | Relay-state predicate; poisoning; V32–V35 earlier |
| F13 | CNPG HBA selector | P1 | Valid; mostly addressed | P1 | Example now has a selector plus a reject guard | Restrict the database column; verify rendered HBA |
| F14 | Failover and outcomes | P1 | Valid | P0/P1 | No phase classification, keepalives or suitability check | `08007`; keepalives; suitability; old-primary close |
| F15 | Kubernetes identity | P1 | Valid | P1 | JWKS mode only; audience not checked for misuse | Dedicated audience; lifetime cap; UID; doc limits |
| F16 | GitHub Actions trust | P1 | Valid | P1 | Preset keys on the mutable owner name; example uses `sub` only | Immutable IDs; workflow/ref/environment in grants |
| F17 | PKI lifecycle | P1 | Valid; partly addressed | P1 | Coherent reload with last-good and expiry metric done | Revocation ≠ reissue docs; CA key boundary; no subPath |
| F18 | Support and compatibility | P2 | Valid | P1 (baseline) | CI tests PostgreSQL 14; README "any client" | PostgreSQL 16+; pinned matrix; accurate claims |
| F19 | Measurement and budgets | P2 | Valid; memory understated | P1 memory / P2 perf | 64 KiB eager buffers; 10 000 clients vs 512 Mi | Lazy buffers; consistent defaults; method |
| F20 | Delivery scope | P1 | Partially accepted | P1 | Roadmap phase order differs from gates | Re-sequence by gates; no new crates until needed |
| F21 | Clients, OAuth, refresh | P1 | Valid (one item already fine) | P1 | Token-password example verifies; OAuth example does not | `sslmode=verify-full`; callback guidance; env exposure |
| F22 | Evidence and licensing | P2 | Partially accepted | P2 | "Clean-room" wording overstated | Pin gprxy commit; provenance note; alternatives |

---

## 4. Findings in detail

Each entry gives what the audit claims, our assessment (including
corrections), the state of the current tree, and the decision. **V**
identifiers refer to the audit's validation plan (appendix B).

### 4.1 Session state and pooling

#### F01 — Startup settings and reset semantics

*Audit:* reusing a backend and replaying startup settings with `SET` does
not reproduce startup defaults. It proposes fresh physical connections first,
plus parameterised `set_config` for approved settings.

*Assessment:* the diagnosis is correct and is confirmed in the PostgreSQL 18
source.

* The reset baseline (`reset_val`) changes only for sources up to
  `PGC_S_OVERRIDE`. Startup parameters are applied with source `PGC_S_CLIENT`.
* `SET` and `set_config()` run as `PGC_S_SESSION`, so neither changes the
  baseline that `RESET`, `RESET ALL` and `DISCARD ALL` return to.

**The audit's remedy is not sufficient.** If the gateway opens a fresh backend
with its own fixed StartupMessage and then applies the client's settings with
`SET` or `set_config`, the client's `RESET` still returns to the gateway's
baseline. This happens with zero reuse. It is not an edge case: Npgsql sends
`search_path` and `TimeZone` as startup keys, and prepends `DISCARD ALL`
whenever its own pool reuses a connection.

The only exact mechanism is to put the client's settings in the **backend
StartupMessage**. This also removes all SQL construction from attach. It
saves a round trip, makes the backend's own ParameterStatus authoritative,
and gives error behaviour identical to a direct connection.

Two corrections to the audit's secondary advice:

* **"Reject unknown startup settings by default" is stricter than needed.**
  A user-settable GUC sent at startup is no more powerful than the same `SET`
  issued after login. The settings that matter are these:
  * startup-only settings (`post_auth_delay`, `ignore_system_indexes`,
    `local_preload_libraries`);
  * identity settings (`role`, `session_authorization`);
  * gateway-owned names (`pgbearer.*`);
  * `replication`;
  * `options` switches other than `-c`.

  These go on a hard deny-list. The backend validates everything else. An
  allow-list mode stays available as an option.
* **`set_config` is the right tool only for values meant to be
  session-level,** such as a per-lease `pgbearer.session_id` when reuse is
  enabled. It is not a general remedy.

*Current state:* the stubs encode `SET` replay.

* `crates/pgbearer-session/src/lib.rs` attach contract: "values quoted as
  string literals".
* `crates/pgbearer-pool/src/lib.rs`: a fixed `application_name=pgbearer`
  and `client_encoding=UTF8`, with no profile parameter.

*Decision (P0):*

* **Add `StartupProfile`.** It parses `options` exactly as `pg_split_opts`
  does (whitespace, backslash escapes) and accepts only `-c name=value`,
  `-cname=value` and `--name=value`.
  * Names are lower-cased, with `-` mapped to `_`.
  * Duplicates of `user`, `database` and `options` are rejected.
  * The hard deny-list applies (§5, issue N10).
  * At most 64 entries.
  * The result is an ordered canonical list, hashable, so it can be part of a
    reuse key.
* **Forward the profile as individual keys.** Never forward raw `options`,
  `_pq_.*` or `replication`. Send the client's own `application_name` and
  `client_encoding`, not fixed values. Reject a backend StartupMessage over
  10 000 bytes (`MAX_STARTUP_PACKET_LENGTH`) with a clear error.
* **Propagation GUCs** (`pgbearer.sub`, `pgbearer.session_id`, …):
  * With no reuse, they go in the startup packet, so they survive the
    client's `RESET ALL` and `DISCARD ALL`.
  * With reuse enabled, per-lease values use a parameterised
    `pg_catalog.set_config($1, $2, false)` over the extended protocol.
* **Map client-caused backend startup errors back to the client** with their
  real SQLSTATE: `22023`, `42704`, `42501` and `3D000`. Keep them out of
  connect backoff and backend-health accounting.
* **Document what `DISCARD ALL` does not reset:**
  * extension and library state (dblink connections, PL/Python `GD`/`SD`,
    PL/Perl `%_SHARED`);
  * `setseed()` state;
  * the backend PID and start time;
  * notifications already queued in the socket.

*Evidence:* V01 and V03 move into **G2**, because they matter for 1:1
sessions. V01 adds a multi-element `search_path`, lower-case libpq keys and
an Npgsql-style pipelined `DISCARD ALL`. V02 is meaningful only with reuse
enabled (G3).

#### F07 — Pool generations and reload

*Audit:* the key `(backend, database, role)` cannot tell configuration
generations apart. Reload must retire old generations and act on active
sessions.

*Assessment:* valid. One nuance the audit could not see: the server contract
treats changes to backends, listeners and IdPs as **restart-required**
(`crates/pgbearer/src/lib.rs`). A single process therefore cannot mix host,
TLS-name or CA generations under one key.

What remains:

* active sessions outliving a removed route or grant (this overlaps F04);
* restart-required changes that silently keep old trust, because they are
  not observable;
* credential-compromise response.

ARCHITECTURE §13 describes an atomic swap of the whole configuration. That
contradicts the server contract and is corrected.

*Decision:*

* **P0:**
  * A `generation` in the pool key and on every pooled connection. This is
    cheap now and avoids API churn later.
  * `retire(selector, mode)` with the modes close-idle, drain-by-deadline
    and terminate.
  * Re-evaluation of active sessions on reload, with a 60 s hard deadline.
* **P1:**
  * The `pgbearer_config_pending_restart{section}` gauge, a config info
    metric with generation and SHA-256, and `/readyz` detail.
  * Refuse reloads that remove security-relevant backend trust unless
    explicitly allowed.
  * An emergency **purge** operation per backend (admin plane, F08).
  * Routine rotation of a Secret affects only new physical connections; a
    purge ends the old ones.

*Evidence:* V20's expected results must match restart-required semantics.
V21 covers route or grant removal during idle, `pg_sleep` and COPY.

#### F11 — Prepared statements and transaction semantics

*Audit:* transaction pooling with prepared-statement virtualisation needs a
complete protocol contract. Treat it as experimental.

*Assessment:* valid, with one example to correct. `search_path` is the
weakest illustration of "same text, different meaning", because the plan
cache re-analyses a statement when the path changes, or fails with "cached
plan must not change result type". The silent-divergence cases are settings
frozen at parse analysis:

* `DateStyle` and `TimeZone`, through literal coercion;
* `standard_conforming_strings`, through lexing.

The audit also misses a better default: **identity-scoped transaction
pools**. For a workload identity (one ServiceAccount, many connections) they
keep almost all of the multiplexing benefit. They also turn hidden leftover
state from a cross-principal confidentiality problem into a same-principal
correctness problem.

*Current state:* configuration accepts `pool_mode: transaction`, and the
session contract silently runs it in session mode. The README advertises
"transaction mode with prepared-statement support".

*Decision:*

* **P0:**
  * Validation rejects transaction mode unless
    `experimental.transaction_pooling: true` is set. There is no silent
    downgrade.
  * Fix the README.
  * Split Phase 3 into **3a** (opt-in session reuse) and **3b**
    (experimental transaction mode).
  * Accept ADR-010 *before* any 3b code is written.
* **The first cut of transaction mode:**
  * identity-scoped pools;
  * detach only at the F12 quiescent point;
  * pin a client for the rest of its session on: a named statement or
    portal, a GUC drift, LISTEN, extended COPY, or any uncertain state;
  * `on_named_statement: error` (with driver hints) or `pin`;
  * no virtualisation until G4 evidence exists.

#### F12 — Relay progress and safe detach

*Audit:* an earlier `ReadyForQuery I` does not mean the connection is idle.
Track command cycles, Sync, COPY and partial frames.

*Assessment:* valid, and **understated**. The most serious case is an
**extended batch left open without Sync**.

1. After Execute without Sync, PostgreSQL marks the transaction as
   pipelined.
2. The next command opens an implicit transaction block.
3. A later Sync, or the end of a multi-statement simple Query, *commits* it.

The proxy's last observed status is still `I` and no Sync is pending. A
Sync-count rule would therefore detach, and the next borrower's Sync would
commit the first client's unconfirmed writes. A configurable multi-statement
reset query would do the same. `DISCARD ALL` is safe only by accident: it
errors inside a transaction block.

On the audit's "`select!` starvation" point: it mostly does not apply to the
contracted two-pump relay. A related problem does: control events (drain,
idle, expiry) that *cancel* pumps mid-frame, and injected FATAL messages that
interleave with a half-sent DataRow.

We also reproduced a defect in the code. If `FrameReader::copy_body` is
cancelled during a partial write, a retry is accepted and duplicates bytes.
The retry wrote `012` + `0123456789` for a 10-byte body and returned
`Ok(10)`. This contradicts the crate's documented cancellation contract.

*Decision (P0):*

* **`RelayState`**, updated only after a whole frame has been forwarded:
  * expected ReadyForQuery messages: incremented by Query, Sync and
    FunctionCall, decremented by `Z`;
  * `ext_open`: set by P/B/D/E/C/H, cleared by S;
  * a `mixed` flag;
  * COPY in and out state; a CopyBoth response is unsafe;
  * partial frames in each direction;
  * a flushed-writer flag;
  * fatal and protocol-error flags;
  * whether a cancel was forwarded during this lease.
* **Predicates:**
  * `quiescent` = all of those clear, with `tx_status == I`;
  * `idle_safe_point` = quiescent, with nothing buffered from the client;
  * `reusable` = quiescent, no cancel this lease, backend at a frame
    boundary.
* `release(conn, ReleaseVerdict)` replaces `release(conn, bool)`.
* **Control events** set a flag that the pumps act on at frame boundaries.
  Only hard deadlines drop the pumps. In that case the client socket is
  closed without writing, if the backend→client direction is mid-frame.
* **Wire fix:** body methods poison the reader on entry and clear it on
  success. Any later use fails fast. Add the regression test.
* **`reset_query` becomes non-configurable** (`DISCARD ALL` only). Its
  reply is verified exactly: `CommandComplete('DISCARD ALL')` then
  `Z('I')`. Anything else discards the connection.
* **On acquire, drain unsolicited input on an idle pooled connection:**
  record ParameterStatus, drop NoticeResponse, and discard the connection
  on NotificationResponse, ErrorResponse or EOF.
* **Backend SSLRequest:** read exactly one byte, then fail if any further
  plaintext arrives before the TLS handshake (the CVE-2021-23222 class).

*Evidence:* V32–V35 move to **G1/G2**, because session-mode drain, idle and
expiry use the same predicate. They are extended with:

* an unsynced batch followed by disconnect;
* P/B/E/S followed by P/B/E;
* extended COPY with a pipelined Sync;
* a Query after a failing Bind;
* FunctionCall;
* a pipelined `DISCARD ALL`;
* idle timeout during a second pipelined query;
* a hard deadline in the middle of a DataRow.

A property test over random message interleavings checks that over-counting
is allowed and under-counting never happens.

### 4.2 Cancellation, failover and capacity

#### F02 — Cancellation ownership and endpoint selection

*Audit:* a 200 ms delay cannot prove isolation. Mark the physical connection
non-reusable before forwarding a cancel. Pin the physical endpoint.

*Assessment:* valid. Two framing corrections:

* **Misrouting through a `-ro`/`-r`/`-rw` Service is a reliability defect,
  not an isolation breach.** A server ignores a CancelRequest whose PID and
  secret do not match one of its own backends. Misrouting therefore makes a
  cancel succeed about 1/n of the time on a reader Service with n replicas.
  The isolation risk is only the race between a delayed cancel and reuse.
* **The server's EOF on the cancel connection is a documented signal** that
  the request has been processed. It is stronger than a completed write, but
  it does not prove the target backend has acted, because signal handling is
  asynchronous. It could support a later optimisation; v1 does not need it.

The audit also misses:

* per-lease **coalescing**: every valid cancel costs PostgreSQL a TCP and TLS
  handshake and a process;
* cancels that land during pgbearer's *own* statements (reset, health check,
  per-lease `set_config`). These must discard the lease and must not surface
  an error to the client.

*Decision (P0):*

* **Remove the delay.** `CancelRegistry` gets `attach(lease_id, target)` and
  `detach() -> {poisoned}`.
* **`cancel()`** does a constant-time key check, then checks that a lease is
  attached and sets `poisoned`, all inside one per-slot critical section
  (sharded, not global). It dispatches outside the lock and coalesces to at
  most one in-flight cancel per lease.
* **Outcomes** are `dispatched`, `coalesced`, `no_backend` and `failed`.
  "Succeeded" is never reported.
* **`CancelTarget`** carries:
  * the **physical `SocketAddr`**;
  * the TLS configuration, with the Service name as the verify name;
  * the backend PID;
  * a zeroising secret;
  * the generation.

  When the session used TLS, the cancel connection uses TLS too.
* **Endpoint discovery** is folded into the per-connection safety query:
  `inet_server_addr()`, `inet_server_port()`, `pg_backend_pid()` and
  `pg_is_in_recovery()`.
  * The discovered address is used only if `pg_backend_pid()` equals the
    BackendKeyData PID. Otherwise, for example behind PgBouncer, pgbearer
    falls back to the connected address, as libpq does.
  * New setting `backend.cancel_endpoint: discovered | connected`. The
    default is `discovered` for CNPG backends and `connected` for static
    ones.
* **README:** cross-replica cancellation is qualified as Phase 4. Until then,
  with two replicas, about half of client cancels reach the wrong pod and are
  dropped.

*Evidence:* V04 and V05 apply as soon as reuse is enabled, even with one
replica. V06 and V07 apply at G3. V05 adds cancels during internal
statements; V06 adds an intermediary (PgBouncer); V07 adds coalescing under
a cancel flood.

#### F14 — Failover and transaction outcomes

*Audit:* the CR watch and Service updates are not atomic. Verify target
suitability. Socket loss after COMMIT has an unknown outcome. Never replay.

*Assessment:* valid. ARCHITECTURE §19's SIGKILL row is *materially* wrong,
not just "too strong":

* an autocommit statement that is running completes and commits;
* a COMMIT in flight has an unknown outcome;
* an idle-in-transaction backend aborts only when it next touches its
  socket. After a node loss that waits for TCP keepalive, holding locks and
  a slot meanwhile.

The audit also misses:

* **CNPG's isolated-primary path.** Per the CNPG 1.30 failover
  documentation, an isolated primary does a *smart* shutdown. Sessions that
  are already open keep committing until `smartShutdownTimeout` (180 s by
  default) expires, while a replica may already have been promoted.
  pgbearer's open read-write sessions widen that window.
* **`pg_is_in_recovery()` cannot detect an isolated old primary,** because
  it is not in recovery. Only correlation with the Cluster CR or the pod IP
  can.
* **No TCP keepalive or `TCP_USER_TIMEOUT` exists anywhere** in the code or
  the docs.

*Decision:*

* **P0:**
  * **Classify backend loss by phase:**
    * before attach: `08006`, `57P03` or `53300`, and retryable;
    * idle with status `I`: `08006`;
    * idle in a transaction: `08006` with "transaction was not committed";
    * **request in flight: `08007` (transaction resolution unknown).**
  * Never synthesise `57P01` or `40001` while a request is in flight. This
    applies to drain hard timeouts, expiry and revocation.
  * Forward backend errors and notices verbatim, and flush them before
    closing. The synchronous-replication "committed locally" warning must
    reach the client.
  * **Target suitability:** `-rw` requires `pg_is_in_recovery() = false`
    and `-ro` requires true. On a mismatch, discard and retry with bounded,
    jittered backoff per backend.
  * **Per-backend generations** and `invalidate_endpoint(addr)`.
* **P1:**
  * SO_KEEPALIVE and `TCP_USER_TIMEOUT` on client and backend sockets.
  * Backend startup parameters `tcp_keepalives_idle` (30 s),
    `tcp_keepalives_interval` (10 s), `tcp_keepalives_count` (3) and
    `client_connection_check_interval` (10 s). All are configurable.
  * The CNPG watch (Phase 4): when `currentPrimary` changes, bump the
    read-write generation and **close old-generation read-write sessions
    immediately**.
  * A runbook for unknown commit outcomes, and application guidance:
    idempotency keys, reconciliation, and "pgbearer never retries".

*Evidence:* V37 moves to **G2**. Unknown outcomes occur with one replica and
no pooling: SIGKILL, drain hard timeout, expiry. It is split into: lost
CommandComplete after a commit; interrupt before commit; a terminated
synchronous-replication wait; SIGKILL during a long UPDATE; and a node
partition. V38 adds the isolated-primary case.

#### F09 — Peak connection budgets and quota semantics

*Audit:* budgets must include HPA maximum, surge and draining pods. Per-replica
quotas must be named as such.

*Assessment:* valid, and **the current state is worse than the audit
assumed**:

* `deploy/examples/cloudnativepg/cluster.yaml` leaves `max_connections` at
  100. That is 97 usable, before CNPG's own connections.
* The CNPG values example effectively allows 60 backend connections per pod.
  With the chart's 2 replicas that is 120 at steady state.
* The default `max_backend_connections` of 100 per pod equals the server's
  whole default capacity.
* Kubernetes does not count terminating pods against `maxSurge`, so draining
  pods are bounded only by rollout pacing and the PDB. The PDB uses
  `minAvailable: 1`, which allows mass eviction.
* Grants with `databases: ["*"]` make pool keys and metric labels
  client-controlled.

*Decision (P1):*

* **Per-instance budget formula** in ARCHITECTURE §10.3 and the CNPG guide,
  with terms for HPA maximum (R), surge (S), terminating pods (T), orphans
  (O), every backend that can reach the instance, and sizing every instance
  for the read-write budget.
* **Renames:** `max_connections_per_identity` →
  `max_sessions_per_identity_per_replica`. Every count limit is documented
  as "per replica". Configured limits are exported as gauges.
* **On drain:** close idle pooled connections immediately and open no new
  backend connections after `accept_grace`.
* **`pool.max_pools`:** pool entries are created only after a successful
  connect; idle empty pools are evicted; wildcard databases are labelled
  `database="*"`.
* **Map backend `53300` to client `53300`**, not `08006`, with a distinct
  reason.
* **Helm:**
  * configurable `maxSurge`;
  * `minReadySeconds` ≥ `accept_grace` + `hard_timeout`;
  * PDB `maxUnavailable: 1`;
  * an optional `connectionBudget` render-time check;
  * the examples set `max_connections` and show their arithmetic.

#### F19 — Measurement and resource budgets

*Audit:* the performance numbers are unmeasured; the 64 KiB buffer conflicts
with the 32 KiB idle target.

*Assessment:* valid. The memory part should be **P1**, not P2.

* `FrameReader` allocates 64 KiB eagerly and reserves full capacity on every
  fill.
* An attached session holds two readers, two 8 KiB writers and two rustls
  connections.
* With the default `max_client_connections` of 10 000, buffers alone exceed
  the chart's 512 Mi memory limit. The pod would be OOM-killed (the F14
  SIGKILL path) before admission limits apply.
* The connection-storm target also depends on the listener key type (RSA
  versus ECDSA signing cost) and on TLS resumption.

*Decision:*

* **P1:**
  * Lazy, adaptive buffers that shrink when idle.
  * A configurable buffer cap.
  * Consistent defaults: lower `max_client_connections` (2 000) or derive
    resources from it.
  * A startup warning against the cgroup's `memory.max`.
* **P2:** rewrite the performance targets as goals with a written method.
  Gate hosted CI on deterministic instruction counts; run wall-clock and soak
  tests on a dedicated runner.

### 4.3 Authorization, revocation and audit

#### F03 — Effective database privileges

*Audit:* checking only the login role's attributes misses SET, INHERIT and
ADMIN paths, predefined roles, ownership and definer functions.
`pg_read_all_data` is not a good example.

*Assessment:* valid, and **confirmed empirically** on PostgreSQL 16.15.

* A login role that passes the documented check reached a SUPERUSER group
  through a SET-only chain and read `data_directory`.
* A role holding ADMIN OPTION through an intermediate role granted itself a
  BYPASSRLS role.

Two more paths:

* Everything granted to the gate role `pgbearer_login` is inherited by every
  gateway-reachable role, because CNPG `inRoles` cannot set
  `INHERIT FALSE`.
* "Invalidate on known role changes" assumes an event source that does not
  exist. PostgreSQL sends no such notification, and CNPG does not revert
  manual `ALTER ROLE` until the next reconcile. A TTL re-check is the
  realistic mechanism.

*Current state:*

* the pool contract checks only `current_user`, only on new connections, and
  not at all for `allow_privileged_role`;
* the pool key does not include that flag, so a break-glass connection can
  be reused by an ordinary grant;
* the example grants `pg_read_all_data`;
* the HBA database column is `all`.

*Decision (P0):*

* **A recursive reachability query.** It walks SET, INHERIT and ADMIN edges
  (PostgreSQL 16+ semantics) and classifies each reachable role:
  * `superuser`, `createrole`, `replication`, `bypassrls`;
  * `server_files` (`pg_read_server_files`, `pg_write_server_files`,
    `pg_execute_server_program`);
  * `admin_option`;
  * `predefined_admin` (`pg_signal_backend`, `pg_write_all_data`, …);
  * `database_owner`, `createdb`, `read_all`.
* **It runs on every new physical connection,** in the same round trip as
  endpoint discovery. The risk set is stored on the connection, and the
  check is re-run on checkout after `role_check_ttl` (60 s).
* **`allow_privileged_role: bool` becomes `acknowledged_role_risks: [...]`.**
  The boolean stays as a deprecated alias for "all". Validation rejects
  grants on the same backend and role that acknowledge different sets.
* **Default blocking:** superuser, createrole, replication, bypassrls,
  server_files, admin_option and predefined_admin are refused unless
  acknowledged. Database owner, createdb and read_all are warned and
  audited. Dangerous `SECURITY DEFINER` functions are **report-only** in
  `pgbearerctl doctor`, because no query can prove a function safe and
  blocking would mostly yield false positives.
* **Optional `login.gate_role` checks:** the gate role is NOLOGIN, a member
  of nothing, owns nothing and has no ADMIN grantees.
* **Examples:**
  * schema-scoped grants instead of `pg_read_all_data`;
  * the HBA database column restricted to `orders`;
  * `client_connection_check_interval` set;
  * comments noting that `orders_owner` is the database owner.

*Evidence:* V08 uses a role-graph fixture with each path. V09 covers the TTL
re-check. V10 covers database gates in HBA.

#### F04 — Revocation and expiry

*Audit:* sessions keep their decision after reload; expiry at idle points
only can last 12 h; overlap rules are undefined; unknown claims can bypass
deny.

*Assessment:* valid, with one correction and three omissions.

* **Correction.** The "Cartesian expansion" concern does not apply. The
  policy contract filters candidates per request by backend and database,
  and the role must come from a candidate. Grant A
  `{orders, [ro]}` and grant B `{reports, [owner]}` cannot yield
  `(orders, owner)`. V48's clause becomes a regression test.
* **The real overlap defects:**
  * order-dependent first-wins merging of limits, default role and expiry
    mode;
  * per-grant `session_max_lifetime` with no upper cap, so a grant can
    *extend* the 12 h maximum;
  * deny rules failing open on unknown data.
* **Omitted 1:** closing the client socket does not stop a running backend
  statement. `client_connection_check_interval` defaults to 0, so a revoked
  autocommit statement can still commit.
* **Omitted 2:** the Helm chart mounts the configuration with `subPath`,
  which never updates in a running pod. Hot reload therefore cannot see any
  policy change. Policy changes ship only by rolling restart, and that
  rollout stalls during an IdP outage, because readiness waits for JWKS.
* **Omitted 3:** no maximum token lifetime is enforced, so the offline bound
  is whatever the IdP issues.

*Decision (P0):*

* **Policy snapshots.** A `PolicySnapshot {generation, sha256, engine,
  router, settings}` is published through a watch channel. Each session
  keeps its identity facts, request, decision and generation, and
  re-evaluates itself on change.
  * If the result is stricter, timers are tightened in place.
  * If the decision is deny, the role changes or the route disappears, the
    session is revoked: at the next safe point, and unconditionally by
    `revocation.hard_timeout` (60 s).
  * `deny[].terminate: immediate` covers emergencies.
  * The generation is re-checked after registration, to close the
    decide-then-attach race.
* **Expiry:** `token_expiry_grace` defaults to **60 s**. The new
  `token_expiry_hard_timeout` defaults to **120 s** and is a hard bound for
  every mode. **`on_token_expiry: ignore` is removed.** Per-grant overrides
  may only shorten global values. A batch exception is capped at 1 h.
* **Forced close:**
  1. send the backend CancelRequest;
  2. wait at most about 2 s for ErrorResponse and ReadyForQuery;
  3. send FATAL to the client, close both sockets and discard the backend.
* **Three-valued predicates.** A condition is True, False or Unknown.
  * A grant matches only on True.
  * A deny fires on True **or Unknown**, unless the rule sets
    `on_unknown: ignore`.
  * Unknown comes from groups overage, a provider that does not emit groups,
    an absent claim, or kind Unknown.
* **Order-independent merging.**
  * Every contributing per-identity limit is enforced.
  * The lifetime is the minimum.
  * The expiry mode is the strictest.
  * Conflicting default roles are denied, with "name a role as user".
  * Conflicting pool modes: see §8, OD10.
  * A property test checks that every permutation of grants and denies gives
    the same decision.
* **Unified claim lookup in `pgbearer-core`:** the literal name first, then
  the dotted path, then RFC 6901 JSON Pointer for names starting with `/`.
  Paths are validated at load.
* **Validation:**
  * every grant names an issuer;
  * a group condition requires the provider to declare that it emits
    groups;
  * a deny on a claim that is not required needs an explicit `on_unknown`.
* **Helm:** a directory mount (no `subPath`). The restart checksum covers
  only restart-required sections. An optional denylist ConfigMap is polled
  every 5 s.

*Published bounds* (ARCHITECTURE §12):

* **Unseen IdP change:** `max_token_lifetime` + grace + hard timeout.
* **Local policy change:** ConfigMap propagation + `revocation.hard_timeout`.
* There is no instant offboarding and no Entra Continuous Access Evaluation.

#### F10 — Audit guarantees

*Audit:* writable GUCs and PIDs are not proof of attribution. Define ids,
intervals, delivery and outage behaviour.

*Assessment:* valid. Two adjustments to priority:

* The **id plumbing** (lease and physical-connection ids) shapes the pool and
  session APIs, so it is **P0**, not P1.
* "Refuse attaches if durable audit cannot be met" is right, but it is
  unattainable with stdout. It needs an acknowledging sink, so it is **P1**.

The audit's example `audit.statements` key does not exist in the
configuration model. That is documentation drift and is removed.

*Decision:*

* **P0: additive schema `pgbearer.audit/v1`.**
  * Envelope: `seq`, `instance_id`, `replica`.
  * `backend.connected`: physical id, peer address actually connected, local
    address (joinable with `pg_stat_activity`), backend PID, database
    session id (`%c`), server version, role risks.
  * `backend.closed`.
  * `session.attached`: lease id, physical id, fresh or reused, config
    generation.
  * `session.detached` and `session.revoked`.
  * `config.applied`.
  * The client-supplied `application_name` and PROXY-derived address are
    labelled untrusted.
  * Attach events are enqueued *before* ReadyForQuery is sent and before any
    client byte reaches the backend.
* **P1:**
  * a non-blocking bounded queue drained by a dedicated thread;
  * drop and error counters;
  * delivery classes `best_effort` and `required`; `required` is refused at
    validation unless an acknowledging sink is configured;
  * a reference page with the correlation recipe, orphan detection after
    SIGKILL, and retention and PII notes.

### 4.4 Token trust and identity

#### F05 — Entra token classes

*Audit:* delegated and application tokens need separate, mutually exclusive
profiles. Key identities on `(issuer, tid, oid)`. Unknown group data must not
bypass deny.

*Assessment:* valid. The current code already covers part of this:

* Entra `idtyp=app` tokens are classified as workloads and exempt from
  `required_scopes`;
* other Entra tokens must carry the delegated scope;
* the subject is `oid` and the issuer is tenant-specific;
* the tenant (`tid`) is checked.

Gaps:

1. **Profiles are implicit.** An app-only token issued without the optional
   `idtyp` claim has no `scp`. It is therefore rejected by
   `required_scopes`, which is safe, but the error does not explain why. The
   guide must say that `idtyp` is required for workloads.
2. **ID tokens.** If the CLI and the API share one app registration, an ID
   token's `aud` equals the API's client ID. The `required_scopes` check
   rejects it only while `required_scopes` is non-empty.
3. **Generic OIDC classification.** Any token with a `scope` claim is
   classified as Human. Keycloak includes `scope` in client-credentials
   tokens, so this is wrong (see N43).
4. **Overage.** Groups overage sets a flag, but the policy contract treats a
   group predicate as "no match", so **group-based deny rules fail open**
   (N4).

*Decision:*

* **P0:** an explicit `token_profiles` setting per provider. For Entra the
  values are `delegated` and `application`; at least one is required.
  * **Delegated:** `scp` must be present and include a required scope;
    `idtyp` must be absent or `user`; the client must be in
    `allowed_client_ids` if that is set.
  * **Application:** `idtyp=app` is required; `scp` must be absent;
    `roles` must be non-empty; the client must be in `allowed_client_ids` if
    that is set.
  * A token that matches neither profile, or both, is rejected.
* **Validation:**
  * Entra providers must set `required_scopes` when `delegated` is enabled;
  * audiences must not equal any configured public-client ID;
  * reject tokens that carry a `nonce` claim (a cheap ID-token signal).
* **Generic OIDC:** `kind` is `Unknown` unless the provider declares a
  profile. `expected_typ: at+jwt` is recommended where the IdP supports
  RFC 9068.
* **Overage:** handled by the three-valued deny (F04).

*Evidence:* V14–V16.

#### F06 — Token and remote-key trust

*Audit:* exact discovery issuer, approved HTTPS origins, bounded redirects,
sizes, key counts and deadlines; finite expiry and bounded age; atomic JWKS
replacement; a hard stale bound; key purge; metrics.

*Assessment:* valid, and **mostly implemented already** in `pgbearer-auth`:

* discovery `issuer` must equal the configured issuer exactly;
* https only, with TLS 1.2 or later;
* responses capped at 1 MiB; at most 64 keys;
* RSA keys of 2 048–8 192 bits; `crit` rejected;
* `alg` checked against the allow-list and against any `alg` pinned on the
  key;
* keys never taken from token headers;
* `exp` required; `iat` and `nbf` checked;
* single-flight, rate-limited on-demand refresh, which acts as a negative
  cache;
* a successful refresh replaces the key set atomically, so removed keys
  disappear;
* stale keys are kept only after failures, and only until `max_stale`;
* refresh and age metrics, and readiness gating.

Remaining gaps:

1. **No maximum token lifetime.** `exp − iat` (or `exp − now`) is
   unbounded.
2. **Redirects.** `Policy::limited(5)` allows cross-origin redirects.
3. **No operator purge** of a compromised key short of a configuration
   change and restart.
4. **Duplicate JSON members.** These resolve last-wins, consistently across
   pgbearer's own parsing. The risk is low, because only the IdP signs
   tokens, but cheap to remove.
5. **The 24 h `max_stale` default** is an availability trade-off. It must be
   documented as such and not presented as a security property.

*Decision:*

* **P1:**
  * `max_token_lifetime` per provider: 24 h by default, 1 h for
    `github-actions`, 24 h for `kubernetes`;
  * a same-origin redirect policy;
  * `revoked_key_ids` per provider (an emergency purge through config
    reload; an admin API later) and the `key_id` on `Identity`, so sessions
    validated with a purged key can be revoked.
* **P2:** top-level duplicate-member rejection for the security-critical
  claims (`iss`, `aud`, `exp`, `nbf`, `iat`, `sub`, `oid`, `tid`, `azp`).

*Evidence:* V17–V19.

#### F15 — Kubernetes identity

*Audit:* use a dedicated audience, scope TokenReview caches, include the
ServiceAccount UID, and document offline limits.

*Assessment:* valid. pgbearer currently validates Kubernetes tokens offline
against the API server's OIDC discovery and JWKS. That cannot detect a
deleted ServiceAccount or pod before the token expires.

The audit understates the audience risk. The default automounted token
(audience = the API server) can have its expiry **extended to about a
year** while kube-apiserver's `--service-account-extend-token-expiration`
is on; it defaults to true. If an operator lists the API server's audience,
pgbearer would accept year-long tokens, and any pod in the cluster could
present its default token.

*Decision (P1):*

* **Validation:** reject Kubernetes providers whose audiences include the
  issuer URL or a `kubernetes.default.svc*` name.
* **`max_token_lifetime` (24 h)** rejects extended tokens anyway.
* **The guide** uses a projected token with `audience: pgbearer` and
  `expirationSeconds: 3600`.
* **Grants** can require `/kubernetes.io/serviceaccount/uid` through the
  JSON Pointer claim path. The guide documents that recreating an account
  with the same namespace and name inherits access unless the UID is pinned.
* **TokenReview mode** (Phase 4) is optional, with a cache keyed by
  verifier, token digest and audience, and a TTL of
  `min(exp, 60 s)`. It fails closed when the API server is unavailable.
* **Helm** uses a projected token for the discovery fetch instead of
  requiring a broadly automounted token.

#### F16 — GitHub Actions trust

*Audit:* `sub` alone does not prove an approved workflow ran. Use immutable
IDs and workflow, ref and environment claims; reject fork and PR contexts.

*Assessment:* valid. The current preset also uses `repository_owner` (a
**mutable** name) as the tenant, and the example grant matches on `sub` only.

*Decision (P1):*

* The preset tenant becomes `repository_owner_id`.
* The example grant also requires `repository_id`, `environment`, `ref`
  (`refs/heads/main`) and `job_workflow_ref` (for reusable workflows) or
  `workflow_ref`. It rejects `event_name` values `pull_request` and
  `pull_request_target`.
* A validation warning is emitted when a `github-actions` grant does not
  constrain `repository_id` or `repository_owner_id`.
* The guide states that claims cannot protect against someone authorised to
  modify the trusted workflow. Branch protection, environment protection and
  required reviewers carry that weight.

*Evidence:* V40.

#### F21 — Clients, OAuth and refresh

*Audit:* examples need `sslmode=verify-full`; token callbacks must run per
new physical connection; avoid tokens in argv and debug output; bind OAuth
discovery to a configured issuer; never hold a backend during a device flow.

*Assessment:* valid, with one item already fine.

* The token-as-password README example already uses `sslmode=verify-full`.
  The **native OAuth example does not.**
* OAuth discovery is already bound per listener (`oauthbearer_provider`).
* Backends are connected only after authentication, so no backend is held
  during a device flow.
* `PGPASSWORD` puts the token in the environment of the process tree, which
  must be documented.
* Clients that require channel binding or SCRAM-only authentication will
  never send a cleartext password, even over TLS. This is a compatibility
  limit of token-as-password and must be stated.

*Decision (P1):*

* Every human example uses `sslmode=verify-full` (or `sslrootcert=system`).
* The client guide has per-driver token callbacks (Npgsql password provider,
  pgx `BeforeConnect`, asyncpg callable password, psycopg pool
  configuration, JDBC data source) and requires app pools to set a
  `maxLifetime` shorter than the token lifetime.
* `pgbearerctl` never puts tokens in argv. It passes them through a
  `0600` passfile or a pipe.

*Evidence:* V46 and V47 (G4 for native OAuth).

### 4.5 Deployment planes and PKI

#### F08 — Management, peers and client IPs

*Audit:* `proxy_protocol: optional` lets a direct client forge its source
IP. Peers need authentication. Mutation endpoints need authorisation. An IdP
outage must not block emergency operations.

*Assessment:* valid.

* The PROXY v2 parser already caps header length and ignores TLVs, so no
  TLS metadata is trusted.
* There is no trusted-peer list, and the shipped example uses `optional`.
  Policies that use `source_cidrs`, deny rules by CIDR, and the audit's
  client address are therefore spoofable (N21).
* The admin mutation API is off by default but unauthenticated when enabled.
* The image is distroless, so `kubectl exec … kill -HUP` is not available
  for an emergency reload.

*Decision (P1):*

* **PROXY:** `proxy_protocol.trusted_proxies` (CIDRs) is required whenever
  the mode is not `off`. A header from an untrusted peer is rejected.
  `source_cidrs` is invalid on listeners that accept PROXY without a trust
  list. The audit records the address source (`tcp` or `proxy`).
* **Admin:**
  * probes and metrics stay on TCP;
  * **mutations move to a Unix socket** inside the pod, authorised by
    Kubernetes `pods/exec` RBAC. This works during an IdP outage and needs
    no new credential;
  * `pgbearerctl admin reload|drain|purge` ships in the image;
  * a bearer-token-protected TCP option is available for non-Kubernetes use.
* **Peers (Phase 4):**
  * mTLS with a deployment-scoped CA;
  * non-recursive forwarding with bounded fan-out;
  * `publishNotReadyAddresses: true` on the headless Service, so draining
    pods still receive forwarded cancels;
  * the peer port stays open until the last session ends.

*Evidence:* V22–V24.

#### F13 — CNPG HBA selector integration

*Audit:* the example's selector was commented out and the address was `all`;
an empty selector omits the allow rule, so a later broad rule may match.

*Assessment:* valid for the audited commit; **mostly addressed since.** The
current example (`deploy/examples/cloudnativepg/cluster.yaml`) has:

* `hostssl all +pgbearer_login ${podselector:pgbearer} cert map=pgbearer`;
* followed by `hostssl all +pgbearer_login all reject`, so an empty selector
  fails closed;
* pgbearer in the same namespace as the cluster, because selectors are
  namespace-local.

Remaining items:

* The database column is `all`.
* The rendered rules (`pg_hba_file_rules`, `pg_ident_file_mappings`) are not
  verified in e2e.
* The guide does not say that writers of Cluster, DatabaseRole and pod
  labels are inside the trusted administration boundary.

*Decision (P1):*

* Restrict the database column, or `REVOKE CONNECT … FROM PUBLIC`.
* Add V36 to the CNPG e2e, including IPv6 and an empty selector.
* Document the cross-namespace alternative: NetworkPolicy plus an explicit
  CIDR rule, with no claim of selector pinning.

#### F17 — PKI lifecycle

*Audit:* reissuing a Secret does not revoke a stolen certificate. Do not
mount CA keys. A namespaced Issuer cannot use a CA Secret from another
namespace. Reload bundles coherently; `subPath` is not a rotation strategy.

*Assessment:* valid; the reload part is **already implemented.**

* Listener TLS reload goes through rustls `with_single_cert`, which rejects
  a certificate and key that do not match (`keys_match`).
* The previous pair is kept on failure.
* Expiry is exported (`pgbearer_tls_cert_expiry_timestamp_seconds`) and
  alerted on (`PgbearerCertificateExpiringSoon`).
* Secrets are mounted as directories.

Gaps:

* The **configuration** is still mounted with `subPath` (N5).
* ARCHITECTURE §14.2 says the certificate is "issued directly into the
  pgbearer namespace". That is only true in the same namespace as the CA
  Issuer, or with a ClusterIssuer.
* The docs never say that **anyone who can read the client-CA Secret can
  mint `streaming_replica` or gateway certificates.** That makes them
  superuser-equivalent.
* The docs never say that reissue is not revocation.

*Decision (P1):*

* **Fix the docs:**
  * real revocation = remove reachable roles or HBA lines, rotate CA trust
    (or use CRLs), then purge sessions (F07);
  * reissuing a Secret affects only future handshakes;
  * the CA key holders are part of the trust boundary;
  * cert-manager namespace constraints.
* **Fix the Helm config mount** (N5).
* **Purge** after a credential compromise (F07).

*Evidence:* V41 and V42.

### 4.6 Delivery and governance

#### F18 — Support and compatibility

*Audit:* PostgreSQL 14 reaches end of support on 12 November 2026. Start from
16+. Pin the test matrix. Do not claim "any client".

*Assessment:* valid.

* CI tests 14/16/17/18.
* D8 proposes 14 as the minimum.
* The README says "works with any client" and "every driver".
* Strategy A needs 16+ anyway (`pg_ident +role`), and so does the
  reachability query's SET/INHERIT semantics.
* The CNPG support claims in the plan need dates and sources.
* SNI is already only a routing hint: policy authorises the routed backend
  and database.

*Decision (P1):*

* **D8 → PostgreSQL 16+.** CI tests 16, 17 and 18; 19 is a non-blocking job.
* A release-specific matrix with image digests and driver versions.
* README claims are scoped to tested drivers, with known exclusions
  (channel-binding-required clients, replication).

*Evidence:* V43.

#### F20 — Delivery scope

*Audit:* phases sum to 22–34 weeks. Deliver a 1:1 session gateway first.
Gate transaction pooling. Start with fewer crates.

*Assessment:* the sequencing advice is accepted in full; see §9.1. The
advice to start with fewer crates is **not** accepted for the crates that
exist.

* The twelve crates already have narrow, tested interfaces: wire with 93
  tests, auth 110, tls 57, config 17.
* Merging them now costs more than it saves.
* The concern behind the advice is fair. We add **no new crates** (such as a
  separate `pgbearer-k8s`) until a boundary is proven, and the
  Kubernetes-specific code starts inside the binary crate.

Re-estimation happens after the first real-IdP and driver spike. The plan
stops presenting durations as commitments.

#### F22 — Evidence, alternatives and licensing

*Audit:* pin upstream comparisons to commits; do not claim a formal
clean-room process; compare with PostgreSQL 18 OAuth plus a validator, a
gateway plus PgBouncer, and Teleport.

*Assessment:* valid.

* pgbearer's authors *read* gprxy's source (MPL-2.0) for the design review,
  at commit `02777248aead399f891b5a5dbd261fd25349b674`, the same commit the
  audit checked. "Clean-room" is therefore the wrong word.
* No gprxy code or fixtures were copied, so MPL-2.0's file-level copyleft
  imposes no obligations.
* That is a statement about copying, not about a formal clean-room process.

*Decision (P2):*

* README, PLAN D1 and ARCHITECTURE §2 say "independent implementation; no
  upstream code copied", and name the reviewed commit.
* §20 adds Teleport and "PgBouncer behind an identity gateway".
* Dependency licences remain enforced by `cargo-deny`.

---

## 5. Issues the audit did not raise

Found during this analysis. Severity follows the audit's scale, and **N**
numbers are referenced from §4. "Fix" summarises the decision; owners and
phases are in §9.2.

| # | Sev. | Issue | Where | Fix |
|---|---|---|---|---|
| N1 | High | `SET` with string literals turns a list GUC into one quoted identifier. `search_path = 'a, b'` becomes the single schema `"a, b"`. `temp_tablespaces` is affected the same way | session attach contract; ARCHITECTURE §10.4 | Startup forwarding (F01); parameterised `set_config` only for per-lease values |
| N2 | High | An extended batch left open without Sync is committed by the next borrower's Sync or by a multi-statement reset | pool and session contracts; §7.3 | `ext_open` in `RelayState`; reset fixed to `DISCARD ALL` (F12) |
| N3 | High | `Identity::claim` splits on every `.`, so namespaced claims (`https://…/roles`, `kubernetes.io`) never resolve. Deny rules on them never fire. Auth's lookup is literal-first, so the two disagree | `pgbearer-core` `Identity::claim` | One lookup: literal, then dotted path, then JSON Pointer |
| N4 | High | Deny rules fail open on unknown data: overage, unemitted optional claims (the example's `acct` deny), kind Unknown | policy contract; example config | Three-valued predicates; deny on Unknown (F04) |
| N5 | High | The Helm `subPath` config mount never updates, so hot reload is dead. Policy changes need a rollout, which stalls during an IdP outage | `deploy/helm/pgbearer/templates/deployment.yaml` | Directory mount; checksum only over restart-required sections |
| N6 | High | Forced close (revocation, expiry, drain) does not stop backend work; a revoked statement can still commit | session contract | Cancel before close; recommend `client_connection_check_interval` |
| N7 | High | The shipped examples and defaults exceed PostgreSQL's connection capacity at steady state | `deploy/examples/*`; pool defaults | Budget formula; explicit `max_connections`; lower defaults (F09) |
| N8 | High | No TCP keepalive or user timeout on any socket; orphaned backends and hung clients after a node loss | pool, session, config | Keepalives plus server-side keepalive and connection-check startup parameters (F14) |
| N9 | Medium | `copy_body` cancelled mid-write accepts a retry and duplicates bytes (reproduced) | `pgbearer-wire` `frame.rs` | Poison on entry; regression test |
| N10 | Medium | The startup filter ignores case, `--name=`, `-cname=`, direct keys and non `-c` switches (`-P`, `-W`, `-d`) | session contract | `StartupProfile` normaliser and deny-list (F01) |
| N11 | Medium | The internal role-safety query is not schema-qualified. Once `search_path` is forwarded, a shadowing schema can fake the result (the CVE-2018-1058 class) | pool contract | `pg_catalog.` prefixes, `OPERATOR(pg_catalog.=)`, extended protocol |
| N12 | Medium | Client-caused backend startup errors are masked as `08006` and would trip connect backoff for every tenant | pool `to_client_error` | Pass the SQLSTATE through; exclude from backoff and health |
| N13 | Medium | Transaction mode is accepted, silently degraded to session mode and advertised | config validation; session; README | Experimental gate (F11) |
| N14 | Medium | Idle pooled connections can carry Notification, Notice, ParameterStatus or FATAL messages from the previous borrower | pool acquire contract | Drain and classify on acquire; discard when in doubt |
| N15 | Medium | `reset_query` accepts arbitrary SQL | config | `DISCARD ALL` only, with a verified response |
| N16 | Medium | Pool reuse bypasses the role check: a break-glass connection can serve an ordinary grant | pool key | Risk set stored per connection; checked on every acquire (F03) |
| N17 | Medium | Grants without an issuer match subjects and role names from *every* IdP | config validation | Issuer required on grants (not on denies) |
| N18 | Medium | Per-grant lifetime and expiry overrides can *loosen* global limits; the merge is first-wins | policy contract; validation | Overrides may only tighten; order-independent merge |
| N19 | Medium | The synchronous, blocking audit sink runs on async worker threads; a stalled log pipe stalls relays | `pgbearer-audit` | Bounded queue plus a dedicated writer thread (F10) |
| N20 | Medium | No cap on accepted token lifetime | `pgbearer-auth` | `max_token_lifetime` (F06) |
| N21 | Medium | `source_cidrs` and audit `client_addr` trust an optional PROXY header | example config; policy | Trusted proxies (F08) |
| N22 | Medium | Sessions stay on an isolated old primary during CNPG's smart shutdown (up to 180 s) | §10.6 | Close old-generation read-write sessions on CR change (F14) |
| N23 | Medium | Cancels for sessions on draining pods are lost, because headless DNS omits not-ready pods | Phase 4 design | `publishNotReadyAddresses`; peer port open until the last session ends |
| N24 | Medium | Cross-replica cancel is not implemented, but the README advertises it and the chart defaults to 2 replicas | README; chart | Qualify as Phase 4; document the limit |
| N25 | Medium | 64 KiB eager buffers × the default 10 000 clients exceed the 512 Mi pod limit | `frame.rs`; defaults | Lazy buffers; consistent defaults (F19) |
| N26 | Medium | Wildcard database grants make pool keys and metric labels client-controlled | pool; telemetry | `max_pools`; pools created after connect; `database="*"` label |
| N27 | Medium | Hard deadlines may send `57P01` while a COMMIT is in flight, inviting duplicate retries | drain and expiry contracts | `08007` when in flight (F14) |
| N28 | Medium | Identities sharing a mapped role can cancel or terminate each other's backends and read their query text through SQL | inherent to strategy A | Document; per-team roles for sensitive data; never grant `pg_signal_backend` |
| N29 | Medium | PDB `minAvailable: 1` plus roll-on-config-change cause mass termination and full rollouts for every policy edit | Helm values | `maxUnavailable: 1`; checksum scope (F09, N5) |
| N30 | Medium | The GitHub preset keys `tenant` on the mutable `repository_owner` name | config presets | `repository_owner_id` (F16) |
| N31 | Medium | A Kubernetes provider that lists the API server audience accepts year-long default tokens from any pod | config validation | Reject such audiences; lifetime cap (F15) |
| N32 | Medium | The admin mutation API is unauthenticated when enabled; the distroless image has no `kill` for SIGHUP | admin plane | Unix-socket mutations; `pgbearerctl admin` (F08) |
| N33 | Low | Backend SSLRequest handling is unspecified (extra plaintext bytes before TLS) | pool contract | Read exactly one byte; fail on extra bytes |
| N34 | Low | The forwarded startup packet can exceed PostgreSQL's 10 000-byte limit; config allows clients up to 64 KiB | config limits | Cap at 10 000; size check before connect |
| N35 | Low | `encode_startup_message` silently truncates at an interior NUL; claim-derived values can contain `\u0000` | `pgbearer-wire` `startup.rs` | Return an error; reject at normalisation |
| N36 | Low | Duplicate startup keys: `get()` returns the first value, PostgreSQL uses the last | `startup.rs` | Reject duplicate `user`/`database`/`options`; the profile applies PostgreSQL precedence |
| N37 | Low | Reload semantics differ between ARCHITECTURE and the server contract; restart-required changes are invisible | §13; server | Align; pending-restart metric (F07) |
| N38 | Low | Each client cancel costs PostgreSQL a TLS handshake and a process; no coalescing | cancel contract | One in-flight cancel per lease; per-session rate limit |
| N39 | Low | Backend `53300` is mapped to client `08006` | pool | Pass through with a distinct reason (F09) |
| N40 | Low | The proxy PID in BackendKeyData differs from `pg_backend_pid()` and can be negative | cancel key design | Document; keep the top bit clear |
| N41 | Low | The default CNPG TLS verify name is the `.svc.cluster.local` FQDN, which user-provided certificates may lack | config `tls_server_name` | Default to `<svc>.<ns>.svc`, or document the SAN requirement |
| N42 | Low | Decide/attach race with a concurrent reload | session | Re-check the generation after registration (F04) |
| N43 | Low | Generic OIDC classifies any token with `scope` as Human; client-credentials tokens are misclassified | `pgbearer-auth` `claims.rs` | `Unknown` unless a token profile attests it (F05) |
| N44 | Low | Documentation drift: time-window deny rules and `audit.statements` do not exist | ARCHITECTURE §9.1, §13 | Remove, or mark as future |
| N45 | Low | CI actions are pinned by tag, the toolchain floats, and there is no `SECURITY.md` | `.github/`; repository root | SHA-pinned actions plus Renovate; `rust-toolchain.toml`; MSRV job; disclosure policy |

---

## 6. Validation plan and release gates

The validation plan (V01–V48) and the gates (G0–G5) are **adopted**, with
these changes:

| Change | Reason |
|---|---|
| V01 and V03 are required for **G2** | Startup forwarding matters for 1:1 sessions (F01) |
| V02 runs with reuse **enabled** and belongs to G3 | With the no-reuse default it passes trivially |
| V32–V35 move to **G1/G2** | Session-mode idle, drain and expiry use the same safe-point predicate (F12) |
| V37 moves to **G2** | Unknown outcomes occur with one replica and no pooling (F14) |
| V04 and V05 apply at whichever comes first, reuse or multiple replicas; V06, V07, V25, V26 and V38 at G3 | Scope of the cancel race (F02) |
| V20 expectations follow the restart-required semantics; V21 adds the hard-deadline cases | F07 |
| V48's "no Cartesian expansion" clause becomes a regression test | Already prevented by design (F04) |
| V44 and V45: deterministic instruction counts on hosted CI; wall-clock and soak on a dedicated runner | Hosted CI jitter (F19) |
| New: `copy_body` cancellation, relay-state property test, schema-shadowing test, startup-packet size, PROXY from an untrusted peer | Issues N9, N11, N21, N34 |

**Gates mapped to releases:**

| Gate | Release | Scope |
|---|---|---|
| G0 — design ready | (this document + ADRs) | Contracts for F01–F07 and F11–F12 written; owner accepts §8; PostgreSQL 16+ baseline |
| G1 — protocol prototype | `v0.1.0-alpha` | Relay with `RelayState`, golden transcripts, local cancel, malformed-input tests; no production auth stub |
| G2 — identity pilot | `v0.1.0` | 1:1 sessions, no reuse; Entra and Kubernetes; CNPG strategy A; revocation and expiry deadlines; connection audit; V01, V03, V08–V19, V24, V27, V32–V37, V39, V43, V47, V48 |
| G3 — reuse and replicas | `v0.2.0` | Opt-in reuse, generations, peer cancel, CNPG watch, budgets, PKI and failover tests; V02, V04–V07, V20–V28, V38, V40–V42, V44, V45 |
| G4 — experimental extensions | `v0.3.0` | Transaction mode (V29–V35 plus a driver matrix) and native OAuth (V46, V47), each behind its own flag |
| G5 — production qualification | `v1.0.0` | All applicable scenarios pass on pinned versions; independent security review; soak and chaos tests; runbooks; signed, reproducible artifacts |

A failed invariant blocks the affected feature. A release date never waives
a gate.

## 7. Proposed ADRs (appendices C and D)

**Appendix C → ADR-005 "Cancellation ownership"**: *accepted with
amendments.*

1. Endpoint discovery through `inet_server_addr()`/`inet_server_port()`,
   checked against `pg_backend_pid()`, with a fallback to the connected
   address. The verify name stays the Service name.
2. Per-slot (sharded) serialisation instead of a global lock.
3. Per-lease coalescing plus per-IP and per-session rate limits.
4. A cancel that lands during pgbearer-internal statements discards the
   lease. It never produces a client error.
5. Draining owners stay reachable: the peer port stays open, and discovery
   includes not-ready pods.
6. Client-visible consequences are documented: the proxy PID is not
   `pg_backend_pid()`, and it is kept positive.
7. A future optimisation path (server EOF plus a fence round trip) needs its
   own ADR and evidence.
8. Outcomes are named *dispatched*, never *succeeded*.

**Appendix D → ADR-014 "Session revocation"**: *accepted with amendments.*

1. Forced close = backend CancelRequest, a bounded wait (about 2 s), close
   and discard.
2. Hard timers for every expiry mode. `ignore` is removed.
3. Expiry defaults are **60 s grace + 120 s hard**, not 60 s + 60 s. Grace
   is operational slack. It does not duplicate the validation leeway, and a
   slightly longer hard tail avoids aborting in-flight commits at the moment
   of expiry.
4. `max_token_lifetime` per provider, so the offline bound is real.
5. `deny[].terminate: immediate` for emergency denies.
6. A directory-mounted configuration and a separate denylist instead of a
   `subPath` mount.
7. The generation is recorded at decision time and re-checked after
   registration.
8. v1 key purge = provider config change plus reload. An online purge API
   follows the admin-plane work (F08).

New ADRs added to the backlog:

* ADR-015 role reachability contract;
* ADR-016 startup profile forwarding;
* ADR-017 relay state and safe release;
* ADR-018 token profiles;
* ADR-019 trust planes (PROXY, admin, peers).

## 8. Owner decisions

These are the maintainers' proposed defaults. They are implemented as stated
unless the owner decides otherwise. Items marked ✅ were already decided.

| # | Decision | Proposed default | Alternatives | Why |
|---|---|---|---|---|
| OD1 | Initial product | **1:1 session identity gateway (G2)** | Pooler first | Smallest proof of the core value (F20) |
| OD2 | PostgreSQL baseline | **16+** | 14+ with exceptions | 14 is end-of-life on 12 Nov 2026; `+role` and SET/INHERIT semantics need 16 (F18) |
| OD3 | Applying client startup settings | **Forward in the backend StartupMessage** | `SET` or `set_config` replay | The only exact semantics (F01) |
| OD4 | Unknown startup GUCs | **Hard deny-list; backend validates the rest; optional allow-list mode** | Strict allow-list | Same power as post-login `SET` (F01) |
| OD5 | Default reuse | **`none`**; `same_identity` and `same_role` opt-in after G3 | Reuse by role | Removes the cancel and reset races from the pilot (F01, F02) |
| OD6 | Transaction pooling | **Experimental flag, identity-scoped pools, `on_named_statement: error`, ADR-010 first** | Drop until after GA | F11 |
| OD7 | Cancel rule | **Poison-and-discard; endpoint `discovered` for CNPG, `connected` for static** | Timer (rejected) | F02 |
| OD8 | Role risks blocked by default | **superuser, createrole, replication, bypassrls, server_files, admin_option, predefined_admin; warn on owner, createdb, read_all; definer functions report-only; recheck TTL 60 s** | Block everything | F03 |
| OD9 | Revocation and expiry | **Local revocation hard 60 s; emergency `terminate: immediate`; expiry grace 60 s + hard 120 s; remove `ignore`; batch grants may extend to ≤ 1 h** | Audit's 60 s + 60 s | F04, ADR-014 |
| OD10 | Conflicting `pool_mode` across matching grants | **Session wins, audited** | Reject (audit) | Rejecting makes access depend on unrelated grants; session is equally safe |
| OD11 | Unknown data in deny rules | **Fail closed; per-rule `on_unknown: ignore`** | Fail open | F04, F05 |
| OD12 | Max token lifetime | **24 h default; 1 h GitHub; 24 h Kubernetes** | Unbounded | F06, F15 |
| OD13 | SQLSTATE for an unknown outcome | **`08007`** | `08006` | The precise standard code (F14) |
| OD14 | Read-write sessions on an old primary after failover | **Close immediately** | Close at idle | Commits there may be lost (F14) |
| OD15 | Server-side keepalive defaults | **30 s / 10 s / 3; `client_connection_check_interval` 10 s** | PostgreSQL defaults (0) | F14, N6, N8 |
| OD16 | Quota scope | **Per replica, named as such** | Fleet-wide (needs coordination) | F09 |
| OD17 | Rollout pacing | **`minReadySeconds` ≥ accept grace + hard timeout; PDB `maxUnavailable: 1`** | Fast rollouts with a larger budget | F09 |
| OD18 | Audit delivery | **`best_effort` with seq and gap metrics in v0.1; `required` (acknowledging sink) before a multi-user pilot; UPN included by default, optional to omit** | — | F10 |
| OD19 | PROXY protocol | **Off by default; `trusted_proxies` required otherwise** | — | F08 |
| OD20 | Admin mutations | **Unix socket (`pods/exec` RBAC); optional bearer-token TCP** | Bearer token only | Works during an IdP outage (F08) |
| OD21 | Backend config reload | **Restart-required and observable, plus purge** | Live apply with generations | F07 |
| OD22 | `replication=false` in startup | **Accept as absent** | Reject any key | Compatibility (F12) |
| OD23 | Crate structure | **Keep the existing crates; no new crates until a boundary is proven** | Merge (audit) | F20 |
| ✅ | Licence | Apache-2.0 (D1) | — | Wording fixed (F22) |

## 9. Consequences for the plan and the implementation

### 9.1 Re-sequenced roadmap

| Phase | Gate → release | Content |
|---|---|---|
| 0 Foundations | — | Done, except `SECURITY.md`, a pinned toolchain, SHA-pinned actions and ADRs 001–004 |
| 1 Protocol core | G1 → `v0.1.0-alpha` | wire ✔, tls ✔; `RelayState`; 1:1 relay to a static backend; local cancel; golden transcripts; relay property tests |
| 2 Identity pilot (MVP) | G2 → `v0.1.0` | auth ✔ (plus token profiles and lifetime cap); policy (three-valued, order-independent); startup forwarding; strategy A with the reachability check; revocation and expiry deadlines with cancel before close; connection audit with ids; phase-aware errors; keepalives; PROXY trust; admin socket; Helm directory mount |
| 3a Session reuse | G3 → `v0.2.0` | Profile-keyed opt-in reuse, verified reset, generations, purge |
| 4 Kubernetes and CNPG at scale | G3 → `v0.2.0` | CNPG watch (old-primary close), peer cancel with mTLS, budgets and pacing, TokenReview (optional), e2e chaos |
| 3b Transaction mode | G4 → `v0.3.0` (experimental) | ADR-010 first; identity-scoped; pin or error; then virtualisation |
| 5 Native OAuth and CLI | G4 → `v0.3.0` (preview) | OAUTHBEARER server ✔ (code exists; gated on V46/V47); `pgbearerctl` |
| 6 Hardening and GA | G5 → `v1.0.0` | Independent review, measured performance, supply chain |

Durations are no longer published until the identity-pilot spike has been
measured (F20).

### 9.2 Contract and code changes by component

| Component | Changes | Priority |
|---|---|---|
| `pgbearer-core` | Unified claim lookup (literal, dotted path, JSON Pointer); `Identity.key_id`; `ReleaseVerdict`; SQLSTATE `08007` | P0 |
| `pgbearer-config` | `pool.reuse`; `experimental.transaction_pooling`; `session.token_expiry_hard_timeout` (120 s), grace 60 s, `ignore` removed; `revocation.hard_timeout` (60 s); `deny[].terminate`, `deny[].on_unknown`; `acknowledged_role_risks`; `role_check_ttl`; issuer required on grants; overrides may only tighten; `max_sessions_per_identity_per_replica`; `max_startup_packet_bytes` ≤ 10 000; `reset_query` removed; `proxy_protocol.trusted_proxies`; keepalive settings; `max_token_lifetime`, `token_profiles`, `revoked_key_ids`; `backend.cancel_endpoint`; `pool.max_pools`; GitHub preset `repository_owner_id`; Kubernetes audience validation; `audit.delivery` | P0/P1 |
| `pgbearer-wire` | Poison body methods on cancellation (N9); reject NUL in encoded values (N35); duplicate-key helpers (N36); lazy, adaptive buffers (N25) | P0/P1 |
| `pgbearer-auth` | Token profiles (F05); `nonce` rejection; OIDC kind `Unknown` by default (N43); `max_token_lifetime`; same-origin redirects; `revoked_key_ids`; `key_id` on `Identity` | P0/P1 |
| `pgbearer-policy` | Three-valued predicates; deny on Unknown; order-independent merge; conflict rules; permutation property tests | P0 |
| `pgbearer-pool` | Startup profile in connect and key; schema-qualified safety and discovery query (reachability, endpoint, suitability, session id); risk set plus TTL; `generation` and `retire`; verified `DISCARD ALL`; acquire-time drain; exact SSLRequest byte; error classification (`53300`, client startup errors); keepalives; bounded backoff | P0/P1 |
| `pgbearer-session` | `StartupProfile`; `RelayState` and verdicts; control events at frame boundaries; lease-ownership cancel registry; re-evaluation on generation change; deadlines with cancel before close; phase-aware termination codes; ordered audit attach | P0 |
| `pgbearer-audit` | Envelope `seq`/`instance_id`; new events; untrusted labels; non-blocking queue; delivery classes | P0 ids / P1 queue |
| `pgbearer` (server) | Policy snapshot watch; pending-restart metric; config info metric; admin Unix socket; purge | P0/P1 |
| Helm chart | Directory config mount; checksum scope; `maxSurge`, `minReadySeconds`, PDB `maxUnavailable`; projected token; `connectionBudget` check; peer Service with `publishNotReadyAddresses` (Phase 4) | P0/P1 |
| Examples | `proxy_protocol: off`; GitHub claims; issuer on every grant; `on_unknown` on the `acct` deny; schema-scoped grants; HBA database column; `max_connections` and pool arithmetic; keepalive and connection-check parameters | P1 |
| CI | PostgreSQL 16/17/18 (+19 non-blocking); SHA-pinned actions; pinned toolchain and MSRV job; budget render check | P1 |
| Docs | ARCHITECTURE §6.1, §7.3, §7.4, §9.1–9.3, §10.3–10.6, §11, §12, §13, §14.2, §16.3, §17, §18, §19, §20; README claims; `SECURITY.md`; runbooks (unknown outcomes, key compromise, certificate expiry, pool exhaustion, policy convergence, audit outage) | P0/P1 |

### 9.3 What has changed so far

**Documents.** The analysis is recorded, and the following are updated:

* PLAN.md: gates, decisions, phases, ADR backlog;
* ARCHITECTURE.md: the corrected contracts above;
* the README: accurate claims;
* the guides.

**Code.** The small, unambiguous fixes are implemented and tested:

* **N3:** one claim lookup in `pgbearer-core` (literal name, dotted path,
  JSON Pointer), used by both auth and policy. Claim names are validated at
  load.
* **N9:** `FrameReader` body methods poison the reader on cancellation or
  failure, with a regression test reproducing the duplicated bytes.
* **N35 and N34:** `encode_startup_message` rejects empty names, NUL bytes
  and packets over 10 000 bytes. `limits.max_startup_packet_bytes` is capped
  at 10 000.
* **N30:** the GitHub preset tenant is `repository_owner_id`.
* **N13:** transaction mode requires `experimental.transaction_pooling`.
* **N17:** grants must name an issuer.
* **N18 (partly):** a per-grant `session_max_lifetime` may not exceed the
  global value.
* **N21 (configuration):** `proxy_protocol` other than `off` requires
  `trusted_proxies`.
* **N31:** Kubernetes providers reject the API server's audience.
* **D5 (partly):** the default `token_expiry_grace` is 60 s.
* **Examples:**
  * PROXY off;
  * pool limits within a stated budget;
  * GitHub immutable-ID and workflow claims, plus a deny rule for
    pull-request events;
  * `max_connections` and `client_connection_check_interval` in the
    cluster;
  * HBA database column `orders`;
  * no `pg_read_all_data`.
* **Helm (N5, N29):**
  * the config is mounted as a directory (`/etc/pgbearer/config`);
  * the restart checksum excludes hot-reloadable sections;
  * PDB `maxUnavailable: 1`;
  * `minReadySeconds: 100`;
  * configurable `maxSurge`.
* **CI:** PostgreSQL 16/17/18.

**Next.** The policy, pool and session crates are written against the revised
contracts in the order of §9.1. Configuration renames and new fields
(`pool.reuse`, deadlines, `acknowledged_role_risks`, token profiles, …) land
with the code that uses them.
