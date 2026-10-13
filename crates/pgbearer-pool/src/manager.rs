//! The pool manager: fair, bounded connection limits per backend and per
//! `(backend, database, role)`, connect backoff, role-risk checks, leases
//! and generations.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use pgbearer_config::{BackendConfig, CancelEndpoint, ResolvedCredential};
use pgbearer_core::RoleRisk;
use pgbearer_telemetry::{BackendLabels, BackendReasonLabels, Metrics, PoolLabels};
use pgbearer_tls::BackendTls;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, watch};
use tracing::{debug, warn};

use crate::backoff::Backoff;
use crate::cancel::CancelTarget;
use crate::connect::{BackendConnection, ConnectParams};
use crate::inspect::{BackendInfo, check_target};
use crate::{BackendError, PoolError};

/// Process-unique lease ids (shared by all managers, so a manager rebuilt
/// on configuration reload never repeats an id).
static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

/// The generation of every backend when the manager is built.
const INITIAL_GENERATION: u64 = 1;

/// What a session needs from the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireRequest {
    /// Backend name.
    pub backend: String,
    /// Database.
    pub database: String,
    /// Role to log in as.
    pub role: String,
    /// StartupMessage parameters after `user` and `database` (client profile
    /// plus pgbearer's own).
    pub parameters: Vec<(String, String)>,
    /// Role risks the policy decision acknowledges.
    pub acknowledged_role_risks: BTreeSet<RoleRisk>,
}

/// A backend connection leased to one session.
pub struct Lease {
    /// The backend connection.
    pub conn: BackendConnection,
    /// Inspection result.
    pub info: BackendInfo,
    /// Process-unique lease id.
    pub lease_id: u64,
    /// Backend generation at acquire time.
    pub generation: u64,
    /// True if the connection was opened for this lease (always true with `reuse: none`).
    pub fresh: bool,
    /// Non-blocking risks the request did not acknowledge (log and audit them).
    pub unacknowledged_risks: BTreeSet<RoleRisk>,
    /// Where to send cancel requests for this connection.
    pub cancel: CancelTarget,
    /// When the backend connection was opened.
    pub created_at: Instant,
    /// Pool and backend slots; freed on drop (after `conn` was closed,
    /// because fields drop in declaration order).
    slots: LeaseSlots,
}

impl Lease {
    /// Backend name.
    pub fn backend(&self) -> &str {
        &self.slots.usage.backend.config.name
    }
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("backend", &self.backend())
            .field("lease_id", &self.lease_id)
            .field("generation", &self.generation)
            .field("fresh", &self.fresh)
            .field("conn", &self.conn)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

/// How sessions on a retired generation end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireMode {
    /// At the session's next safe point, and at the latest after the deadline.
    DrainBy(Duration),
    /// At once (cancel the running statement first).
    TerminateNow,
}

/// Published when a backend's generation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationNotice {
    /// The new (current) generation.
    pub generation: u64,
    /// How sessions on older generations must end.
    pub mode: RetireMode,
}

/// Snapshot of one pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStats {
    /// Backend.
    pub backend: String,
    /// Database.
    pub database: String,
    /// Role.
    pub role: String,
    /// Leased connections.
    pub active: usize,
    /// Sessions waiting in `acquire`.
    pub waiting: usize,
}

/// All pools.
pub struct PoolManager {
    backends: BTreeMap<String, Arc<BackendState>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for PoolManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolManager")
            .field("backends", &self.backends.keys().collect::<Vec<_>>())
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish()
    }
}

/// Everything the manager keeps per backend.
struct BackendState {
    config: BackendConfig,
    tls: Arc<BackendTls>,
    /// `max_backend_connections` (FIFO).
    slots: Arc<Semaphore>,
    /// Pools that have a waiter or a lease; an entry is removed when both
    /// counts drop to zero, so client-chosen database names cannot grow it.
    pools: Mutex<BTreeMap<PoolKey, PoolEntry>>,
    backoff: Mutex<Backoff>,
    generation: watch::Sender<GenerationNotice>,
    metrics: Arc<Metrics>,
    /// Label set for per-backend metrics.
    labels: BackendLabels,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PoolKey {
    database: String,
    role: String,
}

struct PoolEntry {
    /// `pool.max_connections` (FIFO).
    slots: Arc<Semaphore>,
    active: usize,
    waiting: usize,
}

/// Lock a mutex, ignoring poisoning (the protected data stays consistent:
/// every critical section is a few plain assignments).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl BackendState {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn generation(&self) -> u64 {
        self.generation.borrow().generation
    }

    /// Count a failed connect or inspection. Client-caused errors never
    /// touch the backoff.
    fn connect_failed(&self, error: &BackendError) {
        self.count_error(error.reason_code());
        if error.is_client_caused() {
            debug!(backend = %self.name(), %error, "backend refused the client's startup settings");
            return;
        }
        let delay = lock(&self.backoff).record_failure(tokio::time::Instant::now());
        warn!(
            backend = %self.name(),
            %error,
            backoff_ms = delay.as_millis() as u64,
            "backend connect failed"
        );
    }

    fn count_error(&self, reason: &str) {
        self.metrics
            .backend_connect_errors
            .get_or_create(&BackendReasonLabels {
                backend: self.name().to_owned(),
                reason: reason.to_owned(),
            })
            .inc();
    }

    /// Wait for the end of any connect backoff, until `deadline`.
    async fn wait_for_backoff(&self, deadline: tokio::time::Instant) -> Result<(), ()> {
        let retry_at = lock(&self.backoff).retry_at();
        match retry_at {
            Some(at) if at > tokio::time::Instant::now() => {
                if at > deadline {
                    tokio::time::sleep_until(deadline).await;
                    Err(())
                } else {
                    tokio::time::sleep_until(at).await;
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn pool_labels(&self, key: &PoolKey) -> PoolLabels {
        PoolLabels {
            backend: self.name().to_owned(),
            database: key.database.clone(),
            role: key.role.clone(),
            state: "active".to_owned(),
        }
    }
}

/// One session's use of a pool: waiting in `acquire`, then holding a lease.
struct PoolUse {
    backend: Arc<BackendState>,
    key: PoolKey,
    active: bool,
}

impl PoolUse {
    /// Register a waiter, creating the pool entry if needed; returns the
    /// pool's semaphore.
    fn enter(backend: &Arc<BackendState>, key: PoolKey) -> (PoolUse, Arc<Semaphore>) {
        let mut pools = lock(&backend.pools);
        let entry = pools.entry(key.clone()).or_insert_with(|| PoolEntry {
            slots: Arc::new(Semaphore::new(permits(
                backend.config.pool.max_connections,
            ))),
            active: 0,
            waiting: 0,
        });
        entry.waiting += 1;
        let slots = Arc::clone(&entry.slots);
        drop(pools);
        (
            PoolUse {
                backend: Arc::clone(backend),
                key,
                active: false,
            },
            slots,
        )
    }

    /// The waiter got its lease.
    fn activate(&mut self) {
        {
            let mut pools = lock(&self.backend.pools);
            if let Some(entry) = pools.get_mut(&self.key) {
                entry.waiting = entry.waiting.saturating_sub(1);
                entry.active += 1;
            }
        }
        self.active = true;
        self.backend
            .metrics
            .pool_connections
            .get_or_create(&self.backend.pool_labels(&self.key))
            .inc();
    }
}

impl Drop for PoolUse {
    fn drop(&mut self) {
        if self.active {
            self.backend
                .metrics
                .pool_connections
                .get_or_create(&self.backend.pool_labels(&self.key))
                .dec();
        }
        let mut pools = lock(&self.backend.pools);
        if let Some(entry) = pools.get_mut(&self.key) {
            if self.active {
                entry.active = entry.active.saturating_sub(1);
            } else {
                entry.waiting = entry.waiting.saturating_sub(1);
            }
            if entry.active == 0 && entry.waiting == 0 {
                pools.remove(&self.key);
            }
        }
    }
}

/// What a lease holds until it is released or dropped.
struct LeaseSlots {
    _pool: OwnedSemaphorePermit,
    _backend: OwnedSemaphorePermit,
    usage: PoolUse,
}

/// A semaphore size from a configured limit.
fn permits(limit: u32) -> usize {
    usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .min(Semaphore::MAX_PERMITS)
}

/// The discovered physical endpoint (`inet_server_addr()`:
/// `inet_server_port()`), when it is known and belongs to this connection;
/// otherwise the fallback reason (`no_server_addr`, `pid_mismatch`).
pub(crate) fn discovered_endpoint(
    process_id: u32,
    info: &BackendInfo,
) -> Result<SocketAddr, &'static str> {
    let Some(addr) = info.server_addr else {
        return Err("no_server_addr");
    };
    if info.backend_pid != process_id {
        return Err("pid_mismatch");
    }
    Ok(addr)
}

impl PoolManager {
    /// Build from backend configs (creates [`BackendTls`] per backend; no network I/O).
    pub fn new(
        backends: &[BackendConfig],
        metrics: Arc<Metrics>,
    ) -> Result<Arc<PoolManager>, PoolError> {
        let mut map = BTreeMap::new();
        for config in backends {
            if map.contains_key(&config.name) {
                return Err(BackendError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("duplicate backend name {:?}", config.name),
                ))
                .into());
            }
            let server_name = config.tls_server_name().unwrap_or_default();
            let tls = BackendTls::new(&config.tls, &server_name).map_err(|e| {
                BackendError::Tls(format!("backend {:?}: {e}", config.name))
            })?;
            let (generation, _) = watch::channel(GenerationNotice {
                generation: INITIAL_GENERATION,
                mode: RetireMode::DrainBy(Duration::ZERO),
            });
            let state = BackendState {
                config: config.clone(),
                tls: Arc::new(tls),
                slots: Arc::new(Semaphore::new(permits(
                    config.pool.max_backend_connections,
                ))),
                pools: Mutex::new(BTreeMap::new()),
                backoff: Mutex::new(Backoff::default()),
                generation,
                metrics: Arc::clone(&metrics),
                labels: BackendLabels {
                    backend: config.name.clone(),
                },
            };
            map.insert(config.name.clone(), Arc::new(state));
        }
        Ok(Arc::new(PoolManager {
            backends: map,
            closed: AtomicBool::new(false),
        }))
    }

    /// Lease a backend connection (see the crate documentation).
    pub async fn acquire(&self, req: &AcquireRequest) -> Result<Lease, PoolError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(PoolError::Closed);
        }
        let backend = self
            .backends
            .get(&req.backend)
            .ok_or_else(|| PoolError::UnknownBackend(req.backend.clone()))?;
        let credential = backend
            .config
            .login
            .credential_for(&req.role)
            .ok_or_else(|| PoolError::NoCredential {
                backend: req.backend.clone(),
                role: req.role.clone(),
            })?;
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + backend.config.pool.acquire_timeout;
        let (usage, pool_slots) = PoolUse::enter(
            backend,
            PoolKey {
                database: req.database.clone(),
                role: req.role.clone(),
            },
        );
        // After registering, so that `close` either sees the new pool entry
        // (and closes its semaphore) or this check sees the flag.
        if self.closed.load(Ordering::SeqCst) {
            return Err(PoolError::Closed);
        }
        let result = acquire_slots_and_connect(backend, usage, pool_slots, req, &credential, deadline).await;
        match &result {
            Ok(_) => backend
                .metrics
                .pool_acquire_duration
                .get_or_create(&backend.labels)
                .observe(started.elapsed().as_secs_f64()),
            Err(PoolError::Timeout(_)) => {
                backend
                    .metrics
                    .pool_acquire_timeouts
                    .get_or_create(&backend.labels)
                    .inc();
            }
            Err(_) => {}
        }
        result
    }

    /// Return a lease. With `reuse: none` the connection is always closed.
    /// `reusable` is the relay's verdict (ignored until Phase 3a).
    ///
    /// The slots are freed after the connection was closed, so the backend
    /// never holds more than `max_backend_connections` of ours.
    pub async fn release(&self, lease: Lease, reusable: bool) {
        let _ = reusable;
        let Lease { conn, slots, .. } = lease;
        conn.terminate().await;
        drop(slots);
    }

    /// Bump `backend`'s generation and tell subscribers how sessions on older
    /// generations end. Returns the new generation, or `None` for an unknown
    /// backend.
    pub fn retire(&self, backend: &str, mode: RetireMode) -> Option<u64> {
        let state = self.backends.get(backend)?;
        let mut generation = 0;
        state.generation.send_modify(|notice| {
            notice.generation += 1;
            notice.mode = mode;
            generation = notice.generation;
        });
        warn!(backend, generation, ?mode, "backend generation retired");
        Some(generation)
    }

    /// Generation notices for `backend` (`None` for an unknown backend).
    pub fn subscribe(&self, backend: &str) -> Option<watch::Receiver<GenerationNotice>> {
        self.backends
            .get(backend)
            .map(|state| state.generation.subscribe())
    }

    /// Refuse further acquisitions.
    ///
    /// Sessions waiting in [`acquire`](Self::acquire) get
    /// [`PoolError::Closed`]; existing leases are unaffected.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for state in self.backends.values() {
            state.slots.close();
            for entry in lock(&state.pools).values() {
                entry.slots.close();
            }
        }
    }

    /// Pool snapshots.
    pub fn stats(&self) -> Vec<PoolStats> {
        let mut stats = Vec::new();
        for (name, state) in &self.backends {
            for (key, entry) in lock(&state.pools).iter() {
                stats.push(PoolStats {
                    backend: name.clone(),
                    database: key.database.clone(),
                    role: key.role.clone(),
                    active: entry.active,
                    waiting: entry.waiting,
                });
            }
        }
        stats
    }

    /// The configuration of a backend.
    pub fn backend_config(&self, backend: &str) -> Option<&BackendConfig> {
        self.backends.get(backend).map(|state| &state.config)
    }

    /// Consecutive non-client connect failures of `backend` (the backoff
    /// counter; 0 when healthy), or `None` for an unknown backend.
    pub fn connect_failures(&self, backend: &str) -> Option<u32> {
        self.backends
            .get(backend)
            .map(|state| lock(&state.backoff).failures())
    }

    /// The current generation of `backend` (`None` for an unknown backend).
    pub fn generation(&self, backend: &str) -> Option<u64> {
        self.backends.get(backend).map(|state| state.generation())
    }
}

/// Steps 2–6 of the crate documentation, within `deadline`.
async fn acquire_slots_and_connect(
    backend: &Arc<BackendState>,
    mut usage: PoolUse,
    pool_slots: Arc<Semaphore>,
    req: &AcquireRequest,
    credential: &ResolvedCredential,
    deadline: tokio::time::Instant,
) -> Result<Lease, PoolError> {
    let timeout = || PoolError::Timeout(req.backend.clone());
    let closed = |_: AcquireError| PoolError::Closed;

    // 2. Wait in FIFO order: the pool's slot first, so a waiter never holds
    //    a backend slot hostage while its own pool is full.
    let pool_permit = tokio::time::timeout_at(deadline, pool_slots.acquire_owned())
        .await
        .map_err(|_| timeout())?
        .map_err(closed)?;
    let backend_permit = tokio::time::timeout_at(deadline, Arc::clone(&backend.slots).acquire_owned())
        .await
        .map_err(|_| timeout())?
        .map_err(closed)?;

    loop {
        backend
            .wait_for_backoff(deadline)
            .await
            .map_err(|()| timeout())?;
        let generation = backend.generation();

        // 3. Connect.
        let params = ConnectParams {
            backend: &backend.config,
            tls: &backend.tls,
            database: &req.database,
            role: &req.role,
            credential,
            parameters: &req.parameters,
        };
        let mut conn = match tokio::time::timeout_at(deadline, BackendConnection::connect(&params)).await {
            // The acquire deadline, not the backend: no backoff.
            Err(_) => return Err(timeout()),
            Ok(Err(error)) => {
                backend.connect_failed(&error);
                return Err(error.into());
            }
            Ok(Ok(conn)) => conn,
        };
        let created_at = Instant::now();
        backend
            .metrics
            .backend_connects
            .get_or_create(&backend.labels)
            .inc();

        // 4. Inspect, then target suitability.
        let info = match tokio::time::timeout_at(deadline, conn.inspect()).await {
            Err(_) => {
                conn.terminate().await;
                return Err(timeout());
            }
            Ok(Err(error)) => {
                conn.terminate().await;
                backend.connect_failed(&error);
                return Err(error.into());
            }
            Ok(Ok(info)) => info,
        };
        if let Err(mismatch) = check_target(&backend.config, info.in_recovery) {
            conn.terminate().await;
            backend.count_error("wrong_role");
            let delay = lock(&backend.backoff).record_failure(tokio::time::Instant::now());
            warn!(
                backend = %backend.name(),
                reason = %mismatch,
                backoff_ms = delay.as_millis() as u64,
                "backend connection does not suit the target service; retrying"
            );
            continue;
        }
        if backend.generation() != generation {
            // Retired while connecting: never hand out an older generation.
            conn.terminate().await;
            continue;
        }
        lock(&backend.backoff).record_success();

        // 5. Role risks.
        let acknowledged = &req.acknowledged_role_risks;
        let blocking: BTreeSet<RoleRisk> = info
            .role_risks
            .iter()
            .copied()
            .filter(|r| r.blocks_by_default() && !acknowledged.contains(r))
            .collect();
        if !blocking.is_empty() {
            conn.terminate().await;
            return Err(PoolError::RoleRisk {
                role: req.role.clone(),
                risks: blocking,
            });
        }
        let unacknowledged_risks = info
            .role_risks
            .iter()
            .copied()
            .filter(|r| !r.blocks_by_default() && !acknowledged.contains(r))
            .collect();

        // 6. Cancel target.
        let cancel = cancel_target(backend, &conn, &info);
        usage.activate();
        let lease_id = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);
        debug!(
            backend = %backend.name(),
            lease_id,
            generation,
            backend_pid = conn.process_id,
            auth_method = conn.auth_method().as_str(),
            "backend connection leased"
        );
        return Ok(Lease {
            conn,
            info,
            lease_id,
            generation,
            fresh: true,
            unacknowledged_risks,
            cancel,
            created_at,
            slots: LeaseSlots {
                _pool: pool_permit,
                _backend: backend_permit,
                usage,
            },
        });
    }
}

/// Step 6: where cancel requests for `conn` go.
fn cancel_target(backend: &BackendState, conn: &BackendConnection, info: &BackendInfo) -> CancelTarget {
    let endpoint = match backend.config.effective_cancel_endpoint() {
        CancelEndpoint::Connected => conn.peer_addr,
        CancelEndpoint::Discovered => match discovered_endpoint(conn.process_id, info) {
            Ok(addr) => addr,
            Err(reason) => {
                backend
                    .metrics
                    .cancel_endpoint_fallbacks
                    .get_or_create(&BackendReasonLabels {
                        backend: backend.name().to_owned(),
                        reason: reason.to_owned(),
                    })
                    .inc();
                debug!(
                    backend = %backend.name(),
                    reason,
                    "cancel endpoint falls back to the connected address"
                );
                conn.peer_addr
            }
        },
    };
    CancelTarget::new(
        endpoint,
        conn.process_id,
        &conn.secret_key,
        conn.tls.then(|| Arc::clone(&backend.tls)),
    )
}
