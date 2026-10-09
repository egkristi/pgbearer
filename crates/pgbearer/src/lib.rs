//! The pgbearer server as a library, so integration tests can run it in-process.
//!
//! [`start`] wires everything together:
//!
//! 1. Install the rustls crypto provider; initialise metrics.
//! 2. Build the audit sink (or use `opts.audit_sink`), [`TokenValidator`],
//!    [`PolicyEngine`], [`Router`], [`PoolManager`], [`CancelRegistry`]
//!    (replica tag from `opts.replica_name` or the `HOSTNAME` env var),
//!    [`DrainController`] and [`Admission`] into [`Services`].
//! 3. Start the validator (`TokenValidator::start`), pool maintenance and,
//!    for each TLS listener, the certificate reloader.
//! 4. Bind every listener (`TcpListener`), record the bound addresses, and
//!    spawn accept loops that spawn [`serve_connection`] per client on a
//!    `TaskTracker`. Accept errors are logged and retried with a short backoff.
//! 5. Bind the admin HTTP server (axum) if configured:
//!    * `GET /livez` → 200 `ok`;
//!    * `GET /readyz` → 200 when the validator is ready and not draining, else
//!      503 with a JSON body listing provider status and drain state;
//!    * `GET /metrics` → OpenMetrics text (`application/openmetrics-text; version=1.0.0; charset=utf-8`);
//!    * when `admin.enable_admin_api`: `POST /admin/reload` (re-read the
//!      config file and apply it) and `POST /admin/drain`.
//!
//! Reload ([`RunningApp::reload`]): validate the new config, then atomically
//! swap policy, routes and session settings. Changes to listeners, identity
//! providers or backends are not applied live; they are logged as
//! "restart required" and reported in the result.
//!
//! Drain ([`RunningApp::shutdown`]): readiness goes to 503 at once; listeners
//! keep accepting for `drain.accept_grace`, then close; sessions are told via
//! [`DrainController`]; wait for sessions until `drain.hard_timeout`; then
//! close pools and stop background tasks.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use pgbearer_audit::AuditSink;
use pgbearer_config::Config;
use pgbearer_session::Services;

#[allow(unused_imports)]
use pgbearer_auth::TokenValidator;
#[allow(unused_imports)]
use pgbearer_policy::PolicyEngine;
#[allow(unused_imports)]
use pgbearer_pool::PoolManager;
#[allow(unused_imports)]
use pgbearer_session::{Admission, CancelRegistry, DrainController, Router, serve_connection};

/// Options for [`start`].
#[derive(Default)]
pub struct AppOptions {
    /// Path of the config file (used by `/admin/reload` and SIGHUP).
    pub config_path: Option<PathBuf>,
    /// Override the audit sink (tests use `MemorySink`).
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    /// Name used to derive the cancel-key replica tag (defaults to `$HOSTNAME`).
    pub replica_name: Option<String>,
}

/// What a reload changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// Sections applied live.
    pub applied: Vec<String>,
    /// Sections that changed but need a restart.
    pub restart_required: Vec<String>,
}

/// A running server.
pub struct RunningApp {
    /// Bound listener addresses by listener name.
    pub listener_addrs: Vec<(String, SocketAddr)>,
    /// Bound admin address.
    pub admin_addr: Option<SocketAddr>,
    _private: (),
}

impl RunningApp {
    /// Shared services (for tests and diagnostics).
    pub fn services(&self) -> &Arc<Services> {
        todo!("pgbearer: RunningApp::services")
    }

    /// Address of the named listener.
    pub fn listener_addr(&self, name: &str) -> Option<SocketAddr> {
        self.listener_addrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, a)| *a)
    }

    /// Apply a new configuration (see crate docs).
    pub fn reload(&self, config: Config) -> anyhow::Result<ReloadOutcome> {
        let _ = config;
        todo!("pgbearer: RunningApp::reload")
    }

    /// Graceful shutdown (see crate docs). Returns when everything has stopped.
    pub async fn shutdown(self) {
        todo!("pgbearer: RunningApp::shutdown")
    }

    /// Run until SIGTERM/SIGINT (graceful shutdown) and handle SIGHUP (reload
    /// from `config_path`). Used by `main`.
    pub async fn run_until_signal(self) -> anyhow::Result<()> {
        todo!("pgbearer: RunningApp::run_until_signal")
    }
}

/// Start the server (see crate docs). Fails if any listener cannot be bound
/// or any component cannot be built from the config.
pub async fn start(config: Config, opts: AppOptions) -> anyhow::Result<RunningApp> {
    let _ = (config, opts);
    todo!("pgbearer: start")
}
