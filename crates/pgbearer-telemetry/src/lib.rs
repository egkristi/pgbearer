//! Metrics (Prometheus / OpenMetrics) and logging setup for pgbearer.
//!
//! All metric families live in [`Metrics`], created once at startup and
//! shared as `Arc<Metrics>`. Labels are deliberately low-cardinality: there
//! are no per-user or per-session labels. Per-identity data belongs in the
//! audit log.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

/// Label set: `listener`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ListenerLabels {
    /// Listener name.
    pub listener: String,
}

/// Label set: `listener`, `state`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ListenerStateLabels {
    /// Listener name.
    pub listener: String,
    /// `authenticating` or `active`.
    pub state: String,
}

/// Label set: `provider`, `result`, `reason`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AuthLabels {
    /// Identity provider name, or `unknown`.
    pub provider: String,
    /// `success` or `failure`.
    pub result: String,
    /// Short machine-readable reason (`ok`, `expired`, `bad_signature`, …).
    pub reason: String,
}

/// Label set: `provider`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProviderLabels {
    /// Identity provider name.
    pub provider: String,
}

/// Label set: `provider`, `result`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProviderResultLabels {
    /// Identity provider name.
    pub provider: String,
    /// `success` or `failure`.
    pub result: String,
}

/// Label set: `result`, `grant`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DecisionLabels {
    /// `allow` or `deny`.
    pub result: String,
    /// Matched grant (first), deny rule name, or `none`.
    pub grant: String,
}

/// Label set: `backend`, `database`, `role`, `state`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PoolLabels {
    /// Backend name.
    pub backend: String,
    /// Database.
    pub database: String,
    /// PostgreSQL role.
    pub role: String,
    /// `idle` or `active`.
    pub state: String,
}

/// Label set: `backend`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendLabels {
    /// Backend name.
    pub backend: String,
}

/// Label set: `backend`, `reason`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendReasonLabels {
    /// Backend name.
    pub backend: String,
    /// Short reason (`connect`, `tls`, `auth`, `role_check`, …).
    pub reason: String,
}

/// Label set: `backend`, `mode`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendModeLabels {
    /// Backend name.
    pub backend: String,
    /// Pool mode.
    pub mode: String,
}

/// Label set: `direction`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DirectionLabels {
    /// `client_to_backend` or `backend_to_client`.
    pub direction: String,
}

/// Label set: `result`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResultLabels {
    /// Result label value.
    pub result: String,
}

/// Label set: `reason`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabels {
    /// Reason label value.
    pub reason: String,
}

/// Label set: `cert`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CertLabels {
    /// Certificate identifier, for example `listener:postgres` or `backend:orders`.
    pub cert: String,
}

/// Label set: `version`.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BuildLabels {
    /// Build version.
    pub version: String,
}

fn latency_histogram() -> Histogram {
    // 100 µs … ~13 s
    Histogram::new(exponential_buckets(0.0001, 2.0, 18))
}

/// All metric families exposed by pgbearer.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    /// `pgbearer_client_connections{listener,state}`: current client connections.
    pub client_connections: Family<ListenerStateLabels, Gauge>,
    /// `pgbearer_client_connections_accepted_total{listener}`.
    pub client_connections_accepted: Family<ListenerLabels, Counter>,
    /// `pgbearer_client_connections_rejected_total{reason}`: rejected before auth (limits, PROXY, TLS, protocol).
    pub client_connections_rejected: Family<ReasonLabels, Counter>,
    /// `pgbearer_auth_attempts_total{provider,result,reason}`.
    pub auth_attempts: Family<AuthLabels, Counter>,
    /// `pgbearer_auth_duration_seconds{provider}`: token validation latency.
    pub auth_duration: Family<ProviderLabels, Histogram, fn() -> Histogram>,
    /// `pgbearer_policy_decisions_total{result,grant}`.
    pub policy_decisions: Family<DecisionLabels, Counter>,
    /// `pgbearer_pool_connections{backend,database,role,state}`.
    pub pool_connections: Family<PoolLabels, Gauge>,
    /// `pgbearer_pool_acquire_duration_seconds{backend}`.
    pub pool_acquire_duration: Family<BackendLabels, Histogram, fn() -> Histogram>,
    /// `pgbearer_pool_acquire_timeouts_total{backend}`.
    pub pool_acquire_timeouts: Family<BackendLabels, Counter>,
    /// `pgbearer_backend_connects_total{backend}`: new backend connections opened.
    pub backend_connects: Family<BackendLabels, Counter>,
    /// `pgbearer_backend_connect_errors_total{backend,reason}`.
    pub backend_connect_errors: Family<BackendReasonLabels, Counter>,
    /// `pgbearer_transactions_total{backend,mode}`.
    pub transactions: Family<BackendModeLabels, Counter>,
    /// `pgbearer_bytes_total{direction}`.
    pub bytes: Family<DirectionLabels, Counter>,
    /// `pgbearer_cancel_requests_total{result}` (`forwarded`, `unknown`, `no_backend`, `rate_limited`, `error`).
    pub cancel_requests: Family<ResultLabels, Counter>,
    /// `pgbearer_jwks_refresh_total{provider,result}`.
    pub jwks_refresh: Family<ProviderResultLabels, Counter>,
    /// `pgbearer_jwks_age_seconds{provider}`: age of the key set in use.
    pub jwks_age_seconds: Family<ProviderLabels, Gauge<f64, AtomicU64>>,
    /// `pgbearer_tls_cert_expiry_timestamp_seconds{cert}`.
    pub tls_cert_expiry: Family<CertLabels, Gauge>,
    /// `pgbearer_config_reload_total{result}`.
    pub config_reloads: Family<ResultLabels, Counter>,
    /// `pgbearer_sessions_terminated_total{reason}` (`token_expired`, `drain`, `idle`, `idle_in_transaction`, `lifetime`).
    pub sessions_terminated: Family<ReasonLabels, Counter>,
    /// `pgbearer_build_info{version}`: always 1.
    pub build_info: Family<BuildLabels, Gauge>,
}

impl Metrics {
    /// Create and register all metric families.
    pub fn new() -> Arc<Metrics> {
        let mut registry = Registry::with_prefix("pgbearer");
        let m = Metrics {
            client_connections: Family::default(),
            client_connections_accepted: Family::default(),
            client_connections_rejected: Family::default(),
            auth_attempts: Family::default(),
            auth_duration: Family::new_with_constructor(latency_histogram),
            policy_decisions: Family::default(),
            pool_connections: Family::default(),
            pool_acquire_duration: Family::new_with_constructor(latency_histogram),
            pool_acquire_timeouts: Family::default(),
            backend_connects: Family::default(),
            backend_connect_errors: Family::default(),
            transactions: Family::default(),
            bytes: Family::default(),
            cancel_requests: Family::default(),
            jwks_refresh: Family::default(),
            jwks_age_seconds: Family::default(),
            tls_cert_expiry: Family::default(),
            config_reloads: Family::default(),
            sessions_terminated: Family::default(),
            build_info: Family::default(),
            registry: Registry::default(),
        };
        registry.register(
            "client_connections",
            "Current client connections",
            m.client_connections.clone(),
        );
        registry.register(
            "client_connections_accepted",
            "Client TCP connections accepted",
            m.client_connections_accepted.clone(),
        );
        registry.register(
            "client_connections_rejected",
            "Client connections rejected before authentication",
            m.client_connections_rejected.clone(),
        );
        registry.register(
            "auth_attempts",
            "Client authentication attempts",
            m.auth_attempts.clone(),
        );
        registry.register(
            "auth_duration_seconds",
            "Token validation latency",
            m.auth_duration.clone(),
        );
        registry.register(
            "policy_decisions",
            "Policy decisions",
            m.policy_decisions.clone(),
        );
        registry.register(
            "pool_connections",
            "Backend connections held by pools",
            m.pool_connections.clone(),
        );
        registry.register(
            "pool_acquire_duration_seconds",
            "Time to acquire a backend connection",
            m.pool_acquire_duration.clone(),
        );
        registry.register(
            "pool_acquire_timeouts",
            "Backend connection acquisitions that timed out",
            m.pool_acquire_timeouts.clone(),
        );
        registry.register(
            "backend_connects",
            "New backend connections opened",
            m.backend_connects.clone(),
        );
        registry.register(
            "backend_connect_errors",
            "Failed backend connection attempts",
            m.backend_connect_errors.clone(),
        );
        registry.register(
            "transactions",
            "Completed transactions",
            m.transactions.clone(),
        );
        registry.register("bytes", "Bytes relayed", m.bytes.clone());
        registry.register(
            "cancel_requests",
            "Query cancel requests",
            m.cancel_requests.clone(),
        );
        registry.register(
            "jwks_refresh",
            "JWKS refresh attempts",
            m.jwks_refresh.clone(),
        );
        registry.register(
            "jwks_age_seconds",
            "Age of the JWKS key set in use",
            m.jwks_age_seconds.clone(),
        );
        registry.register(
            "tls_cert_expiry_timestamp_seconds",
            "Certificate expiry time (Unix seconds)",
            m.tls_cert_expiry.clone(),
        );
        registry.register(
            "config_reload",
            "Configuration reload attempts",
            m.config_reloads.clone(),
        );
        registry.register(
            "sessions_terminated",
            "Client sessions terminated by pgbearer",
            m.sessions_terminated.clone(),
        );
        registry.register("build_info", "Build information", m.build_info.clone());
        m.build_info
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .set(1);
        Arc::new(Metrics { registry, ..m })
    }

    /// Render all metrics in OpenMetrics text format.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        // Encoding into a String cannot fail.
        let _ = prometheus_client::encoding::text::encode(&mut out, &self.registry);
        out
    }

    /// Record an authentication attempt.
    pub fn auth_attempt(&self, provider: &str, success: bool, reason: &str) {
        self.auth_attempts
            .get_or_create(&AuthLabels {
                provider: provider.to_string(),
                result: if success { "success" } else { "failure" }.to_string(),
                reason: reason.to_string(),
            })
            .inc();
    }

    /// Record a policy decision.
    pub fn policy_decision(&self, allowed: bool, grant: &str) {
        self.policy_decisions
            .get_or_create(&DecisionLabels {
                result: if allowed { "allow" } else { "deny" }.to_string(),
                grant: grant.to_string(),
            })
            .inc();
    }

    /// Record a terminated session.
    pub fn session_terminated(&self, reason: &str) {
        self.sessions_terminated
            .get_or_create(&ReasonLabels {
                reason: reason.to_string(),
            })
            .inc();
    }

    /// Record a cancel request outcome.
    pub fn cancel_request(&self, result: &str) {
        self.cancel_requests
            .get_or_create(&ResultLabels {
                result: result.to_string(),
            })
            .inc();
    }

    /// Record a rejected client connection.
    pub fn connection_rejected(&self, reason: &str) {
        self.client_connections_rejected
            .get_or_create(&ReasonLabels {
                reason: reason.to_string(),
            })
            .inc();
    }

    /// Add relayed bytes.
    pub fn add_bytes(&self, client_to_backend: u64, backend_to_client: u64) {
        if client_to_backend > 0 {
            self.bytes
                .get_or_create(&DirectionLabels {
                    direction: "client_to_backend".into(),
                })
                .inc_by(client_to_backend);
        }
        if backend_to_client > 0 {
            self.bytes
                .get_or_create(&DirectionLabels {
                    direction: "backend_to_client".into(),
                })
                .inc_by(backend_to_client);
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// JSON lines.
    Json,
    /// Human-readable.
    Pretty,
}

/// Install the global `tracing` subscriber.
///
/// `PGBEARER_LOG` (env-filter syntax) overrides `level`. Calling this twice
/// is harmless; the second call is ignored.
pub fn init_logging(level: &str, format: LogFormat) {
    use tracing_subscriber::EnvFilter;
    let filter = std::env::var("PGBEARER_LOG")
        .ok()
        .and_then(|v| EnvFilter::try_new(v).ok())
        .or_else(|| EnvFilter::try_new(level).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_registered_metrics() {
        let m = Metrics::new();
        m.auth_attempt("entra", false, "expired");
        m.policy_decision(true, "readers");
        m.add_bytes(10, 20);
        m.auth_duration
            .get_or_create(&ProviderLabels {
                provider: "entra".into(),
            })
            .observe(0.002);
        let text = m.encode();
        assert!(text.contains("pgbearer_auth_attempts_total{provider=\"entra\",result=\"failure\",reason=\"expired\"} 1"), "{text}");
        assert!(
            text.contains("pgbearer_policy_decisions_total{result=\"allow\",grant=\"readers\"} 1")
        );
        assert!(text.contains("pgbearer_bytes_total{direction=\"backend_to_client\"} 20"));
        assert!(text.contains("pgbearer_build_info{version="));
        assert!(text.contains("pgbearer_auth_duration_seconds_bucket"));
    }
}
