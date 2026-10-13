//! Per-backend connect backoff: exponential with jitter, reset on success.

use std::time::Duration;

use tokio::time::Instant;

/// Delay after the first failure.
pub(crate) const BACKOFF_BASE: Duration = Duration::from_millis(100);
/// Largest delay before jitter.
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(5);
/// Relative jitter: the delay is scaled by a factor in `[1 - J, 1 + J]`.
pub(crate) const BACKOFF_JITTER: f64 = 0.2;

/// The delay before jitter after `failures` consecutive failures:
/// `100 ms · 2^(failures - 1)`, at most 5 s (zero without failures).
pub(crate) fn backoff_delay(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    // 2^6 · 100 ms already exceeds the cap; avoid overflow for large counts.
    let exponent = (failures - 1).min(16);
    BACKOFF_BASE
        .saturating_mul(1u32 << exponent)
        .min(BACKOFF_MAX)
}

/// `delay` scaled by `1 + BACKOFF_JITTER · unit`, with `unit` in `[-1, 1]`.
pub(crate) fn apply_jitter(delay: Duration, unit: f64) -> Duration {
    delay.mul_f64(1.0 + BACKOFF_JITTER * unit.clamp(-1.0, 1.0))
}

/// Backoff state of one backend.
#[derive(Debug, Default)]
pub(crate) struct Backoff {
    /// Consecutive non-client failures.
    failures: u32,
    /// New connects wait until then.
    retry_at: Option<Instant>,
}

impl Backoff {
    /// Count a failure at `now`; returns the (jittered) delay until new
    /// connects may start.
    pub(crate) fn record_failure(&mut self, now: Instant) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let delay = apply_jitter(
            backoff_delay(self.failures),
            rand::random_range(-1.0..=1.0),
        );
        self.retry_at = Some(now + delay);
        delay
    }

    /// A usable connection: clear the backoff.
    pub(crate) fn record_success(&mut self) {
        *self = Backoff::default();
    }

    /// When new connects may start, if backing off.
    pub(crate) fn retry_at(&self) -> Option<Instant> {
        self.retry_at
    }

    /// Consecutive non-client failures.
    pub(crate) fn failures(&self) -> u32 {
        self.failures
    }
}
