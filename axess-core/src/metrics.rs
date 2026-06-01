//! Metrics hook trait for observability.
//!
//! Implement [`AuthnMetrics`] to connect axess to your metrics backend
//! (Prometheus, StatsD, OpenTelemetry, etc.). All methods have no-op defaults
//! so you only need to override the ones you care about.
//!
//! # Reference implementation (atomic counters)
//!
//! ```rust
//! use axess_core::metrics::AuthnMetrics;
//! use std::sync::atomic::{AtomicU64, Ordering};
//!
//! /// Minimal metrics using atomic counters. Replace with prometheus or
//! /// opentelemetry counters in production.
//! pub struct CountingMetrics {
//!     pub login_attempts: AtomicU64,
//!     pub login_successes: AtomicU64,
//!     pub login_failures: AtomicU64,
//!     pub factor_attempts: AtomicU64,
//!     pub factor_successes: AtomicU64,
//!     pub factor_failures: AtomicU64,
//!     pub lockouts: AtomicU64,
//!     pub sessions_created: AtomicU64,
//!     pub rate_limit_rejected: AtomicU64,
//! }
//!
//! impl CountingMetrics {
//!     pub fn new() -> Self {
//!         Self {
//!             login_attempts: AtomicU64::new(0),
//!             login_successes: AtomicU64::new(0),
//!             login_failures: AtomicU64::new(0),
//!             factor_attempts: AtomicU64::new(0),
//!             factor_successes: AtomicU64::new(0),
//!             factor_failures: AtomicU64::new(0),
//!             lockouts: AtomicU64::new(0),
//!             sessions_created: AtomicU64::new(0),
//!             rate_limit_rejected: AtomicU64::new(0),
//!         }
//!     }
//! }
//!
//! impl AuthnMetrics for CountingMetrics {
//!     fn auth_attempt(&self) { self.login_attempts.fetch_add(1, Ordering::Relaxed); }
//!     fn auth_success(&self) { self.login_successes.fetch_add(1, Ordering::Relaxed); }
//!     fn auth_failure(&self) { self.login_failures.fetch_add(1, Ordering::Relaxed); }
//!     fn factor_attempt(&self) { self.factor_attempts.fetch_add(1, Ordering::Relaxed); }
//!     fn factor_success(&self) { self.factor_successes.fetch_add(1, Ordering::Relaxed); }
//!     fn factor_failure(&self) { self.factor_failures.fetch_add(1, Ordering::Relaxed); }
//!     fn account_locked(&self) { self.lockouts.fetch_add(1, Ordering::Relaxed); }
//!     fn session_created(&self) { self.sessions_created.fetch_add(1, Ordering::Relaxed); }
//!     fn rate_limit_rejected(&self) { self.rate_limit_rejected.fetch_add(1, Ordering::Relaxed); }
//! }
//! ```
//!
//! Wire it in:
//!
//! ```rust,ignore
//! let authn = AuthnService::new(identity, factors)
//!     .with_metrics(CountingMetrics::new());
//! ```

/// Trait for reporting authentication and session metrics.
///
/// All methods have no-op defaults so implementations can be incremental.
/// Methods are `&self` and take no parameters; implementations should
/// increment internal counters/gauges. If you need labels (user, tenant,
/// factor kind), capture them in the implementation via thread-local or
/// span context.
pub trait AuthnMetrics: Send + Sync + 'static {
    // ── Authentication ──────────────────────────────────────────────────

    /// A login attempt was started (begin_login called).
    fn auth_attempt(&self) {}

    /// Authentication completed successfully (all factors passed).
    fn auth_success(&self) {}

    /// Authentication failed (bad credentials, locked, etc.).
    fn auth_failure(&self) {}

    /// A factor verification was attempted.
    fn factor_attempt(&self) {}

    /// A factor verification succeeded.
    fn factor_success(&self) {}

    /// A factor verification failed.
    fn factor_failure(&self) {}

    /// The failed-attempt counter store errored on `record_failed_attempt`.
    ///
    /// Distinct from [`factor_failure`](Self::factor_failure): the user did
    /// supply credentials, but the persistent counter that drives lockout
    /// could not be incremented. The request still returns
    /// `InvalidCredential` (so attackers can't probe store outages), but
    /// operators should alert on this; it means lockout policy is
    /// silently disabled while the outage persists.
    fn factor_counter_store_outage(&self) {}

    /// An account was locked due to too many failed attempts.
    fn account_locked(&self) {}

    // ── Sessions ────────────────────────────────────────────────────────

    /// A new session was created (ID cycled after auth or first visit).
    fn session_created(&self) {}

    /// A session was invalidated (logout, suspend, forced logout).
    fn session_invalidated(&self) {}

    /// Session binding mismatch detected (possible hijacking).
    fn session_binding_mismatch(&self) {}

    // ── Rate limiting ───────────────────────────────────────────────────

    /// A request was allowed through the rate limiter.
    fn rate_limit_allowed(&self) {}

    /// A request was rejected by the rate limiter (429).
    fn rate_limit_rejected(&self) {}

    // ── AuthZ entity cache ──────────────────────────────────────────────
    //
    // Cache hit/miss signals from the Cedar entity-resolution cache on
    // the authorization decision path. The default `EntityCache` (and
    // the opt-in `Moka` / `Valkey` decorators) call these once per
    // lookup so ops dashboards can compute hit rates without poking at
    // the internal `axess_cache::CacheStats` snapshot.

    /// An authz entity lookup found the value in cache (saved a provider call).
    fn authz_cache_hit(&self) {}

    /// An authz entity lookup missed and had to call through to the provider.
    fn authz_cache_miss(&self) {}

    /// The cache rejected a write because the capacity-bounded LRU is full
    /// and evicted an existing entry to make room. Persistent high counts
    /// suggest the configured capacity is too small for the working set.
    fn authz_cache_eviction(&self) {}

    /// An invalidation channel cleared one or more cache entries (e.g.
    /// policy change, principal revocation). Useful for verifying that
    /// downstream invalidation actually reaches the cache layer.
    fn authz_cache_invalidation(&self) {}
}

/// No-op metrics implementation. Used when no metrics backend is configured.
#[derive(Debug, Clone, Default)]
pub struct NoopMetrics;

impl AuthnMetrics for NoopMetrics {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingMetrics {
        attempts: AtomicU32,
        successes: AtomicU32,
        failures: AtomicU32,
    }

    impl CountingMetrics {
        fn new() -> Self {
            Self {
                attempts: AtomicU32::new(0),
                successes: AtomicU32::new(0),
                failures: AtomicU32::new(0),
            }
        }
    }

    impl AuthnMetrics for CountingMetrics {
        fn auth_attempt(&self) {
            self.attempts.fetch_add(1, Ordering::Relaxed);
        }
        fn auth_success(&self) {
            self.successes.fetch_add(1, Ordering::Relaxed);
        }
        fn auth_failure(&self) {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn noop_metrics_compiles() {
        let m = NoopMetrics;
        m.auth_attempt();
        m.auth_success();
        m.auth_failure();
        m.factor_attempt();
        m.session_created();
        m.rate_limit_allowed();
        m.rate_limit_rejected();
    }

    #[test]
    fn counting_metrics_increments() {
        let m = CountingMetrics::new();
        m.auth_attempt();
        m.auth_attempt();
        m.auth_success();
        m.auth_failure();

        assert_eq!(m.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(m.successes.load(Ordering::Relaxed), 1);
        assert_eq!(m.failures.load(Ordering::Relaxed), 1);
    }
}
