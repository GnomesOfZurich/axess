//! A metrics recorder for tests: every concern, one call log.
//!
//! [`RecordingMetrics`] implements all eight metric traits and appends the
//! name of each call to a shared log, so a test attaches it to the one
//! concern under test and asserts on the names that arrived:
//!
//! ```rust
//! use axess_core::metrics::{AuthFlowMetrics, MetricSinks};
//! use axess_core::testing::RecordingMetrics;
//! use std::sync::Arc;
//!
//! let recorder = Arc::new(RecordingMetrics::default());
//! let sinks = MetricSinks::noop().with_auth_flow(recorder.clone());
//! # let _ = sinks;
//! recorder.auth_attempt();
//! assert_eq!(recorder.count("auth_attempt"), 1);
//! ```

use crate::metrics::{
    AuditMetrics, AuthFlowMetrics, AuthzCacheMetrics, CsrfRefusal, FactorMetrics, ProviderCategory,
    ProviderRegistryMetrics, RequestGuardMetrics, RotationMetrics, SessionMetrics,
};
use std::sync::Mutex;

/// Records the name of every metric call, and the count a batched call
/// carried, in order.
#[derive(Debug, Default)]
pub struct RecordingMetrics {
    calls: Mutex<Vec<(&'static str, u64)>>,
}

impl RecordingMetrics {
    fn record(&self, name: &'static str, amount: u64) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((name, amount));
        }
    }

    /// Every call so far, as `(method name, amount)`; amount is 1 for a
    /// method without a count.
    pub fn calls(&self) -> Vec<(&'static str, u64)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// The sum of the amounts of the calls to `name`: how many times a
    /// per-event method fired, or the total a batched one carried.
    pub fn count(&self, name: &str) -> u64 {
        self.calls()
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, amount)| amount)
            .sum()
    }
}

impl AuthFlowMetrics for RecordingMetrics {
    fn auth_attempt(&self) {
        self.record("auth_attempt", 1);
    }
    fn auth_success(&self) {
        self.record("auth_success", 1);
    }
    fn auth_failure(&self) {
        self.record("auth_failure", 1);
    }
    fn account_locked(&self) {
        self.record("account_locked", 1);
    }
}

impl FactorMetrics for RecordingMetrics {
    fn factor_attempt(&self) {
        self.record("factor_attempt", 1);
    }
    fn factor_success(&self) {
        self.record("factor_success", 1);
    }
    fn factor_failure(&self) {
        self.record("factor_failure", 1);
    }
    fn factor_counter_store_outage(&self) {
        self.record("factor_counter_store_outage", 1);
    }
    fn attempt_throttled(&self) {
        self.record("attempt_throttled", 1);
    }
    fn recovery_codes_under_previous_pepper(&self) {
        self.record("recovery_codes_under_previous_pepper", 1);
    }
}

impl SessionMetrics for RecordingMetrics {
    fn session_created(&self) {
        self.record("session_created", 1);
    }
    fn session_invalidated(&self) {
        self.record("session_invalidated", 1);
    }
    fn session_binding_mismatch(&self) {
        self.record("session_binding_mismatch", 1);
    }
    fn session_fingerprint_backfilled(&self) {
        self.record("session_fingerprint_backfilled", 1);
    }
    fn sid_map_evicted(&self, count: u64) {
        self.record("sid_map_evicted", count);
    }
    fn back_channel_logout_unmatched(&self) {
        self.record("back_channel_logout_unmatched", 1);
    }
}

impl RotationMetrics for RecordingMetrics {
    fn encryption_key_fallback(&self) {
        self.record("encryption_key_fallback", 1);
    }
    fn fingerprint_key_fallback(&self) {
        self.record("fingerprint_key_fallback", 1);
    }
}

impl ProviderRegistryMetrics for RecordingMetrics {
    fn provider_duplicate_registration(&self) {
        self.record("provider_duplicate_registration", 1);
    }
    fn provider_reloaded(&self, category: ProviderCategory) {
        self.record(
            match category {
                ProviderCategory::OAuth => "provider_reloaded:oauth",
                ProviderCategory::Fido2 => "provider_reloaded:fido2",
                ProviderCategory::Ldap => "provider_reloaded:ldap",
            },
            1,
        );
        self.record("provider_reloaded", 1);
    }
    fn provider_removed(&self, category: ProviderCategory) {
        self.record(
            match category {
                ProviderCategory::OAuth => "provider_removed:oauth",
                ProviderCategory::Fido2 => "provider_removed:fido2",
                ProviderCategory::Ldap => "provider_removed:ldap",
            },
            1,
        );
        self.record("provider_removed", 1);
    }
    fn provider_reload_refused(&self, category: ProviderCategory) {
        self.record(
            match category {
                ProviderCategory::OAuth => "provider_reload_refused:oauth",
                ProviderCategory::Fido2 => "provider_reload_refused:fido2",
                ProviderCategory::Ldap => "provider_reload_refused:ldap",
            },
            1,
        );
        self.record("provider_reload_refused", 1);
    }
    fn fido2_rp_id_changed(&self) {
        self.record("fido2_rp_id_changed", 1);
    }
}

impl RequestGuardMetrics for RecordingMetrics {
    fn rate_limit_allowed(&self) {
        self.record("rate_limit_allowed", 1);
    }
    fn rate_limit_rejected(&self) {
        self.record("rate_limit_rejected", 1);
    }
    fn csrf_rejected(&self, reason: CsrfRefusal) {
        self.record(
            match reason {
                CsrfRefusal::NoSession => "csrf_rejected:no_session",
                CsrfRefusal::OriginMismatch => "csrf_rejected:origin_mismatch",
                CsrfRefusal::WebSocketOrigin => "csrf_rejected:websocket_origin",
                CsrfRefusal::TokenUnreadable => "csrf_rejected:token_unreadable",
                CsrfRefusal::TokenInvalid => "csrf_rejected:token_invalid",
            },
            1,
        );
        self.record("csrf_rejected", 1);
    }
}

impl AuthzCacheMetrics for RecordingMetrics {
    fn authz_policy_reloaded(&self) {
        self.record("authz_policy_reloaded", 1);
    }
    fn authz_policy_reload_refused(&self) {
        self.record("authz_policy_reload_refused", 1);
    }
    fn authz_cache_hits(&self, count: u64) {
        self.record("authz_cache_hits", count);
    }
    fn authz_cache_misses(&self, count: u64) {
        self.record("authz_cache_misses", count);
    }
    fn authz_cache_evictions(&self, count: u64) {
        self.record("authz_cache_evictions", count);
    }
    fn authz_cache_invalidations(&self, count: u64) {
        self.record("authz_cache_invalidations", count);
    }
}

impl AuditMetrics for RecordingMetrics {
    fn audit_store_outage(&self) {
        self.record("audit_store_outage", 1);
    }
    fn audit_event_shed(&self) {
        self.record("audit_event_shed", 1);
    }
}
