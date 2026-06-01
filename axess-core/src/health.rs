//! Health-check abstraction for operational readiness probes.
//!
//! Implement [`HealthCheck`] on your session stores, registries, or any other
//! backend to expose a `/healthz`-style endpoint. Use [`CompositeHealthCheck`]
//! to aggregate multiple backends into a single probe.
//!
//! # Example
//!
//! ```rust,ignore
//! use axess_core::health::{CompositeHealthCheck, HealthCheck};
//!
//! let health = CompositeHealthCheck::new()
//!     .add("session_store", store.clone())
//!     .add("session_registry", registry.clone());
//!
//! // In an Axum handler:
//! let status = health.check_all().await;
//! if status.is_healthy() { /* 200 */ } else { /* 503 */ }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Result of a single health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// The component is operating normally.
    Healthy,
    /// The component is functional but experiencing issues (e.g. high latency).
    Degraded(String),
    /// The component is not functional.
    Unhealthy(String),
}

impl HealthStatus {
    /// Returns `true` if the status is [`Healthy`](HealthStatus::Healthy).
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Returns `true` if the status is [`Unhealthy`](HealthStatus::Unhealthy).
    pub fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy(_))
    }
}

/// Aggregated result of checking multiple components.
#[derive(Debug, Clone)]
pub struct CompositeStatus {
    /// Per-component results, in the order they were registered.
    pub components: Vec<(String, HealthStatus)>,
}

impl CompositeStatus {
    /// Returns `true` if every component is [`Healthy`](HealthStatus::Healthy).
    pub fn is_healthy(&self) -> bool {
        self.components.iter().all(|(_, s)| s.is_healthy())
    }

    /// Returns `true` if any component is [`Unhealthy`](HealthStatus::Unhealthy).
    pub fn has_unhealthy(&self) -> bool {
        self.components.iter().any(|(_, s)| s.is_unhealthy())
    }

    /// Returns only the aggregate status without component details.
    ///
    /// Use this for external-facing endpoints to avoid leaking infrastructure
    /// information (component names, error messages) to unauthenticated callers.
    pub fn for_external(&self) -> HealthStatus {
        self.worst()
    }

    /// Returns the worst status across all components.
    pub fn worst(&self) -> HealthStatus {
        if self.has_unhealthy() {
            let msgs: Vec<&str> = self
                .components
                .iter()
                .filter_map(|(name, s)| match s {
                    HealthStatus::Unhealthy(_) => Some(name.as_str()),
                    _ => None,
                })
                .collect();
            HealthStatus::Unhealthy(format!("unhealthy: {}", msgs.join(", ")))
        } else if self
            .components
            .iter()
            .any(|(_, s)| matches!(s, HealthStatus::Degraded(_)))
        {
            HealthStatus::Degraded("one or more components degraded".to_string())
        } else {
            HealthStatus::Healthy
        }
    }
}

/// Async health check for a backend component.
///
/// Implement this on session stores, registries, or any other
/// infrastructure dependency that should be monitored.
pub trait HealthCheck: Send + Sync {
    /// Probe the component and return its current health.
    fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>>;
}

/// Aggregates multiple [`HealthCheck`] implementations into a single probe.
///
/// Use this to build a composite `/healthz` endpoint that checks all backends.
#[derive(Clone, Default)]
pub struct CompositeHealthCheck {
    checks: Vec<(String, Arc<dyn HealthCheck>)>,
}

impl CompositeHealthCheck {
    /// Create an empty composite health check.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named health check.
    ///
    /// If a check with the same name already exists, it is replaced.
    pub fn add(mut self, name: impl Into<String>, check: impl HealthCheck + 'static) -> Self {
        let name = name.into();
        self.checks.retain(|(n, _)| n != &name);
        self.checks.push((name, Arc::new(check)));
        self
    }

    /// Run all registered checks and return the aggregate status.
    ///
    /// Checks are run sequentially to avoid pulling in a `futures` dependency.
    /// Health probes are typically cheap (PING, SELECT 1) so this is fine for
    /// a small number of backends.
    pub async fn check_all(&self) -> CompositeStatus {
        let mut components = Vec::with_capacity(self.checks.len());
        for (name, check) in &self.checks {
            let status = check.check().await;
            components.push((name.clone(), status));
        }
        CompositeStatus { components }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysHealthy;
    impl HealthCheck for AlwaysHealthy {
        fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
            Box::pin(async { HealthStatus::Healthy })
        }
    }

    struct AlwaysUnhealthy;
    impl HealthCheck for AlwaysUnhealthy {
        fn check(&self) -> Pin<Box<dyn Future<Output = HealthStatus> + Send + '_>> {
            Box::pin(async { HealthStatus::Unhealthy("down".into()) })
        }
    }

    #[test]
    fn health_status_predicates() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(!HealthStatus::Healthy.is_unhealthy());
        assert!(!HealthStatus::Degraded("slow".into()).is_healthy());
        assert!(HealthStatus::Unhealthy("down".into()).is_unhealthy());
    }

    #[tokio::test]
    async fn composite_all_healthy() {
        let health = CompositeHealthCheck::new()
            .add("a", AlwaysHealthy)
            .add("b", AlwaysHealthy);
        let status = health.check_all().await;
        assert!(status.is_healthy());
        assert!(status.worst().is_healthy());
    }

    #[tokio::test]
    async fn composite_one_unhealthy() {
        let health = CompositeHealthCheck::new()
            .add("ok", AlwaysHealthy)
            .add("down", AlwaysUnhealthy);
        let status = health.check_all().await;
        assert!(!status.is_healthy());
        assert!(status.has_unhealthy());
        assert!(status.worst().is_unhealthy());
    }

    #[tokio::test]
    async fn composite_empty_is_healthy() {
        let health = CompositeHealthCheck::new();
        let status = health.check_all().await;
        assert!(status.is_healthy());
    }

    /// `worst()` rolls the names of all `Unhealthy` components
    /// into the aggregate message so operators can pinpoint which
    /// backend is down. Pins `delete match arm Unhealthy(_)` in the
    /// `filter_map`; without that arm, every component would fall
    /// through to the `_ => None` branch and the rolled-up message
    /// would contain no names ("unhealthy: ").
    #[tokio::test]
    async fn composite_worst_message_lists_unhealthy_component_names() {
        let health = CompositeHealthCheck::new()
            .add("primary-db", AlwaysUnhealthy)
            .add("cache", AlwaysHealthy)
            .add("queue", AlwaysUnhealthy);
        let status = health.check_all().await;
        let worst = status.worst();
        let HealthStatus::Unhealthy(msg) = worst else {
            panic!("worst() must return Unhealthy when components are down");
        };
        assert!(
            msg.contains("primary-db"),
            "worst() message must list 'primary-db' (got: {msg})"
        );
        assert!(
            msg.contains("queue"),
            "worst() message must list 'queue' (got: {msg})"
        );
        // Healthy components must NOT be in the rolled-up message.
        assert!(
            !msg.contains("cache"),
            "worst() must not name healthy components (got: {msg})"
        );
    }

    /// Registering a check with a name that already exists
    /// replaces the prior registration. Pins `!=` → `==` on the
    /// `retain` predicate at line 126; the mutant flips dedup so the
    /// new entry would *replace everything else* (keep only entries
    /// whose name matches the new one), making the per-name semantics
    /// silently break for any composite that registers more than one
    /// check.
    #[tokio::test]
    async fn composite_add_replaces_existing_name_and_keeps_others() {
        let health = CompositeHealthCheck::new()
            .add("db", AlwaysHealthy)
            .add("cache", AlwaysHealthy)
            // Re-register `db` with an Unhealthy stub; must replace the
            // prior `db` entry, not other entries.
            .add("db", AlwaysUnhealthy);
        let status = health.check_all().await;
        // Original behavior: ["db" -> Unhealthy, "cache" -> Healthy].
        // Mutant `==` would keep only entries whose name == new name,
        // so adding "cache" would wipe out "db", and re-adding "db"
        // would wipe out "cache", leaving exactly ["db" -> Unhealthy].
        assert_eq!(
            status.components.len(),
            2,
            "dedup must replace same-named entry, not wipe others (got: {:?})",
            status.components
        );
        let names: Vec<_> = status.components.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"db"), "'db' must be present");
        assert!(names.contains(&"cache"), "'cache' must remain");
        // The 'db' entry must be the new (Unhealthy) registration, not stale.
        let db_status = status
            .components
            .iter()
            .find(|(n, _)| n == "db")
            .map(|(_, s)| s.clone())
            .unwrap();
        assert!(
            db_status.is_unhealthy(),
            "'db' must reflect the most recent registration (Unhealthy)"
        );
    }
}
