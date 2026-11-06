//! The set of sinks a component reports to, one per concern.

use super::{
    AuditMetrics, AuthFlowMetrics, AuthzCacheMetrics, FactorMetrics, NoopMetrics,
    ProviderRegistryMetrics, RequestGuardMetrics, RotationMetrics, SessionMetrics,
};
use std::sync::Arc;

/// A type that reports every concern. Implemented for any type that
/// implements all eight concern traits; use it to wire one exporter to
/// everything with [`MetricSinks::all`].
pub trait AxessMetrics:
    AuthFlowMetrics
    + FactorMetrics
    + SessionMetrics
    + RotationMetrics
    + ProviderRegistryMetrics
    + RequestGuardMetrics
    + AuthzCacheMetrics
    + AuditMetrics
{
}

impl<T> AxessMetrics for T where
    T: AuthFlowMetrics
        + FactorMetrics
        + SessionMetrics
        + RotationMetrics
        + ProviderRegistryMetrics
        + RequestGuardMetrics
        + AuthzCacheMetrics
        + AuditMetrics
{
}

/// One sink per concern. Cheap to clone; clones share the sinks.
///
/// Starts as all no-ops ([`noop`](Self::noop)); each `with_*` method replaces
/// the sink of one concern. A component reads only the concerns it reports,
/// so the same value can be handed to every builder and layer.
#[derive(Clone)]
pub struct MetricSinks {
    pub(crate) auth_flow: Arc<dyn AuthFlowMetrics>,
    pub(crate) factors: Arc<dyn FactorMetrics>,
    pub(crate) session: Arc<dyn SessionMetrics>,
    pub(crate) rotation: Arc<dyn RotationMetrics>,
    pub(crate) registry: Arc<dyn ProviderRegistryMetrics>,
    pub(crate) guard: Arc<dyn RequestGuardMetrics>,
    pub(crate) authz_cache: Arc<dyn AuthzCacheMetrics>,
    pub(crate) audit: Arc<dyn AuditMetrics>,
}

impl MetricSinks {
    /// Every concern reports to nothing.
    pub fn noop() -> Self {
        let noop = Arc::new(NoopMetrics);
        Self {
            auth_flow: noop.clone(),
            factors: noop.clone(),
            session: noop.clone(),
            rotation: noop.clone(),
            registry: noop.clone(),
            guard: noop.clone(),
            authz_cache: noop.clone(),
            audit: noop,
        }
    }

    /// Every concern reports to `metrics`.
    pub fn all<M: AxessMetrics>(metrics: Arc<M>) -> Self {
        Self {
            auth_flow: metrics.clone(),
            factors: metrics.clone(),
            session: metrics.clone(),
            rotation: metrics.clone(),
            registry: metrics.clone(),
            guard: metrics.clone(),
            authz_cache: metrics.clone(),
            audit: metrics,
        }
    }

    /// Report the authentication-flow concern to `sink`.
    pub fn with_auth_flow(mut self, sink: Arc<dyn AuthFlowMetrics>) -> Self {
        self.auth_flow = sink;
        self
    }

    /// Report the factor concern to `sink`.
    pub fn with_factors(mut self, sink: Arc<dyn FactorMetrics>) -> Self {
        self.factors = sink;
        self
    }

    /// Report the session concern to `sink`.
    pub fn with_session(mut self, sink: Arc<dyn SessionMetrics>) -> Self {
        self.session = sink;
        self
    }

    /// Report the rotation-window concern to `sink`.
    pub fn with_rotation(mut self, sink: Arc<dyn RotationMetrics>) -> Self {
        self.rotation = sink;
        self
    }

    /// Report the provider-registry concern to `sink`.
    pub fn with_provider_registry(mut self, sink: Arc<dyn ProviderRegistryMetrics>) -> Self {
        self.registry = sink;
        self
    }

    /// Report the request-guard concern (rate limiting, CSRF) to `sink`.
    pub fn with_request_guard(mut self, sink: Arc<dyn RequestGuardMetrics>) -> Self {
        self.guard = sink;
        self
    }

    /// Report the authorization-cache concern to `sink`.
    pub fn with_authz_cache(mut self, sink: Arc<dyn AuthzCacheMetrics>) -> Self {
        self.authz_cache = sink;
        self
    }

    /// Report the audit concern to `sink`.
    pub fn with_audit(mut self, sink: Arc<dyn AuditMetrics>) -> Self {
        self.audit = sink;
        self
    }

    /// The authorization-cache sink, for
    /// [`EntityCache::flush_metrics`](crate::authz::cache::EntityCache::flush_metrics).
    pub fn authz_cache(&self) -> &dyn AuthzCacheMetrics {
        self.authz_cache.as_ref()
    }

    /// The rotation-window sink, for
    /// [`SessionCrypto::with_metrics`](crate::session::SessionCrypto::with_metrics).
    pub fn rotation(&self) -> Arc<dyn RotationMetrics> {
        self.rotation.clone()
    }
}

impl Default for MetricSinks {
    fn default() -> Self {
        Self::noop()
    }
}

impl std::fmt::Debug for MetricSinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricSinks").finish_non_exhaustive()
    }
}
