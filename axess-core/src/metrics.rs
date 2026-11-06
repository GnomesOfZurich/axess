//! Metrics hooks, one narrow trait per concern.
//!
//! Connect axess to a metrics backend (Prometheus, StatsD, OpenTelemetry) by
//! implementing the traits of the concerns you export, and hand them to the
//! components through [`MetricSinks`]. Every trait method defaults to a
//! no-op, and a concern you do not implement costs nothing, so a counter
//! added to one concern never touches the implementors of another.
//!
//! | Trait | Concern | Fed by |
//! |-------|---------|--------|
//! | [`AuthFlowMetrics`] | logins and lockouts | `AuthnService` |
//! | [`FactorMetrics`] | factor verification, throttle, lockout store | `AuthnService` |
//! | [`SessionMetrics`] | session lifecycle, binding, the `sid` map | `AuthnService`, `SessionLayer` |
//! | [`RotationMetrics`] | previous-key use during a rotation | `SessionCrypto`, `SessionLayer` |
//! | [`ProviderRegistryMetrics`] | duplicate provider registrations, live provider reloads | `AuthnService` |
//! | [`RequestGuardMetrics`] | rate limiting and CSRF | `RateLimitLayer`, `CsrfLayer` |
//! | [`AuthzCacheMetrics`] | entity-cache hits and misses | `EntityCache::flush_metrics` |
//! | [`AuditMetrics`] | audit store outage and shedding | `AuthnService` |
//!
//! # One exporter for every concern
//!
//! A type that implements all eight traits satisfies [`AxessMetrics`], and
//! [`MetricSinks::all`] wires it to every concern at once. A type that
//! implements some wires them one by one:
//!
//! ```rust
//! use axess_core::metrics::{AuthFlowMetrics, MetricSinks, SessionMetrics};
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicU64, Ordering};
//!
//! /// Counts logins and session creations; every other concern stays silent.
//! #[derive(Default)]
//! struct Counting {
//!     logins: AtomicU64,
//!     sessions: AtomicU64,
//! }
//!
//! impl AuthFlowMetrics for Counting {
//!     fn auth_attempt(&self) { self.logins.fetch_add(1, Ordering::Relaxed); }
//! }
//! impl SessionMetrics for Counting {
//!     fn session_created(&self) { self.sessions.fetch_add(1, Ordering::Relaxed); }
//! }
//!
//! let counting = Arc::new(Counting::default());
//! let sinks = MetricSinks::noop()
//!     .with_auth_flow(counting.clone())
//!     .with_session(counting.clone());
//! # let _ = sinks;
//! ```
//!
//! Then pass the sinks to the component:
//!
//! ```rust,ignore
//! let authn = AuthnService::builder(identity, factors)
//!     .with_metrics(sinks.clone())
//!     .build();
//! let sessions = SessionLayer::new(store, key, registry).with_metrics(sinks);
//! ```
//!
//! The rules for what is a metric, the naming scheme and the labels an
//! exporter may add are in the observability page of the book.

mod audit;
mod auth_flow;
mod authz_cache;
mod factors;
mod guard;
mod registry;
mod rotation;
mod session;
mod sinks;

pub use audit::AuditMetrics;
pub use auth_flow::AuthFlowMetrics;
pub use authz_cache::AuthzCacheMetrics;
pub use factors::FactorMetrics;
pub use guard::{CsrfRefusal, RequestGuardMetrics};
pub use registry::{ProviderCategory, ProviderRegistryMetrics};
pub use rotation::RotationMetrics;
pub use session::SessionMetrics;
pub use sinks::{AxessMetrics, MetricSinks};

/// No-op metrics implementation of every concern. Used when no metrics
/// backend is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopMetrics;

impl AuthFlowMetrics for NoopMetrics {}
impl FactorMetrics for NoopMetrics {}
impl SessionMetrics for NoopMetrics {}
impl RotationMetrics for NoopMetrics {}
impl ProviderRegistryMetrics for NoopMetrics {}
impl RequestGuardMetrics for NoopMetrics {}
impl AuthzCacheMetrics for NoopMetrics {}
impl AuditMetrics for NoopMetrics {}
