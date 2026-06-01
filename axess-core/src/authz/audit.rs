//! Documented `tracing` schema for authorization decisions.
//!
//! axess emits a structured `tracing` event per Cedar evaluation inside
//! the [`PolicyEvaluator::is_authorized`](super::store::PolicyEvaluator::is_authorized)
//! impl on [`PolicyStore`](super::store::PolicyStore). Apps that need
//! audit logs route those events via `tracing-subscriber::Layer` to
//! wherever the audit needs to go: a file, an OpenTelemetry collector,
//! an Iggy/Kafka/Pulsar producer, a SIEM agent, etc.
//!
//! axess deliberately does **not** ship its own audit transport: the
//! `tracing` ecosystem already solves this and is the de facto Rust
//! pattern. This module documents the event shape so consumers can
//! filter and route confidently.
//!
//! # Event target
//!
//! All authorization-decision events use the target string:
//!
//! ```text
//! axess::authz::decision
//! ```
//!
//! The constant [`DECISION_TARGET`] holds this string; prefer it over
//! re-typing the literal so a future axess release can rename it
//! safely.
//!
//! # Event level
//!
//! `INFO`. Both allow and deny are emitted at the same level: both are
//! audit-relevant. Use `tracing-subscriber::filter::Targets` or a custom
//! `Layer::enabled` to drop allows in environments that only need
//! denies (rarely the right call for compliance regimes; keep both).
//!
//! # Event fields
//!
//! | Field | Type | Notes |
//! |---|---|---|
//! | `principal` | string (`Display` of `cedar_policy::EntityUid`) | e.g. `App::User::"alice"` |
//! | `action` | string (`Display` of `cedar_policy::EntityUid`) | e.g. `App::Action::"ViewLedger"` |
//! | `resource` | string (`Display` of `cedar_policy::EntityUid`) | e.g. `App::Ledger::"ledger-1"` |
//! | `decision` | string | `"allow"` or `"deny"` |
//! | `reasons` | `Debug` of `Vec<String>` | Cedar `PolicyId`s that produced the decision; empty for default-deny |
//! | `latency_us` | u64 | Cedar evaluation latency in microseconds |
//! | `reason` (optional) | string | Set when the decision is forced by a non-policy condition (e.g. `"request_validation_failed"`) |
//!
//! # Example: route audit to a file via tracing-subscriber
//!
//! ```ignore
//! use tracing_subscriber::{filter::Targets, layer::SubscriberExt, prelude::*};
//!
//! let audit_layer = tracing_subscriber::fmt::layer()
//!     .json()
//!     .with_writer(std::fs::File::create("audit.log").unwrap());
//!
//! let audit_filter = axess_core::authz::audit::tracing_filter();
//!
//! tracing_subscriber::registry()
//!     .with(tracing_subscriber::fmt::layer())                  // app logs
//!     .with(audit_layer.with_filter(audit_filter))             // audit -> file
//!     .init();
//! ```
//!
//! # Example: route audit to Iggy (or Kafka, etc.)
//!
//! Application implements its own `tracing_subscriber::Layer` whose
//! `on_event` filters on `axess::authz::decision` and forwards to the
//! desired transport. axess does not ship transport-specific code;
//! consumers pick the crate that fits their stack.

/// Target string used by all axess Cedar-decision events.
///
/// Prefer `DECISION_TARGET` over re-typing the literal so consumers stay
/// aligned with future axess naming.
pub const DECISION_TARGET: &str = "axess::authz::decision";

/// Returns true if `metadata` describes an axess authorization-decision
/// event. Use as a custom filter:
///
/// ```ignore
/// use tracing_subscriber::filter::filter_fn;
/// let audit_only = filter_fn(|m| axess_core::authz::audit::is_decision_event(m));
/// ```
pub fn is_decision_event(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.target() == DECISION_TARGET
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{Layer, Registry};

    /// Capture the bool result of `is_decision_event` for any event that
    /// fires while the layer is installed. We use this instead of building
    /// a `tracing::Metadata` directly (the upstream type is marked
    /// non-exhaustive and cannot be constructed externally).
    struct CaptureLayer {
        recorded: std::sync::Arc<std::sync::Mutex<Vec<bool>>>,
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            // Query `ctx` for span context as a sanity touch; the test
            // subscribers below run events at the root, so this always
            // returns `false`, but observing the value pins the read so
            // a future regression that re-routes events through a span
            // would surface as a test failure here rather than silently.
            assert!(ctx.event_span(event).is_none());
            self.recorded
                .lock()
                .unwrap()
                .push(is_decision_event(event.metadata()));
        }
    }

    #[test]
    fn matches_event_with_decision_target() {
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            recorded: recorded.clone(),
        };
        let subscriber = Registry::default().with(layer);
        with_default(subscriber, || {
            tracing::event!(target: "axess::authz::decision", tracing::Level::INFO, "decision");
        });
        assert_eq!(recorded.lock().unwrap().as_slice(), &[true]);
    }

    #[test]
    fn does_not_match_event_with_other_target() {
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            recorded: recorded.clone(),
        };
        let subscriber = Registry::default().with(layer);
        with_default(subscriber, || {
            tracing::event!(target: "some::other::target", tracing::Level::INFO, "other");
        });
        assert_eq!(recorded.lock().unwrap().as_slice(), &[false]);
    }
}
