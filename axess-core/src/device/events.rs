//! Emission surface for device-lifecycle audit events.
//!
//! The [`DeviceEventSink`] trait is the bridge between the device
//! subsystem (which transitions trust levels, creates rows, revokes
//! devices) and the application's audit pipeline (which knows where
//! `auth_events` rows actually live; typically the
//! [`IdentityStore`](crate::authn::store::IdentityStore) but
//! could equally be a separate SIEM forwarder, an Iggy stream, etc.).
//!
//! # Why a sink rather than a coupling to `IdentityStore`
//!
//! The device subsystem is tenant-scoped and depends only on its own
//! storage trait. Coupling it directly to `IdentityStore` would force
//! every device-only deployment to bring the full identity/factor
//! stack along. The sink is dyn-safe, default-noop, and applications
//! plug whichever audit pipeline they have.
//!
//! # Best-effort semantics
//!
//! Sink failures are logged at `warn!` and do **not** abort the
//! caller's transition. A device cascade that revokes 100 rows and
//! whose sink times out on event #50 still revokes all 100. This
//! mirrors the existing best-effort pattern in
//! [`cascade::cascade_revoke_devices`](super::cascade::cascade_revoke_devices)
//! since operationally, the device-state mutation is the security signal
//! and audit is for forensics.
//!
//! # What's wired today
//!
//! - [`DeviceLifecycleService::ensure_device`](super::lifecycle::DeviceLifecycleService::ensure_device)
//!   emits `AuthEventType::DeviceFirstSeen` on the create path.
//!
//! Cascade-time and sweep-time emission (`DeviceRevoked` /
//! `DevicePurged`) is left to the application: the cascade returns
//! the count of revoked devices and the sweep returns
//! [`SweepCounts`](super::store::SweepCounts), so callers can emit
//! aggregate or per-device events as their audit volume tolerance
//! permits.

use std::pin::Pin;
use std::sync::Arc;

use crate::authn::event::AuthEvent;

/// Application-provided sink for device-lifecycle audit events.
///
/// Object-safe (boxed future) so a single
/// [`DeviceLifecycleService`](super::lifecycle::DeviceLifecycleService)
/// can hold an `Arc<dyn DeviceEventSink>` without picking up an extra
/// generic parameter that ripples through every wiring site.
pub trait DeviceEventSink: Send + Sync + 'static {
    /// Persist the supplied [`AuthEvent`]. Sink failures are
    /// logged-and-swallowed by the caller; return `()` even on
    /// internal failure once you've decided whether to propagate the
    /// signal up your stack.
    fn emit<'a>(
        &'a self,
        event: AuthEvent,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// No-op sink. Used as the default when no real sink is wired so
/// the device subsystem stays operational on a deployment that
/// doesn't (yet) record audit events.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDeviceEventSink;

impl DeviceEventSink for NoopDeviceEventSink {
    fn emit<'a>(
        &'a self,
        event: AuthEvent,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        tracing::trace!(
            target: "axess::device::events",
            event_type = ?event.event_type,
            "NoopDeviceEventSink: device event discarded",
        );
        Box::pin(async {})
    }
}

/// Adapter that forwards events to an
/// [`IdentityAuthnLog::record_event`](crate::authn::IdentityAuthnLog::record_event).
///
/// This is the canonical production wiring: applications already
/// implement `IdentityStore` for their backend and have an
/// `auth_events` table; the adapter just plugs the device subsystem
/// into that pipeline.
///
/// Errors from the underlying store are logged at `warn!` and
/// swallowed so a transient DB blip on the audit path doesn't abort
/// the device-state mutation that triggered the event.
pub struct IdentityStoreEventSink<S>
where
    S: crate::authn::store::IdentityStore,
{
    store: Arc<S>,
}

impl<S> IdentityStoreEventSink<S>
where
    S: crate::authn::store::IdentityStore,
{
    /// Wrap an `IdentityStore` so its `record_event` becomes a
    /// [`DeviceEventSink`].
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
        }
    }
}

impl<S> DeviceEventSink for IdentityStoreEventSink<S>
where
    S: crate::authn::store::IdentityStore,
{
    fn emit<'a>(
        &'a self,
        event: AuthEvent,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let store = self.store.clone();
        Box::pin(async move {
            if let Err(e) = store.record_event(event).await {
                tracing::warn!(error = %e, "device-event sink: record_event failed");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authn::event::{AuthEventBuilder, AuthEventType};
    use std::sync::Mutex;

    /// Test sink that records every emitted event for assertion.
    pub(crate) struct CapturingSink {
        pub(crate) events: Mutex<Vec<AuthEvent>>,
    }

    impl CapturingSink {
        pub(crate) fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
    }

    impl DeviceEventSink for CapturingSink {
        fn emit<'a>(
            &'a self,
            event: AuthEvent,
        ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().unwrap().push(event);
            })
        }
    }

    /// Pin: the noop sink doesn't panic and doesn't observe the event.
    #[tokio::test]
    async fn noop_sink_is_a_silent_drop() {
        let sink = NoopDeviceEventSink;
        let event = AuthEventBuilder::success(AuthEventType::DeviceFirstSeen).build();
        sink.emit(event).await;
        // Nothing to assert; the test passes if the future resolves.
    }

    /// Pin: the capturing sink records every emit, in order.
    #[tokio::test]
    async fn capturing_sink_records_every_emit() {
        let sink = CapturingSink::new();
        sink.emit(AuthEventBuilder::success(AuthEventType::DeviceFirstSeen).build())
            .await;
        sink.emit(AuthEventBuilder::success(AuthEventType::DeviceRevoked).build())
            .await;
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, AuthEventType::DeviceFirstSeen);
        assert_eq!(events[1].event_type, AuthEventType::DeviceRevoked);
    }
}
