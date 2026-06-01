//! [`EventSink`], the trait every producer rides, plus the standard
//! sinks ([`NoopEventSink`] and [`LogAndSwallow`]).

use crate::Event;
use crate::kind::EventPayload;
use core::marker::PhantomData;

/// Errors a sink can report. Concrete sinks define their own variants
/// behind this façade so the trait stays object-safe.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// Sink could not reach its backend (broker, store, etc.).
    #[error("sink unavailable: {0}")]
    Unavailable(String),

    /// Sink rejected the batch (rate-limit, payload size, schema).
    #[error("sink rejected batch: {0}")]
    Rejected(String),

    /// Wrapped underlying error from a sink-specific source.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Application-provided sink for events. Async, batched, and
/// `Result`-returning so the producer can decide how to handle
/// transient failures (retry, dead-letter, log+swallow).
///
/// For best-effort emission paths where the producer cannot block on
/// the sink and treats failures as recoverable, wrap the sink in
/// [`LogAndSwallow`].
///
/// Uses native AFIT (`impl Future + Send`) for zero-allocation
/// dispatch; no `Box<Pin<dyn Future>>` per call. The trait is not
/// `dyn`-compatible as a consequence; consumers take `S: EventSink<P>`
/// generically rather than `dyn EventSink<P>`. No production callers
/// use dynamic dispatch on this trait.
pub trait EventSink<P>: Send + Sync + 'static
where
    P: EventPayload,
{
    /// Persist or publish a batch of events. Backends are free to
    /// fan-out, persist, or both. The contract is "after a
    /// successful return, all supplied events have been accepted by
    /// the backend."
    fn emit(
        &self,
        events: &[Event<P>],
    ) -> impl core::future::Future<Output = Result<(), SinkError>> + Send;
}

/// Sink that drops every event. Used as a default when no real sink
/// is wired so producers can stay operational on a deployment that
/// doesn't (yet) record events.
#[derive(Debug, Default)]
pub struct NoopEventSink<P>(PhantomData<fn() -> P>);

impl<P> NoopEventSink<P> {
    /// Construct a no-op sink.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<P> EventSink<P> for NoopEventSink<P>
where
    P: EventPayload,
{
    async fn emit(&self, events: &[Event<P>]) -> Result<(), SinkError> {
        tracing::trace!(
            target: "axess::events::noop_sink",
            count = events.len(),
            "NoopEventSink: batch discarded",
        );
        Ok(())
    }
}

/// Wraps any [`EventSink`] and converts errors into a `warn!` log,
/// returning `Ok(())` regardless. Intended for best-effort emission
/// paths where the producer's primary work has already committed and
/// the audit/observability emit must not block or roll back.
///
/// Mirrors the existing best-effort pattern in axess's device
/// subsystem; operationally, the state mutation is the security
/// signal; audit is for forensics.
#[derive(Debug)]
pub struct LogAndSwallow<S>(pub S);

impl<P, S> EventSink<P> for LogAndSwallow<S>
where
    P: EventPayload,
    S: EventSink<P>,
{
    async fn emit(&self, events: &[Event<P>]) -> Result<(), SinkError> {
        if let Err(e) = self.0.emit(events).await {
            tracing::warn!(error = %e, count = events.len(), "event sink: emit failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind::KindTag;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Debug)]
    struct DummyPayload;

    impl EventPayload for DummyPayload {
        fn kind_tag(&self) -> KindTag {
            KindTag::new("test.dummy.v1")
        }
        #[cfg(feature = "serde")]
        fn to_inner_json(&self) -> serde_json::Value {
            serde_json::json!({})
        }
    }

    struct RecorderSink {
        calls: Arc<AtomicUsize>,
    }

    impl EventSink<DummyPayload> for RecorderSink {
        async fn emit(&self, events: &[Event<DummyPayload>]) -> Result<(), SinkError> {
            tracing::trace!(
                target: "axess::events::recorder_sink",
                count = events.len(),
                "RecorderSink: call observed",
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// `LogAndSwallow::emit` MUST forward to the inner sink. Mutation
    /// `-> Ok(())` would skip the inner call; pin by counting.
    #[tokio::test]
    async fn log_and_swallow_forwards_to_inner_sink() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = RecorderSink {
            calls: calls.clone(),
        };
        let sink = LogAndSwallow(inner);
        let res = sink.emit(&[]).await;
        assert!(res.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
