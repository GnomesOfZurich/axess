use super::*;
use crate::authn::store::IdentityAuthnLog as _;
use crate::testing::mock_authn::MockIdentityStore;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

fn event_at(time: i64) -> AuthEvent {
    let mut e = make_test_event();
    e.event_time = time;
    e
}

fn make_test_event() -> AuthEvent {
    use crate::authn::event::{AuthEventBuilder, AuthEventStatus, AuthEventType};
    AuthEventBuilder::new(
        None,
        None,
        AuthEventType::LoginAttempt,
        AuthEventStatus::Failure,
    )
    .build()
}

async fn enrich(e: AuthEvent) -> RichAuthnEvent {
    RichAuthnEvent::from_event(e)
}

/// Records the `event_time` of every event it is handed, in order.
#[derive(Clone, Default)]
struct RecordingSink(Arc<Mutex<Vec<i64>>>);

impl AuthnAnalyticsSink for RecordingSink {
    type Error = std::convert::Infallible;
    async fn record_rich(&self, e: RichAuthnEvent) -> Result<(), Self::Error> {
        self.0.lock().unwrap().push(e.event.event_time);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "recording"
    }
}

impl RecordingSink {
    fn seen(&self) -> Vec<i64> {
        self.0.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn noop_sink_accepts_any_event() {
    let sink = NoopAuthnAnalyticsSink;
    let event = RichAuthnEvent::from_event(make_test_event());
    assert!(sink.record_rich(event).await.is_ok());
    assert_eq!(sink.name(), "noop");
}

#[test]
fn rich_event_builder_chain_populates_optionals() {
    let rich = RichAuthnEvent::from_event(make_test_event())
        .with_geo_country("CH")
        .with_geo_asn(13335)
        .with_tag("channel", "mobile");

    assert_eq!(rich.geo_country.as_deref(), Some("CH"));
    assert_eq!(rich.geo_asn, Some(13335));
    assert_eq!(rich.tags.len(), 1);
    assert_eq!(rich.tags[0], ("channel".to_string(), "mobile".to_string()));
}

#[tokio::test]
async fn events_reach_the_sink_in_order_after_a_flush() {
    let sink = RecordingSink::default();
    let (log, worker) = AuditLogWithAnalytics::new(MockIdentityStore::new(), sink.clone(), enrich);
    let drain = worker.spawn();
    for t in 1..=5 {
        log.record_event(event_at(t)).await.unwrap();
    }
    log.flush().await.unwrap();
    assert_eq!(sink.seen(), vec![1, 2, 3, 4, 5]);
    assert_eq!(log.dropped_events(), 0);
    log.shutdown().await;
    drain.await.unwrap();
}

#[tokio::test]
async fn analytics_is_queued_only_after_the_regulatory_write_succeeds() {
    for fail in [true, false] {
        let inner = MockIdentityStore::new();
        if fail {
            inner.arm_record_event_failure();
        }
        let sink = RecordingSink::default();
        let (log, worker) = AuditLogWithAnalytics::new(inner, sink.clone(), enrich);
        let drain = worker.spawn();
        assert_eq!(log.record_event(event_at(9)).await.is_err(), fail);
        log.flush().await.unwrap();
        assert_eq!(sink.seen().len(), usize::from(!fail), "fail={fail}");
        log.shutdown().await;
        drain.await.unwrap();
    }
}

#[tokio::test]
async fn shutdown_drains_the_queue_before_the_worker_ends() {
    let sink = RecordingSink::default();
    let (log, worker) = AuditLogWithAnalytics::new(MockIdentityStore::new(), sink.clone(), enrich);
    // Queue first, start the worker after: everything must still arrive.
    for t in 1..=4 {
        log.record_event(event_at(t)).await.unwrap();
    }
    let drain = worker.spawn();
    log.shutdown().await;
    drain.await.unwrap();
    assert_eq!(sink.seen(), vec![1, 2, 3, 4]);
}

/// With no worker running the queue fills and the overflow is counted:
/// recording never waits and never spawns. Construction and recording need
/// no worker, and the unbounded spawn-per-event shape had no counter.
#[tokio::test]
async fn a_full_queue_drops_and_counts_without_waiting() {
    let sink = RecordingSink::default();
    let (log, worker) =
        AuditLogWithAnalytics::with_capacity(MockIdentityStore::new(), sink.clone(), enrich, 2);
    for t in 1..=5 {
        log.record_event(event_at(t))
            .await
            .expect("a full analytics queue never fails the regulatory write");
    }
    assert_eq!(log.dropped_events(), 3);
    assert_eq!(log.inner().events().len(), 5, "all five are on the record");

    let drain = worker.spawn();
    log.shutdown().await;
    drain.await.unwrap();
    assert_eq!(
        sink.seen(),
        vec![1, 2],
        "the first two fit, the rest were shed"
    );
}

struct BlockedSink {
    gate: Arc<Notify>,
    started: Arc<AtomicUsize>,
}

impl AuthnAnalyticsSink for BlockedSink {
    type Error = std::convert::Infallible;
    async fn record_rich(&self, _: RichAuthnEvent) -> Result<(), Self::Error> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.gate.notified().await;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "blocked"
    }
}

#[tokio::test]
async fn a_stalled_sink_never_stalls_recording() {
    let gate = Arc::new(Notify::new());
    let started = Arc::new(AtomicUsize::new(0));
    let sink = BlockedSink {
        gate: gate.clone(),
        started: started.clone(),
    };
    let (log, worker) =
        AuditLogWithAnalytics::with_capacity(MockIdentityStore::new(), sink, enrich, 1);
    let drain = worker.spawn();

    log.record_event(event_at(1)).await.unwrap();
    while started.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    // The sink holds event 1 and never returns. One more fits the queue; the
    // rest are shed, and every call still returns at once.
    for t in 2..=6 {
        log.record_event(event_at(t)).await.unwrap();
    }
    assert_eq!(log.dropped_events(), 4);

    gate.notify_one();
    gate.notify_one();
    log.shutdown().await;
    drain.await.unwrap();
}

struct PanicsOnce(Arc<AtomicUsize>);

#[tokio::test]
async fn a_panicking_enricher_costs_one_event_not_the_worker() {
    let calls = Arc::new(AtomicUsize::new(0));
    let panics = PanicsOnce(calls.clone());
    let sink = RecordingSink::default();
    let enricher = move |e: AuthEvent| {
        let first = panics.0.fetch_add(1, Ordering::SeqCst) == 0;
        async move {
            assert!(!first, "enricher failure for the first event");
            RichAuthnEvent::from_event(e)
        }
    };
    let (log, worker) =
        AuditLogWithAnalytics::new(MockIdentityStore::new(), sink.clone(), enricher);
    let drain = worker.spawn();
    log.record_event(event_at(1)).await.unwrap();
    log.record_event(event_at(2)).await.unwrap();
    log.flush().await.unwrap();
    assert_eq!(sink.seen(), vec![2], "event 1 was lost, event 2 arrived");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    log.shutdown().await;
    drain.await.unwrap();
}

#[tokio::test]
async fn flush_reports_a_stopped_worker() {
    let (log, worker) =
        AuditLogWithAnalytics::new(MockIdentityStore::new(), RecordingSink::default(), enrich);
    drop(worker);
    assert_eq!(log.flush().await, Err(AnalyticsClosed));
    log.record_event(event_at(1)).await.unwrap();
    assert_eq!(log.dropped_events(), 1, "a stopped worker counts as a drop");
}
