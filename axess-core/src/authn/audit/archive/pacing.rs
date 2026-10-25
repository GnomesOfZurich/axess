//! A tick that overruns the interval does not make the loop fire the
//! missed ticks back to back.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

/// Records when each `select_unarchived_before` call starts and ends, and
/// takes `work` to answer.
struct SlowSource {
    spans: Arc<Mutex<Vec<(Instant, Instant)>>>,
    work: Duration,
}

impl AuditRetentionSource for SlowSource {
    type EventId = u64;
    type Error = std::convert::Infallible;

    async fn select_unarchived_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        _: usize,
    ) -> Result<Vec<(u64, AuthEvent)>, Self::Error> {
        let start = Instant::now();
        tokio::time::sleep(self.work).await;
        self.spans.lock().unwrap().push((start, Instant::now()));
        Ok(vec![])
    }
    async fn mark_archived(
        &self,
        _: &[u64],
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    async fn purge_hot_archived_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

#[tokio::test]
async fn an_overrunning_tick_is_followed_by_a_full_interval_of_rest() {
    let spans = Arc::new(Mutex::new(Vec::new()));
    let interval = Duration::from_millis(60);
    let handle = AuditRetentionLoop::new(
        SlowSource {
            spans: spans.clone(),
            work: Duration::from_millis(200),
        },
        NoopAuditArchiver,
        AuditRetentionPolicy::default(),
    )
    .with_tick_interval(interval)
    .spawn();

    tokio::time::sleep(Duration::from_millis(900)).await;
    handle.abort();

    let spans = spans.lock().unwrap().clone();
    assert!(
        spans.len() >= 2,
        "expected several ticks, got {}",
        spans.len()
    );
    for pair in spans.windows(2) {
        let rest = pair[1].0.duration_since(pair[0].1);
        assert!(
            rest >= interval - Duration::from_millis(15),
            "next tick started {rest:?} after the previous one ended"
        );
    }
}
