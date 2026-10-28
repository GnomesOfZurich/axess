//! Draining the backlog in one wake, and starting without a first rest.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::authn::event::{AuthEventBuilder, AuthEventStatus, AuthEventType};

fn event() -> AuthEvent {
    AuthEventBuilder::new(
        None,
        None,
        AuthEventType::LoginAttempt,
        AuthEventStatus::Success,
    )
    .build()
}

/// An in-memory hot table: `select` returns the oldest rows up to the limit
/// and `mark_archived` removes them, as a real table's `archived_at IS NULL`
/// filter would.
#[derive(Clone)]
struct Table {
    rows: Arc<Mutex<Vec<u64>>>,
    selects: Arc<Mutex<u32>>,
}

impl Table {
    fn with(n: u64) -> Self {
        Self {
            rows: Arc::new(Mutex::new((0..n).collect())),
            selects: Arc::new(Mutex::new(0)),
        }
    }
    fn left(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
}

impl AuditRetentionSource for Table {
    type EventId = u64;
    type Error = std::convert::Infallible;

    async fn select_unarchived_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> Result<Vec<(u64, AuthEvent)>, Self::Error> {
        *self.selects.lock().unwrap() += 1;
        let rows = self.rows.lock().unwrap();
        Ok(rows.iter().take(limit).map(|id| (*id, event())).collect())
    }
    async fn mark_archived(
        &self,
        ids: &[u64],
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Self::Error> {
        self.rows.lock().unwrap().retain(|id| !ids.contains(id));
        Ok(())
    }
    async fn purge_hot_archived_before(
        &self,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, Self::Error> {
        Ok(0)
    }
}

fn retention(table: &Table, batch: usize) -> AuditRetentionLoop<Table, NoopAuditArchiver> {
    AuditRetentionLoop::new(
        table.clone(),
        NoopAuditArchiver,
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(batch)
}

#[tokio::test]
async fn one_drain_clears_a_backlog_of_several_batches() {
    let table = Table::with(35);
    let report = retention(&table, 10).drain().await.unwrap();
    assert_eq!(report.archived, 35);
    assert_eq!(table.left(), 0);
    assert_eq!(*table.selects.lock().unwrap(), 4, "10 + 10 + 10 + 5");
}

#[tokio::test]
async fn a_short_batch_takes_exactly_one_tick() {
    let table = Table::with(5);
    let report = retention(&table, 10).drain().await.unwrap();
    assert_eq!(report.archived, 5);
    assert_eq!(*table.selects.lock().unwrap(), 1);
}

#[tokio::test]
async fn a_full_final_batch_costs_one_empty_tick_to_confirm() {
    let table = Table::with(20);
    let report = retention(&table, 10).drain().await.unwrap();
    assert_eq!(report.archived, 20);
    assert_eq!(*table.selects.lock().unwrap(), 3);
}

#[tokio::test]
async fn a_drain_is_capped_per_wake() {
    let table = Table::with(10_000);
    let report = retention(&table, 1).drain().await.unwrap();
    assert_eq!(report.archived, MAX_TICKS_PER_DRAIN as u64);
    assert_eq!(table.left(), 10_000 - MAX_TICKS_PER_DRAIN);
}

/// A failing tick ends the drain with its error, and the batches before it
/// stay archived.
#[tokio::test]
async fn a_drain_stops_at_the_first_error() {
    struct FailsAfter(Mutex<u32>);
    impl AuditArchiver for FailsAfter {
        type Error = std::io::Error;
        async fn archive_batch(
            &self,
            _: &ArchiveBatchId,
            _: &[AuthEvent],
        ) -> Result<(), Self::Error> {
            let mut left = self.0.lock().unwrap();
            if *left == 0 {
                return Err(std::io::Error::other("sink down"));
            }
            *left -= 1;
            Ok(())
        }
        fn name(&self) -> &'static str {
            "fails-after"
        }
    }
    let table = Table::with(50);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        FailsAfter(Mutex::new(2)),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(10);
    assert!(lp.drain().await.is_err());
    assert_eq!(table.left(), 30, "two batches were archived and marked");
}

/// The spawned loop does its first drain at once, not after a full interval.
#[tokio::test]
async fn the_spawned_loop_works_before_its_first_interval_has_passed() {
    let table = Table::with(25);
    let handle = retention(&table, 10)
        .with_tick_interval(Duration::from_secs(3600))
        .spawn();
    let mut waited = 0;
    while table.left() > 0 && waited < 200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += 1;
    }
    handle.abort();
    assert_eq!(
        table.left(),
        0,
        "nothing archived within 2 s of an hour tick"
    );
}
