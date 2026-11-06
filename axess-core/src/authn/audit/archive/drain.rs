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

/// The event of row `id`: its `event_time` names the row, so a sink can
/// refuse one particular row.
fn event_of(id: u64) -> AuthEvent {
    let mut e = event();
    e.event_time = id as i64;
    e
}

/// An in-memory hot table: `select` returns the oldest rows up to the limit
/// and `mark_archived` removes them, as a real table's `archived_at IS NULL`
/// filter would.
#[derive(Clone)]
struct Table {
    rows: Arc<Mutex<Vec<u64>>>,
    selects: Arc<Mutex<u32>>,
    purges: Arc<Mutex<u32>>,
}

impl Table {
    fn with(n: u64) -> Self {
        Self {
            rows: Arc::new(Mutex::new((0..n).collect())),
            selects: Arc::new(Mutex::new(0)),
            purges: Arc::new(Mutex::new(0)),
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
        Ok(rows
            .iter()
            .take(limit)
            .map(|id| (*id, event_of(*id)))
            .collect())
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
        *self.purges.lock().unwrap() += 1;
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

/// A sink that refuses every batch holding the event of one row.
struct Refuses(u64);

impl AuditArchiver for Refuses {
    type Error = std::io::Error;
    async fn archive_batch(
        &self,
        _: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> Result<(), Self::Error> {
        if events.iter().any(|e| e.event_time == self.0 as i64) {
            return Err(std::io::Error::other("row refused"));
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        "refuses"
    }
}

/// One row the sink cannot take must not keep the other rows of its batch
/// on the hot table, and must not stop the purge.
#[tokio::test]
async fn a_row_the_sink_refuses_does_not_hold_back_the_others() {
    let table = Table::with(5);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        Refuses(3),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(10);

    assert!(lp.tick().await.is_err(), "the refused row is reported");

    assert_eq!(
        *table.rows.lock().unwrap(),
        vec![3],
        "only the refused row is left unarchived"
    );
    assert_eq!(*table.purges.lock().unwrap(), 1, "the purge still ran");
}

/// A sink that is down for everything must not stop archived rows from
/// leaving the hot table once their window has passed.
#[tokio::test]
async fn a_sink_that_is_down_does_not_stop_the_purge() {
    struct Down;
    impl AuditArchiver for Down {
        type Error = std::io::Error;
        async fn archive_batch(
            &self,
            _: &ArchiveBatchId,
            _: &[AuthEvent],
        ) -> Result<(), Self::Error> {
            Err(std::io::Error::other("sink down"))
        }
        fn name(&self) -> &'static str {
            "down"
        }
    }
    let table = Table::with(3);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        Down,
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    );

    assert!(lp.tick().await.is_err());

    assert_eq!(*table.purges.lock().unwrap(), 1, "the purge still ran");
    assert_eq!(table.left(), 3, "nothing was marked archived");
}

/// A sink that refuses every call and counts them.
struct CountingDown(Arc<Mutex<u32>>);

impl AuditArchiver for CountingDown {
    type Error = std::io::Error;
    async fn archive_batch(&self, _: &ArchiveBatchId, _: &[AuthEvent]) -> Result<(), Self::Error> {
        *self.0.lock().unwrap() += 1;
        Err(std::io::Error::other("sink down"))
    }
    fn name(&self) -> &'static str {
        "counting-down"
    }
}

/// A down sink costs a handful of calls a tick, not one per row.
#[tokio::test]
async fn a_down_sink_costs_three_calls_not_one_per_row() {
    let calls = Arc::new(Mutex::new(0));
    let table = Table::with(10);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        CountingDown(calls.clone()),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(10);
    assert!(lp.tick().await.is_err());
    assert_eq!(*calls.lock().unwrap(), 3, "the batch, then two probes");
    assert_eq!(table.left(), 10);
}

/// The oldest row refused for good does not stop the drain: the other rows
/// are archived across ticks and the refusal is reported at the end.
#[tokio::test]
async fn a_drain_archives_around_a_row_the_sink_always_refuses() {
    let table = Table::with(25);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        Refuses(0),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(10);
    assert!(lp.drain().await.is_err(), "the refused row is reported");
    assert_eq!(*table.rows.lock().unwrap(), vec![0]);
}

/// A sink that refuses every batch holding the event of any of its rows.
struct RefusesAll(Vec<u64>);

impl AuditArchiver for RefusesAll {
    type Error = std::io::Error;
    async fn archive_batch(
        &self,
        _: &ArchiveBatchId,
        events: &[AuthEvent],
    ) -> Result<(), Self::Error> {
        if events
            .iter()
            .any(|e| self.0.contains(&(e.event_time as u64)))
        {
            return Err(std::io::Error::other("row refused"));
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        "refuses-all"
    }
}

/// With a batch of one, the oldest row refused for good is the whole batch:
/// the rows behind it must still be archived.
#[tokio::test]
async fn a_batch_of_one_moves_past_a_row_the_sink_always_refuses() {
    let table = Table::with(4);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        Refuses(0),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(1);
    for _ in 0..20 {
        let _ = lp.tick().await;
    }
    assert_eq!(*table.rows.lock().unwrap(), vec![0]);
}

/// Bad rows at both ends of a batch look like a sink that is down; they must
/// not hold the good rows between them back for ever.
#[tokio::test]
async fn bad_rows_at_both_ends_of_a_batch_do_not_stop_the_rows_between() {
    let table = Table::with(14);
    let lp = AuditRetentionLoop::new(
        table.clone(),
        RefusesAll(vec![0, 9]),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(10);
    for _ in 0..20 {
        let _ = lp.tick().await;
    }
    assert_eq!(*table.rows.lock().unwrap(), vec![0, 9]);
}

/// A sink that was down for a while takes the rows once it is back.
#[tokio::test]
async fn a_row_skipped_while_the_sink_was_down_is_offered_again() {
    struct Switch(Arc<Mutex<bool>>);
    impl AuditArchiver for Switch {
        type Error = std::io::Error;
        async fn archive_batch(
            &self,
            _: &ArchiveBatchId,
            _: &[AuthEvent],
        ) -> Result<(), Self::Error> {
            if *self.0.lock().unwrap() {
                Ok(())
            } else {
                Err(std::io::Error::other("sink down"))
            }
        }
        fn name(&self) -> &'static str {
            "switch"
        }
    }
    let up = Arc::new(Mutex::new(false));
    let table = Table::with(3);
    let clock = axess_clock::testing::MockClock::now();
    let lp = AuditRetentionLoop::new(
        table.clone(),
        Switch(up.clone()),
        AuditRetentionPolicy::default().with_archive_after(Duration::ZERO),
    )
    .with_batch_size(1)
    .with_clock(Arc::new(clock.clone()));
    for _ in 0..10 {
        let _ = lp.tick().await;
    }
    assert_eq!(table.left(), 3, "nothing could be archived");
    *up.lock().unwrap() = true;
    clock.advance(chrono::Duration::hours(25));
    for _ in 0..10 {
        let _ = lp.tick().await;
    }
    assert_eq!(
        table.left(),
        0,
        "everything is archived once the sink is up"
    );
}
