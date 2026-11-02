//! The compare-and-swap driver against a row whose answers a test scripts.

use super::*;
use std::sync::Mutex;

/// A row that answers reads with the revisions queued in `reads` and
/// conditional writes with the outcomes queued in `writes`, recording which
/// write steps ran.
struct Scripted {
    reads: Mutex<Vec<Option<u64>>>,
    writes: Mutex<Vec<CasWrite>>,
    ran: Mutex<Vec<&'static str>>,
}

impl Scripted {
    fn new(reads: Vec<Option<u64>>, writes: Vec<CasWrite>) -> Self {
        Self {
            reads: Mutex::new(reads),
            writes: Mutex::new(writes),
            ran: Mutex::new(Vec::new()),
        }
    }

    fn next_write(&self, step: &'static str) -> CasWrite {
        self.ran.lock().unwrap().push(step);
        self.writes.lock().unwrap().remove(0)
    }
}

impl CasRow for Scripted {
    type Seen = ();
    type Error = std::convert::Infallible;

    async fn read(&self, _: &SessionId) -> Result<Option<(u64, ())>, Self::Error> {
        Ok(self.reads.lock().unwrap().remove(0).map(|r| (r, ())))
    }

    async fn delete_if(&self, _: &SessionId, _: &()) -> Result<CasWrite, Self::Error> {
        Ok(self.next_write("delete"))
    }

    async fn replace_if(
        &self,
        _: &SessionId,
        _: &(),
        _: &SessionData,
        _: Duration,
    ) -> Result<CasWrite, Self::Error> {
        Ok(self.next_write("replace"))
    }
}

const TTL: Duration = Duration::from_secs(60);

fn id() -> SessionId {
    SessionId::new(&crate::testing::mock_random::MockRng::new(1))
}

async fn run(row: &Scripted, ttl: Duration) -> ConditionalUpdate {
    let Ok(outcome) = cas_by_revision(row, &id(), 4, &SessionData::default(), ttl).await;
    outcome
}

#[tokio::test]
async fn a_row_still_at_the_revision_is_replaced() {
    let row = Scripted::new(vec![Some(4)], vec![CasWrite::Done]);
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Written);
    assert_eq!(*row.ran.lock().unwrap(), ["replace"]);
}

#[tokio::test]
async fn a_row_at_another_revision_is_a_conflict_and_is_not_written() {
    let row = Scripted::new(vec![Some(5)], vec![]);
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Conflict);
    assert!(row.ran.lock().unwrap().is_empty());
}

#[tokio::test]
async fn no_row_is_gone() {
    let row = Scripted::new(vec![None], vec![]);
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Gone);
}

/// A re-seal changes the bytes and keeps the revision: the second read sees
/// the same revision and the write lands.
#[tokio::test]
async fn a_miss_under_the_same_revision_is_read_again_and_written() {
    let row = Scripted::new(
        vec![Some(4), Some(4)],
        vec![CasWrite::Missed, CasWrite::Done],
    );
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Written);
}

/// A writer moves the revision: the second read answers a conflict.
#[tokio::test]
async fn a_miss_that_a_writer_caused_is_a_conflict() {
    let row = Scripted::new(vec![Some(4), Some(5)], vec![CasWrite::Missed]);
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Conflict);
}

#[tokio::test]
async fn two_misses_are_a_conflict() {
    let row = Scripted::new(
        vec![Some(4), Some(4)],
        vec![CasWrite::Missed, CasWrite::Missed],
    );
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Conflict);
    assert_eq!(row.ran.lock().unwrap().len(), CAS_ATTEMPTS);
}

#[tokio::test]
async fn a_row_gone_under_the_write_is_gone() {
    let row = Scripted::new(vec![Some(4)], vec![CasWrite::Gone]);
    assert_eq!(run(&row, TTL).await, ConditionalUpdate::Gone);
}

/// A zero TTL stores nothing: the matched row is removed, never replaced,
/// and the session is reported gone.
#[tokio::test]
async fn a_zero_ttl_removes_the_matched_row_and_reports_it_gone() {
    let row = Scripted::new(vec![Some(4)], vec![CasWrite::Done]);
    assert_eq!(run(&row, Duration::ZERO).await, ConditionalUpdate::Gone);
    assert_eq!(*row.ran.lock().unwrap(), ["delete"]);
}
