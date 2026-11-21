//! The check of what an audit query does with a row it cannot read, held
//! against stores that drop such a row in silence, fail the whole query on
//! it, count it under another reason, or leave out the readable event: each
//! fault is caught by name.

use super::*;
use crate::authn::event::AuthEventBuilder;
use crate::authn::store::{AuditTrail, UnreadableReason};

/// What a planted store does with the rows it holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// None: each row it cannot read is counted under its reason.
    Sound,
    /// Leaves a row it cannot read out of the answer, uncounted.
    DropsInSilence,
    /// Fails the whole query on the first row it cannot read.
    FailsTheQuery,
    /// Counts every row it cannot read as `Other`.
    CountsUnderAnotherReason,
    /// Answers no event for the readable row.
    LeavesOutTheReadableEvent,
}

/// One row of a planted store: an event it reads, or a row it cannot read
/// and why.
enum Row {
    Readable(Box<AuthEvent>),
    Unreadable(UnreadableReason),
}

/// An audit store over planted rows of one tenant, behind a fault.
struct Planted {
    rows: Vec<Row>,
    fault: Fault,
}

#[derive(Debug, thiserror::Error)]
#[error("a row could not be read")]
struct RowError;

impl AuditQuery for Planted {
    type Error = RowError;

    async fn query_events(
        &self,
        _: &TenantId,
        _: &EventQueryFilter,
    ) -> Result<AuditTrail, Self::Error> {
        let mut trail = AuditTrail::default();
        for row in &self.rows {
            match (row, self.fault) {
                (Row::Readable(_), Fault::LeavesOutTheReadableEvent) => {}
                (Row::Readable(event), _) => trail.events.push(AuthEvent::clone(event)),
                (Row::Unreadable(_), Fault::DropsInSilence) => {}
                (Row::Unreadable(_), Fault::FailsTheQuery) => return Err(RowError),
                (Row::Unreadable(_), Fault::CountsUnderAnotherReason) => {
                    trail.unreadable.count(UnreadableReason::Other)
                }
                (Row::Unreadable(reason), Fault::Sound | Fault::LeavesOutTheReadableEvent) => {
                    trail.unreadable.count(*reason)
                }
            }
        }
        Ok(trail)
    }
}

fn tenant() -> TenantId {
    "00000000-0000-4000-8000-0000000000a1"
        .parse()
        .expect("a tenant id")
}

fn readable() -> AuthEvent {
    let user: UserId = "00000000-0000-4000-8000-0000000000b1"
        .parse()
        .expect("a user id");
    AuthEventBuilder::success(AuthEventType::Authenticated)
        .attributed_to(&user, &tenant())
        .with_session(SessionKey::from_bytes([0x5a; 32]))
        .build_at(
            axess_clock::Timestamp::from_unix_seconds(1_800_000_000).expect("a valid instant"),
        )
}

/// The four rows the check asks for, in a store behind `fault`.
fn planted(fault: Fault) -> Planted {
    Planted {
        rows: vec![
            Row::Unreadable(UnreadableReason::Session),
            Row::Readable(Box::new(readable())),
            Row::Unreadable(UnreadableReason::EventType),
            Row::Unreadable(UnreadableReason::Other),
        ],
        fault,
    }
}

#[tokio::test]
async fn a_store_that_counts_each_row_it_cannot_read_passes() {
    assert_unreadable_rows_contract(&planted(Fault::Sound), &tenant(), &readable()).await;
}

#[tokio::test]
#[should_panic(
    expected = "each row that cannot be read must be counted once, under its own reason"
)]
async fn a_store_that_drops_a_row_it_cannot_read_in_silence_is_caught() {
    assert_unreadable_rows_contract(&planted(Fault::DropsInSilence), &tenant(), &readable()).await;
}

#[tokio::test]
#[should_panic(expected = "a row that cannot be read must not fail the query")]
async fn a_store_that_fails_the_query_on_a_row_it_cannot_read_is_caught() {
    assert_unreadable_rows_contract(&planted(Fault::FailsTheQuery), &tenant(), &readable()).await;
}

#[tokio::test]
#[should_panic(
    expected = "each row that cannot be read must be counted once, under its own reason"
)]
async fn a_store_that_counts_a_row_under_another_reason_is_caught() {
    assert_unreadable_rows_contract(
        &planted(Fault::CountsUnderAnotherReason),
        &tenant(),
        &readable(),
    )
    .await;
}

#[tokio::test]
#[should_panic(expected = "the query must answer the readable event, and only it")]
async fn a_store_that_leaves_out_the_readable_event_is_caught() {
    assert_unreadable_rows_contract(
        &planted(Fault::LeavesOutTheReadableEvent),
        &tenant(),
        &readable(),
    )
    .await;
}

#[test]
fn a_count_holds_each_reason_apart_and_sums_them() {
    let mut rows = UnreadableRows::default();
    rows.count(UnreadableReason::Session);
    rows.count(UnreadableReason::EventType);
    rows.count(UnreadableReason::EventType);
    rows.count(UnreadableReason::Other);
    rows.count(UnreadableReason::Other);
    rows.count(UnreadableReason::Other);
    assert_eq!(
        rows,
        UnreadableRows {
            session: 1,
            event_type: 2,
            other: 3,
        }
    );
    assert_eq!(rows.total(), 6);
    let full = UnreadableRows {
        session: u32::MAX,
        event_type: 1,
        other: 0,
    };
    assert_eq!(full.total(), u32::MAX, "the total saturates");
}
