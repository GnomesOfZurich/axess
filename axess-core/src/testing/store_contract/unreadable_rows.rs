//! The store kit's check of what an audit query does with a row it cannot
//! read.

use crate::authn::event::{AuthEvent, AuthEventStatus, AuthEventType};
use crate::authn::ids::{TenantId, UserId};
use crate::authn::store::{AuditQuery, EventQueryFilter, UnreadableRows};
use crate::session::id::SessionKey;

/// Exercise what an [`AuditQuery`] does with the rows it cannot read, and
/// panic with a message naming the broken rule.
///
/// The store is handed in holding, for `tenant`, exactly four rows that the
/// test planted by its own means: `readable`, written as the store's own
/// writer writes an event, and one row for each
/// [`UnreadableReason`](crate::authn::store::UnreadableReason): a session
/// field that names no session, an event type this release does not know,
/// and another field that does not decode (a status or a time). Then
/// [`AuditQuery::query_events`] over the tenant:
///
/// - answers `Ok`: a row it cannot read does not fail the query, so one
///   bad row cannot hide the others;
/// - answers the readable event, and only it;
/// - counts each other row once, under its own reason: a row left out
///   uncounted is hidden from the auditor.
///
/// The check sees the answer, not what the store logs: that no text of an
/// unreadable row reaches a log is the test's to check, with a subscriber
/// of its own.
///
/// # Panics
///
/// On the first rule the store breaks.
pub async fn assert_unreadable_rows_contract<S: AuditQuery>(
    store: &S,
    tenant: &TenantId,
    readable: &AuthEvent,
) {
    let trail = match store
        .query_events(tenant, &EventQueryFilter::default())
        .await
    {
        Ok(trail) => trail,
        Err(error) => {
            panic!("a row that cannot be read must not fail the query: it failed with {error}")
        }
    };
    let expected = UnreadableRows {
        session: 1,
        event_type: 1,
        other: 1,
    };
    assert_eq!(
        trail.unreadable, expected,
        "each row that cannot be read must be counted once, under its own reason"
    );
    let answered: Vec<_> = trail.events.iter().map(identity_of).collect();
    assert_eq!(
        answered,
        vec![identity_of(readable)],
        "the query must answer the readable event, and only it"
    );
}

/// The fields of an event that every store writes and reads back as they
/// were: what tells the planted readable row apart from any other.
#[derive(Debug, PartialEq)]
struct Identity<'a> {
    event_type: &'a AuthEventType,
    event_status: &'a AuthEventStatus,
    event_time: i64,
    user_id: Option<&'a UserId>,
    tenant_id: Option<&'a TenantId>,
    session_id: Option<SessionKey>,
}

fn identity_of(event: &AuthEvent) -> Identity<'_> {
    Identity {
        event_type: &event.event_type,
        event_status: &event.event_status,
        event_time: event.event_time,
        user_id: event.user_id.as_ref(),
        tenant_id: event.tenant_id.as_ref(),
        session_id: event.session_id,
    }
}

#[cfg(test)]
mod tests;
