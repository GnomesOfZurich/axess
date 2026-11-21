//! The rows the service's sink writes for a session the layer ends.

use crate::authn::event::{AuthEvent, AuthEventStatus, AuthEventType, AuthFailureReason};
use crate::authn::ids::UserId;
use crate::authn::service::AuthnService;
use crate::session::id::{SessionId, SessionKey};
use crate::session::{LayerSessionEnded, SessionEndAudit, SessionEndReason};
use crate::testing::mock_authn::{CallLog, MockFactorStore, MockIdentityStore};
use crate::testing::mock_random::MockRng;
use axess_clock::Clock as _;
use axess_clock::testing::MockClock;
use axess_identity::testing::{tenant, user};
use std::sync::Arc;

/// The row kind of an ending for its age.
fn expired() -> (AuthEventType, AuthEventStatus) {
    (AuthEventType::SessionExpired, AuthEventStatus::Expired)
}

/// The row kind of every other ending.
fn invalidated() -> (AuthEventType, AuthEventStatus) {
    (AuthEventType::SessionInvalidated, AuthEventStatus::Success)
}

/// The table of the reasons the layer ends a session for, each with the row
/// kind it is recorded as. One list of rows makes both an exhaustive `match`
/// and the list the tests walk, so a reason added to the enum without a row
/// here does not compile, and none can be left out of the walk.
macro_rules! reason_rows {
    ($($reason:ident => $kind:ident),* $(,)?) => {
        fn row_of(reason: SessionEndReason) -> (AuthEventType, AuthEventStatus) {
            match reason {
                $(SessionEndReason::$reason => $kind(),)*
            }
        }

        const EVERY_REASON: &[SessionEndReason] = &[$(SessionEndReason::$reason),*];
    };
}

reason_rows! {
    AgeCap => expired,
    ImpersonationAgeCap => expired,
    NotRegistered => invalidated,
    ImpersonationNotRegistered => invalidated,
    RevokedDuringRotation => invalidated,
    NotTracked => invalidated,
    RotationFailed => invalidated,
    KeyBindingRequired => invalidated,
    TenantNotConfirmed => invalidated,
}

/// Every reason the layer ends a session for, with the row kind it is
/// recorded as.
fn reasons() -> Vec<(SessionEndReason, AuthEventType, AuthEventStatus)> {
    EVERY_REASON
        .iter()
        .map(|reason| {
            let (event_type, status) = row_of(*reason);
            (*reason, event_type, status)
        })
        .collect()
}

/// A service whose identity store knows nobody, the store it writes rows
/// to, its sink, and the clock it stamps them on (ninety seconds past the
/// reference instant).
fn service() -> (MockIdentityStore, Arc<dyn SessionEndAudit>, MockClock) {
    let clock = MockClock::at_reference();
    clock.advance_secs(90);
    let identity = MockIdentityStore::new().with_clock(clock.clone());
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    (identity, authn.session_end_audit(), clock)
}

/// The ending of a session of user `u1` in tenant `t1`.
fn ending(reason: SessionEndReason, impersonator: Option<UserId>) -> LayerSessionEnded {
    LayerSessionEnded {
        user_id: user("u1"),
        tenant_id: tenant("t1"),
        session_id: SessionKey::of(&SessionId::new(&MockRng::new(9))),
        impersonator,
        reason,
    }
}

/// The one row the sink wrote for `ended`.
async fn row_for(ended: &LayerSessionEnded) -> (AuthEvent, MockClock) {
    let (identity, sink, clock) = service();
    sink.session_ended(ended).await.expect("the row is written");
    let rows = identity.events();
    assert_eq!(rows.len(), 1, "one row per ending: {rows:?}");
    (rows[0].clone(), clock)
}

/// An age cap, the session's or the impersonation's, is a `SessionExpired`
/// row with the status `Expired`; every other reason is a
/// `SessionInvalidated` row with the status `Success`. Each names the user,
/// the session's tenant and the session, carries the reason in `error`, is
/// stamped on the service's clock, and has no actor and no client.
#[tokio::test]
async fn each_ending_is_one_row_of_its_kind_naming_the_session_and_the_reason() {
    for (reason, event_type, status) in reasons() {
        let ended = ending(reason, None);
        let (row, clock) = row_for(&ended).await;
        let tag = reason.as_str();
        assert_eq!(row.event_type, event_type, "{tag}");
        assert_eq!(row.event_status, status, "{tag}");
        assert_eq!(row.user_id, Some(ended.user_id), "{tag}");
        assert_eq!(row.session_id, Some(ended.session_id), "{tag}");
        assert_eq!(row.tenant_id, Some(tenant("t1")), "{tag}");
        assert_eq!(row.error, Some(AuthFailureReason::from(tag)), "{tag}");
        assert_eq!(row.error.as_ref().map(|e| e.as_str()), Some(tag));
        assert_eq!(row.event_time, clock.now().unix_micros(), "{tag}");
        assert!(row.actor_id.is_none(), "{tag}: no administrator acted");
        assert!(row.ip_address.is_none(), "{tag}: no client is named");
        assert!(row.user_agent.is_none(), "{tag}: no client is named");
    }
}

/// The tenant of the row is the session's. The identity store here knows no
/// user at all (a user deleted since the login is the common case), and the
/// row is written with the tenant all the same.
#[tokio::test]
async fn the_row_takes_its_tenant_from_the_session_and_not_from_a_lookup() {
    let ended = ending(SessionEndReason::NotRegistered, None);
    let (row, _) = row_for(&ended).await;
    assert_eq!(row.user_id, Some(user("u1")));
    assert_eq!(row.tenant_id, Some(tenant("t1")));
}

/// The sink reads nothing from the identity store: the one call it makes is
/// the write of the row, so no lookup that fails can stand between an
/// ending and its row.
#[tokio::test]
async fn the_sink_makes_one_store_call_the_write_of_the_row() {
    let calls = CallLog::new();
    let clock = MockClock::at_reference();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_call_log(&calls);
    let authn = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock)
        .build();
    let sink = authn.session_end_audit();
    calls.clear();

    sink.session_ended(&ending(SessionEndReason::AgeCap, None))
        .await
        .expect("the row is written");

    assert_eq!(calls.calls(), ["record_event"]);
}

/// The row of a session that carried an impersonation names the
/// administrator as its actor, for every reason: the two that are about
/// the impersonation and the five that are about the session.
#[tokio::test]
async fn the_row_of_an_ended_impersonation_names_the_administrator() {
    for (reason, _, _) in reasons() {
        let ended = ending(reason, Some(user("admin")));
        let (row, _) = row_for(&ended).await;
        let tag = reason.as_str();
        assert_eq!(
            row.user_id,
            Some(user("u1")),
            "{tag}: the impersonated user"
        );
        assert_eq!(
            row.actor_id,
            Some(user("admin")),
            "{tag}: the administrator"
        );
    }
}

/// A row the identity store refuses is an error to the layer, which then
/// leaves the session stored; nothing was recorded.
#[tokio::test]
async fn a_row_the_store_refuses_is_an_error_to_the_layer() {
    let (identity, sink, _) = service();
    identity.arm_record_event_failure();
    let refused = sink
        .session_ended(&ending(SessionEndReason::NotRegistered, None))
        .await;
    assert!(refused.is_err(), "the write failed: {refused:?}");
    assert!(identity.events().is_empty());
}
