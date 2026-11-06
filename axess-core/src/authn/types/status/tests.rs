//! A status detail states its cause, a row written before the cause existed
//! still reads, and every cause survives a round trip through serde.

use super::*;
use crate::authn::types::EntityState;

const SINCE: &str = "2026-06-01T12:00:00Z";

#[test]
fn constructors_state_their_cause_and_no_end() {
    let now = chrono::Utc::now();
    let cases = [
        (
            StatusDetail::administrative("fraud review", now),
            StatusCause::Administrative,
        ),
        (
            StatusDetail::verification("awaiting email", now),
            StatusCause::Verification,
        ),
        (
            StatusDetail::lockout("too many attempts", now),
            StatusCause::Lockout,
        ),
        (
            StatusDetail::closure("left the firm", now),
            StatusCause::Closure,
        ),
        (
            StatusDetail::other("billing", "invoice overdue", now),
            StatusCause::Other("billing".into()),
        ),
    ];
    for (detail, cause) in cases {
        assert_eq!(detail.cause, cause);
        assert_eq!(detail.since, now);
        assert_eq!(detail.until, None, "{cause:?}");
    }
    let timed = StatusDetail::administrative("review", now)
        .with_until(Some(now + chrono::Duration::hours(1)));
    assert_eq!(timed.until, Some(now + chrono::Duration::hours(1)));
    assert_eq!(timed.cause, StatusCause::Administrative);
}

/// A row written by 0.15.0 has no `cause`; it reads as an unspecified
/// cause, which no eligibility question says yes to.
#[test]
fn a_row_written_without_a_cause_reads_as_unspecified() {
    let json = format!(r#"{{"reason":"review","since":"{SINCE}","until":null}}"#);
    let detail: StatusDetail = serde_json::from_str(&json).expect("0.15.0 row reads");
    assert_eq!(detail.cause, StatusCause::unspecified());
    assert_eq!(detail.cause, StatusCause::Other("unspecified".into()));
    assert_eq!(&*detail.reason, "review");

    let json = format!(r#"{{"Suspended":{{"reason":"review","since":"{SINCE}","until":null}}}}"#);
    let state: EntityState = serde_json::from_str(&json).expect("0.15.0 state reads");
    assert!(
        !state.can_self_recover(),
        "an unreadable cause admits nobody"
    );
    assert!(!state.is_administratively_disabled());
    assert!(state.is_suspended());
}

#[test]
fn every_cause_round_trips_through_serde() {
    let now = chrono::Utc::now();
    for cause in [
        StatusCause::Administrative,
        StatusCause::Verification,
        StatusCause::Lockout,
        StatusCause::Closure,
        StatusCause::Other("billing".into()),
        StatusCause::unspecified(),
    ] {
        let detail = StatusDetail {
            cause: cause.clone(),
            reason: "r".into(),
            since: now,
            until: Some(now),
        };
        let json = serde_json::to_string(&detail).expect("serialise");
        let back: StatusDetail = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, detail, "{cause:?}");
    }
}

/// A written row carries the cause explicitly, so a reader of the stored
/// value sees the same answer the type gives.
#[test]
fn a_written_row_carries_its_cause() {
    let now = chrono::Utc::now();
    let value =
        serde_json::to_value(StatusDetail::lockout("too many attempts", now)).expect("serialise");
    assert_eq!(value["cause"], serde_json::json!("Lockout"));
    let value =
        serde_json::to_value(StatusDetail::other("billing", "overdue", now)).expect("serialise");
    assert_eq!(value["cause"], serde_json::json!({ "Other": "billing" }));
}
