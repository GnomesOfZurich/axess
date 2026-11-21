//! The end of a suspension is shown to a caller only for a lockout: an
//! administrative hold, a pending verification or a closure that a store
//! keeps with an end is answered with no expiry and no `Retry-After`, on
//! every path that refuses with `NotActive(Suspended)` (a tenant suspension,
//! a signup completed on an account suspended meanwhile, an impersonation).
//! A lockout that never ends shows its end in the body and sends no
//! `Retry-After`.

use axess_clock::testing::Shift;
use axess_clock::{SignedDuration, Timestamp};
use axess_core::authn::error::AuthnError;
use axess_core::authn::types::{EntityState, StatusDetail};

#[derive(Debug)]
struct Never;

impl std::fmt::Display for Never {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("never")
    }
}

impl std::error::Error for Never {}

fn at() -> Timestamp {
    Timestamp::parse_rfc3339("2026-06-01T00:00:00Z").expect("an instant")
}

/// Each cause with the end it may show.
fn causes() -> Vec<(&'static str, StatusDetail, bool)> {
    let since = at().minus(SignedDuration::days(1));
    vec![
        ("lockout", StatusDetail::lockout("attempts", since), true),
        (
            "administrative",
            StatusDetail::administrative("hold", since),
            false,
        ),
        (
            "verification",
            StatusDetail::verification("pending", since),
            false,
        ),
        ("closure", StatusDetail::closure("closing", since), false),
    ]
}

#[test]
fn a_suspension_shows_its_end_only_when_it_is_a_lockout() {
    let ends = at().plus(SignedDuration::hours(1));
    for (name, detail, shown) in causes() {
        let err: AuthnError<Never> = AuthnError::NotActive(EntityState::Suspended(
            detail.with_until(Some(axess_clock::Until::At(ends))),
        ));
        assert_eq!(
            err.lockout_expiry(),
            shown.then_some(ends).map(axess_clock::Until::At),
            "{name}: the end the helper reads"
        );
    }
}

#[cfg(feature = "default-error-response")]
#[test]
fn the_default_response_sends_retry_after_only_for_a_lockout() {
    use axum::http::header;
    let ends = at().plus(SignedDuration::hours(1));
    for (name, detail, shown) in causes() {
        let err: AuthnError<Never> = AuthnError::NotActive(EntityState::Suspended(
            detail.with_until(Some(axess_clock::Until::At(ends))),
        ));
        let response = err.into_response_at(at());
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).is_some(),
            shown,
            "{name}: Retry-After on the default response"
        );
    }
}

/// A lock that never ends sends no `Retry-After`, since the header can only
/// state a time, and its body states the end as the reading it is stored as,
/// the latest reading: on the failure counter's `Locked` and on a lockout
/// suspension alike.
#[cfg(feature = "default-error-response")]
#[tokio::test]
async fn a_lock_that_never_ends_sends_no_retry_after_and_states_its_end() {
    use axum::http::header;
    let never = Some(axess_clock::Until::Forever);
    let shapes: [(&str, AuthnError<Never>); 2] = [
        ("Locked", AuthnError::Locked { until: never }),
        (
            "Suspended",
            AuthnError::NotActive(EntityState::Suspended(
                StatusDetail::lockout("attempts", at()).with_until(never),
            )),
        ),
    ];
    for (name, err) in shapes {
        let response = err.into_response_at(at());
        assert!(
            response.headers().get(header::RETRY_AFTER).is_none(),
            "{name}: no Retry-After for a lock that never ends"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("a body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            body["until_iso"],
            serde_json::json!("+262142-12-31T23:59:59.999999999+00:00"),
            "{name}: the end the body states"
        );
    }
}
