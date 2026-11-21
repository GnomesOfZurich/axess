use super::*;
use axess_clock::testing::Shift;
use axum::response::IntoResponse;

/// The reference time the tests pass to `into_response_at`.
fn fixed_now() -> axess_clock::Timestamp {
    axess_clock::Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap()
}

/// Concrete error type so the generic impl is monomorphised.
#[derive(Debug, thiserror::Error)]
#[error("test")]
struct TestStoreError;

/// Every variant maps to its documented HTTP status and a
/// JSON `{"error": "..."}` body. Pins the whole `into_response`
/// against the `Default::default()` body-replacement mutation,
/// which would emit an empty 200 OK and silently break the
/// recommended mapping for every variant.
#[tokio::test]
async fn into_response_emits_documented_status_per_variant() {
    let cases: Vec<(AuthnError<TestStoreError>, axum::http::StatusCode)> = vec![
        (
            AuthnError::Store(TestStoreError),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (AuthnError::NoFlow, axum::http::StatusCode::CONFLICT),
        (AuthnError::Impersonated, axum::http::StatusCode::FORBIDDEN),
        (
            AuthnError::NotActive(EntityState::Active),
            axum::http::StatusCode::FORBIDDEN,
        ),
        (
            AuthnError::Locked { until: None },
            axum::http::StatusCode::LOCKED,
        ),
        (
            AuthnError::InvalidAssertion,
            axum::http::StatusCode::UNAUTHORIZED,
        ),
        (
            AuthnError::ExternalService("upstream timeout".into()),
            axum::http::StatusCode::BAD_GATEWAY,
        ),
        (AuthnError::CrossTenant, axum::http::StatusCode::FORBIDDEN),
        (AuthnError::UnknownTenant, axum::http::StatusCode::FORBIDDEN),
        (
            AuthnError::Busy {
                retry_after: std::time::Duration::from_secs(1),
            },
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AuthnError::Throttled {
                retry_after: std::time::Duration::from_secs(2),
            },
            axum::http::StatusCode::TOO_MANY_REQUESTS,
        ),
        (
            AuthnError::Internal("hash task panicked".into()),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ];

    for (err, expected_status) in cases {
        let label = format!("{err:?}");
        let response = err.into_response_at(fixed_now());
        assert_eq!(
            response.status(),
            expected_status,
            "{label} must map to {expected_status:?}"
        );
        // Body must be a non-empty JSON object; distinguishes the
        // real impl from a `Default::default()` empty 200.
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("collect body");
        assert!(!body.is_empty(), "{label} response body must be non-empty");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body must be JSON");
        assert!(
            parsed.get("error").and_then(|v| v.as_str()).is_some(),
            "{label} body must contain a string `error` field, got {parsed}"
        );
    }
}

/// `Throttled { retry_after }` answers 429 with the delay as
/// `Retry-After`, rounded up so a fraction of a second is never
/// `Retry-After: 0`, and no `until_iso`: the delay is a duration, not an
/// instant.
#[tokio::test]
async fn throttled_emits_429_with_the_delay_rounded_up_as_retry_after() {
    use axum::http::header;
    for (delay_ms, expected) in [(2_000u64, "2"), (1_400, "2"), (300, "1")] {
        let err: AuthnError<TestStoreError> = AuthnError::Throttled {
            retry_after: std::time::Duration::from_millis(delay_ms),
        };
        let response = err.into_response_at(fixed_now());
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .expect("Retry-After present")
                .to_str()
                .unwrap(),
            expected,
            "a delay of {delay_ms} ms"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "too many attempts, retry later");
        assert!(json.get("until_iso").is_none());
    }
}

/// `Locked { until: Some(future) }` emits a `Retry-After` header
/// carrying delta-seconds AND surfaces `until_iso` in the JSON
/// body so clients have a standard way to learn the lockout window.
#[tokio::test]
async fn locked_with_future_until_emits_retry_after_and_until_iso() {
    use axum::http::header;

    let until = fixed_now().plus(axess_clock::SignedDuration::seconds(900));
    let err: AuthnError<TestStoreError> = AuthnError::Locked {
        until: Some(axess_clock::Until::At(until)),
    };
    let response = err.into_response_at(fixed_now());

    assert_eq!(response.status(), axum::http::StatusCode::LOCKED);

    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After header must be present when until is in the future")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("Retry-After must be a numeric delta-seconds value");
    assert!(
        retry_after > 0 && retry_after <= 900,
        "Retry-After should be in (0, 900] seconds, got {retry_after}"
    );

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("collect body");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "account locked");
    let until_iso = parsed["until_iso"]
        .as_str()
        .expect("until_iso must be present in the body");
    assert!(
        until_iso.contains('T'),
        "until_iso must be RFC 3339 (got {until_iso:?})"
    );
}

/// `Locked { until: None }` is the indefinite-lock /
/// failed-attempt-counter case. No `Retry-After` (the client has
/// nothing to wait *for*; an admin reset is required) and no
/// `until_iso` in the body: back-compat with the previous body
/// shape for clients that didn't inspect the new field.
#[tokio::test]
async fn locked_with_no_until_omits_retry_after_and_until_iso() {
    use axum::http::header;

    let err: AuthnError<TestStoreError> = AuthnError::Locked { until: None };
    let response = err.into_response_at(fixed_now());

    assert_eq!(response.status(), axum::http::StatusCode::LOCKED);
    assert!(
        response.headers().get(header::RETRY_AFTER).is_none(),
        "Retry-After must be absent when until is None"
    );

    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("collect body");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed.get("until_iso").is_none());
}

/// `NotActive(Suspended(_))` of a lockout carries `until` deep-nested
/// in `StatusDetail`. The `lockout_expiry()` accessor reaches it; the
/// IntoResponse impl must too, so a locked-out user gets the same
/// Retry-After signal as a `Locked { until }` user. Any other cause of
/// suspension sends none (`tests/lockout_expiry_cause.rs`).
#[tokio::test]
async fn not_active_suspended_with_future_until_emits_retry_after() {
    use crate::authn::types::StatusDetail;
    use axum::http::header;

    let until = fixed_now().plus(axess_clock::SignedDuration::seconds(60));
    let detail = StatusDetail::lockout("test lockout", fixed_now())
        .with_until(Some(axess_clock::Until::At(until)));
    let err: AuthnError<TestStoreError> = AuthnError::NotActive(EntityState::Suspended(detail));
    let response = err.into_response_at(fixed_now());

    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    assert!(
        response.headers().get(header::RETRY_AFTER).is_some(),
        "Suspended-with-until must also emit Retry-After (parity with Locked)"
    );
}

/// A Suspended `until` already in the past collapses to no
/// `Retry-After` and no `until_iso`: there's nothing to wait for.
/// Avoids emitting `Retry-After: 0` which clients interpret as
/// "retry immediately."
#[tokio::test]
async fn locked_with_past_until_omits_retry_after() {
    use axum::http::header;

    let past = fixed_now().minus(axess_clock::SignedDuration::seconds(60));
    let err: AuthnError<TestStoreError> = AuthnError::Locked {
        until: Some(axess_clock::Until::At(past)),
    };
    let response = err.into_response_at(fixed_now());

    assert!(
        response.headers().get(header::RETRY_AFTER).is_none(),
        "a `until` in the past must not emit Retry-After"
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("collect body");
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        parsed.get("until_iso").is_none(),
        "a `until` in the past must not emit until_iso"
    );
}

/// A lock with a fractional second left reports the next whole second.
#[test]
fn retry_secs_from_rounds_a_partial_second_up() {
    let now = fixed_now();
    assert_eq!(
        retry_secs_from(
            now.plus(axess_clock::SignedDuration::milliseconds(500)),
            now
        ),
        Some(1),
        "a half-second lock must not read as retry-now"
    );
    assert_eq!(
        retry_secs_from(
            now.plus(axess_clock::SignedDuration::milliseconds(1500)),
            now
        ),
        Some(2)
    );
}

/// Pin the strict-greater boundary `secs > 0` inside `retry_secs_from`.
/// Discriminates `> 0` against `>= 0`, `> 1`, `delete >`:
/// - `until == now` (delta = 0): original returns None; `>= 0` would
///   return `Some(0)`, which clients read as "retry immediately"
///   and breaks the lockout semantic.
/// - `until = now + 1s`: original returns `Some(1)`; pins `> 1`
///   which would collapse 1-second locks to None.
/// - `until = now - 1s`: original returns None; pins the past path
///   for completeness.
#[test]
fn retry_secs_from_pins_strict_greater_boundary() {
    let now = fixed_now();

    // until == now: delta = 0. Must return None; kills `>= 0` mutation
    // (which would emit `Some(0)` and produce a `Retry-After: 0`
    // header that clients interpret as immediate retry).
    assert_eq!(
        retry_secs_from(now, now),
        None,
        "until == now must return None (kills `> → >=` boundary mutation)"
    );

    // until = now + 1s: delta = 1. Must return Some(1).
    assert_eq!(
        retry_secs_from(now.plus(axess_clock::SignedDuration::seconds(1)), now),
        Some(1)
    );

    // until = now + 60s: delta = 60. Must return Some(60).
    assert_eq!(
        retry_secs_from(now.plus(axess_clock::SignedDuration::seconds(60)), now),
        Some(60)
    );

    // until = now - 1s: delta = -1. Must return None.
    assert_eq!(
        retry_secs_from(now.minus(axess_clock::SignedDuration::seconds(1)), now),
        None
    );
}

/// `into_response_at` lets test code pin the `Retry-After` header
/// deterministically by supplying its own reference time, instead
/// of being subject to the wall clock `into_response` uses by
/// default.
#[tokio::test]
async fn into_response_at_uses_caller_supplied_reference_time() {
    use axum::http::header;

    // Anchor "now" in the past so the lockout window we compute is
    // independent of test-execution wall clock. With `now = 2026-01-01T00:00:00Z`
    // and `until = now + 300s`, the Retry-After must be exactly 300
    // regardless of when the test runs.
    let now = axess_clock::Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap();
    let until = now.plus(axess_clock::SignedDuration::seconds(300));

    let err: AuthnError<TestStoreError> = AuthnError::Locked {
        until: Some(axess_clock::Until::At(until)),
    };
    let response = err.into_response_at(now);

    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After present")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("delta-seconds value");
    assert_eq!(
        retry_after, 300,
        "Retry-After must equal until-now exactly when caller pins the reference time"
    );
}

/// `lockout_expiry` returns the inner `Option<Timestamp>`
/// from `Locked { until }` and from a lockout kept as
/// `NotActive(EntityState::Suspended(StatusDetail { until, .. }))`,
/// and `None` for any other variant. Pins the body against the
/// `-> None` body-replacement mutation, which would lose the
/// `Locked`/`Suspended` payloads and collapse every lockout to
/// "no expiry".
#[test]
fn lockout_expiry_extracts_from_locked_and_suspended_variants() {
    use crate::authn::types::{EntityState, StatusDetail};

    let t = axess_clock::Timestamp::parse_rfc3339("2026-06-01T00:00:00Z").unwrap();

    // Locked { until: Some(t) } → Some(t)
    let locked: AuthnError<TestStoreError> = AuthnError::Locked {
        until: Some(axess_clock::Until::At(t)),
    };
    assert_eq!(
        locked.lockout_expiry(),
        Some(axess_clock::Until::At(t)),
        "Locked must surface its `until` (kills `-> None`)"
    );

    // Locked { until: None } → None (indefinite lock, not the same
    // as a missing variant).
    let locked_indefinite: AuthnError<TestStoreError> = AuthnError::Locked { until: None };
    assert_eq!(locked_indefinite.lockout_expiry(), None);

    // NotActive(Suspended(lockout with until: Some(t))) → Some(t)
    let suspended: AuthnError<TestStoreError> = AuthnError::NotActive(EntityState::Suspended(
        StatusDetail::lockout(
            std::sync::Arc::from("test-suspended"),
            t.minus(axess_clock::SignedDuration::seconds(60)),
        )
        .with_until(Some(axess_clock::Until::At(t))),
    ));
    assert_eq!(
        suspended.lockout_expiry(),
        Some(axess_clock::Until::At(t)),
        "Suspended StatusDetail.until must surface (kills `-> None`)"
    );

    // Other variants → None
    let cross: AuthnError<TestStoreError> = AuthnError::CrossTenant;
    assert_eq!(cross.lockout_expiry(), None);
}

/// The trait impl delegates to `into_response_at` with the machine's
/// time, the declared exception to the injected clock, so the test
/// cannot say what that time is. A lockout that ends a century after
/// the reference instant is still running whenever the test runs, so
/// the header must land in (0, the century]; the bound protects against
/// the trait impl ignoring `until` or emitting a negative or zero value.
#[tokio::test]
async fn into_response_trait_impl_still_emits_retry_after() {
    use axum::http::header;

    let century = axess_clock::SignedDuration::days(36_525);
    let until = axess_clock::testing::MockClock::reference_time().plus(century);
    let err: AuthnError<TestStoreError> = AuthnError::Locked {
        until: Some(axess_clock::Until::At(until)),
    };
    let response = err.into_response();

    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After present via trait impl")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("delta-seconds value");
    assert!(
        (1..=century.whole_seconds().unsigned_abs()).contains(&retry_after),
        "Retry-After via trait impl must land in (0, a century], got {retry_after}"
    );
}
