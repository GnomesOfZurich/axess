//! The login handler's refusals: what an unknown user, a locked account and
//! a throttled guess are answered with, and what each costs.

use super::*;

/// The service, with a counted executor for its password checks.
fn counted_service() -> (
    Arc<AuthnService<InMemoryBackend, InMemoryBackend>>,
    Arc<axess::blocking::KdfExecutor>,
) {
    let clock = axess_core::testing::MockClock::at_reference();
    let kdf = Arc::new(axess::blocking::KdfExecutor::inline());
    let backend = InMemoryBackend::new()
        .with_clock(clock.clone())
        .with_default_tenant("default", "Default tenant")
        .with_user_password("alice", "default", "Sample2+");
    let service = AuthnService::builder_from_backend(backend)
        .with_clock(clock)
        .with_kdf_executor(kdf.clone())
        .build();
    (Arc::new(service), kdf)
}

/// Refuse a wrong password for `username` and return the status.
async fn refuse(
    service: &Arc<AuthnService<InMemoryBackend, InMemoryBackend>>,
    username: &str,
) -> StatusCode {
    let form = LoginForm {
        username: username.to_string(),
        password: "not the password".to_string(),
    };
    login(
        axess_core::testing::test_session(),
        State(service.clone()),
        AuditContext::default(),
        Json(form),
    )
    .await
    .into_response()
    .status()
}

/// An unknown username costs exactly one password check, as a known one
/// does, so the two cannot be told apart by how long the check takes.
#[tokio::test]
async fn an_unknown_user_costs_one_password_check_like_a_known_one() {
    let (service, kdf) = counted_service();

    let before = kdf.jobs_started();
    assert_eq!(refuse(&service, "alice").await, StatusCode::UNAUTHORIZED);
    let known = kdf.jobs_started() - before;

    let before = kdf.jobs_started();
    assert_eq!(refuse(&service, "mallory").await, StatusCode::UNAUTHORIZED);
    let unknown = kdf.jobs_started() - before;

    assert_eq!(known, 1, "a known user's refusal");
    assert_eq!(unknown, known, "an unknown user's refusal");
}

/// One check each is the same cost only when the two checks are as heavy:
/// the Argon2 run of an unknown user's refusal has the memory, time and
/// parallelism parameters of a known user's. The parameters are what the
/// work is, on any machine and under any load; a comparison of elapsed time
/// says the same only on an idle one. The executor is inline, so every run
/// is recorded on this thread.
#[tokio::test]
async fn an_unknown_user_spends_the_argon2_work_of_a_known_one() {
    use axess_factors::password::recording::take_runs;

    let (service, _) = counted_service();
    // The hash an unknown user is checked against is made once per service;
    // make it before measuring.
    refuse(&service, "nobody").await;
    take_runs();

    refuse(&service, "alice").await;
    let known = take_runs();
    refuse(&service, "mallory").await;
    let unknown = take_runs();

    assert_eq!(known.len(), 1, "a known user's refusal: {known:?}");
    assert_eq!(unknown, known, "an unknown user's refusal");
}

#[tokio::test]
async fn a_locked_account_gets_the_wrong_password_answer() {
    let reply = locked_reply(Some("tomorrow"));
    assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(reply.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"invalid credentials");
}

/// The whole answer to a wrong password for `username`: status, headers
/// and body, so two answers can be compared byte for byte.
async fn answer(
    service: &Arc<AuthnService<InMemoryBackend, InMemoryBackend>>,
    username: &str,
) -> (StatusCode, axum::http::HeaderMap, axum::body::Bytes) {
    let form = LoginForm {
        username: username.to_string(),
        password: "not the password".to_string(),
    };
    let reply = login(
        axess_core::testing::test_session(),
        State(service.clone()),
        AuditContext::default(),
        Json(form),
    )
    .await
    .into_response();
    let (parts, body) = reply.into_parts();
    let body = axum::body::to_bytes(body, 1024).await.unwrap();
    (parts.status, parts.headers, body)
}

/// A guess the throttle refuses (a second wrong password inside the
/// delay) is answered as the wrong password before it was, byte for
/// byte and at the cost of one password check, so the throttle does
/// not say which usernames exist: only an account that exists can be
/// throttled. The clock is frozen, so the second guess lands inside the
/// delay whatever the machine is doing.
#[tokio::test]
async fn a_throttled_guess_is_answered_as_a_wrong_password() {
    let clock = axess_core::testing::MockClock::at_reference();
    let kdf = Arc::new(axess::blocking::KdfExecutor::inline());
    let backend = InMemoryBackend::new()
        .with_clock(clock.clone())
        .with_default_tenant("default", "Default tenant")
        .with_user_password("alice", "default", "Sample2+");
    let audit = backend.identity_store().clone();
    let service = Arc::new(
        AuthnService::builder_from_backend(backend)
            .with_clock(clock)
            .with_kdf_executor(kdf.clone())
            .build(),
    );

    let before = kdf.jobs_started();
    let wrong = answer(&service, "alice").await;
    let wrong_checks = kdf.jobs_started() - before;

    let before = kdf.jobs_started();
    let throttled = answer(&service, "alice").await;
    let throttled_checks = kdf.jobs_started() - before;

    let throttled_rows = audit
        .events()
        .iter()
        .filter(|e| e.error == Some(axess::authn::AuthFailureReason::Throttled))
        .count();
    assert_eq!(throttled_rows, 1, "the second guess was throttled");
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        throttled, wrong,
        "a throttled guess is answered as a wrong password is"
    );
    assert_eq!(wrong_checks, 1, "a wrong password costs one check");
    assert_eq!(
        throttled_checks, wrong_checks,
        "a throttled guess spends the one password check"
    );
}
