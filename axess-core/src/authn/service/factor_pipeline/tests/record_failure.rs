//! `record_factor_failure`: below the threshold a failure is a wrong
//! credential, at it a lockout, and a counter store outage fails closed
//! unless configured open.

use super::*;

/// The failed-factor row names the session the attempt came from, as the
/// locked-attempt row does.
#[tokio::test]
async fn the_failed_factor_row_names_its_session() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .unwrap();

    let event = inspector
        .events()
        .into_iter()
        .find(|e| {
            matches!(e.event_type, AuthEventType::FactorVerified)
                && matches!(e.event_status, AuthEventStatus::Failure)
        })
        .expect("failure audit row must be emitted");
    assert_eq!(event.session_id, Some(session.session_key().await));
}

#[tokio::test]
async fn record_factor_failure_below_threshold_returns_invalid_credential() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let outcome = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .unwrap();
    assert!(matches!(outcome, FactorOutcome::InvalidCredential));

    // Counter incremented by exactly one.
    assert_eq!(inspector.failed_attempts_for("u1"), 1);

    // A `FactorVerified Failure` row with the kind attached.
    let event = inspector
        .events()
        .into_iter()
        .find(|e| {
            matches!(e.event_type, AuthEventType::FactorVerified)
                && matches!(e.event_status, AuthEventStatus::Failure)
        })
        .expect("failure audit row must be emitted");
    assert_eq!(event.factor_kind.as_ref(), Some(&FactorKind::Password));
}

#[tokio::test]
async fn record_factor_failure_at_threshold_returns_locked() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    // Lockout policy in `build_service_with_user` is max_attempts=3.
    // First two attempts: InvalidCredential. Third: Locked.
    for _ in 0..2 {
        let outcome = service
            .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
            .await
            .unwrap();
        assert!(matches!(outcome, FactorOutcome::InvalidCredential));
    }
    let third = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .unwrap();
    // At the lockout threshold the helper returns Locked, not
    // InvalidCredential.
    // The verdict that *creates* the lockout now carries the
    // lockout window (`now + policy.duration`); earlier code dropped
    // the duration even when the policy carried it. The default mock
    // policy has `duration: Some(15 min)`, so `until` is `Some(_)`.
    let FactorOutcome::Locked { until } = third else {
        panic!("expected Locked at threshold, got {third:?}");
    };
    let until =
        until.expect("Locked must carry policy.duration as `until` when the policy has one");
    // `until` must be in the FUTURE relative to the call site.
    // Default LockoutPolicy duration is 15 min, so `until` ≈ now + 15min.
    // The `replace + with -` mutation on `clock.now() + d` would put
    // `until` 15 min in the *past*; silently leaving the verdict
    // "locked but expired immediately". Pin the direction.
    let before = start();
    assert!(
        until > axess_clock::Until::At(before),
        "Locked.until must be in the future (kills `+ → -` on \
         `clock.now() + policy.duration`); until={until:?} before={before}"
    );
    assert_eq!(inspector.failed_attempts_for("u1"), 3);
}

#[tokio::test]
async fn counter_store_outage_fails_closed_by_default() {
    // `CounterUnavailable::Lock` is the default. A dead counter store must
    // not hand an attacker an unbounded brute-force window: the attempt
    // counts as locked even though the counter never moved.
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    inspector.arm_record_failed_attempt_failure();

    let outcome = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .expect("store errors must not propagate as Err");
    let until = match outcome {
        FactorOutcome::Locked { until } => until,
        other => panic!("outage must fail closed to Locked, got {other:?}"),
    };
    // The window comes from the policy, exactly as on the ordinary
    // threshold path, so a caller cannot tell the two apart.
    let until = until.expect("policy duration is Some, so until must be Some");
    assert!(
        until > axess_clock::Until::At(start()),
        "Locked.until must be in the future; until={until:?}"
    );

    // The counter did not advance, and the audit row is still written,
    // because audit comes before the increment.
    assert_eq!(inspector.failed_attempts_for("u1"), 0);
    assert!(
        inspector.events().iter().any(|e| {
            matches!(e.event_type, AuthEventType::FactorVerified)
                && matches!(e.event_status, AuthEventStatus::Failure)
        }),
        "audit row must be emitted BEFORE the counter increment, so a \
         counter-store outage doesn't suppress the SOC signal"
    );
}

#[tokio::test]
async fn counter_store_outage_fails_open_when_configured() {
    // `CounterUnavailable::Allow` keeps logins working while the counter is
    // dead, at the cost of disabling lockout. It must still not propagate
    // `Err(AuthnError::Store)`: that would leak a distinct timing and error
    // signature, letting an attacker separate good usernames from bad.
    let user = user_with_status(EntityState::Active);
    let identity = MockIdentityStore::new()
        .with_tenant(fixture_tenant())
        .with_user(user)
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 3,
            on_counter_unavailable: CounterUnavailable::Allow,
            ..LockoutPolicy::default()
        });
    let inspector = identity.clone();
    let service =
        service_over(identity, MockFactorStore::new()).with_audit_context(AuditContext::default());
    let session = authenticating_session(vec![FactorKind::Password]).await;

    inspector.arm_record_failed_attempt_failure();

    let outcome = service
        .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
        .await
        .expect("store errors must not propagate as Err");
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "Allow must surface the outage as InvalidCredential, not Locked or Err"
    );
    assert_eq!(inspector.failed_attempts_for("u1"), 0);
}

/// A lockout duration an operator set to an extreme value never panics
/// the verdict that reads it: the guess that creates the lockout, the
/// failure recorded while the counter cannot be written, the guess refused
/// while it cannot be reserved, and the status check while it cannot be
/// read all answer `Locked` with an end, saturated when the sum does not
/// fit a date.
#[tokio::test]
async fn an_extreme_lockout_duration_never_panics_a_verdict() {
    for extreme in axess_testing::durations::extreme_durations() {
        let identity = MockIdentityStore::new()
            .with_tenant(fixture_tenant())
            .with_user(user_with_status(EntityState::Active))
            .with_lockout_policy(LockoutPolicy {
                max_attempts: 1,
                duration: Some(extreme.value),
                ..LockoutPolicy::default()
            });
        let inspector = identity.clone();
        let service = service_over(identity, MockFactorStore::new())
            .with_audit_context(AuditContext::default());
        let session = authenticating_session(vec![FactorKind::Password]).await;
        let locked_with_end =
            |outcome: &FactorOutcome| matches!(outcome, FactorOutcome::Locked { until: Some(_) });

        // The guess that reaches the limit.
        let verdict = service
            .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
            .await
            .unwrap_or_else(|e| panic!("duration of {}: {e:?}", extreme.name));
        assert!(
            locked_with_end(&verdict),
            "limit, {}: {verdict:?}",
            extreme.name
        );

        // The counter cannot be written: the failure and the reservation.
        inspector.arm_record_failed_attempt_failure();
        let verdict = service
            .record_factor_failure(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
            .await
            .unwrap_or_else(|e| panic!("duration of {}: {e:?}", extreme.name));
        assert!(
            locked_with_end(&verdict),
            "outage, {}: {verdict:?}",
            extreme.name
        );
        let slot = service
            .reserve_guess(&uid("u1"), &tid("t1"), &FactorKind::Password, &session)
            .await
            .unwrap_or_else(|e| panic!("duration of {}: {e:?}", extreme.name));
        let super::GuessSlot::Refused(verdict) = slot else {
            panic!("reserve in an outage, {}: {slot:?}", extreme.name);
        };
        assert!(
            locked_with_end(&verdict),
            "reserve outage, {}: {verdict:?}",
            extreme.name
        );

        // The counter cannot be read: the status check before a verifier.
        inspector.arm_failed_attempts_failure();
        let status = service
            .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
            .await
            .unwrap_or_else(|e| panic!("duration of {}: {e:?}", extreme.name));
        assert!(
            matches!(status, AccountStatusEnforcement::Locked { until: Some(_) }),
            "status in an outage, {}: {status:?}",
            extreme.name
        );
    }
}
