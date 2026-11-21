//! `enforce_account_status`: an active account passes, a locked one answers
//! `Locked` with its end only for a lockout, and each refusal writes its row.

use super::*;
use axess_clock::testing::Shift;

#[tokio::test]
async fn enforce_account_status_returns_ok_for_active() {
    let user = user_with_status(EntityState::Active);
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
        .await
        .unwrap();

    assert!(matches!(result, AccountStatusEnforcement::Ok));
    // No audit row for an Active account.
    assert!(
        locked_events(&inspector.events()).is_empty(),
        "Active account must not trigger a `locked` audit row"
    );
}

#[tokio::test]
async fn enforce_account_status_locked_with_until_passes_through_until_and_emits_audit() {
    // In the future: a suspension whose `until` has passed is over. A
    // lockout a store keeps as a state is the one suspension whose end is
    // shown.
    let until = start().plus(axess_clock::SignedDuration::days(1));
    let detail = StatusDetail::lockout("too many attempts", start())
        .with_until(Some(axess_clock::Until::At(until)));
    let user = user_with_status(EntityState::Suspended(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Totp]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Totp), &session)
        .await
        .unwrap();

    match result {
        AccountStatusEnforcement::Locked { until: got_until } => {
            assert_eq!(got_until, Some(axess_clock::Until::At(until)));
        }
        other => panic!("expected Locked, got {other:?}"),
    }

    // Exactly one `Locked` row, with the next factor kind on it.
    let all_events = inspector.events();
    let locked_events = locked_events(&all_events);
    assert_eq!(
        locked_events.len(),
        1,
        "locked-account attempt must emit exactly one Locked audit row"
    );
    // And it must not be recorded as an ordinary failure: the two are
    // separate outcomes on a dashboard, which is the point of the status.
    assert!(
        !all_events.iter().any(|e| matches!(
            (&e.event_type, &e.event_status),
            (AuthEventType::FactorVerified, AuthEventStatus::Failure)
        )),
        "a lockout must not also appear as a Failure row"
    );
    let event = locked_events[0];
    assert_eq!(event.factor_kind.as_ref(), Some(&FactorKind::Totp));
    assert_eq!(event.user_id.as_ref(), Some(&uid("u1")));
}

#[tokio::test]
async fn enforce_account_status_locked_indefinite_returns_until_none() {
    let detail = StatusDetail::administrative("indefinite", start());
    let user = user_with_status(EntityState::Suspended(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
        .await
        .unwrap();

    match result {
        AccountStatusEnforcement::Locked { until, .. } => {
            assert_eq!(until, None, "indefinite suspension must surface as None")
        }
        other => panic!("expected Locked, got {other:?}"),
    }
    assert_eq!(locked_events(&inspector.events()).len(), 1);
}

#[tokio::test]
async fn enforce_account_status_pending_returns_not_active_without_audit() {
    let detail = StatusDetail::verification("pending email verification", start());
    let user = user_with_status(EntityState::Pending(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![FactorKind::Password]).await;

    let result = service
        .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Password), &session)
        .await
        .unwrap();

    assert!(matches!(result, AccountStatusEnforcement::NotActive(_)));
    // The locked-attempt audit fires only on `Locked` (Suspended).
    // Pending / Terminated / Archived must not emit one; the SOC
    // signal is specific to brute-force-after-lockout, not "any
    // non-active attempt."
    assert!(
        locked_events(&inspector.events()).is_empty(),
        "Pending account must not trigger the `locked` audit"
    );
}

#[tokio::test]
async fn enforce_account_status_no_next_kind_still_emits_audit_without_factor_field() {
    let detail = StatusDetail::administrative("policy", start());
    let user = user_with_status(EntityState::Suspended(detail));
    let (service, inspector) = build_service_with_user(user);
    let session = authenticating_session(vec![]).await;

    // `next_kind = None` mirrors `verify_factor`'s behaviour when
    // `remaining.first()` yields nothing (factor list exhausted but
    // session somehow still in Authenticating). The audit row still
    // fires, just without a `factor_kind` attribution.
    service
        .enforce_account_status(&uid("u1"), &tid("t1"), None, &session)
        .await
        .unwrap();

    let all_events = inspector.events();
    let events = locked_events(&all_events);
    assert_eq!(events.len(), 1);
    assert!(
        events[0].factor_kind.is_none(),
        "no next-kind ⇒ no `with_factor` on the audit row"
    );
}

/// A later factor step shows the end of a suspension only when the
/// suspension is a lockout a store keeps as a state. An administrative
/// hold, a pending verification or a closure that a store keeps as
/// `Suspended` answers `Locked` with no end, so the step does not say
/// that an operator holds the account or until when; the audit row is
/// the same for both.
#[tokio::test]
async fn enforce_account_status_shows_the_end_of_a_lockout_only() {
    let until = start().plus(axess_clock::SignedDuration::days(1));
    let causes = [
        (
            "lockout",
            StatusDetail::lockout("too many", start()),
            Some(until),
        ),
        (
            "administrative",
            StatusDetail::administrative("hold", start()),
            None,
        ),
        (
            "verification",
            StatusDetail::verification("pending", start()),
            None,
        ),
        ("closure", StatusDetail::closure("closed", start()), None),
        (
            "other",
            StatusDetail::other("legal-hold", "hold", start()),
            None,
        ),
    ];
    for (name, detail, shown) in causes {
        let user = user_with_status(EntityState::Suspended(
            detail.with_until(Some(axess_clock::Until::At(until))),
        ));
        let (service, inspector) = build_service_with_user(user);
        let session = authenticating_session(vec![FactorKind::Totp]).await;
        let result = service
            .enforce_account_status(&uid("u1"), &tid("t1"), Some(FactorKind::Totp), &session)
            .await
            .unwrap();
        match result {
            AccountStatusEnforcement::Locked { until } => {
                assert_eq!(
                    until,
                    shown.map(axess_clock::Until::At),
                    "{name}: the end shown"
                );
            }
            other => panic!("{name}: expected Locked, got {other:?}"),
        }
        assert_eq!(
            locked_events(&inspector.events()).len(),
            1,
            "{name}: the audit row"
        );
    }
}
