//! Concurrent first use and replay: parallel passes accept one, and parallel
//! first failures are all counted.

use super::*;

#[tokio::test]
async fn parallel_pass_against_user_row_accepts_only_one() {
    // Two requests verified the same code against the same stored
    // config (counter 5). The first saves counter 6; the second still
    // expects the value it verified against and must lose.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let (service, _, _) = build_service_with_factors(user, factors);
    let verified = hotp_config(5);

    let first = service
        .persist_pass_with_update(
            &fixture_scope(),
            &verified,
            &fixture_scope(),
            hotp_config(6),
        )
        .await
        .unwrap();
    let second = service
        .persist_pass_with_update(
            &fixture_scope(),
            &verified,
            &fixture_scope(),
            hotp_config(6),
        )
        .await
        .unwrap();
    assert!(first);
    assert!(!second, "the replayed code must be rejected");
}

#[tokio::test]
async fn parallel_pass_against_inherited_config_accepts_only_one() {
    // No user row: both requests verified against the tenant template.
    let user = user_with_status(EntityState::Active);
    let (service, _, factors) = build_service_with_factors(user, MockFactorStore::new());
    let tenant = AuthnScope::Tenant(tid("t1"));
    let verified = hotp_config(5);

    let first = service
        .persist_pass_with_update(&fixture_scope(), &verified, &tenant, hotp_config(6))
        .await
        .unwrap();
    let second = service
        .persist_pass_with_update(&fixture_scope(), &verified, &tenant, hotp_config(6))
        .await
        .unwrap();
    assert!(first);
    assert!(!second, "the second first-use write must lose");
    let stored = factors
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hotp_counter(&stored), 6);
}

#[tokio::test]
async fn parallel_first_failures_are_all_counted() {
    // A concurrent request already recorded the first failure (count
    // 1), but this request's read ran before that write landed, so it
    // sees no row and computed count 1 from the inherited template.
    // Its failure must still be added: count 2, not 1.
    let user = user_with_status(EntityState::Active);
    let factors =
        MockFactorStore::new().with_factor(fixture_scope(), hotp_config_with_attempts(0, 1));
    let (service, _, inspector) = build_service_with_factors(user, factors);
    inspector.arm_blind_loads(1);

    service
        .persist_fail_with_update(
            &fixture_scope(),
            FactorKind::Hotp,
            &hotp_config_with_attempts(0, 1),
        )
        .await
        .unwrap();

    let stored = inspector
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .unwrap();
    let FactorConfig::Hotp(h) = stored else {
        panic!("expected Hotp")
    };
    assert_eq!(h.attempt_count, 2, "the second failure must not be lost");
}
