//! `persist_pass_with_update`: a pass inserts when no user-scope row exists,
//! compares and saves against the prior it read, and reports a lost compare
//! as a replay.

use super::*;

#[tokio::test]
async fn persist_pass_with_update_inserts_when_no_user_scope_row() {
    // First successful verification under an inherited (tenant or
    // global) template; no user-scope row to CAS against, so the
    // helper does a plain insert and returns `true`.
    let user = user_with_status(EntityState::Active);
    let (service, _, factors) = build_service_with_factors(user, MockFactorStore::new());

    let updated = hotp_config(8); // post-verification counter advance
    let saved = service
        .persist_pass_with_update(
            &fixture_scope(),
            &hotp_config(7),
            &AuthnScope::Tenant(tid("t1")),
            updated,
        )
        .await
        .unwrap();

    assert!(saved, "no prior row ⇒ must save and return true");
    let stored = factors
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("hotp must be saved to user scope");
    let FactorConfig::Hotp(cfg) = stored else {
        panic!("expected Hotp")
    };
    assert_eq!(cfg.counter, 8);
}

#[tokio::test]
async fn persist_pass_with_update_cas_succeeds_when_prior_matches() {
    // User-scope row already exists and matches what the caller saw
    // when verifying; CAS swaps cleanly and returns true.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    let saved = service
        .persist_pass_with_update(
            &fixture_scope(),
            &hotp_config(5),
            &fixture_scope(),
            hotp_config(6),
        )
        .await
        .unwrap();
    assert!(saved);

    let stored = factors_inspector
        .load_factor(&fixture_scope(), FactorKind::Hotp)
        .await
        .unwrap()
        .expect("present");
    let FactorConfig::Hotp(cfg) = stored else {
        panic!("expected Hotp")
    };
    assert_eq!(cfg.counter, 6);
}

#[tokio::test]
async fn persist_pass_with_update_cas_loss_returns_false_as_replay_signal() {
    // CAS-loss path for `persist_pass_with_update`. With
    // `arm_cas_failures(1)` the first (and only) CAS attempt loses,
    // so the helper must return `Ok(false)`; the caller in
    // `verify_factor` reads that as "another writer spent the same
    // step/counter already" and treats it as a replay.
    let user = user_with_status(EntityState::Active);
    let factors = MockFactorStore::new().with_factor(fixture_scope(), hotp_config(5));
    let (service, _, factors_inspector) = build_service_with_factors(user, factors);

    factors_inspector.arm_cas_failures(1);

    let saved = service
        .persist_pass_with_update(
            &fixture_scope(),
            &hotp_config(5),
            &fixture_scope(),
            hotp_config(6),
        )
        .await
        .unwrap();
    assert!(
        !saved,
        "CAS loss must surface as Ok(false) so the caller can flag a replay"
    );
}
