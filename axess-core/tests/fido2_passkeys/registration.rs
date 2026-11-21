//! Registering a passkey must never replace the passkeys a user already has,
//! and deleting one must never lose a passkey registered meanwhile.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use std::sync::atomic::Ordering;

use super::fixture::*;
use axess_core::authn::store::FactorStore;
use axess_core::testing::test_session;
use common::{session_for, test_user};
use webauthn_rs::prelude::*;

#[tokio::test]
async fn registration_adds_to_the_existing_passkeys() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await
        .unwrap();
    assert_eq!(stored_count(&f).await, 2);
}

#[tokio::test]
async fn failed_read_during_registration_keeps_the_existing_passkeys() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();

    f.factors.fail_next_load.store(true, Ordering::SeqCst);
    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await;

    assert!(result.is_err(), "a failed read must fail the registration");
    assert_eq!(
        stored_count(&f).await,
        1,
        "the existing passkey must survive"
    );
}

#[tokio::test]
async fn failed_read_when_beginning_registration_is_an_error() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors.fail_next_load.store(true, Ordering::SeqCst);
    let result = f
        .service
        .begin_fido2_registration(&user, &session_for(&user).await)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn an_ended_suspension_no_longer_blocks_passkey_registration() {
    let past = common::start().minus(axess_clock::SignedDuration::hours(1));
    let (service, user) = fixture_with_status(suspended_until(past));
    service
        .begin_fido2_registration(&user, &session_for(&user).await)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_running_suspension_still_blocks_passkey_registration() {
    let future = common::start().plus(axess_clock::SignedDuration::hours(1));
    let (service, user) = fixture_with_status(suspended_until(future));
    assert!(
        service
            .begin_fido2_registration(&user, &session_for(&user).await)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_ended_suspension_no_longer_blocks_discoverable_login() {
    use axess_core::authn::error::AuthnError;
    let past = common::start().minus(axess_clock::SignedDuration::hours(1));
    let (service, user) = fixture_with_status(suspended_until(past));
    let assertion: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": "AAAA", "userHandle": null }
    }))
    .unwrap();
    let err = service
        .finish_discoverable_login(&assertion, &user, &[], &test_session())
        .await
        .unwrap_err();
    // Past the status check it stops at the missing ceremony, not at the suspension.
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn failed_read_during_delete_is_an_error_not_a_refusal() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors.fail_next_load.store(true, Ordering::SeqCst);
    let result = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 0)
        .await;
    assert!(result.is_err(), "got {result:?}");
    assert_eq!(stored_count(&f).await, 1);
}

#[tokio::test]
async fn failed_write_during_delete_is_an_error_and_the_credential_stays() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors.fail_next_write.store(true, Ordering::SeqCst);
    let result = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 0)
        .await;
    assert!(result.is_err(), "got {result:?}");
    assert_eq!(stored_ids(&f).await, vec![cred_id(AAAA)]);
}

#[tokio::test]
async fn registration_racing_another_registration_keeps_both() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA, CCCC]));
    f.service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await
        .unwrap();
    assert_eq!(
        stored_ids(&f).await,
        vec![cred_id(AAAA), cred_id(CCCC), cred_id(BBBB)]
    );
}

/// A concurrent registration by the same user stored this credential
/// between the request's read and its failed write. The stored credential
/// depends on the claim, so the failed request leaves it in place.
#[tokio::test]
async fn a_failed_write_keeps_the_claim_a_stored_credential_depends_on() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA, BBBB]));
    f.factors.fail_next_write.store(true, Ordering::SeqCst);
    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await;
    assert!(result.is_err(), "got {result:?}");
    assert_eq!(stored_ids(&f).await, vec![cred_id(AAAA), cred_id(BBBB)]);
    assert!(
        released(&f).is_empty(),
        "the claim a stored credential depends on was released: {:?}",
        released(&f)
    );
}

/// The passkey is removed before the claim is given back; a store that
/// refuses the release does not undo the removal, so the call succeeds and
/// the audit row that says the factor was disabled is written.
#[tokio::test]
async fn a_failed_claim_release_after_deletion_is_still_a_recorded_success() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.factors.fail_next_release.store(true, Ordering::SeqCst);
    let deleted = f
        .service
        .delete_fido2_credential(&user, &session, &cred_id(AAAA), 0)
        .await;
    assert!(
        matches!(deleted, Ok(true)),
        "the passkey is gone, so the deletion is a success: {deleted:?}"
    );
    assert_eq!(stored_ids(&f).await, Vec::<CredentialID>::new());
    let rows = f.identity.events();
    assert!(
        rows.iter()
            .any(|e| e.event_type == AuthEventType::FactorDisabled
                && e.event_status == AuthEventStatus::Success),
        "no FactorDisabled row for the removed passkey: {rows:?}"
    );
}

#[tokio::test]
async fn delete_racing_a_registration_keeps_the_new_passkey() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors
        .inner
        .save_factor(&f.scope, config_of(&[AAAA, CCCC]))
        .await
        .unwrap();
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA, CCCC, DDDD]));
    let deleted = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 1)
        .await
        .unwrap();
    assert!(deleted);
    assert_eq!(stored_ids(&f).await, vec![cred_id(CCCC), cred_id(DDDD)]);
}

#[tokio::test]
async fn delete_racing_a_delete_respects_the_minimum_on_the_fresh_list() {
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors
        .inner
        .save_factor(&f.scope, config_of(&[AAAA, CCCC]))
        .await
        .unwrap();
    // A concurrent request removes CCCC; deleting AAAA would now leave none.
    *f.factors.race_after_next_load.lock().unwrap() = Some(config_of(&[AAAA]));
    let deleted = f
        .service
        .delete_fido2_credential(&user, &session_for(&user).await, &cred_id(AAAA), 1)
        .await
        .unwrap();
    assert!(!deleted, "the minimum must hold against the fresh list");
    assert_eq!(stored_ids(&f).await, vec![cred_id(AAAA)]);
}
