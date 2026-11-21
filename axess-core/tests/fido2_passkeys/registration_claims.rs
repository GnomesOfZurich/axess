//! The credential-id claim around a passkey registration and deletion: a
//! failed write keeps it, a deletion releases it, a refused claim and a
//! race are audited by name, and the finish span escapes the passkey name.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::fixture::*;
use axess_core::authn::factor::{FactorConfig, FactorKind};
use axess_core::authn::store::{FactorStore, Fido2CredentialClaim};
use axess_core::authn::types::AuthnScope;
use axess_core::testing::mock_authn::MockStoreError;
use common::{session_for, test_user};
use webauthn_rs::prelude::*;

/// The name a caller gives a passkey is the request's own text, and the span
/// of the finish carries it on every line written inside it: it is escaped
/// and cut there, so a long or hostile name cannot fill or forge a line.
#[tokio::test]
async fn the_finish_span_carries_the_credential_name_escaped_and_cut() {
    let printed = axess_testing::mock_tracing::LineCapture::install();
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    let named = format!("x\r\nWARN forged line\u{1b}[2J\u{2028}{}", "a".repeat(4096));
    let _ = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), &named, &session)
        .await;

    let text = printed.text();
    assert!(
        text.split('\n').any(
            |line| line.contains(" finish_fido2_registration{") && line.contains("forged line")
        ),
        "no line for the finish span keeps the name, escaped"
    );
    for line in text.split('\n') {
        let head: String = line.chars().take(160).collect();
        assert!(
            !line.chars().any(char::is_control),
            "a control character reached a line raw: {head:?}"
        );
        assert!(
            line.len() < 1024,
            "the name is cut: a line is {} bytes: {head:?}",
            line.len()
        );
    }
}

/// A deletion whose `FactorDisabled` row cannot be written still gives the
/// credential id back (the passkey is gone either way) and says at error
/// level that the passkey was removed without its row, before it returns
/// the audit error.
#[tokio::test]
async fn a_deletion_whose_row_fails_still_releases_the_claim_and_says_so() {
    use axess_testing::mock_tracing::TracingCapture;
    let capture = TracingCapture::install();
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.identity.arm_record_event_failure();
    let deleted = f
        .service
        .delete_fido2_credential(&user, &session, &cred_id(AAAA), 0)
        .await;
    assert!(deleted.is_err(), "the audit error is returned: {deleted:?}");
    assert_eq!(stored_ids(&f).await, Vec::<CredentialID>::new());
    assert_eq!(
        released(&f),
        vec![cred_id(AAAA).as_slice().to_vec()],
        "the claim of the removed passkey is given back"
    );
    assert!(
        capture.contains_at_level(tracing::Level::ERROR, "removed"),
        "the removal without its row is logged: {:?}",
        capture.events()
    );
}

/// A failed write returns its own error, never a later step's, and leaves
/// the claim in place: a concurrent registration by the same user may store
/// the credential after any check this request could make, and a released
/// claim would leave that credential standing without one.
#[tokio::test]
async fn a_failed_write_keeps_the_claim_and_returns_its_own_error() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.factors.fail_next_write.store(true, Ordering::SeqCst);
    f.factors.fail_next_release.store(true, Ordering::SeqCst);
    let capture = axess_testing::mock_tracing::TracingCapture::install();
    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await;
    assert!(
        matches!(result, Err(AuthnError::Store(MockStoreError::NotFound))),
        "the write's own error: {result:?}"
    );
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.level == tracing::Level::WARN
                && e.message.contains("claim is kept")
                && e.message.contains("error=")),
        "an operator sees why the id stays held, with the error: {:?}",
        capture.events()
    );
    assert!(released(&f).is_empty(), "released: {:?}", released(&f));
    let other = test_user("u2", "mallory");
    assert_eq!(
        f.factors
            .inner
            .claim_fido2_credential(&other.tenant_id, &other.id, cred_id(BBBB).as_slice())
            .await
            .unwrap(),
        Fido2CredentialClaim::HeldBy(user.id),
        "the id is still held for the user who claimed it"
    );
}

/// A claim the store refuses while naming no other holder is refused with
/// a failed `FactorSetup` row whose reason is `credential_id_claim_refused`,
/// and nothing is stored.
#[tokio::test]
async fn a_refused_claim_with_no_holder_is_audited_as_claim_refused() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    *f.factors.next_claim.lock().unwrap() = Some(Fido2CredentialClaim::Refused);
    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "second", &session)
        .await;
    assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
    assert_eq!(stored_ids(&f).await, vec![cred_id(AAAA)]);
    let reasons: Vec<String> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::FactorSetup && e.event_status == AuthEventStatus::Failure
        })
        .filter_map(|e| e.error.map(|r| r.to_string()))
        .collect();
    assert_eq!(reasons, vec!["credential_id_claim_refused".to_owned()]);
}

/// A claim the store refuses while the id it names is the registering
/// user's own is refused as `credential_id_claim_refused`: the row names
/// another holder only when another user holds the id.
#[tokio::test]
async fn a_refused_claim_held_by_the_same_user_is_audited_as_claim_refused() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let user = test_user("u1", "alice");
    f.factors
        .inner
        .save_factor(&f.scope, config_of(&[AAAA, BBBB]))
        .await
        .unwrap();
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    *f.factors.next_claim.lock().unwrap() = Some(Fido2CredentialClaim::HeldBy(user.id));
    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "again", &session)
        .await;
    assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
    let reasons: Vec<String> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::FactorSetup && e.event_status == AuthEventStatus::Failure
        })
        .filter_map(|e| e.error.map(|r| r.to_string()))
        .collect();
    assert_eq!(reasons, vec!["credential_id_claim_refused".to_owned()]);
}

/// The reason on the row of a refused claim is the holder the claim itself
/// named: the store here holds nothing for the other user, so a reason read
/// from the store afterwards would name nobody.
#[tokio::test]
async fn the_reason_of_a_refused_claim_is_the_holder_the_claim_named() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let user = test_user("u1", "alice");
    let other = test_user("u3", "bob");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    *f.factors.next_claim.lock().unwrap() = Some(Fido2CredentialClaim::HeldBy(other.id));

    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "mine", &session)
        .await;

    assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
    let reasons: Vec<String> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::FactorSetup && e.event_status == AuthEventStatus::Failure
        })
        .filter_map(|e| e.error.map(|r| r.to_string()))
        .collect();
    assert_eq!(reasons, vec!["credential_held_by_another_user".to_owned()]);
}

/// A registration refused while another user's registration of the same id
/// holds the claim and has not stored its passkey yet is audited as held by
/// another user: the row says who holds the id whichever of the two writes
/// first.
#[tokio::test]
async fn a_claim_another_user_holds_before_storing_is_audited_as_held_by_another_user() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let user = test_user("u1", "alice");
    let other = test_user("u3", "bob");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    assert!(
        f.factors
            .inner
            .claim_fido2_credential(&other.tenant_id, &other.id, cred_id(BBBB).as_slice())
            .await
            .unwrap()
            .is_claimed(),
        "the other user's registration claims the id and has stored nothing yet"
    );

    let result = f
        .service
        .finish_fido2_registration(&user, &dummy_response(), "mine", &session)
        .await;

    assert!(matches!(result, Err(AuthnError::NoFlow)), "{result:?}");
    let reasons: Vec<String> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::FactorSetup && e.event_status == AuthEventStatus::Failure
        })
        .filter_map(|e| e.error.map(|r| r.to_string()))
        .collect();
    assert_eq!(reasons, vec!["credential_held_by_another_user".to_owned()]);
}

/// Two users of one tenant finishing a registration of the same credential
/// id at once: exactly one stores it, the other is refused with a row
/// naming the holder, through the service and not only at the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_racing_registrations_of_one_credential_id_store_it_once() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    for round in 0..16 {
        let f = fixture();
        let alice = test_user("u1", "alice");
        let bob = test_user("u3", "bob");
        let _ = f.identity.clone().with_user(bob.clone());
        let (alice_session, bob_session) = (session_for(&alice).await, session_for(&bob).await);
        f.service
            .begin_fido2_registration(&alice, &alice_session)
            .await
            .unwrap();
        f.service
            .begin_fido2_registration(&bob, &bob_session)
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let racer = |user: axess_core::authn::types::User, session| {
            let (service, barrier) = (f.service.clone(), barrier.clone());
            tokio::spawn(async move {
                barrier.wait().await;
                service
                    .finish_fido2_registration(&user, &dummy_response(), "mine", &session)
                    .await
            })
        };
        let (a, b) = (
            racer(alice.clone(), alice_session),
            racer(bob.clone(), bob_session),
        );
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert!(
            a.is_ok() != b.is_ok(),
            "round {round}: exactly one registration stands: {a:?} / {b:?}"
        );
        let loser = if a.is_ok() { b } else { a };
        assert!(
            matches!(loser, Err(AuthnError::NoFlow)),
            "round {round}: {loser:?}"
        );
        let mut holders = 0;
        for user in [&alice, &bob] {
            let scope = AuthnScope::User {
                tenant_id: user.tenant_id,
                user_id: user.id,
            };
            if let Some(FactorConfig::Fido2(cfg)) = f
                .factors
                .inner
                .load_factor(&scope, FactorKind::Fido2)
                .await
                .unwrap()
                && cfg
                    .credentials
                    .iter()
                    .any(|k| k.cred_id() == &cred_id(BBBB))
            {
                holders += 1;
            }
        }
        assert_eq!(holders, 1, "round {round}: one holder of the id");
        let refusals: Vec<String> = f
            .identity
            .events()
            .into_iter()
            .filter(|e| {
                e.event_type == AuthEventType::FactorSetup
                    && e.event_status == AuthEventStatus::Failure
            })
            .filter_map(|e| e.error.map(|r| r.to_string()))
            .collect();
        assert_eq!(
            refusals,
            vec!["credential_held_by_another_user".to_owned()],
            "round {round}: the loser leaves one row naming the holder"
        );
    }
}

/// The two registration calls refuse a suspended account by the rule the
/// discoverable login and the deletion follow: the end is shown for a
/// lockout and for no other cause.
#[tokio::test]
async fn a_registration_refusal_shows_the_end_of_a_lockout_only() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::store::IdentityAdmin as _;
    use axess_core::authn::types::StatusDetail;
    let ends = axess_clock::Timestamp::from_unix_seconds(4_102_444_800).expect("an instant");
    let began = ends.minus(axess_clock::SignedDuration::days(1));
    let causes = [
        (
            "lockout",
            StatusDetail::lockout("attempts", began),
            Some(ends),
        ),
        (
            "administrative",
            StatusDetail::administrative("hold", began),
            None,
        ),
        (
            "verification",
            StatusDetail::verification("pending", began),
            None,
        ),
        ("closure", StatusDetail::closure("closing", began), None),
    ];
    for (name, detail, shown) in causes {
        let detail = detail.with_until(Some(axess_clock::Until::At(ends)));
        // A ceremony begun before the suspension: the finish refuses it.
        let f = fixture();
        let alice = test_user("u1", "alice");
        let session = session_for(&alice).await;
        f.service
            .begin_fido2_registration(&alice, &session)
            .await
            .unwrap();
        f.identity.suspend_user(&alice.id, detail).await.unwrap();
        let finish = f
            .service
            .finish_fido2_registration(&alice, &dummy_response(), "late", &session)
            .await
            .unwrap_err();
        let AuthnError::Locked { until } = finish else {
            panic!("{name}: the finish answered {finish:?}");
        };
        assert_eq!(
            until,
            shown.map(axess_clock::Until::At),
            "{name}: the end the finish shows"
        );

        // A ceremony begun while suspended: the begin refuses it.
        let begin = f
            .service
            .begin_fido2_registration(&alice, &session_for(&alice).await)
            .await
            .unwrap_err();
        let AuthnError::Locked { until } = begin else {
            panic!("{name}: the begin answered {begin:?}");
        };
        assert_eq!(
            until,
            shown.map(axess_clock::Until::At),
            "{name}: the end the begin shows"
        );
    }
}
