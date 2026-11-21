//! Who may enrol and delete a passkey, how a suspended or inactive account
//! is refused, and the audit rows the management paths write.

use axess_clock::testing::Shift;
use axess_core::testing::fixtures as common;

use super::fixture::*;
use axess_core::Clock;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{FactorConfig, FactorKind, Fido2Config, Fido2Credential};
use axess_core::authn::store::FactorStore;
use axess_core::authn::types::AuthnScope;
use axess_core::{authn::service::AuthnService, testing::test_session};
use axess_factors::fido2::DefaultFido2Provider;
use common::{session_for, test_user};
use url::Url;
use webauthn_rs::prelude::*;

// ── Who may enrol and delete ─────────────────────────────────────────────────

#[tokio::test]
async fn a_guest_session_cannot_begin_a_registration() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let user = test_user("u1", "alice");
    let err = f
        .service
        .begin_fido2_registration(&user, &test_session())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn another_users_session_cannot_begin_finish_or_delete() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let mallory = test_user("u2", "mallory");
    let session = session_for(&mallory).await;
    let err = f
        .service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "begin: {err:?}");
    let err = f
        .service
        .finish_fido2_registration(&alice, &dummy_response(), "evil", &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "finish: {err:?}");
    let err = f
        .service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "delete: {err:?}");
    assert_eq!(stored_count(&f).await, 1, "nothing was added or removed");
}

#[tokio::test]
async fn a_session_of_the_same_id_in_another_tenant_is_refused() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let impostor = common::test_user_in_tenant("u1", "alice", "t2");
    let err = f
        .service
        .begin_fido2_registration(&alice, &session_for(&impostor).await)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn a_signup_session_can_enrol_its_first_passkey_but_only_its_own() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = common::signup_session_for(&alice).await;
    f.service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&alice, &dummy_response(), "first", &session)
        .await
        .unwrap();
    let bob = test_user("u3", "bob");
    let err = f
        .service
        .begin_fido2_registration(&bob, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
}

#[tokio::test]
async fn a_refused_enrolment_leaves_a_failed_audit_row() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let alice = test_user("u1", "alice");
    let _ = f
        .service
        .begin_fido2_registration(&alice, &test_session())
        .await;
    let rows = f.identity.events();
    assert!(
        rows.iter()
            .any(|e| e.event_type == AuthEventType::FactorEnabled
                && e.event_status == AuthEventStatus::Failure),
        "{rows:?}"
    );
}

/// The five-minute recency is the default: the gate holds for begin, finish
/// and deletion without the adopter setting `max_authn_age`.
#[tokio::test]
async fn a_session_authenticated_too_long_ago_cannot_change_credentials() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let fresh = session_aged(&alice, axess_clock::SignedDuration::minutes(1)).await;
    f.service
        .begin_fido2_registration(&alice, &fresh)
        .await
        .expect("a minute-old authentication is recent enough");

    let stale = session_aged(&alice, axess_clock::SignedDuration::minutes(10)).await;
    let err = f
        .service
        .begin_fido2_registration(&alice, &stale)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "begin: {err:?}");
    let err = f
        .service
        .finish_fido2_registration(&alice, &dummy_response(), "late", &stale)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "finish: {err:?}");
    let err = f
        .service
        .delete_fido2_credential(&alice, &stale, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "delete: {err:?}");
    assert_eq!(stored_count(&f).await, 1, "nothing was added or removed");
}

/// `max_authn_age: None`, written out, is the opt-out: a session of any age
/// may change credentials.
#[tokio::test]
async fn naming_no_recency_limit_accepts_an_old_authentication() {
    use axess_core::authn::factor::Fido2Options;
    let f = fixture_with(Fido2Options {
        max_authn_age: None,
        ..Fido2Options::default()
    });
    let alice = test_user("u1", "alice");
    let stale = session_aged(&alice, axess_clock::SignedDuration::hours(10)).await;
    f.service
        .begin_fido2_registration(&alice, &stale)
        .await
        .expect("the named opt-out applies no age limit");
}

#[tokio::test]
async fn an_impersonated_session_cannot_change_credentials() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_for(&alice).await;
    // The marker `begin_impersonation` leaves; only server code writes it.
    assert!(
        axess_core::testing::AuthSessionTestExt::set_impersonator(
            &session,
            test_user("u9", "admin").id,
            f.clock.now(),
        )
        .await,
        "the session is impersonated"
    );
    let err = f
        .service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::Impersonated), "begin: {err:?}");
    let err = f
        .service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::Impersonated), "delete: {err:?}");
    assert_eq!(stored_count(&f).await, 1, "nothing was added or removed");
}

#[tokio::test]
async fn a_signup_session_cannot_delete_a_passkey() {
    use axess_core::authn::error::AuthnError;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = common::signup_session_for(&alice).await;
    let err = f
        .service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthnError::NoFlow), "got {err:?}");
    assert_eq!(stored_count(&f).await, 1, "the passkey stays");
}

// ── Status and audit rows on the management paths ───────────────────────────

/// Deleting checked the session and nothing else: a suspended account
/// could still remove its passkeys, where it could neither enrol one nor
/// finish enrolling one.
#[tokio::test]
async fn a_suspended_account_cannot_delete_a_passkey() {
    use axess_core::authn::error::AuthnError;
    let future = common::start().plus(axess_clock::SignedDuration::hours(1));
    let (service, alice) = fixture_with_status(suspended_until(future));
    let session = session_for(&alice).await;

    let res = service
        .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
        .await;

    assert!(matches!(res, Err(AuthnError::Locked { .. })), "{res:?}");
}

/// A suspended account refused on a passkey path is told the end of the
/// suspension by the rule of the factor steps: only for a lockout a store
/// keeps as a state. The discoverable login answers before the assertion is
/// verified, so the end of an operator's hold would be shown to a caller who
/// has proved nothing.
#[tokio::test]
async fn a_passkey_refusal_shows_the_end_of_a_lockout_only() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::types::{EntityState, StatusDetail};
    // The year 2100: a suspension still running whenever this is run.
    let ends = axess_clock::Timestamp::from_unix_seconds(4_102_444_800).expect("an instant");
    let began = ends.minus(axess_clock::SignedDuration::days(1));
    let causes = [
        (
            "lockout",
            StatusDetail::lockout("too many attempts", began),
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
    let assertion: PublicKeyCredential = serde_json::from_value(serde_json::json!({
        "id": "AAAA", "rawId": "AAAA", "type": "public-key",
        "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                      "signature": "AAAA", "userHandle": null }
    }))
    .unwrap();
    for (name, detail, shown) in causes {
        let status = EntityState::Suspended(detail.with_until(Some(axess_clock::Until::At(ends))));
        let (service, alice) = fixture_with_status(status);

        let login = service
            .finish_discoverable_login(&assertion, &alice, &[], &test_session())
            .await
            .unwrap_err();
        let AuthnError::Locked { until } = login else {
            panic!("{name}: the login answered {login:?}");
        };
        assert_eq!(
            until,
            shown.map(axess_clock::Until::At),
            "{name}: the end the login shows"
        );

        let deletion = service
            .delete_fido2_credential(&alice, &session_for(&alice).await, &cred_id(AAAA), 0)
            .await
            .unwrap_err();
        let AuthnError::Locked { until } = deletion else {
            panic!("{name}: the deletion answered {deletion:?}");
        };
        assert_eq!(
            until,
            shown.map(axess_clock::Until::At),
            "{name}: the end the deletion shows"
        );
    }
}

/// The success rows of a registration and a deletion carry the session
/// that made the change, as every refusal row does.
#[tokio::test]
async fn the_registration_and_deletion_rows_carry_the_session() {
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_for(&alice).await;
    let sid = session.session_key().await;
    f.service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&alice, &dummy_response(), "second", &session)
        .await
        .unwrap();
    assert!(
        f.service
            .delete_fido2_credential(&alice, &session, &cred_id(AAAA), 0)
            .await
            .unwrap()
    );

    for kind in [AuthEventType::FactorSetup, AuthEventType::FactorDisabled] {
        let rows: Vec<_> = f
            .identity
            .events()
            .into_iter()
            .filter(|e| e.event_type == kind && e.event_status == AuthEventStatus::Success)
            .collect();
        assert_eq!(rows.len(), 1, "{kind:?}");
        assert_eq!(rows[0].session_id, Some(sid), "{kind:?}: {rows:?}");
    }
}

/// A finish refused for an account suspended since the ceremony began is
/// recorded under the finish's own kind, `FactorSetup`, which its success
/// row and its other refusals use, and not as a `FactorEnabled` row.
#[tokio::test]
async fn an_inactive_account_refused_at_finish_is_recorded_as_a_setup() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    use axess_core::authn::store::IdentityAdmin as _;
    let f = fixture();
    let alice = test_user("u1", "alice");
    let session = session_for(&alice).await;
    f.service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();
    f.identity
        .suspend_user(
            &alice.id,
            axess_core::authn::types::StatusDetail::administrative("test", f.clock.now()),
        )
        .await
        .unwrap();

    let err = f
        .service
        .finish_fido2_registration(&alice, &dummy_response(), "late", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::Locked { .. }), "{err:?}");
    let rows: Vec<_> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| e.event_status == AuthEventStatus::Locked)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].event_type, AuthEventType::FactorSetup);
    assert_eq!(rows[0].session_id, Some(session.session_key().await));
}

#[tokio::test]
async fn beginning_registration_fails_when_the_ceremony_state_cannot_be_stored() {
    let f = fixture();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    assert!(
        session
            .set_custom("pad", serde_json::json!("x".repeat(65_500)))
            .await
    );

    let result = f.service.begin_fido2_registration(&user, &session).await;

    assert!(
        matches!(result, Err(axess_core::authn::error::AuthnError::NoFlow)),
        "a challenge whose state was not stored can never be finished: {result:?}"
    );
}

/// A registration the authenticator's answer fails to verify is audited, and
/// its row names the session it came from like the other rows of the flow.
#[tokio::test]
async fn a_rejected_registration_row_names_its_session() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let f = fixture();
    let alice = test_user("u1", "alice");
    let webauthn =
        WebauthnBuilder::new("localhost", &Url::parse("https://localhost:8443").unwrap())
            .unwrap()
            .build()
            .unwrap();
    // The real verifier: the placeholder attestation does not verify.
    let service = AuthnService::builder(f.identity.clone(), f.factors.clone())
        .with_clock(f.clock.clone())
        .with_fido2(DefaultFido2Provider::new(webauthn))
        .build()
        .with_audit_context(AuditContext::default());
    let session = session_for(&alice).await;
    service
        .begin_fido2_registration(&alice, &session)
        .await
        .unwrap();

    let err = service
        .finish_fido2_registration(&alice, &dummy_response(), "bad", &session)
        .await
        .unwrap_err();

    assert!(matches!(err, AuthnError::NoFlow), "{err:?}");
    let rows: Vec<_> = f
        .identity
        .events()
        .into_iter()
        .filter(|e| {
            e.event_type == AuthEventType::FactorSetup && e.event_status == AuthEventStatus::Failure
        })
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].session_id, Some(session.session_key().await));
}

#[tokio::test]
async fn a_credential_id_another_user_of_the_tenant_holds_is_refused_and_audited() {
    use axess_core::authn::error::AuthnError;
    use axess_core::authn::event::{AuthEventStatus, AuthEventType};
    let (f, result) = bob_finishes_with_a_credential_held_by("u2").await;
    assert!(matches!(result, Err(AuthnError::NoFlow)), "got {result:?}");
    let bob_scope = AuthnScope::User {
        tenant_id: test_user("u3", "bob").tenant_id,
        user_id: test_user("u3", "bob").id,
    };
    assert!(
        f.factors
            .inner
            .load_factor(&bob_scope, FactorKind::Fido2)
            .await
            .unwrap()
            .is_none(),
        "nothing was stored for the second user"
    );
    let rows = f.identity.events();
    assert!(
        rows.iter()
            .any(|e| e.event_type == AuthEventType::FactorSetup
                && e.event_status == AuthEventStatus::Failure),
        "{rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|e| e.event_type == AuthEventType::FactorSetup
                && e.event_status == AuthEventStatus::Success),
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_credential_id_held_in_another_tenant_is_not_a_conflict() {
    let f = fixture();
    let owner = common::test_user_in_tenant("u2", "owner", "t2");
    f.factors
        .inner
        .save_factor(
            &AuthnScope::User {
                tenant_id: owner.tenant_id,
                user_id: owner.id,
            },
            FactorConfig::Fido2(Fido2Config {
                credentials: vec![Fido2Credential::new(passkey(BBBB), "theirs", f.clock.now())],
            }),
        )
        .await
        .unwrap();
    let user = test_user("u1", "alice");
    let session = session_for(&user).await;
    f.service
        .begin_fido2_registration(&user, &session)
        .await
        .unwrap();
    f.service
        .finish_fido2_registration(&user, &dummy_response(), "mine", &session)
        .await
        .unwrap();
}
