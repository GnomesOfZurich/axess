#![cfg(feature = "testing")]
//! An unverified `Candidate` account holds its identifier only for a bounded
//! time, so a stranger who starts a signup nobody finishes cannot keep the
//! identifier from the person it belongs to.

mod common;

use axess_clock::testing::MockClock;
use axess_core::authn::{AuditContext, RequestAuthnService};
use axess_core::authn::{
    event::AuthEventType,
    ids::UserId,
    service::{AuthnService, DEFAULT_CANDIDATE_TTL, SignupOutcome},
    store::IdentityLookup,
    types::{EntityState, User},
};
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use chrono::Utc;
use common::{test_tenant, tid, uid};
use std::time::Duration;

type Svc = RequestAuthnService<MockIdentityStore, MockFactorStore>;

fn candidate(id: &str, identifier: &str) -> User {
    let now = Utc::now();
    User {
        id: uid(id),
        tenant_id: tid("t1"),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Candidate,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

fn rig(
    configure: impl FnOnce(AuthnServiceBuilder) -> AuthnServiceBuilder,
) -> (Svc, MockClock, MockIdentityStore) {
    let clock = MockClock::at(Utc::now());
    let identity = MockIdentityStore::new().with_tenant(test_tenant());
    let builder =
        AuthnService::builder(identity.clone(), MockFactorStore::new()).with_clock(clock.clone());
    let svc = configure(builder)
        .build()
        .with_audit_context(AuditContext::default());
    (svc, clock, identity)
}

type AuthnServiceBuilder =
    axess_core::authn::service::AuthnServiceBuilder<MockIdentityStore, MockFactorStore>;

async fn begin(svc: &Svc, who: &str, identifier: &str) -> SignupOutcome {
    svc.begin_signup(candidate(who, identifier), "default", &test_session())
        .await
        .unwrap()
}

#[tokio::test]
async fn an_expired_unverified_candidate_no_longer_holds_its_identifier() {
    let (svc, clock, identity) = rig(|b| b);
    assert!(matches!(
        begin(&svc, "attacker", "alice@corp.example").await,
        SignupOutcome::Started(Some(_))
    ));

    clock.advance(
        chrono::Duration::from_std(DEFAULT_CANDIDATE_TTL).unwrap() + chrono::Duration::seconds(1),
    );
    let out = begin(&svc, "victim", "alice@corp.example").await;

    assert!(
        matches!(out, SignupOutcome::Started(Some(_))),
        "victim blocked by an expired unverified candidate: {out:?}"
    );
    let holder = identity
        .find_user("alice@corp.example", &tid("t1"))
        .await
        .unwrap()
        .expect("the victim's candidate exists");
    assert_eq!(holder.id, uid("victim"));
    assert!(
        identity
            .events()
            .iter()
            .any(|e| e.event_type == AuthEventType::AccountDeleted
                && e.user_id == Some(uid("attacker"))),
        "the release of the identifier is audited"
    );
}

#[tokio::test]
async fn a_candidate_inside_its_lifetime_still_holds_its_identifier() {
    let (svc, clock, _) = rig(|b| b);
    begin(&svc, "first", "alice@corp.example").await;

    clock.advance(
        chrono::Duration::from_std(DEFAULT_CANDIDATE_TTL).unwrap() - chrono::Duration::seconds(1),
    );
    let out = begin(&svc, "second", "alice@corp.example").await;

    assert!(matches!(out, SignupOutcome::Started(None)), "{out:?}");
}

#[tokio::test]
async fn the_lifetime_is_the_builders() {
    let (svc, clock, _) = rig(|b| {
        b.with_signup_verification_ttl(Duration::from_secs(60))
            .with_candidate_ttl(Duration::from_secs(600))
    });
    begin(&svc, "first", "alice@corp.example").await;

    clock.advance(chrono::Duration::seconds(601));
    let out = begin(&svc, "second", "alice@corp.example").await;

    assert!(matches!(out, SignupOutcome::Started(Some(_))), "{out:?}");
}

#[tokio::test]
async fn a_candidate_never_expires_before_its_verification_secret() {
    let (svc, clock, _) = rig(|b| {
        b.with_signup_verification_ttl(Duration::from_secs(3600))
            .with_candidate_ttl(Duration::from_secs(60))
    });
    begin(&svc, "first", "alice@corp.example").await;

    clock.advance(chrono::Duration::seconds(600));
    let out = begin(&svc, "second", "alice@corp.example").await;

    assert!(matches!(out, SignupOutcome::Started(None)), "{out:?}");
}

#[tokio::test]
async fn the_session_that_began_a_signup_resumes_it_past_the_lifetime() {
    let (svc, clock, _) = rig(|b| b);
    let session = test_session();
    svc.begin_signup(candidate("mine", "alice@corp.example"), "default", &session)
        .await
        .unwrap();

    clock.advance(
        chrono::Duration::from_std(DEFAULT_CANDIDATE_TTL).unwrap() + chrono::Duration::hours(1),
    );
    let out = svc
        .begin_signup(candidate("mine", "alice@corp.example"), "default", &session)
        .await
        .unwrap();

    assert!(matches!(out, SignupOutcome::Started(Some(_))), "{out:?}");
}

#[tokio::test]
async fn an_active_account_never_expires() {
    let (svc, clock, identity) = rig(|b| b);
    let session = test_session();
    let SignupOutcome::Started(Some(v)) = svc
        .begin_signup(candidate("real", "alice@corp.example"), "default", &session)
        .await
        .unwrap()
    else {
        panic!("signup did not start");
    };
    svc.complete_signup(&session, v.secret()).await.unwrap();

    clock.advance(chrono::Duration::days(400));
    let out = begin(&svc, "other", "alice@corp.example").await;

    assert!(matches!(out, SignupOutcome::Started(None)), "{out:?}");
    assert!(
        identity
            .find_user("alice@corp.example", &tid("t1"))
            .await
            .unwrap()
            .is_some_and(|u| u.id == uid("real"))
    );
}

#[tokio::test]
async fn the_sweep_deletes_expired_candidates_nobody_asked_for_again() {
    let (svc, clock, identity) = rig(|b| b);
    begin(&svc, "old-a", "a@corp.example").await;
    begin(&svc, "old-b", "b@corp.example").await;
    clock.advance(chrono::Duration::hours(25));
    begin(&svc, "young", "c@corp.example").await;

    let deleted = svc.purge_expired_candidates(100).await.unwrap();

    assert_eq!(deleted, 2);
    for gone in ["a@corp.example", "b@corp.example"] {
        assert!(
            identity
                .find_user(gone, &tid("t1"))
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        identity
            .find_user("c@corp.example", &tid("t1"))
            .await
            .unwrap()
            .is_some()
    );
    let audited = identity
        .events()
        .iter()
        .filter(|e| e.event_type == AuthEventType::AccountDeleted)
        .count();
    assert_eq!(audited, 2, "one audit row per deletion");
    assert_eq!(svc.purge_expired_candidates(100).await.unwrap(), 0);
}

#[tokio::test]
async fn the_sweep_is_bounded_and_never_touches_an_active_account() {
    let (svc, clock, identity) = rig(|b| b);
    let session = test_session();
    let SignupOutcome::Started(Some(v)) = svc
        .begin_signup(candidate("real", "r@corp.example"), "default", &session)
        .await
        .unwrap()
    else {
        panic!("signup did not start");
    };
    svc.complete_signup(&session, v.secret()).await.unwrap();
    for n in 0..5 {
        begin(&svc, &format!("c{n}"), &format!("c{n}@corp.example")).await;
    }
    clock.advance(chrono::Duration::days(3));

    assert_eq!(svc.purge_expired_candidates(3).await.unwrap(), 3);
    assert_eq!(svc.purge_expired_candidates(3).await.unwrap(), 2);
    assert!(
        identity
            .find_user("r@corp.example", &tid("t1"))
            .await
            .unwrap()
            .is_some_and(|u| u.id == uid("real"))
    );
}
