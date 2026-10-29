#![cfg(feature = "testing")]
//! Login-path security: the lockout is derived from the failure counter and
//! enforced before any verifier, half-finished flows expire and die with a
//! credential change, a password reset revokes refresh tokens, and the
//! combined password entry point spends one hash on every path.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::service::{AuthnService, FactorOutcome, LoginOutcome, RequestAuthnService};
use axess_core::authn::{
    error::AuthnError,
    factor::{FactorCredential, FactorKind, ZeroizedString},
    types::{EntityState, LockoutPolicy, StatusDetail},
};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    mock_authn::{CallLog, MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{
    generate_totp_code, password_config, password_method, password_totp_method, test_tenant,
    test_user, totp_config, uid, user_scope,
};
use std::sync::Arc;
use std::time::Duration;

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

struct Rig {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    clock: MockClock,
    kdf: Arc<KdfExecutor>,
}

fn policy() -> LockoutPolicy {
    LockoutPolicy {
        max_attempts: 3,
        duration: Some(Duration::from_secs(15 * 60)),
        ..LockoutPolicy::default()
    }
}

fn rig_with(user_status: EntityState, totp: bool) -> Rig {
    let clock = MockClock::now();
    let mut user = test_user("u1", "alice");
    user.status = user_status;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(user)
        .with_lockout_policy(policy());
    let mut factors = MockFactorStore::new().with_factor(user_scope(), password_config("Gnomes2+"));
    if totp {
        factors = factors
            .with_factor(user_scope(), totp_config(SECRET))
            .with_method(&uid("u1"), password_totp_method());
    } else {
        factors = factors.with_method(&uid("u1"), password_method());
    }
    let kdf = Arc::new(KdfExecutor::inline());
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_kdf_executor(kdf.clone())
        .build()
        .with_audit_context(AuditContext::default());
    Rig {
        svc,
        identity,
        clock,
        kdf,
    }
}

fn rig() -> Rig {
    rig_with(EntityState::Active, false)
}

fn pw(p: &str) -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(p))
}

/// One whole attempt in a fresh session: begin, then verify.
async fn attempt(r: &Rig, password: &str) -> String {
    let session = test_session();
    match r.svc.begin_login("alice", "default", &session).await {
        Ok(LoginOutcome::FactorRequired(_)) => {}
        Ok(LoginOutcome::Locked { until }) => return format!("begin-locked:{}", until.is_some()),
        Ok(other) => return format!("begin:{other:?}"),
        Err(e) => return format!("begin-err:{e}"),
    }
    match r.svc.verify_factor(&pw(password), &session).await {
        Ok(FactorOutcome::Locked { until }) => format!("locked:{}", until.is_some()),
        Ok(other) => format!("{other:?}"),
        Err(e) => format!("err:{e}"),
    }
}

// ── D3: lockout derived from the counter ────────────────────────────────────

#[tokio::test]
async fn lockout_is_enforced_before_the_verifier_and_expires() {
    let r = rig();
    // A flow begun before the lock, to prove the verify gate (not only
    // begin_login) refuses.
    let early = test_session();
    r.svc.begin_login("alice", "default", &early).await.unwrap();

    assert_eq!(attempt(&r, "wrong1").await, "InvalidCredential");
    assert_eq!(attempt(&r, "wrong2").await, "InvalidCredential");
    assert_eq!(attempt(&r, "wrong3").await, "locked:true");
    assert_eq!(r.identity.failed_attempts_for("u1"), 3);

    // The store never changed account_status, yet the correct password no
    // longer gets in, at either gate, and the verifier does not run.
    let jobs = r.kdf.jobs_started();
    assert_eq!(attempt(&r, "Gnomes2+").await, "begin-locked:true");
    let outcome = r.svc.verify_factor(&pw("Gnomes2+"), &early).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Locked { until: Some(_) }),
        "{outcome:?}"
    );
    assert_eq!(r.kdf.jobs_started(), jobs, "no password hash ran");
    assert_eq!(r.identity.failed_attempts_for("u1"), 3, "counter untouched");
    assert!(!early.is_authenticated().await);

    // Past `until` the correct password works and clears the counter.
    r.clock.advance(chrono::Duration::minutes(16));
    assert_eq!(attempt(&r, "Gnomes2+").await, "Authenticated");
    assert_eq!(r.identity.failed_attempts_for("u1"), 0);
}

#[tokio::test]
async fn a_zero_max_attempts_policy_does_not_lock_everyone() {
    let r = rig();
    let identity = r.identity.clone().with_lockout_policy(LockoutPolicy {
        max_attempts: 0,
        ..policy()
    });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity, factors)
        .with_clock(r.clock.clone())
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let begun = svc.begin_login("alice", "default", &session).await.unwrap();
    assert!(
        matches!(begun, LoginOutcome::FactorRequired(_)),
        "{begun:?}"
    );
    // The first wrong guess is not a lockout either (zero reads as five).
    let first = svc.verify_factor(&pw("nope"), &session).await.unwrap();
    assert!(
        matches!(first, FactorOutcome::InvalidCredential),
        "{first:?}"
    );
}

#[test]
fn derived_lockout_rules() {
    use chrono::Utc;
    let now = Utc::now();
    let p = policy();
    assert!(p.derived_lockout(2, Some(now), now).is_none());
    assert!(p.derived_lockout(3, Some(now), now).is_some());
    assert!(
        p.derived_lockout(3, Some(now - chrono::Duration::minutes(16)), now)
            .is_none()
    );
    // No timestamp from the store: stay locked rather than guess.
    assert_eq!(p.derived_lockout(9, None, now).unwrap().until, None);
    let forever = LockoutPolicy {
        duration: None,
        ..policy()
    };
    assert_eq!(
        forever
            .derived_lockout(3, Some(now - chrono::Duration::days(30)), now)
            .unwrap()
            .until,
        None
    );
}

// ── W7: a non-active account answers like an unknown identifier ─────────────

#[tokio::test]
async fn a_pending_account_is_not_distinguishable_at_begin_login() {
    let r = rig_with(
        EntityState::Pending(StatusDetail {
            reason: "review".into(),
            since: chrono::Utc::now(),
            until: None,
        }),
        false,
    );
    let outcome = r
        .svc
        .begin_login("alice", "default", &test_session())
        .await
        .expect("no distinct error");
    assert!(
        matches!(outcome, LoginOutcome::InvalidCredentials),
        "{outcome:?}"
    );
}

// ── W34: a barred known user makes the unknown identifier's store calls ─────

#[tokio::test]
async fn a_locked_known_user_makes_the_same_store_calls_as_an_unknown_one() {
    async fn calls_for(identifier: &str, locked: bool) -> Vec<&'static str> {
        let log = CallLog::new();
        let mut user = test_user("u1", "alice");
        if locked {
            user.status = EntityState::Suspended(StatusDetail {
                reason: "hold".into(),
                since: chrono::Utc::now(),
                until: None,
            });
        }
        let identity = MockIdentityStore::new()
            .with_call_log(&log)
            .with_tenant(test_tenant())
            .with_user(user);
        let svc = AuthnService::builder(identity, MockFactorStore::new().with_call_log(&log))
            .with_kdf_executor(Arc::new(KdfExecutor::inline()))
            .build()
            .with_audit_context(AuditContext::default());
        let _ = svc
            .begin_login(identifier, "default", &test_session())
            .await;
        log.calls()
    }
    assert_eq!(
        calls_for("alice", true).await,
        calls_for("nobody", false).await
    );
}

// ── D17 / F52: the flow dies with a credential change, and with time ────────

#[tokio::test]
async fn a_flow_at_the_second_factor_does_not_survive_a_password_reset() {
    let r = rig_with(EntityState::Active, true);
    let session = test_session();
    r.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let next = r
        .svc
        .verify_factor(&pw("Gnomes2+"), &session)
        .await
        .unwrap();
    assert!(
        matches!(next, FactorOutcome::FactorRequired(FactorKind::Totp)),
        "{next:?}"
    );

    let token = r
        .svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .unwrap();
    assert!(
        r.svc
            .complete_password_reset(&uid("u1"), &token, "A-long-new-passphrase-9!")
            .await
            .unwrap()
    );

    let code = generate_totp_code(SECRET, r.clock.now().into());
    let res = r
        .svc
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn an_idle_flow_expires_after_the_flow_ttl() {
    let r = rig();
    let session = test_session();
    r.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    r.clock.advance(chrono::Duration::minutes(11));
    let res = r.svc.verify_factor(&pw("Gnomes2+"), &session).await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(!session.is_authenticated().await);
}

#[tokio::test]
async fn a_flow_started_by_an_earlier_release_has_no_stamp_and_is_refused() {
    let r = rig();
    let session = test_session();
    r.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    session.remove_custom("axess.login.flow").await;
    let res = r.svc.verify_factor(&pw("Gnomes2+"), &session).await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
}

// ── D4: a password reset revokes refresh tokens ─────────────────────────────

#[tokio::test]
async fn a_password_reset_revokes_the_users_refresh_tokens() {
    use axess_core::session::refresh::*;
    use axess_core::testing::{MemoryRefreshTokenStore, MockRng};

    let clock = MockClock::now();
    let store = MemoryRefreshTokenStore::new();
    let config = RefreshTokenConfig::default();
    let rng = MockRng::new(5);
    let user = uid("u1");
    let tenant = common::tid("t1");
    let (plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &user,
            tenant_id: &tenant,
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &config,
        &store,
        &rng,
        clock.now(),
    )
    .await
    .unwrap();

    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_method(&uid("u1"), password_method());
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .with_refresh_store(store.clone())
        .build()
        .with_audit_context(AuditContext::default());

    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .unwrap();
    assert!(
        svc.complete_password_reset(&user, &token, "A-long-new-passphrase-9!")
            .await
            .unwrap()
    );

    let refreshed = refresh_session_with_status_check(
        &plaintext,
        &store,
        &config,
        &rng,
        clock.now(),
        None,
        |_| async { true },
    )
    .await;
    assert!(
        refreshed.is_err(),
        "the old refresh token must not mint a session"
    );
}

// ── E5 / W2 / E20 / W29: password reset refusals ────────────────────────────

#[tokio::test]
async fn a_refused_reset_leaves_a_failed_audit_row() {
    let r = rig();
    let refused = r
        .svc
        .complete_password_reset(&uid("u1"), "not-the-token", "A-long-new-passphrase-9!")
        .await
        .unwrap();
    assert!(!refused);
    let events = r.identity.events();
    let row = events
        .iter()
        .find(|e| e.event_type == AuthEventType::PasswordReset)
        .expect("a PasswordReset row");
    assert_eq!(row.event_status, AuthEventStatus::Failure);
    assert_eq!(
        row.error.as_ref().map(|e| e.as_str()),
        Some("token_mismatch")
    );
}

#[tokio::test]
async fn an_unknown_user_is_resolved_before_the_status_is_read() {
    let log = CallLog::new();
    let identity = MockIdentityStore::new()
        .with_call_log(&log)
        .with_tenant(test_tenant());
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let res = svc
        .complete_password_reset(&uid("ghost"), "t", "A-long-new-passphrase-9!")
        .await
        .unwrap();
    assert!(!res);
    assert!(
        !log.calls().contains(&"account_status"),
        "account_status must not run for an unknown id: {:?}",
        log.calls()
    );
}

#[tokio::test]
async fn a_reset_in_another_tenant_answers_like_an_unknown_user() {
    let r = rig();
    let token = r
        .svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .unwrap();
    let res = r
        .svc
        .complete_password_reset_in_tenant(
            &uid("u1"),
            &common::tid("t2"),
            &token,
            "A-long-new-passphrase-9!",
        )
        .await;
    assert!(matches!(res, Ok(false)), "{res:?}");
    // The token was not spent.
    assert!(
        r.svc
            .complete_password_reset(&uid("u1"), &token, "A-long-new-passphrase-9!")
            .await
            .unwrap()
    );
}

// ── D21 / F49: one hash on every path of the combined entry point ───────────

#[tokio::test]
async fn login_with_password_spends_exactly_one_hash_on_every_path() {
    let r = rig();
    let one = |outcome: Result<FactorOutcome, AuthnError<_>>| format!("{outcome:?}");

    let before = r.kdf.jobs_started();
    let unknown = one(r
        .svc
        .login_with_password("nobody", "default", "x", &test_session())
        .await);
    assert_eq!(r.kdf.jobs_started() - before, 1);

    let before = r.kdf.jobs_started();
    let wrong = one(r
        .svc
        .login_with_password("alice", "default", "wrong", &test_session())
        .await);
    assert_eq!(r.kdf.jobs_started() - before, 1);

    // Lock the account, then try the right password.
    for _ in 0..2 {
        let _ = r
            .svc
            .login_with_password("alice", "default", "wrong", &test_session())
            .await;
    }
    let before = r.kdf.jobs_started();
    let locked = one(r
        .svc
        .login_with_password("alice", "default", "Gnomes2+", &test_session())
        .await);
    assert_eq!(r.kdf.jobs_started() - before, 1);

    assert_eq!(unknown, wrong);
    assert_eq!(wrong, locked);
    assert_eq!(wrong, "Ok(InvalidCredential)");

    // And the right password still works for an unlocked account.
    let r2 = rig();
    let ok = r2
        .svc
        .login_with_password("alice", "default", "Gnomes2+", &test_session())
        .await
        .unwrap();
    assert!(matches!(ok, FactorOutcome::Authenticated), "{ok:?}");
}

// ── D19: step-up ────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_asks_an_authenticated_session_for_another_factor() {
    let r = rig_with(EntityState::Active, true);
    // A password-only session: log in with the password method, then add TOTP.
    let session = test_session();
    session
        .set_authenticated(uid("u1"), common::tid("t1"), r.clock.now())
        .await;
    assert!(!session.has_completed_factor(&FactorKind::Totp).await);

    let first = r
        .svc
        .begin_step_up(&session, vec![FactorKind::Totp])
        .await
        .unwrap();
    assert_eq!(first, FactorKind::Totp);
    assert!(!session.is_authenticated().await, "mid step-up");

    let wrong = r
        .svc
        .verify_factor(&FactorCredential::OtpCode("000000".into()), &session)
        .await
        .unwrap();
    assert!(
        matches!(wrong, FactorOutcome::InvalidCredential),
        "{wrong:?}"
    );

    r.clock.advance(chrono::Duration::seconds(60));
    let code = generate_totp_code(SECRET, r.clock.now().into());
    let done = r
        .svc
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
        .unwrap();
    assert!(matches!(done, FactorOutcome::Authenticated), "{done:?}");
    assert!(session.has_completed_factor(&FactorKind::Totp).await);
    assert!(
        session
            .authenticated_within(Duration::from_secs(5), r.clock.now())
            .await
    );
}

#[tokio::test]
async fn step_up_requires_an_authenticated_session() {
    let r = rig();
    let res = r
        .svc
        .begin_step_up(&test_session(), vec![FactorKind::Totp])
        .await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
}

// ── E3 / E26: impersonation ─────────────────────────────────────────────────

#[tokio::test]
async fn impersonation_requires_the_session_to_be_the_admin_and_marks_the_result() {
    let clock = MockClock::now();
    let admin = common::test_user("admin", "ops");
    let target = common::test_user("u2", "bob");
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(admin.clone())
        .with_user(target.clone());
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build()
        .with_audit_context(AuditContext::default());

    // An unauthenticated session is refused and audited with the actor.
    let anon = test_session();
    let res = svc
        .begin_impersonation_across_tenants(&admin.id, &target, &anon)
        .await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");
    assert!(!anon.is_authenticated().await);
    assert!(identity.events().iter().any(|e| {
        e.event_type == AuthEventType::Impersonation
            && e.event_status == AuthEventStatus::Failure
            && e.actor_id.as_ref() == Some(&admin.id)
    }));

    // A session authenticated as somebody else is refused too.
    let other = test_session();
    other
        .set_authenticated(uid("u2"), common::tid("t1"), clock.now())
        .await;
    let res = svc
        .begin_impersonation_across_tenants(&admin.id, &target, &other)
        .await;
    assert!(matches!(res, Err(AuthnError::NoFlow)), "{res:?}");

    // The admin's own session impersonates, keeps the admin's auth time and
    // carries the marker.
    clock.advance(chrono::Duration::hours(2));
    let session = test_session();
    let admin_login = clock.now() - chrono::Duration::hours(2);
    session
        .set_authenticated(admin.id, admin.tenant_id, admin_login)
        .await;
    svc.begin_impersonation_across_tenants(&admin.id, &target, &session)
        .await
        .unwrap();
    assert_eq!(session.user_id().await, Some(target.id));
    assert_eq!(session.impersonator().await, Some(admin.id));
    assert_eq!(session.snapshot().await.unwrap().authn_time, admin_login);

    svc.end_impersonation(&session).await.unwrap();
    assert!(!session.is_authenticated().await);
    assert_eq!(session.impersonator().await, None);
}

// ── F1: signup does not hand over somebody else's half-made account ────────

#[tokio::test]
async fn a_candidate_is_not_resumed_by_a_different_session() {
    let mut candidate = test_user("u9", "carol");
    candidate.status = EntityState::Candidate;
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(candidate.clone());
    let svc = AuthnService::new(identity.clone(), MockFactorStore::new())
        .with_audit_context(AuditContext::default());
    let stranger = test_session();
    let outcome = svc
        .begin_signup(candidate.clone(), "default", &stranger)
        .await
        .unwrap();
    assert!(
        matches!(
            outcome,
            axess_core::authn::service::SignupOutcome::AlreadyExists
        ),
        "{outcome:?}"
    );
    assert!(
        stranger.user_id().await.is_none(),
        "nothing attached to the stranger"
    );
    assert!(
        identity
            .events()
            .iter()
            .any(|e| e.event_type == AuthEventType::SignupStarted
                && e.event_status == AuthEventStatus::Failure)
    );
}

// ── W3: a token store outage answers like an unknown identifier ─────────────

#[tokio::test]
async fn a_token_store_outage_answers_none_for_a_known_identifier_too() {
    let r = rig();
    r.identity.arm_store_reset_token_failure();
    let known = r
        .svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await;
    let unknown = r
        .svc
        .begin_password_reset("nobody", "default", Duration::from_secs(300))
        .await;
    assert!(matches!(known, Ok(None)), "{known:?}");
    assert!(matches!(unknown, Ok(None)), "{unknown:?}");
}

// ── E63: oversized identifiers are refused like unknown ones ────────────────

#[tokio::test]
async fn an_oversized_reset_identifier_is_answered_as_unknown() {
    let r = rig();
    let huge = "x".repeat(10_000);
    let res = r
        .svc
        .begin_password_reset(&huge, "default", Duration::from_secs(300))
        .await;
    assert!(matches!(res, Ok(None)), "{res:?}");
}
