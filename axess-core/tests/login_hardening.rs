#![cfg(feature = "testing")]
//! Login hardening: a password hash made under old Argon2 parameters is
//! replaced on a successful login, parallel guesses cannot pass the attempt
//! limit, a taken signup identifier can be answered like a free one, and a
//! password reset request has a per-identifier cooldown.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, PasswordConfig, PasswordRules, ZeroizedString,
};
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService, SignupOutcome};
use axess_core::authn::store::{FactorStore, IdentityLookup};
use axess_core::authn::types::{CounterUnavailable, EntityState, LockoutPolicy};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{
    generate_totp_code, password_method, password_totp_method, test_tenant, test_user, totp_config,
    uid, user_scope,
};
use std::sync::Arc;
use std::time::Duration;

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// `Gnomes2+` under Argon2id version 19 with m=8, t=1, p=1: weaker than the
/// pinned parameters, so a login with it is the moment to rehash.
const OLD_PARAMETERS: &str =
    "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$MqIhMSj5Frink9coqITn+DRhryB/VmDRYGbeJ3sTqRc";

fn config_with(hash: &str) -> FactorConfig {
    FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(hash),
        rules: PasswordRules::default(),
    })
}

fn pw(p: &str) -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(p))
}

struct Rig {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    factors: MockFactorStore,
    clock: MockClock,
    kdf: Arc<KdfExecutor>,
}

fn rig(hash: &str, totp: bool, kdf: KdfExecutor, policy: LockoutPolicy) -> Rig {
    let clock = MockClock::now();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(policy);
    let mut factors = MockFactorStore::new().with_factor(user_scope(), config_with(hash));
    factors = if totp {
        factors
            .with_factor(user_scope(), totp_config(SECRET))
            .with_method(&uid("u1"), password_totp_method())
    } else {
        factors.with_method(&uid("u1"), password_method())
    };
    let kdf = Arc::new(kdf);
    let svc = AuthnService::builder(identity.clone(), factors.clone())
        .with_clock(clock.clone())
        .with_kdf_executor(kdf.clone())
        .build()
        .with_audit_context(AuditContext::default());
    Rig {
        svc,
        identity,
        factors,
        clock,
        kdf,
    }
}

fn policy(max_attempts: u32) -> LockoutPolicy {
    LockoutPolicy {
        max_attempts,
        duration: Some(Duration::from_secs(900)),
        ..LockoutPolicy::default()
    }
}

async fn stored_hash(r: &Rig) -> String {
    match r
        .factors
        .load_factor(&user_scope(), FactorKind::Password)
        .await
        .unwrap()
    {
        Some(FactorConfig::Password(cfg)) => {
            let hash: &str = cfg.hash.as_ref();
            hash.to_owned()
        }
        other => panic!("no password row: {other:?}"),
    }
}

// ── Password rehash ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_hash_under_old_parameters_is_replaced_on_login() {
    let r = rig(OLD_PARAMETERS, false, KdfExecutor::inline(), policy(5));
    assert!(axess_factors::password_needs_rehash(OLD_PARAMETERS));
    let session = test_session();
    let outcome = r
        .svc
        .login_with_password("alice", "default", "Gnomes2+", &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );

    let now = stored_hash(&r).await;
    assert_ne!(now, OLD_PARAMETERS, "the hash was replaced");
    assert!(!axess_factors::password_needs_rehash(&now));
    assert!(axess_factors::verify_password("Gnomes2+", &now).is_ok());
}

#[tokio::test]
async fn a_rehash_does_not_drop_the_login_that_caused_it() {
    // The password hash feeds the flow's credential epoch. Without a
    // re-stamp the second factor would find the credentials "changed".
    let r = rig(OLD_PARAMETERS, true, KdfExecutor::inline(), policy(5));
    let session = test_session();
    let first = r
        .svc
        .login_with_password("alice", "default", "Gnomes2+", &session)
        .await
        .unwrap();
    assert!(
        matches!(first, FactorOutcome::FactorRequired(_)),
        "{first:?}"
    );
    assert_ne!(stored_hash(&r).await, OLD_PARAMETERS);

    let code = generate_totp_code(SECRET, r.clock.now().into());
    let second = r
        .svc
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
        .unwrap();
    assert!(matches!(second, FactorOutcome::Authenticated), "{second:?}");
}

#[tokio::test]
async fn a_wrong_password_leaves_an_old_hash_alone() {
    let r = rig(OLD_PARAMETERS, false, KdfExecutor::inline(), policy(5));
    let session = test_session();
    let outcome = r
        .svc
        .login_with_password("alice", "default", "not the password", &session)
        .await
        .unwrap();
    assert!(matches!(outcome, FactorOutcome::InvalidCredential));
    assert_eq!(stored_hash(&r).await, OLD_PARAMETERS);
}

#[tokio::test]
async fn a_current_hash_is_not_rewritten() {
    let current = axess_factors::generate_password_hash("Gnomes2+");
    let r = rig(&current, false, KdfExecutor::inline(), policy(5));
    let session = test_session();
    r.svc
        .login_with_password("alice", "default", "Gnomes2+", &session)
        .await
        .unwrap();
    assert_eq!(stored_hash(&r).await, current);
}

// ── Atomic attempt reservation ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_guesses_cannot_pass_the_attempt_limit() {
    let r = rig(
        &axess_factors::generate_password_hash("Gnomes2+"),
        false,
        KdfExecutor::pool(),
        policy(3),
    );
    // Twenty flows, each begun and so past every lockout read, then all
    // guessing at once. A check-then-act lockout lets all twenty run their
    // verifier; a reservation lets the first three.
    let mut sessions = Vec::new();
    for _ in 0..20 {
        let session = test_session();
        r.svc
            .begin_login("alice", "default", &session)
            .await
            .unwrap();
        sessions.push(session);
    }
    let jobs_before = r.kdf.jobs_started();
    let mut set = tokio::task::JoinSet::new();
    for (i, session) in sessions.into_iter().enumerate() {
        let svc = r.svc.clone();
        set.spawn(async move {
            svc.verify_factor(&pw(&format!("wrong guess {i}")), &session)
                .await
        });
    }
    let mut locked = 0;
    while let Some(done) = set.join_next().await {
        if matches!(done.unwrap().unwrap(), FactorOutcome::Locked { .. }) {
            locked += 1;
        }
    }
    assert_eq!(
        r.kdf.jobs_started() - jobs_before,
        3,
        "only the reserved guesses reached the verifier"
    );
    assert_eq!(r.identity.failed_attempts_for("u1"), 3);
    assert!(locked >= 17, "the rest were refused as locked: {locked}");
}

#[tokio::test]
async fn a_verified_guess_gives_its_reservation_back() {
    let r = rig(
        &axess_factors::generate_password_hash("Gnomes2+"),
        true,
        KdfExecutor::inline(),
        policy(3),
    );
    let session = test_session();
    r.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    // One earlier wrong guess stays counted; the right password's own
    // reservation is released, and the login is not complete yet.
    let wrong = test_session();
    r.svc.begin_login("alice", "default", &wrong).await.unwrap();
    r.svc.verify_factor(&pw("nope"), &wrong).await.unwrap();
    assert_eq!(r.identity.failed_attempts_for("u1"), 1);

    let outcome = r
        .svc
        .verify_factor(&pw("Gnomes2+"), &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::FactorRequired(_)),
        "{outcome:?}"
    );
    assert_eq!(
        r.identity.failed_attempts_for("u1"),
        1,
        "the verified guess was released, the earlier failure kept"
    );
}

#[tokio::test]
async fn a_counter_outage_refuses_a_guess_when_the_policy_fails_closed() {
    let r = rig(
        &axess_factors::generate_password_hash("Gnomes2+"),
        false,
        KdfExecutor::inline(),
        policy(3),
    );
    let session = test_session();
    r.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    r.identity.arm_record_failed_attempt_failure();
    let jobs = r.kdf.jobs_started();
    let outcome = r
        .svc
        .verify_factor(&pw("Gnomes2+"), &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Locked { .. }),
        "{outcome:?}"
    );
    assert_eq!(r.kdf.jobs_started(), jobs, "the verifier did not run");
}

#[tokio::test]
async fn a_counter_outage_lets_a_guess_through_when_the_policy_allows() {
    let allow = LockoutPolicy {
        on_counter_unavailable: CounterUnavailable::Allow,
        ..policy(3)
    };
    let r = rig(
        &axess_factors::generate_password_hash("Gnomes2+"),
        false,
        KdfExecutor::inline(),
        allow,
    );
    let session = test_session();
    r.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    r.identity.arm_record_failed_attempt_failure();
    let outcome = r
        .svc
        .verify_factor(&pw("Gnomes2+"), &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
}

// ── Hidden signup conflicts ──────────────────────────────────────────────────

fn signup_service(
    hide: bool,
) -> (
    RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockIdentityStore,
) {
    let mut existing = test_user("u1", "alice@example.com");
    existing.status = EntityState::Active;
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(existing);
    let mut builder = AuthnService::builder(identity.clone(), MockFactorStore::new());
    if hide {
        builder = builder.with_hidden_signup_conflicts();
    }
    let svc = builder.build().with_audit_context(AuditContext::default());
    (svc, identity)
}

fn newcomer() -> axess_core::authn::types::User {
    let mut user = test_user("u2", "alice@example.com");
    user.status = EntityState::Candidate;
    user
}

#[tokio::test]
async fn a_taken_identifier_answers_as_a_free_one_when_conflicts_are_hidden() {
    let (svc, identity) = signup_service(true);
    let taken = test_session();
    let outcome = svc
        .begin_signup(newcomer(), "default", &taken)
        .await
        .unwrap();
    assert!(matches!(outcome, SignupOutcome::Started), "{outcome:?}");
    // The caller sees `Started`; the application sees an anonymous session.
    assert!(taken.auth_state().await.is_guest());
    assert!(taken.user_id().await.is_none());
    // Nothing was created.
    assert!(identity.get_user(&uid("u2")).await.unwrap().is_none());
    assert!(
        identity
            .events()
            .iter()
            .any(|e| e.event_type == AuthEventType::SignupStarted
                && e.event_status == AuthEventStatus::Failure),
        "the refusal is audited"
    );

    let mut free = newcomer();
    free.identifier = "bob@example.com".into();
    let fresh = test_session();
    let outcome = svc.begin_signup(free, "default", &fresh).await.unwrap();
    assert!(matches!(outcome, SignupOutcome::Started), "{outcome:?}");
    assert!(
        fresh.pending_user_id().await.is_some(),
        "a free identifier is created and the signup is pending for it"
    );
}

#[tokio::test]
async fn a_taken_identifier_is_reported_by_default() {
    let (svc, _) = signup_service(false);
    let outcome = svc
        .begin_signup(newcomer(), "default", &test_session())
        .await
        .unwrap();
    assert!(
        matches!(outcome, SignupOutcome::AlreadyExists),
        "{outcome:?}"
    );
}

// ── Password reset cooldown ──────────────────────────────────────────────────

fn reset_service(
    cooldown: Option<Duration>,
) -> (
    RequestAuthnService<MockIdentityStore, MockFactorStore>,
    MockClock,
) {
    let clock = MockClock::now();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let mut builder =
        AuthnService::builder(identity, MockFactorStore::new()).with_clock(clock.clone());
    if let Some(cooldown) = cooldown {
        builder = builder.with_password_reset_cooldown(cooldown);
    }
    (
        builder.build().with_audit_context(AuditContext::default()),
        clock,
    )
}

const TTL: Duration = Duration::from_secs(300);

#[tokio::test]
async fn a_second_reset_request_inside_the_cooldown_is_refused() {
    let (svc, clock) = reset_service(Some(Duration::from_secs(60)));
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_none(),
        "inside the cooldown"
    );
    clock.advance(chrono::Duration::seconds(61));
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some(),
        "after the cooldown"
    );
}

#[tokio::test]
async fn the_cooldown_treats_an_unknown_identifier_like_a_known_one() {
    let (svc, clock) = reset_service(Some(Duration::from_secs(60)));
    // An unknown identifier answers None before and during the cooldown, so
    // the cooldown tells a caller nothing about which identifiers exist.
    for _ in 0..2 {
        assert!(
            svc.begin_password_reset("nobody", "default", TTL)
                .await
                .unwrap()
                .is_none()
        );
    }
    clock.advance(chrono::Duration::seconds(61));
    assert!(
        svc.begin_password_reset("nobody", "default", TTL)
            .await
            .unwrap()
            .is_none()
    );
    // Another identifier is not held up by the first one's cooldown.
    assert!(
        svc.begin_password_reset("alice", "default", TTL)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn without_a_cooldown_repeated_requests_each_get_a_token() {
    let (svc, _) = reset_service(None);
    for _ in 0..3 {
        assert!(
            svc.begin_password_reset("alice", "default", TTL)
                .await
                .unwrap()
                .is_some()
        );
    }
}
