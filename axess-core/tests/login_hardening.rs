#![cfg(feature = "testing")]
//! Login hardening: a password hash made under old Argon2 parameters is
//! replaced on a successful login, parallel guesses cannot pass the attempt
//! limit, and a wrong password costs the same Argon2 work on every path. The
//! signup and password reset hardening is in `signup_reset_hardening.rs`.

mod hotp_code;
mod totp_code;
use axess_core::testing::fixtures as common;
use totp_code::generate_totp_code;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, PasswordConfig, PasswordRules, ZeroizedString,
};
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService};
use axess_core::authn::store::FactorStore;
use axess_core::authn::types::{CounterUnavailable, LockoutPolicy};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{
    password_method, password_totp_method, start, test_tenant, test_user, totp_config, uid,
    user_scope,
};
use std::sync::Arc;
use std::time::Duration;

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// `Sample2+` under Argon2id version 19 with m=8, t=1, p=1: weaker than the
/// pinned parameters, so a login with it is the moment to rehash.
const OLD_PARAMETERS: &str =
    "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$oybFowQtTE9kuoK7zFTnTK3zH1OGJ92nz/nj6AoKJj8";

fn config_with(hash: &str) -> FactorConfig {
    FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(hash),
        rules: PasswordRules::default(),
        password_id: None,
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
    let clock = common::test_clock();
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
        .allow_plaintext_factor_secrets()
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
        .login_with_password("alice", "default", "Sample2+", &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );

    let now = stored_hash(&r).await;
    assert_ne!(now, OLD_PARAMETERS, "the hash was replaced");
    assert!(!axess_factors::password_needs_rehash(&now));
    assert!(axess_factors::verify_password("Sample2+", &now).is_ok());
}

#[tokio::test]
async fn a_rehash_does_not_drop_the_login_that_caused_it() {
    // The password hash feeds the flow's credential epoch. Without a
    // re-stamp the second factor would find the credentials "changed".
    let r = rig(OLD_PARAMETERS, true, KdfExecutor::inline(), policy(5));
    let session = test_session();
    let first = r
        .svc
        .login_with_password("alice", "default", "Sample2+", &session)
        .await
        .unwrap();
    assert!(
        matches!(first, FactorOutcome::FactorRequired(_)),
        "{first:?}"
    );
    assert_ne!(stored_hash(&r).await, OLD_PARAMETERS);

    let code = generate_totp_code(SECRET, r.clock.now().try_into().unwrap());
    let second = r
        .svc
        .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
        .unwrap();
    assert!(matches!(second, FactorOutcome::Authenticated), "{second:?}");
}

/// Two logins of the same user are in flight; the first to verify the
/// password rehashes it. The second, stamped against the old hash, is not
/// dropped at its next step as if the password had been changed.
#[tokio::test]
async fn a_rehash_does_not_drop_another_login_of_the_same_user() {
    let r = rig(OLD_PARAMETERS, true, KdfExecutor::inline(), policy(5));
    let first = test_session();
    let second = test_session();
    r.svc.begin_login("alice", "default", &first).await.unwrap();
    r.svc
        .begin_login("alice", "default", &second)
        .await
        .unwrap();

    let outcome = r.svc.verify_factor(&pw("Sample2+"), &first).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::FactorRequired(FactorKind::Totp)),
        "{outcome:?}"
    );
    assert_ne!(
        stored_hash(&r).await,
        OLD_PARAMETERS,
        "the first login rehashed"
    );

    let outcome = r.svc.verify_factor(&pw("Sample2+"), &second).await;
    assert!(
        matches!(outcome, Ok(FactorOutcome::FactorRequired(FactorKind::Totp))),
        "the second login goes on under the rehashed password: {outcome:?}"
    );
    let code = generate_totp_code(SECRET, r.clock.now().try_into().unwrap());
    let done = r
        .svc
        .verify_factor(&FactorCredential::OtpCode(code.into()), &second)
        .await
        .unwrap();
    assert!(matches!(done, FactorOutcome::Authenticated), "{done:?}");
}

/// The same, with the two logins on two instances of the service over the
/// same stores: a rehash is no change of credential whichever instance
/// carries the other login on.
#[tokio::test]
async fn a_rehash_does_not_drop_a_login_on_another_instance() {
    let r = rig(OLD_PARAMETERS, true, KdfExecutor::inline(), policy(5));
    let other = AuthnService::builder(r.identity.clone(), r.factors.clone())
        .with_clock(r.clock.clone())
        .with_kdf_executor(r.kdf.clone())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    let first = test_session();
    let second = test_session();
    r.svc.begin_login("alice", "default", &first).await.unwrap();
    other
        .begin_login("alice", "default", &second)
        .await
        .unwrap();
    r.svc.verify_factor(&pw("Sample2+"), &first).await.unwrap();
    assert_ne!(
        stored_hash(&r).await,
        OLD_PARAMETERS,
        "the first login rehashed"
    );

    let outcome = other.verify_factor(&pw("Sample2+"), &second).await;
    assert!(
        matches!(outcome, Ok(FactorOutcome::FactorRequired(FactorKind::Totp))),
        "the login on the other instance goes on: {outcome:?}"
    );
}

/// The tolerance is for a rehash only: a flow begun before the password
/// was replaced is still dropped.
#[tokio::test]
async fn a_replaced_password_still_drops_a_flow_begun_before_it() {
    let r = rig(OLD_PARAMETERS, true, KdfExecutor::inline(), policy(5));
    let first = test_session();
    let second = test_session();
    r.svc.begin_login("alice", "default", &first).await.unwrap();
    r.svc
        .begin_login("alice", "default", &second)
        .await
        .unwrap();
    r.svc.verify_factor(&pw("Sample2+"), &first).await.unwrap();
    let rehashed = stored_hash(&r).await;
    assert_ne!(rehashed, OLD_PARAMETERS);

    // A password change by any other path: a fresh hash of another password.
    r.factors
        .save_factor(
            &user_scope(),
            config_with(&axess_factors::generate_password_hash("Other-password-9")),
        )
        .await
        .unwrap();
    let outcome = r.svc.verify_factor(&pw("Other-password-9"), &second).await;
    assert!(
        matches!(outcome, Err(AuthnError::NoFlow)),
        "a flow begun before a password change is dropped: {outcome:?}"
    );
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
    let current = axess_factors::generate_password_hash("Sample2+");
    let r = rig(&current, false, KdfExecutor::inline(), policy(5));
    let session = test_session();
    r.svc
        .login_with_password("alice", "default", "Sample2+", &session)
        .await
        .unwrap();
    assert_eq!(stored_hash(&r).await, current);
}

// ── Atomic attempt reservation ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_guesses_cannot_pass_the_attempt_limit() {
    let r = rig(
        &axess_factors::generate_password_hash("Sample2+"),
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
        &axess_factors::generate_password_hash("Sample2+"),
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

    // Past the delay the wrong guess earned this address.
    r.clock.advance(axess_clock::SignedDuration::seconds(1));
    let outcome = r
        .svc
        .verify_factor(&pw("Sample2+"), &session)
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
        &axess_factors::generate_password_hash("Sample2+"),
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
        .verify_factor(&pw("Sample2+"), &session)
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
        &axess_factors::generate_password_hash("Sample2+"),
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
        .verify_factor(&pw("Sample2+"), &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
}

/// A wrong password against a hash made under old parameters spends an
/// Argon2 operation at the current parameters, as a wrong password for an
/// unknown identifier and for a current hash do, so a dormant account whose
/// hash predates a cost change is not cheaper to probe than any other
/// answer. The old verification itself still runs: it is the only way to
/// know the password was wrong.
#[tokio::test]
async fn a_wrong_password_against_an_old_hash_costs_the_current_parameters_too() {
    use axess_factors::password::recording::take_runs;
    let r = rig(
        OLD_PARAMETERS,
        false,
        KdfExecutor::inline(),
        LockoutPolicy::default().without_throttle(),
    );
    let current = axess_factors::Argon2Cost::default();
    let current = (current.m_cost_kib(), current.t_cost(), current.p_cost());
    // The dummy hash is made once per service; make it before measuring.
    r.svc.burn_password_check("warm").await.unwrap();
    take_runs();

    let unknown = r
        .svc
        .login_with_password("nobody", "default", "not the password", &test_session())
        .await
        .unwrap();
    assert!(matches!(unknown, FactorOutcome::InvalidCredential));
    let unknown_runs = take_runs();
    assert_eq!(unknown_runs, vec![current], "an unknown identifier");

    let old = r
        .svc
        .login_with_password("alice", "default", "not the password", &test_session())
        .await
        .unwrap();
    assert!(matches!(old, FactorOutcome::InvalidCredential));
    let old_runs = take_runs();
    assert!(
        old_runs.contains(&(8, 1, 1)),
        "the old hash is verified under its own parameters: {old_runs:?}"
    );
    assert!(
        old_runs.contains(&current),
        "a wrong password against an old hash spends an operation at the current parameters \
         as every other refusal does: {old_runs:?}"
    );
}

/// An account closed between `begin_login` and the password is refused by
/// the check before the step, which runs no hash of its own; the refusal
/// spends the Argon2 work an unknown identifier spends, so the two answers
/// cost the same.
#[tokio::test]
async fn an_account_closed_before_the_password_spends_what_an_unknown_identifier_spends() {
    let clock = common::test_clock();
    use axess_core::authn::types::{EntityState, StatusDetail};
    use axess_core::testing::mock_authn::CallLog;
    use axess_factors::password::recording::take_runs;
    let log = CallLog::new();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_call_log(&log)
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(LockoutPolicy::default().without_throttle());
    let factors = MockFactorStore::new()
        .with_call_log(&log)
        .with_factor(user_scope(), common::password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let kdf = Arc::new(KdfExecutor::inline());
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_clock(clock.clone())
        .with_kdf_executor(kdf.clone())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    svc.burn_password_check("warm").await.unwrap();
    let measure = async |identifier: &str| {
        take_runs();
        let jobs = kdf.jobs_started();
        let outcome = svc
            .login_with_password(identifier, "default", "Sample2+", &test_session())
            .await
            .unwrap();
        let mut runs = take_runs();
        runs.sort_unstable();
        (outcome, runs, kdf.jobs_started() - jobs)
    };
    let (_, unknown_runs, unknown_jobs) = measure("nobody").await;

    // `begin_login` reads the status and then the methods; the account is
    // closed at that read, after the status said `Active`.
    let closing = identity.clone();
    log.on("available_methods", move || {
        let mut closed = test_user("u1", "alice");
        closed.status = EntityState::Terminated(StatusDetail::closure("closed", start()));
        let _ = closing.clone().with_user(closed);
    });
    let (outcome, runs, jobs) = measure("alice").await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "a closed account answers as a wrong password: {outcome:?}"
    );
    assert!(
        !unknown_runs.is_empty(),
        "an unknown identifier spends work"
    );
    assert_eq!(
        (runs, jobs),
        (unknown_runs, unknown_jobs),
        "an account closed before the password"
    );
}
