#![cfg(feature = "testing")]
//! Every refusal on the password form spends the same Argon2 work, counted
//! run by run with the parameters each ran at, never by the wall clock: an
//! unknown identifier, a wrong password against a current hash, a wrong
//! password against a hash under the previous cost, a throttled guess and a
//! locked account each spend one run at the current cost and one at the
//! previous cost, in two executor jobs, and so does an account closed
//! between the lookup and the password. A right password against a previous
//! hash spends the same, its check and its rehash at the current cost. A
//! hash under a third cost spends its own check on top, and says so once.

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventType, AuthFailureReason};
use axess_core::authn::factor::{
    FactorConfig, FactorKind, PasswordConfig, PasswordRules, ZeroizedString,
};
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService};
use axess_core::authn::store::FactorStore as _;
use axess_core::authn::types::{EntityState, StatusDetail};
use axess_core::authn::types::{LockoutPolicy, Throttle};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::{
    mock_authn::{CallLog, MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::Argon2Cost;
use axess_factors::password::recording::{Parameters, take_runs};
use common::{password_method, start, test_tenant, test_user, uid, user_scope};
use std::sync::Arc;
use std::time::Duration;

const PASSWORD: &str = "Sample2+";

/// A cost above the library's, as a deployment that raised it holds.
fn raised() -> Argon2Cost {
    Argon2Cost::new(20 * 1024, 2, 1).expect("a cost above the floor")
}

fn params(cost: Argon2Cost) -> Parameters {
    (cost.m_cost_kib(), cost.t_cost(), cost.p_cost())
}

fn hash_at(cost: Argon2Cost) -> String {
    axess_factors::hash_password_with_salt_and_cost(PASSWORD, &[7u8; 16], cost)
}

struct Rig {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    identity: MockIdentityStore,
    factors: MockFactorStore,
    kdf: Arc<KdfExecutor>,
    clock: MockClock,
}

/// A service at the raised cost with the library default as the previous
/// one (its own default), holding `alice` with a hash made at `stored`.
fn rig(clock: &MockClock, stored: Argon2Cost, policy: LockoutPolicy) -> Rig {
    rig_with_hash(clock, &hash_at(stored), policy, None)
}

/// [`rig`] with the stored hash given as text and the stores' calls written
/// to `log` when one is given.
fn rig_with_hash(
    clock: &MockClock,
    stored: &str,
    policy: LockoutPolicy,
    log: Option<&CallLog>,
) -> Rig {
    let mut identity = MockIdentityStore::new().with_clock(clock.clone());
    if let Some(log) = log {
        identity = identity.with_call_log(log);
    }
    let identity = identity
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(policy);
    let mut factors = MockFactorStore::new();
    if let Some(log) = log {
        factors = factors.with_call_log(log);
    }
    let factors = factors
        .with_factor(
            user_scope(),
            FactorConfig::Password(PasswordConfig {
                hash: ZeroizedString::new(stored),
                rules: PasswordRules::default(),
                password_id: None,
            }),
        )
        .with_method(&uid("u1"), password_method());
    let kdf = Arc::new(KdfExecutor::inline());
    let svc = AuthnService::builder(identity.clone(), factors.clone())
        .with_clock(clock.clone())
        .with_kdf_executor(kdf.clone())
        .with_argon2_cost(raised())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    Rig {
        svc,
        identity,
        factors,
        kdf,
        clock: clock.clone(),
    }
}

fn wide_policy() -> LockoutPolicy {
    LockoutPolicy {
        max_attempts: 100,
        ..LockoutPolicy::default()
    }
    .without_throttle()
}

/// The Argon2 runs and executor jobs of one `login_with_password`, with the
/// answer it gave. The dummy hashes are made before measuring.
async fn measured(
    r: &Rig,
    identifier: &str,
    password: &str,
) -> (FactorOutcome, Vec<Parameters>, u64) {
    r.svc.burn_password_check("warm").await.unwrap();
    take_runs();
    let jobs = r.kdf.jobs_started();
    let outcome = r
        .svc
        .login_with_password(identifier, "default", password, &test_session())
        .await
        .unwrap();
    let mut runs = take_runs();
    runs.sort_unstable();
    (outcome, runs, r.kdf.jobs_started() - jobs)
}

/// The work every refusal spends: one run at each cost, two jobs.
fn refusal_work() -> (Vec<Parameters>, u64) {
    let mut runs = vec![params(raised()), params(Argon2Cost::default())];
    runs.sort_unstable();
    (runs, 2)
}

#[tokio::test]
async fn every_refusal_on_the_password_form_spends_the_same_argon2_work() {
    let clock = common::test_clock();
    let want = refusal_work();

    let r = rig(&clock, raised(), wide_policy());
    let (outcome, runs, jobs) = measured(&r, "nobody", "wrong").await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "{outcome:?}"
    );
    assert_eq!((runs, jobs), want, "an unknown identifier");

    let (outcome, runs, jobs) = measured(&r, "alice", "wrong").await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "{outcome:?}"
    );
    assert_eq!(
        (runs, jobs),
        want,
        "a wrong password against a current hash"
    );

    let r = rig(&clock, Argon2Cost::default(), wide_policy());
    let (outcome, runs, jobs) = measured(&r, "alice", "wrong").await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "{outcome:?}"
    );
    assert_eq!(
        (runs, jobs),
        want,
        "a wrong password against a hash under the previous cost"
    );
}

#[tokio::test]
async fn a_throttled_guess_spends_the_same_argon2_work() {
    let clock = common::test_clock();
    let policy = LockoutPolicy {
        max_attempts: 100,
        throttle: Some(Throttle {
            first_delay: Duration::from_secs(60),
            ..Throttle::default()
        }),
        ..LockoutPolicy::default()
    };
    let r = rig(&clock, raised(), policy);
    // One wrong guess earns a delay; the next, at the same instant, is
    // throttled before any hash of its own runs.
    let _ = measured(&r, "alice", "wrong").await;
    let (outcome, runs, jobs) = measured(&r, "alice", "wrong").await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "{outcome:?}"
    );
    assert_eq!((runs, jobs), refusal_work(), "a throttled guess");
}

#[tokio::test]
async fn a_locked_account_spends_the_same_argon2_work() {
    let clock = common::test_clock();
    let policy = LockoutPolicy {
        max_attempts: 2,
        duration: Some(Duration::from_secs(900)),
        ..LockoutPolicy::default()
    }
    .without_throttle();
    let r = rig(&clock, raised(), policy);
    for _ in 0..2 {
        let _ = measured(&r, "alice", "wrong").await;
    }
    let (outcome, runs, jobs) = measured(&r, "alice", PASSWORD).await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "a locked account answers as a wrong password: {outcome:?}"
    );
    assert_eq!((runs, jobs), refusal_work(), "a locked account");
    let _ = &r.clock;
}

#[tokio::test]
async fn a_right_password_against_a_previous_hash_spends_its_check_and_its_rehash() {
    let clock = common::test_clock();
    let r = rig(&clock, Argon2Cost::default(), wide_policy());
    let (outcome, runs, jobs) = measured(&r, "alice", PASSWORD).await;
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    assert_eq!((runs, jobs), refusal_work(), "the check and the rehash");
    let stored = match r
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
    };
    assert!(
        !axess_factors::password_needs_rehash_for(&stored, raised()),
        "the hash is at the current cost after the login"
    );
}

/// Without a previous cost a refusal spends one run at the current cost;
/// the opt-out is for a deployment whose hashes are all current.
#[tokio::test]
async fn without_a_previous_cost_a_refusal_spends_one_run() {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let kdf = Arc::new(KdfExecutor::inline());
    let svc = AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_kdf_executor(kdf.clone())
        .with_argon2_cost(raised())
        .without_previous_argon2_cost()
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    svc.burn_password_check("warm").await.unwrap();
    take_runs();
    let jobs = kdf.jobs_started();
    let _ = svc
        .login_with_password("nobody", "default", "wrong", &test_session())
        .await
        .unwrap();
    assert_eq!(take_runs(), vec![params(raised())]);
    assert_eq!(kdf.jobs_started() - jobs, 1);
}

/// A hash under a cost that is neither the current nor the previous one, as
/// a deployment that changed its cost twice holds.
const THIRD_COST_HASH: &str =
    "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$oybFowQtTE9kuoK7zFTnTK3zH1OGJ92nz/nj6AoKJj8";

/// A wrong password against a hash under a third cost spends its own check
/// and a run at each of the current and the previous cost, in three jobs:
/// more than every other refusal, which is why the service says so, once,
/// naming the builder call that brings the cost back to the shared work.
#[tokio::test]
async fn a_hash_under_a_third_cost_spends_its_check_and_both_runs_and_is_reported_once() {
    use axess_testing::mock_tracing::TracingCapture;
    let clock = common::test_clock();
    let capture = TracingCapture::install();
    let r = rig_with_hash(&clock, THIRD_COST_HASH, wide_policy(), None);
    let mut want = vec![(8, 1, 1), params(raised()), params(Argon2Cost::default())];
    want.sort_unstable();
    let reported = || {
        capture
            .events()
            .iter()
            .filter(|e| {
                e.level == tracing::Level::WARN && e.message.contains("with_previous_argon2_cost")
            })
            .count()
    };
    for _ in 0..2 {
        let (outcome, runs, jobs) = measured(&r, "alice", "wrong").await;
        assert!(
            matches!(outcome, FactorOutcome::InvalidCredential),
            "{outcome:?}"
        );
        assert_eq!(
            (runs, jobs),
            (want.clone(), 3),
            "the own check, the current cost and the previous cost"
        );
        assert_eq!(
            reported(),
            1,
            "reported at the first such refusal and not again: {:?}",
            capture.events()
        );
    }
}

/// A wrong password against a hash under the current cost, or under the
/// previous one, is the shared work and nothing to report: the line names
/// only a hash under a cost the service was not told about.
#[tokio::test]
async fn a_hash_under_the_current_or_the_previous_cost_is_not_reported() {
    use axess_testing::mock_tracing::TracingCapture;
    let clock = common::test_clock();
    let capture = TracingCapture::install();
    for stored in [raised(), Argon2Cost::default()] {
        let r = rig(&clock, stored, wide_policy());
        for _ in 0..2 {
            let (outcome, runs, jobs) = measured(&r, "alice", "wrong").await;
            assert!(
                !matches!(outcome, FactorOutcome::Authenticated),
                "{outcome:?}"
            );
            assert_eq!((runs, jobs), refusal_work(), "a wrong password");
        }
    }
    let reported: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| {
            e.level == tracing::Level::WARN && e.message.contains("with_previous_argon2_cost")
        })
        .collect();
    assert!(reported.is_empty(), "nothing to report: {reported:?}");
}

/// The account is closed after the lookup and before the password is
/// checked: the check before the step refuses it with no hash of its own,
/// and the refusal spends the work every other refusal spends.
#[tokio::test]
async fn an_account_closed_before_the_password_spends_the_same_argon2_work() {
    let clock = common::test_clock();
    let log = CallLog::new();
    let r = rig_with_hash(&clock, &hash_at(raised()), wide_policy(), Some(&log));
    let identity = r.identity.clone();
    // The lookup in `begin_login` reads the status and then the methods; the
    // account is closed at that read, after the status said `Active`.
    log.on("available_methods", move || {
        let mut closed = test_user("u1", "alice");
        closed.status = EntityState::Terminated(StatusDetail::closure("closed", start()));
        let _ = identity.clone().with_user(closed);
    });
    let (outcome, runs, jobs) = measured(&r, "alice", PASSWORD).await;
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "a closed account answers as a wrong password: {outcome:?}"
    );
    assert_eq!(
        (runs, jobs),
        refusal_work(),
        "an account closed before the password"
    );
    let refused_at_the_step = r.identity.events().iter().any(|e| {
        e.event_type == AuthEventType::FactorVerified
            && e.error == Some(AuthFailureReason::NotActive)
    });
    assert!(
        refused_at_the_step,
        "the check before the step refused it, not the lookup: {:?}",
        r.identity.events()
    );
}

/// A password over `MAX_PASSWORD_BYTES` is refused by the stored-hash path
/// before Argon2 runs, and the paths without a stored hash refuse it the
/// same way: an unknown identifier and a known user, under a current or a
/// previous hash, get the same answer, the same executor jobs and no
/// Argon2 run, so the length check cannot tell them apart.
#[tokio::test]
async fn an_over_length_password_costs_a_known_and_an_unknown_user_alike() {
    let clock = common::test_clock();
    let long = "a".repeat(axess_core::validation::MAX_PASSWORD_BYTES + 1);

    let r = rig(&clock, raised(), wide_policy());
    let unknown = measured(&r, "nobody", &long).await;
    let known = measured(&r, "alice", &long).await;
    let r = rig(&clock, Argon2Cost::default(), wide_policy());
    let known_previous = measured(&r, "alice", &long).await;

    for (what, (outcome, runs, jobs)) in [
        ("an unknown identifier", unknown),
        ("a known user under the current cost", known),
        ("a known user under the previous cost", known_previous),
    ] {
        assert!(
            matches!(outcome, FactorOutcome::InvalidCredential),
            "{what}: {outcome:?}"
        );
        assert_eq!((runs, jobs), (Vec::new(), 2), "{what}");
    }

    // At the cap the password is checked as any other: the refusal's work.
    let at_cap = "a".repeat(axess_core::validation::MAX_PASSWORD_BYTES);
    let r = rig(&clock, raised(), wide_policy());
    let (_, runs, jobs) = measured(&r, "nobody", &at_cap).await;
    assert_eq!(
        (runs, jobs),
        refusal_work(),
        "an unknown identifier at the cap"
    );
}
