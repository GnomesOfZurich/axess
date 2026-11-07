#![cfg(feature = "testing")]
//! The delay earned by wrong guesses at a later factor is not cleared by the
//! earlier factor passing: it is cleared when the whole login completes.

mod common;

use axess_clock::{Clock, testing::MockClock};
use axess_core::authn::AuditContext;
use axess_core::authn::{
    factor::{FactorCredential, ZeroizedString},
    service::{AuthnService, FactorOutcome, RequestAuthnService},
    types::LockoutPolicy,
};
use axess_core::blocking::KdfExecutor;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_core::testing::test_session;
use common::{
    generate_totp_code, password_config, password_totp_method, test_tenant, test_user, totp_config,
    uid, user_scope,
};
use std::sync::Arc;
use std::time::SystemTime;

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

struct World {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    clock: MockClock,
}

fn world() -> World {
    let clock = MockClock::now();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"))
        .with_lockout_policy(LockoutPolicy {
            max_attempts: 100,
            ..LockoutPolicy::default()
        });
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Gnomes2+"))
        .with_factor(user_scope(), totp_config(SECRET))
        .with_method(&uid("u1"), password_totp_method());
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_kdf_executor(Arc::new(KdfExecutor::inline()))
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    World { svc, clock }
}

fn password(p: &str) -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(p))
}

/// A fresh login that passes the password and then submits `code`; `None`
/// when the password step itself was refused as throttled.
async fn password_then(w: &World, code: &str) -> Option<FactorOutcome> {
    let session = test_session();
    w.svc
        .begin_login("alice", "default", &session)
        .await
        .unwrap();
    let first = w
        .svc
        .verify_factor(&password("Gnomes2+"), &session)
        .await
        .unwrap();
    if matches!(first, FactorOutcome::Throttled { .. }) {
        return None;
    }
    Some(
        w.svc
            .verify_factor(&FactorCredential::OtpCode(code.into()), &session)
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn a_password_that_passes_does_not_clear_the_delay_earned_at_the_second_factor() {
    let w = world();
    let step = chrono::Duration::seconds(1);

    let first = password_then(&w, "000000").await;
    assert!(
        matches!(first, Some(FactorOutcome::InvalidCredential)),
        "{first:?}"
    );
    w.clock.advance(step);
    let second = password_then(&w, "000000").await;
    assert!(
        matches!(second, Some(FactorOutcome::InvalidCredential)),
        "{second:?}"
    );

    // Two wrong codes in a row have earned two seconds; one has passed.
    w.clock.advance(step);
    let third = password_then(&w, "000000").await;
    assert!(
        third.is_none(),
        "the password cleared the delay the wrong codes had earned: {third:?}"
    );
}

#[tokio::test]
async fn completing_the_login_clears_the_delay() {
    let w = world();
    let wrong = password_then(&w, "000000").await;
    assert!(
        matches!(wrong, Some(FactorOutcome::InvalidCredential)),
        "{wrong:?}"
    );
    w.clock.advance(chrono::Duration::seconds(2));
    let code = generate_totp_code(SECRET, SystemTime::from(w.clock.now()));
    let done = password_then(&w, &code).await;
    assert!(
        matches!(done, Some(FactorOutcome::Authenticated)),
        "{done:?}"
    );

    // The count started over: the next wrong code is not delayed.
    let again = password_then(&w, "000000").await;
    assert!(
        matches!(again, Some(FactorOutcome::InvalidCredential)),
        "{again:?}"
    );
}
