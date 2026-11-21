#![cfg(feature = "testing")]
//! The bounds the security profile and the OTP factors hold, driven through
//! the login pipeline rather than read off a constant: an OTP factor
//! configured with 255 attempts locks after the tenth wrong code, an HOTP
//! look-ahead past its bound verifies nothing, and the strict profile's
//! Argon2 cost is the cost the service hashes a password under.

mod hotp_code;
use axess_core::testing::fixtures as common;
use hotp_code::generate_hotp_code;

use axess_core::Clock as _;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::{
    FactorConfig, FactorCredential, FactorKind, HotpConfig, ZeroizedString,
};
use axess_core::authn::service::{AuthnService, FactorOutcome, RequestAuthnService};
use axess_core::authn::store::{AuthMethod, FactorStore as _};
use axess_core::authn::types::LockoutPolicy;
use axess_core::testing::{
    MockClock,
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use common::{password_config, password_method, test_tenant, test_user, uid, user_scope};

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

struct Rig {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    factors: MockFactorStore,
    clock: MockClock,
}

/// A password then HOTP login for `carol`, under an account policy wide
/// enough that only the factor's own limit can lock.
fn hotp_rig(hotp: HotpConfig) -> Rig {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "carol"))
        .with_clock(clock.clone())
        .with_lockout_policy(
            LockoutPolicy {
                max_attempts: 100,
                ..LockoutPolicy::default()
            }
            .without_throttle(),
        );
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_factor(user_scope(), FactorConfig::Hotp(hotp))
        .with_method(
            &uid("u1"),
            AuthMethod::sequential(
                "password+hotp",
                vec![FactorKind::Password, FactorKind::Hotp],
                user_scope(),
            ),
        );
    let svc = AuthnService::builder(identity, factors.clone())
        .with_clock(clock.clone())
        .allow_plaintext_factor_secrets()
        .build()
        .with_audit_context(AuditContext::default());
    Rig {
        svc,
        factors,
        clock,
    }
}

/// Begin, the password, then `code` at the HOTP step.
async fn try_code(r: &Rig, code: &str) -> FactorOutcome {
    let session = test_session();
    r.svc
        .begin_login("carol", "default", &session)
        .await
        .unwrap();
    let step = r
        .svc
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("Sample2+")),
            &session,
        )
        .await
        .unwrap();
    assert!(
        matches!(step, FactorOutcome::FactorRequired(FactorKind::Hotp)),
        "{step:?}"
    );
    r.svc
        .verify_factor(
            &FactorCredential::OtpCode(code.to_string().into()),
            &session,
        )
        .await
        .unwrap()
}

async fn stored_hotp(r: &Rig) -> HotpConfig {
    match r
        .factors
        .load_factor(&user_scope(), FactorKind::Hotp)
        .await
        .unwrap()
    {
        Some(FactorConfig::Hotp(hotp)) => hotp,
        other => panic!("no HOTP row: {other:?}"),
    }
}

#[tokio::test]
async fn an_otp_factor_configured_with_255_attempts_locks_after_the_tenth_wrong_code() {
    let r = hotp_rig(HotpConfig {
        secret: ZeroizedString::new(SECRET).into(),
        counter: 0,
        lookahead_window: 10,
        max_attempts: 255,
        ..HotpConfig::default()
    });
    for n in 1..=9 {
        assert!(matches!(
            try_code(&r, "000000").await,
            FactorOutcome::InvalidCredential
        ));
        assert!(
            !stored_hotp(&r).await.is_locked_at(r.clock.now()),
            "locked after {n} wrong codes"
        );
    }
    assert!(matches!(
        try_code(&r, "000000").await,
        FactorOutcome::InvalidCredential
    ));
    assert!(
        stored_hotp(&r).await.is_locked_at(r.clock.now()),
        "the tenth wrong code locks the factor whatever its config says"
    );
    assert!(
        matches!(
            try_code(&r, &generate_hotp_code(SECRET, 0)).await,
            FactorOutcome::InvalidCredential
        ),
        "the genuine code is refused while the lock holds"
    );
}

#[tokio::test]
async fn an_hotp_look_ahead_past_its_bound_verifies_nothing() {
    let r = hotp_rig(HotpConfig {
        secret: ZeroizedString::new(SECRET).into(),
        counter: 0,
        lookahead_window: axess_factors::MAX_HOTP_LOOKAHEAD + 1,
        max_attempts: 5,
        ..HotpConfig::default()
    });
    assert!(
        matches!(
            try_code(&r, &generate_hotp_code(SECRET, 0)).await,
            FactorOutcome::InvalidCredential
        ),
        "a factor stored past the bound accepted a code"
    );
}

/// The strict profile applied to a builder is the cost the service hashes
/// under: a login whose stored hash was made under the default cost is
/// rehashed at the strict one, read off the hashes the service runs.
#[tokio::test]
async fn the_strict_profiles_argon2_cost_is_the_cost_the_service_hashes_under() {
    let clock = common::test_clock();
    use axess_core::profile::SecurityProfile;
    use axess_factors::password::recording::take_runs;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), password_config("Sample2+"))
        .with_method(&uid("u1"), password_method());
    let builder = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_kdf_executor(std::sync::Arc::new(
            axess_core::blocking::KdfExecutor::inline(),
        ))
        .allow_plaintext_factor_secrets();
    let svc = SecurityProfile::Strict
        .values()
        .authn_service_builder(builder)
        .build()
        .with_audit_context(AuditContext::default());
    take_runs();
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let outcome = svc
        .verify_factor(
            &FactorCredential::Password(ZeroizedString::new("Sample2+")),
            &session,
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    let strict = SecurityProfile::Strict.values().argon2_cost;
    let strict = (strict.m_cost_kib(), strict.t_cost(), strict.p_cost());
    assert!(
        take_runs().contains(&strict),
        "no hash ran at the strict cost {strict:?}"
    );
}
