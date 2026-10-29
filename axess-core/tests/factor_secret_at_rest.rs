//! OTP secrets sealed at rest: the service opens a sealed secret to verify a
//! code, keeps it sealed when it writes the row back, and moves a plain secret
//! to the sealed form on the login that verifies it.

#![cfg(feature = "testing")]

mod common;

use axess_clock::Clock;
use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::error::AuthnError;
use axess_core::authn::factor_secret::{FactorSecretBinding, FactorSecretCipher};
use axess_core::{
    authn::{
        factor::{FactorConfig, FactorCredential, FactorKind, HotpConfig},
        service::{AuthnService, FactorOutcome},
        store::{AuthMethod, FactorStore},
        types::AuthnScope,
    },
    session::LegacyBlobs,
    testing::{
        mock_authn::{MockFactorStore, MockIdentityStore},
        test_session,
    },
};
use axess_factors::FactorSecret;
use chrono::{DateTime, Duration, Utc};
use common::{generate_hotp_code, test_tenant, test_user, tid, uid, user_scope};
use std::sync::Arc;

const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const KEY_A: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";
const KEY_B: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

fn hotp(secret: FactorSecret, counter: u64) -> FactorConfig {
    FactorConfig::Hotp(HotpConfig {
        secret,
        counter,
        ..HotpConfig::default()
    })
}

fn hotp_method() -> AuthMethod {
    AuthMethod::sequential("hotp", vec![FactorKind::Hotp], user_scope())
}

fn cipher(key: [u8; 32]) -> FactorSecretCipher {
    FactorSecretCipher::new(key)
}

fn sealed_for(
    cipher: &FactorSecretCipher,
    scope: &AuthnScope,
    counter: u64,
) -> (FactorConfig, String) {
    let config = cipher
        .seal_config(hotp(SECRET.into(), counter), scope)
        .unwrap();
    let key_id = match &config {
        FactorConfig::Hotp(cfg) => match &cfg.secret {
            FactorSecret::Sealed(s) => s.key_id.clone(),
            FactorSecret::Plain(_) => panic!("seal_config left the secret plain"),
        },
        _ => unreachable!(),
    };
    (config, key_id)
}

fn service(
    factors: MockFactorStore,
    cipher: Option<FactorSecretCipher>,
) -> axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore> {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let mut builder = AuthnService::builder(identity, factors);
    if let Some(cipher) = cipher {
        builder = builder.with_factor_secret_cipher(Arc::new(cipher));
    }
    builder.build().with_audit_context(AuditContext::default())
}

async fn login(
    svc: &axess_core::authn::service::RequestAuthnService<MockIdentityStore, MockFactorStore>,
    counter: u64,
) -> Result<
    FactorOutcome,
    AuthnError<<MockIdentityStore as axess_core::authn::store::IdentityLookup>::Error>,
> {
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let code = generate_hotp_code(SECRET, counter);
    svc.verify_factor(&FactorCredential::OtpCode(code.into()), &session)
        .await
}

async fn stored(factors: &MockFactorStore, scope: &AuthnScope) -> Option<FactorConfig> {
    factors.load_factor(scope, FactorKind::Hotp).await.unwrap()
}

fn secret_of(config: &FactorConfig) -> &FactorSecret {
    match config {
        FactorConfig::Hotp(cfg) => &cfg.secret,
        _ => unreachable!(),
    }
}

fn future() -> DateTime<Utc> {
    Utc::now() + Duration::days(30)
}

#[tokio::test]
async fn a_plain_secret_is_sealed_by_the_login_that_verifies_it() {
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), hotp(SECRET.into(), 0))
        .with_method(&uid("u1"), hotp_method());
    let cipher = cipher(KEY_A).with_plain_secrets(LegacyBlobs::AcceptUntil(future()));
    let svc = service(factors.clone(), Some(cipher));

    let outcome = login(&svc, 0).await.unwrap();
    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );

    let row = stored(&factors, &user_scope()).await.unwrap();
    assert!(
        secret_of(&row).is_sealed(),
        "the secret is still plain at rest"
    );
    let json = serde_json::to_string(&row).unwrap();
    assert!(
        !json.contains(SECRET),
        "the serialised row leaks the secret: {json}"
    );
}

#[tokio::test]
async fn a_sealed_secret_verifies_and_stays_as_it_was() {
    let cipher = cipher(KEY_A);
    let (config, _) = sealed_for(&cipher, &user_scope(), 0);
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), config.clone())
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors.clone(), Some(cipher));

    assert!(matches!(
        login(&svc, 0).await.unwrap(),
        FactorOutcome::Authenticated
    ));
    let after_one = stored(&factors, &user_scope()).await.unwrap();
    assert_eq!(
        serde_json::to_value(secret_of(&after_one)).unwrap(),
        serde_json::to_value(secret_of(&config)).unwrap(),
        "an unchanged secret is not sealed again"
    );
    assert!(matches!(
        login(&svc, 1).await.unwrap(),
        FactorOutcome::Authenticated
    ));
}

#[tokio::test]
async fn a_wrong_code_against_a_sealed_secret_fails_like_any_other() {
    let cipher = cipher(KEY_A);
    let (config, _) = sealed_for(&cipher, &user_scope(), 0);
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), config)
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors.clone(), Some(cipher));

    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let outcome = svc
        .verify_factor(&FactorCredential::OtpCode("000000".into()), &session)
        .await
        .unwrap();
    assert!(
        matches!(outcome, FactorOutcome::InvalidCredential),
        "{outcome:?}"
    );
    let row = stored(&factors, &user_scope()).await.unwrap();
    assert!(secret_of(&row).is_sealed());
}

#[tokio::test]
async fn the_default_policy_refuses_a_plain_secret_and_leaves_the_row() {
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), hotp(SECRET.into(), 0))
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors.clone(), Some(cipher(KEY_A)));

    let err = login(&svc, 0).await.unwrap_err();
    assert!(
        matches!(&err, AuthnError::Internal(text) if text.contains("plain text")),
        "{err:?}"
    );
    let row = stored(&factors, &user_scope()).await.unwrap();
    assert!(!secret_of(&row).is_sealed());
}

#[tokio::test]
async fn a_plain_secret_is_refused_once_the_window_closes() {
    let clock = MockClock::at(Utc::now());
    let until = clock.now() + Duration::days(1);
    let cipher = cipher(KEY_A)
        .with_clock(Arc::new(clock.clone()))
        .with_plain_secrets(LegacyBlobs::AcceptUntil(until));
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), hotp(SECRET.into(), 0))
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors, Some(cipher));

    clock.advance(Duration::days(2));
    let err = login(&svc, 0).await.unwrap_err();
    assert!(matches!(err, AuthnError::Internal(_)), "{err:?}");
}

#[tokio::test]
async fn a_sealed_secret_with_no_cipher_is_a_clear_error() {
    let (config, _) = sealed_for(&cipher(KEY_A), &user_scope(), 0);
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), config)
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors, None);

    let err = login(&svc, 0).await.unwrap_err();
    assert!(
        matches!(&err, AuthnError::Internal(text) if text.contains("no FactorSecretCipher")),
        "{err:?}"
    );
}

#[tokio::test]
async fn with_no_cipher_a_plain_secret_works_as_before() {
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), hotp(SECRET.into(), 0))
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors.clone(), None);

    assert!(matches!(
        login(&svc, 0).await.unwrap(),
        FactorOutcome::Authenticated
    ));
    let row = stored(&factors, &user_scope()).await.unwrap();
    assert!(!secret_of(&row).is_sealed());
}

#[tokio::test]
async fn a_secret_sealed_for_another_user_does_not_open_on_this_row() {
    let other = AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u2"),
    };
    let cipher = cipher(KEY_A);
    let (copied, _) = sealed_for(&cipher, &other, 0);
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), copied)
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors, Some(cipher));

    let err = login(&svc, 0).await.unwrap_err();
    assert!(
        matches!(&err, AuthnError::Internal(text) if text.contains("did not authenticate")),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_secret_sealed_under_the_previous_key_is_sealed_again_under_the_current_one() {
    let old = cipher(KEY_A);
    let (config, old_id) = sealed_for(&old, &user_scope(), 0);
    let rotated = cipher(KEY_B).with_previous_key(KEY_A);
    let factors = MockFactorStore::new()
        .with_factor(user_scope(), config)
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors.clone(), Some(rotated.clone()));

    assert!(matches!(
        login(&svc, 0).await.unwrap(),
        FactorOutcome::Authenticated
    ));
    let row = stored(&factors, &user_scope()).await.unwrap();
    match secret_of(&row) {
        FactorSecret::Sealed(sealed) => {
            assert_ne!(sealed.key_id, old_id);
            assert!(rotated.is_current(sealed));
        }
        FactorSecret::Plain(_) => panic!("plain"),
    }
}

#[tokio::test]
async fn a_tenant_template_is_copied_to_the_user_row_sealed_for_that_user() {
    let tenant_scope = AuthnScope::Tenant(tid("t1"));
    let cipher = cipher(KEY_A);
    let (template, _) = sealed_for(&cipher, &tenant_scope, 0);
    let factors = MockFactorStore::new()
        .with_factor(tenant_scope.clone(), template.clone())
        .with_method(&uid("u1"), hotp_method());
    let svc = service(factors.clone(), Some(cipher.clone()));

    assert!(matches!(
        login(&svc, 0).await.unwrap(),
        FactorOutcome::Authenticated
    ));
    let user_row = stored(&factors, &user_scope()).await.unwrap();
    let FactorSecret::Sealed(sealed) = secret_of(&user_row) else {
        panic!("the user row is plain");
    };
    let kind = FactorKind::Hotp;
    let opened = cipher
        .open(sealed, FactorSecretBinding::new(&user_scope(), &kind))
        .unwrap();
    assert_eq!(&*opened.secret, SECRET);
    assert!(
        cipher
            .open(sealed, FactorSecretBinding::new(&tenant_scope, &kind))
            .is_err(),
        "the user row must be bound to the user, not the template"
    );
    let template_after = stored(&factors, &tenant_scope).await.unwrap();
    assert_eq!(
        serde_json::to_value(secret_of(&template_after)).unwrap(),
        serde_json::to_value(secret_of(&template)).unwrap()
    );
    assert!(matches!(
        login(&svc, 1).await.unwrap(),
        FactorOutcome::Authenticated
    ));
}
