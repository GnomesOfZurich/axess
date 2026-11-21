#![cfg(all(feature = "testing", feature = "ldap"))]
//! What the LDAP factor refuses before it asks the directory: a bind DN
//! override holding a character outside the DN set, a password over the cap
//! and a credential that is not a password. Each is refused against a
//! directory that would accept the bind, and the directory is never asked.
//! A DN override exactly as long as the cap is the longest one that binds.

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::RequestAuthnService;
use axess_core::authn::factor::LdapBindFactorConfig;
use axess_core::authn::factor::{FactorConfig, FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::service::{AuthnService, FactorOutcome};
use axess_core::authn::store::AuthMethod;
use axess_core::session::extractor::AuthSession;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::ldap::{LdapBindResult, LdapError, LdapProvider};
use common::{test_tenant, test_user, uid, user_scope};
use std::sync::{Arc, Mutex};
use std::{future::Future, pin::Pin};

/// The longest bind DN override the factor binds as.
const MAX_BIND_DN_BYTES: usize = 1024;

/// A directory that binds anyone with any password, and keeps the DN of
/// every bind it was asked for.
#[derive(Clone, Default)]
struct AcceptsAnyBind {
    asked: Arc<Mutex<Vec<String>>>,
}

impl AcceptsAnyBind {
    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl LdapProvider for AcceptsAnyBind {
    fn verify_bind<'a>(
        &'a self,
        identifier: &'a str,
        bind_dn: &'a str,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async move {
            tracing::trace!(
                identifier,
                password_bytes = password.len(),
                "binding whoever asks"
            );
            self.asked.lock().unwrap().push(bind_dn.to_owned());
            Ok(LdapBindResult {
                bind_dn: bind_dn.to_owned(),
                groups: Vec::new(),
            })
        })
    }

    fn build_bind_dn(&self, identifier: &str) -> String {
        format!("uid={identifier},ou=people,dc=example,dc=com")
    }
}

struct Rig {
    svc: RequestAuthnService<MockIdentityStore, MockFactorStore>,
    directory: AcceptsAnyBind,
    session: AuthSession,
}

/// A login for `alice` waiting at its LDAP step, whose factor binds as
/// `bind_dn`.
async fn at_the_ldap_step(bind_dn: &str) -> Rig {
    let clock = common::test_clock();
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(bind_dn.to_owned()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let directory = AcceptsAnyBind::default();
    let svc = AuthnService::builder(identity, factors)
        .with_clock(clock.clone())
        .with_ldap(directory.clone())
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    Rig {
        svc,
        directory,
        session,
    }
}

/// `credential` is refused at `rig`'s LDAP step without a bind.
async fn assert_refused_before_the_bind(rig: &Rig, credential: &FactorCredential, what: &str) {
    let outcome = rig.svc.verify_factor(credential, &rig.session).await;
    assert!(
        matches!(outcome, Ok(FactorOutcome::InvalidCredential)),
        "{what}: {outcome:?}"
    );
    assert!(!rig.session.is_authenticated().await, "{what}");
    assert_eq!(
        rig.directory.asked(),
        Vec::<String>::new(),
        "{what}: the directory is not asked"
    );
}

fn password(text: &str) -> FactorCredential {
    FactorCredential::Password(ZeroizedString::new(text))
}

/// The control: the directory binds a well-formed DN with any password, so
/// every refusal below is the factor's own.
#[tokio::test]
async fn the_directory_binds_a_well_formed_override() {
    let dn = "uid=alice,ou=people,dc=example,dc=com";
    let rig = at_the_ldap_step(dn).await;

    let outcome = rig
        .svc
        .verify_factor(&password("anything"), &rig.session)
        .await
        .unwrap();

    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    assert_eq!(rig.directory.asked(), vec![dn.to_owned()]);
}

/// A wildcard, a filter parenthesis, a separator the DN grammar does not
/// use, a control character or a non-ASCII letter in the override refuses
/// the credential.
#[tokio::test]
async fn a_bind_dn_with_a_character_outside_the_dn_set_is_refused() {
    for dn in [
        "uid=*,ou=people,dc=example,dc=com",
        "uid=alice)(uid=bob,dc=example,dc=com",
        "uid=alice;dc=example,dc=com",
        "uid=alice/admin,dc=example,dc=com",
        "uid=alice<admin>,dc=example,dc=com",
        "uid=alice\u{0000},dc=example,dc=com",
        "uid=alice\n,dc=example,dc=com",
        "uid=\u{00E4}lice,dc=example,dc=com",
    ] {
        let rig = at_the_ldap_step(dn).await;
        assert_refused_before_the_bind(&rig, &password("anything"), &format!("{dn:?}")).await;
    }
}

/// A password one byte over the cap is refused.
#[tokio::test]
async fn a_password_over_the_cap_is_refused() {
    let rig = at_the_ldap_step("uid=alice,ou=people,dc=example,dc=com").await;
    let long = "a".repeat(axess_core::validation::MAX_PASSWORD_BYTES + 1);

    assert_refused_before_the_bind(&rig, &password(&long), "a password over the cap").await;
}

/// A DN override exactly as long as the cap binds: the cap is the longest
/// DN taken, not the first one refused.
#[tokio::test]
async fn a_bind_dn_exactly_at_the_length_cap_binds() {
    let dn = format!("uid={}", "a".repeat(MAX_BIND_DN_BYTES - "uid=".len()));
    assert_eq!(dn.len(), MAX_BIND_DN_BYTES);
    let rig = at_the_ldap_step(&dn).await;

    let outcome = rig
        .svc
        .verify_factor(&password("anything"), &rig.session)
        .await
        .unwrap();

    assert!(
        matches!(outcome, FactorOutcome::Authenticated),
        "{outcome:?}"
    );
    assert_eq!(rig.directory.asked(), vec![dn]);
}

/// A one-time code or a recovery code handed to the LDAP step is refused,
/// though its text is a password the directory would bind with.
#[tokio::test]
async fn a_credential_that_is_not_a_password_is_refused() {
    for credential in [
        FactorCredential::OtpCode("ldap-secret".into()),
        FactorCredential::RecoveryCode("ldap-secret".into()),
        FactorCredential::Fido2Assertion(serde_json::json!("ldap-secret")),
    ] {
        let rig = at_the_ldap_step("uid=alice,ou=people,dc=example,dc=com").await;
        assert_refused_before_the_bind(&rig, &credential, "a credential of another kind").await;
    }
}
