#![cfg(all(feature = "testing", feature = "ldap"))]
//! A directory outage during an LDAP bind leaves an audit row, and the log
//! line names the user rather than the bind DN.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEventStatus, AuthEventType};
use axess_core::authn::factor::LdapBindFactorConfig;
use axess_core::authn::factor::{FactorConfig, FactorCredential, FactorKind, ZeroizedString};
use axess_core::authn::service::AuthnService;
use axess_core::authn::store::AuthMethod;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::ldap::{LdapBindResult, LdapError, LdapProvider};
use axess_testing::mock_tracing::TracingCapture;
use common::{test_tenant, test_user, uid, user_scope};
use std::{future::Future, pin::Pin};

const DN: &str = "uid=alice,ou=people,dc=example,dc=com";

struct Down;

impl LdapProvider for Down {
    fn verify_bind<'a>(
        &'a self,
        _identifier: &'a str,
        _bind_dn: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async { Err(LdapError::Connection("ldap.internal:636 refused".into())) })
    }

    fn build_bind_dn(&self, _identifier: &str) -> String {
        DN.to_owned()
    }
}

#[tokio::test]
async fn a_directory_outage_is_audited_and_does_not_log_the_bind_dn() {
    let capture = TracingCapture::install();
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(DN.to_owned()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_ldap(Down)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("whatever"));
    assert!(svc.verify_factor(&cred, &session).await.is_err());

    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::FactorVerified)
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(rows[0].factor_kind, Some(FactorKind::LdapBind));
    assert!(!capture.contains(DN), "the bind DN must not be logged");
    assert!(capture.contains("LDAP bind failed"));
}

/// A directory that accepted the connection and then could not perform
/// the bind (`unavailable`, rc 52). Not a verdict on the password.
struct Unavailable;

impl LdapProvider for Unavailable {
    fn verify_bind<'a>(
        &'a self,
        _identifier: &'a str,
        _bind_dn: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async {
            Err(LdapError::Directory {
                rc: 52,
                text: "shutting down".into(),
            })
        })
    }

    fn build_bind_dn(&self, _identifier: &str) -> String {
        DN.to_owned()
    }
}

/// The directory's own error codes used to be read as a wrong password and
/// counted towards the lockout, so an outage locked every user out. They
/// are an external-service error now, with the reserved guess given back.
#[tokio::test]
async fn a_directory_that_cannot_bind_counts_no_failed_attempt() {
    use axess_core::authn::error::AuthnError;
    // A capture of its own: a test in this binary with no subscriber that
    // hits the log callsite first would cache it as never interesting for
    // the sibling test that asserts on the log line.
    let capture = TracingCapture::install();
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(DN.to_owned()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let svc = AuthnService::builder(identity.clone(), factors)
        .with_ldap(Unavailable)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();
    let cred = FactorCredential::Password(ZeroizedString::new("whatever"));
    let err = svc.verify_factor(&cred, &session).await.unwrap_err();
    assert!(matches!(err, AuthnError::ExternalService(_)), "{err:?}");
    assert_eq!(
        identity.failed_attempts_for("u1"),
        0,
        "an outage is not a guess"
    );
    let rows: Vec<_> = identity
        .events()
        .into_iter()
        .filter(|e| e.event_type == AuthEventType::FactorVerified)
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_status, AuthEventStatus::Failure);
    assert_eq!(
        rows[0].error.as_ref().map(ToString::to_string).as_deref(),
        Some("external_service")
    );
    assert!(capture.contains("LDAP bind failed"));
    assert!(!capture.contains(DN), "the bind DN must not be logged");
}

/// A directory that accepts an unauthenticated bind (an empty password) must
/// not let anyone in: core refuses the empty password before any bind.
struct AcceptsAnyBind;

impl LdapProvider for AcceptsAnyBind {
    fn verify_bind<'a>(
        &'a self,
        _identifier: &'a str,
        bind_dn: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(LdapBindResult {
                bind_dn: bind_dn.to_owned(),
                groups: Vec::new(),
            })
        })
    }

    fn build_bind_dn(&self, _identifier: &str) -> String {
        DN.to_owned()
    }
}

#[tokio::test]
async fn an_empty_ldap_password_is_refused_even_when_the_directory_would_bind() {
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(DN.to_owned()),
            }),
        )
        .with_method(
            &uid("u1"),
            AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
        );
    let svc = AuthnService::builder(identity, factors)
        .with_ldap(AcceptsAnyBind)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    svc.begin_login("alice", "default", &session).await.unwrap();

    let cred = FactorCredential::Password(ZeroizedString::new(""));
    let outcome = svc.verify_factor(&cred, &session).await;

    assert!(
        !matches!(
            outcome,
            Ok(axess_core::authn::service::FactorOutcome::Authenticated)
        ),
        "{outcome:?}"
    );
    assert!(
        !session.is_authenticated().await,
        "an empty password must never authenticate, whatever the directory answers"
    );
}

/// With no session registry, a store outage at any point of an LDAP login
/// never leaves the session authenticated behind an error.
#[tokio::test]
async fn a_store_outage_during_an_ldap_login_never_leaves_the_session_authenticated() {
    let mut errored = 0;
    for skip in 0..12 {
        let identity = MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice"));
        let factors = MockFactorStore::new()
            .with_factor(
                user_scope(),
                FactorConfig::LdapBind(LdapBindFactorConfig {
                    bind_dn: Some(DN.to_owned()),
                }),
            )
            .with_method(
                &uid("u1"),
                AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
            );
        let svc = AuthnService::builder(identity, factors.clone())
            .with_ldap(AcceptsAnyBind)
            .build()
            .with_audit_context(AuditContext::default());
        let session = test_session();
        svc.begin_login("alice", "default", &session).await.unwrap();
        factors.arm_resolve_failures_after(skip, 1);

        let cred = FactorCredential::Password(ZeroizedString::new("correct horse"));
        let outcome = svc.verify_factor(&cred, &session).await;

        errored += usize::from(outcome.is_err());
        assert_eq!(
            session.is_authenticated().await,
            matches!(
                outcome,
                Ok(axess_core::authn::service::FactorOutcome::Authenticated)
            ),
            "an outage after {skip} good reads left the session at odds with the answer: {outcome:?}"
        );
    }
    assert!(
        errored > 0,
        "the armed outage never fired, so nothing was checked"
    );
}

/// A method whose steps include one with no usable factor (an empty `AnyOf`)
/// is skipped whole: dropping only that step would let the login pass with
/// fewer steps than the method requires.
#[tokio::test]
async fn a_method_with_an_empty_any_of_step_is_skipped_not_shortened() {
    use axess_core::authn::factor::FactorStep;
    let identity = MockIdentityStore::new()
        .with_tenant(test_tenant())
        .with_user(test_user("u1", "alice"));
    let mut method = AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope());
    method.steps.push(FactorStep::AnyOf(Vec::new()));
    let factors = MockFactorStore::new()
        .with_factor(
            user_scope(),
            FactorConfig::LdapBind(LdapBindFactorConfig {
                bind_dn: Some(DN.to_owned()),
            }),
        )
        .with_method(&uid("u1"), method);
    let svc = AuthnService::builder(identity, factors)
        .with_ldap(AcceptsAnyBind)
        .build()
        .with_audit_context(AuditContext::default());
    let session = test_session();
    let begun = svc.begin_login("alice", "default", &session).await;
    assert!(
        matches!(
            begun,
            Ok(axess_core::authn::service::LoginOutcome::InvalidCredentials)
        ),
        "{begun:?}"
    );
    let cred = FactorCredential::Password(ZeroizedString::new("correct horse"));
    let verified = svc.verify_factor(&cred, &session).await;
    assert!(
        matches!(verified, Err(axess_core::authn::error::AuthnError::NoFlow)),
        "{verified:?}"
    );

    assert!(
        !session.is_authenticated().await,
        "one step of a two-step method must not authenticate"
    );
}

struct Accepts;

impl LdapProvider for Accepts {
    fn verify_bind<'a>(
        &'a self,
        _identifier: &'a str,
        _bind_dn: &'a str,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<LdapBindResult, LdapError>> + Send + 'a>> {
        Box::pin(async {
            Ok(LdapBindResult {
                bind_dn: DN.to_owned(),
                groups: vec![],
            })
        })
    }

    fn build_bind_dn(&self, _identifier: &str) -> String {
        DN.to_owned()
    }
}

/// The rows of an LDAP login, the outage and the success alike, name the
/// session they belong to, as the other rows of a login do.
#[tokio::test]
async fn the_ldap_rows_name_their_session() {
    for accepts in [false, true] {
        let identity = MockIdentityStore::new()
            .with_tenant(test_tenant())
            .with_user(test_user("u1", "alice"));
        let factors = MockFactorStore::new()
            .with_factor(
                user_scope(),
                FactorConfig::LdapBind(LdapBindFactorConfig {
                    bind_dn: Some(DN.to_owned()),
                }),
            )
            .with_method(
                &uid("u1"),
                AuthMethod::sequential("ldap", vec![FactorKind::LdapBind], user_scope()),
            );
        let builder = AuthnService::builder(identity.clone(), factors);
        let svc = if accepts {
            builder.with_ldap(Accepts)
        } else {
            builder.with_ldap(Down)
        }
        .build()
        .with_audit_context(AuditContext::default());
        let session = test_session();
        svc.begin_login("alice", "default", &session).await.unwrap();
        // The id the row is written under, before a finished login may rotate it.
        let before = session.session_id().await;
        let cred = FactorCredential::Password(ZeroizedString::new("whatever"));
        let _ = svc.verify_factor(&cred, &session).await;

        let rows: Vec<_> = identity
            .events()
            .into_iter()
            .filter(|e| {
                e.event_type == AuthEventType::FactorVerified
                    && e.factor_kind == Some(FactorKind::LdapBind)
            })
            .collect();
        assert_eq!(rows.len(), 1, "accepts={accepts}");
        assert_eq!(
            rows[0].session_id,
            Some(before),
            "accepts={accepts}: the row has no session id"
        );
    }
}
