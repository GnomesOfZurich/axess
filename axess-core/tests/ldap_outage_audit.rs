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
use axess_core::testing::mock_tracing::TracingCapture;
use axess_core::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    test_session,
};
use axess_factors::ldap::{LdapBindResult, LdapError, LdapProvider};
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
