#![cfg(feature = "testing")]
//! A tenant whose timed suspension has run out is active again for a
//! password reset, as it is for a login.

mod common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::AuthnService;
use axess_core::authn::types::{EntityState, StatusDetail};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use common::{test_tenant, test_user, uid};
use std::time::Duration;

#[tokio::test]
async fn a_lapsed_tenant_suspension_does_not_refuse_a_reset() {
    let now = chrono::Utc::now();
    let mut tenant = test_tenant();
    tenant.status = EntityState::Suspended(
        StatusDetail::administrative("hold", now - chrono::Duration::days(2))
            .with_until(Some(now - chrono::Duration::hours(1))),
    );
    let user = test_user("u1", "alice");
    let identity = MockIdentityStore::new().with_tenant(tenant).with_user(user);
    let svc = AuthnService::new(identity, MockFactorStore::new())
        .with_audit_context(AuditContext::default());

    let token = svc
        .begin_password_reset("alice", "default", Duration::from_secs(300))
        .await
        .unwrap()
        .expect("a lapsed suspension no longer bars the tenant");
    let done = svc
        .complete_password_reset(&uid("u1"), &token, "Another-password-2")
        .await
        .unwrap();

    assert!(
        done,
        "the reset completes in a tenant whose suspension ended"
    );
}
