//! A source of provider configuration can withdraw FIDO2 and LDAP as it can an
//! OAuth provider: the factor's steps refuse afterwards, the metrics count
//! the removal, a second removal is `NotFound`, and the change is announced.
//!
//! Run with: `cargo test -p axess-core --features testing,jwt-aws-lc,fido2,ldap --test provider_withdraw`

#![cfg(all(any(feature = "fido2", feature = "ldap"), feature = "testing"))]

use axess_core::testing::fixtures as common;

use axess_core::authn::AuditContext;
use axess_core::authn::service::{AuthnService, ProviderChangeKind, ProviderReloadError};
use axess_core::metrics::MetricSinks;
#[cfg(feature = "fido2")]
use axess_core::reload::{InProcessCoordinator, ReloadCoordinator};
#[cfg(feature = "fido2")]
use axess_core::testing::test_session;
use axess_core::testing::{
    RecordingMetrics,
    mock_authn::{MockFactorStore, MockIdentityStore},
};
use common::{provider_admin, reload_refusal, test_tenant};
#[cfg(feature = "fido2")]
use std::num::NonZeroUsize;
use std::sync::Arc;

#[cfg(feature = "fido2")]
#[tokio::test]
async fn removing_fido2_refuses_its_ceremony_counts_and_announces() {
    let clock = common::test_clock();
    use axess_core::authn::AuthnError;
    use axess_factors::fido2::DefaultFido2Provider;
    use webauthn_rs::prelude::{Url, WebauthnBuilder};
    let origin = Url::parse("https://localhost:8443").unwrap();
    let webauthn = WebauthnBuilder::new("localhost", &origin)
        .unwrap()
        .build()
        .unwrap();
    let metrics = Arc::new(RecordingMetrics::default());
    let bus = Arc::new(InProcessCoordinator::new(NonZeroUsize::new(8).unwrap()));
    let mut notices = bus.subscribe().await.unwrap();
    let service = AuthnService::builder(
        MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .with_metrics(MetricSinks::all(metrics.clone()))
    .with_provider_coordinator(bus.clone())
    .with_fido2(DefaultFido2Provider::new(webauthn))
    .build();
    let session = test_session();
    assert!(service.begin_discoverable_login(&session).await.is_ok());

    let change = service
        .with_audit_context(AuditContext::default())
        .remove_fido2_as(&provider_admin())
        .await
        .unwrap();
    assert_eq!(change.kind, ProviderChangeKind::Removed);
    assert!(change.announced);
    assert!(!service.has_fido2());
    assert!(matches!(
        service.begin_discoverable_login(&session).await,
        Err(AuthnError::NoFlow)
    ));
    assert_eq!(metrics.count("provider_removed:fido2"), 1);
    assert_eq!(notices.recv().await.unwrap().digest, "fido2");

    let again = service
        .with_audit_context(AuditContext::default())
        .remove_fido2_as(&provider_admin())
        .await
        .map_err(reload_refusal)
        .expect_err("nothing to remove");
    assert!(matches!(again, ProviderReloadError::NotFound { .. }));
    assert_eq!(metrics.count("provider_reload_refused:fido2"), 1);
    assert_eq!(metrics.count("provider_removed:fido2"), 1);
}

#[cfg(feature = "ldap")]
#[tokio::test]
async fn removing_ldap_detaches_the_directory_counts_and_refuses_a_second_removal() {
    let clock = common::test_clock();
    use axess_factors::ldap::MockLdapProvider;
    let metrics = Arc::new(RecordingMetrics::default());
    let service = AuthnService::builder(
        MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_clock(clock.clone())
    .with_metrics(MetricSinks::all(metrics.clone()))
    .with_ldap(MockLdapProvider::new("{user}@corp"))
    .build();
    assert!(service.has_ldap());

    let change = service
        .with_audit_context(AuditContext::default())
        .remove_ldap_as(&provider_admin())
        .await
        .unwrap();
    assert_eq!(change.kind, ProviderChangeKind::Removed);
    assert!(!change.announced, "no coordinator, nothing announced");
    assert!(!service.has_ldap());
    assert_eq!(metrics.count("provider_removed:ldap"), 1);

    let again = service
        .with_audit_context(AuditContext::default())
        .remove_ldap_as(&provider_admin())
        .await
        .map_err(reload_refusal)
        .expect_err("nothing to remove");
    assert!(matches!(again, ProviderReloadError::NotFound { .. }));
    assert_eq!(metrics.count("provider_reload_refused:ldap"), 1);
}
