//! The live tenant registry keeps an `(issuer, client_id)` pair to one
//! provider, as the stored directory does: a reload that would give a second
//! tenant provider, or a pair a global provider holds, is refused by name and
//! the registry stays as it was. A provider's own reload under the same
//! pair, and other pairs, go through.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc --test provider_reload_pair`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;
use axess_core::authn::AuditContext;
use axess_core::authn::factor::FederatedProvider;
use axess_core::authn::ids::TenantId;
use axess_core::authn::service::{AuthnService, ProviderChangeError, ProviderReloadError};
use axess_core::federation::oauth_tenant::LiveTenantOAuthProviders;
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::oauth::MockOAuthProvider;
use common::{test_tenant, tid, uid};
use std::sync::Arc;

const ISSUER: &str = "https://idp.shared.example";

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

fn service(clock: &MockClock, live: &Arc<LiveTenantOAuthProviders>) -> Service {
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    AuthnService::builder(identity, MockFactorStore::new())
        .with_clock(clock.clone())
        .with_oauth_provider(
            MockOAuthProvider::new("global")
                .with_clock(Arc::new(clock.clone()))
                .with_issuer(ISSUER)
                .with_client_id("global-client"),
        )
        .with_live_tenant_oauth_providers(live.clone())
        .build()
}

async fn provider(
    clock: &MockClock,
    issuer: &str,
    client_id: &str,
) -> Result<MockOAuthProvider, std::convert::Infallible> {
    Ok(MockOAuthProvider::new("sso")
        .with_clock(Arc::new(clock.clone()))
        .with_issuer(issuer)
        .with_client_id(client_id))
}

async fn reload(
    clock: &MockClock,
    service: &Service,
    tenant: &TenantId,
    client_id: &str,
) -> Result<(), ProviderChangeError> {
    service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &uid("admin-1"),
            tenant,
            "sso",
            FederatedProvider::Custom("sso".into()),
            provider(clock, ISSUER, client_id),
        )
        .await
        .map(|_| ())
}

/// The issuer and client id the registry holds for `tenant`'s `sso`.
fn pair_of(live: &LiveTenantOAuthProviders, tenant: &TenantId) -> Option<(String, String)> {
    live.get(tenant, "sso").map(|provider| {
        (
            provider.issuer().unwrap_or_default().to_string(),
            provider.client_id().unwrap_or_default().to_string(),
        )
    })
}

/// A second tenant's reload over the pair a first tenant holds is refused
/// by name, and the second tenant has no provider.
#[tokio::test]
async fn a_tenant_reload_over_a_pair_another_tenant_holds_is_refused() {
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = service(&clock, &live);
    reload(&clock, &service, &tid("acme"), "client-x")
        .await
        .unwrap();

    let refused = reload(&clock, &service, &tid("beta"), "client-x")
        .await
        .expect_err("the pair is held");

    assert!(
        matches!(
            refused,
            ProviderChangeError::Refused(ProviderReloadError::PairHeld {
                by_global: false,
                ..
            })
        ),
        "{refused}"
    );
    assert!(
        refused
            .to_string()
            .contains("already registered by another provider"),
        "{refused}"
    );
    assert_eq!(pair_of(&live, &tid("beta")), None);
    assert_eq!(
        pair_of(&live, &tid("acme")),
        Some((ISSUER.to_string(), "client-x".to_string()))
    );
}

/// A tenant's own second provider over its pair, under another name, is
/// refused as well: one pair, one provider.
#[tokio::test]
async fn a_tenants_second_name_over_its_own_pair_is_refused() {
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = service(&clock, &live);
    reload(&clock, &service, &tid("acme"), "client-x")
        .await
        .unwrap();

    let refused = service
        .with_audit_context(AuditContext::default())
        .reload_tenant_oauth_provider_as(
            &uid("admin-1"),
            &tid("acme"),
            "sso-copy",
            FederatedProvider::Custom("sso-copy".into()),
            async {
                Ok::<_, std::convert::Infallible>(
                    MockOAuthProvider::new("sso-copy")
                        .with_clock(Arc::new(clock.clone()))
                        .with_issuer(ISSUER)
                        .with_client_id("client-x"),
                )
            },
        )
        .await
        .expect_err("the pair is held");

    assert!(
        refused
            .to_string()
            .contains("already registered by another provider"),
        "{refused}"
    );
    assert!(live.get(&tid("acme"), "sso-copy").is_none());
}

/// A tenant cannot take the pair of a global provider.
#[tokio::test]
async fn a_tenant_reload_over_a_global_pair_is_refused() {
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = service(&clock, &live);

    let refused = reload(&clock, &service, &tid("acme"), "global-client")
        .await
        .expect_err("the global provider holds the pair");

    assert!(
        matches!(
            refused,
            ProviderChangeError::Refused(ProviderReloadError::PairHeld {
                by_global: true,
                ..
            })
        ),
        "{refused}"
    );
    assert!(
        refused.to_string().contains("the global provider"),
        "{refused}"
    );
    assert_eq!(pair_of(&live, &tid("acme")), None);
}

/// What stays allowed: a provider reloaded under its own pair, another
/// client id at the same issuer, and the pair once its holder is removed.
#[tokio::test]
async fn a_providers_own_reload_and_other_pairs_go_through() {
    let clock = common::test_clock();
    let live = Arc::new(LiveTenantOAuthProviders::new());
    let service = service(&clock, &live);
    reload(&clock, &service, &tid("acme"), "client-x")
        .await
        .unwrap();

    reload(&clock, &service, &tid("acme"), "client-x")
        .await
        .expect("a provider reloads under its own pair");
    reload(&clock, &service, &tid("beta"), "client-y")
        .await
        .expect("another client id at the same issuer");
    service
        .with_audit_context(AuditContext::default())
        .remove_tenant_oauth_provider_as(&uid("admin-1"), &tid("acme"), "sso")
        .await
        .unwrap();
    reload(&clock, &service, &tid("gamma"), "client-x")
        .await
        .expect("a pair nobody holds any more");
}
