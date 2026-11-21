//! The audited provider changes of the global registrations: the global
//! OAuth provider, FIDO2 and LDAP. Each reload writes one `MethodEnabled`
//! row and each removal one `MethodDisabled` row naming the administrator
//! and the factor, with no tenant, and a change whose row cannot be written
//! is undone. The tenant forms are in `provider_reload.rs`; every form goes
//! through the same settling, and these hold the three that had no caller.
//!
//! Run with: `cargo test -p axess-core --features testing,oauth,jwt-aws-lc,fido2,ldap --test provider_reload_audited`

#![cfg(all(feature = "testing", feature = "oauth"))]

use axess_core::testing::fixtures as common;

use axess_clock::testing::MockClock;

use axess_core::authn::AuditContext;
use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType};
use axess_core::authn::factor::{FactorKind, FederatedProvider};
use axess_core::authn::service::{AuthnService, ProviderChangeError, ProviderChangeKind};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::oauth::{OAuthProviderBuilder, OAuthProviderConfig};
use axess_testing::oauth_wiremock::{oauth_generate_rsa_keypair, oauth_mount_oidc_endpoints};
use common::{test_tenant, uid};
use wiremock::MockServer;

/// The rows an administrator's change wrote: one per change, each naming
/// them as the actor and `factor` as the provider, no user and no tenant.
fn assert_rows(rows: &[AuthEvent], factor: &FactorKind) {
    assert_eq!(rows.len(), 2, "one row per change: {rows:?}");
    for (row, event_type) in rows
        .iter()
        .zip([AuthEventType::MethodEnabled, AuthEventType::MethodDisabled])
    {
        assert_eq!(row.event_type, event_type);
        assert_eq!(row.event_status, AuthEventStatus::Success);
        assert_eq!(row.actor_id, Some(uid("admin-1")), "the administrator");
        assert_eq!(row.factor_kind.as_ref(), Some(factor));
        assert!(row.tenant_id.is_none(), "a global provider's row: {row:?}");
        assert!(row.user_id.is_none(), "the subject is the provider");
    }
}

async fn candidate(
    clock: &MockClock,
    server: &MockServer,
) -> Result<OAuthProviderConfig, axess_factors::oauth::OAuthError> {
    OAuthProviderConfig::discover_screened(
        "sso",
        &server.uri(),
        "client",
        "secret",
        "http://localhost:3000/callback",
        axess_factors::egress::EgressPolicy::screened_allowing_loopback_http(),
    )
    .await
    .map(|b| b.with_clock(std::sync::Arc::new(clock.clone())))
    .and_then(OAuthProviderBuilder::build)
}

#[tokio::test]
async fn a_global_oauth_provider_change_writes_one_row_per_change_naming_the_administrator() {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let admin = uid("admin-1");

    let added = request
        .reload_oauth_provider_as(
            &admin,
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, &server),
        )
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    assert!(service.has_oauth_providers());
    let removed = request
        .remove_oauth_provider_as(&admin, "sso")
        .await
        .unwrap();
    assert_eq!(removed.kind, ProviderChangeKind::Removed);
    assert!(!service.has_oauth_providers());

    assert_rows(
        &identity.events(),
        &FactorKind::Federated(FederatedProvider::Custom("sso".into())),
    );
}

#[tokio::test]
async fn a_global_oauth_provider_change_whose_row_cannot_be_written_is_undone() {
    let clock = common::test_clock();
    let server = MockServer::start().await;
    let (_, jwk, _) = oauth_generate_rsa_keypair();
    oauth_mount_oidc_endpoints(&server, &jwk).await;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    identity.arm_record_event_failure();

    let refused = request
        .reload_oauth_provider_as(
            &uid("admin-1"),
            "sso",
            FederatedProvider::Custom("sso".into()),
            candidate(&clock, &server),
        )
        .await
        .expect_err("a change nobody can account for does not stand");
    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
    assert!(!service.has_oauth_providers(), "the reload was undone");
}

#[cfg(feature = "fido2")]
#[tokio::test]
async fn a_fido2_change_writes_one_row_per_change_and_an_unwritten_one_is_undone() {
    let clock = common::test_clock();
    use axess_factors::fido2::MockFido2Provider;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let admin = uid("admin-1");

    let added = request
        .reload_fido2_as(&admin, async { Ok::<_, String>(MockFido2Provider::new()) })
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    let removed = request.remove_fido2_as(&admin).await.unwrap();
    assert_eq!(removed.kind, ProviderChangeKind::Removed);
    assert!(!service.has_fido2());
    assert_rows(&identity.events(), &FactorKind::Fido2);

    request
        .reload_fido2_as(&admin, async { Ok::<_, String>(MockFido2Provider::new()) })
        .await
        .unwrap();
    identity.arm_record_event_failure();
    let refused = request
        .remove_fido2_as(&admin)
        .await
        .expect_err("a removal nobody can account for does not stand");
    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
    assert!(service.has_fido2(), "the removal was undone");
}

#[cfg(feature = "ldap")]
#[tokio::test]
async fn an_ldap_change_writes_one_row_per_change_and_an_unwritten_one_is_undone() {
    let clock = common::test_clock();
    use axess_factors::ldap::MockLdapProvider;
    let identity = MockIdentityStore::new()
        .with_clock(clock.clone())
        .with_tenant(test_tenant());
    let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_clock(clock.clone())
        .build();
    let request = service.with_audit_context(AuditContext::default());
    let admin = uid("admin-1");

    let added = request
        .reload_ldap_as(&admin, async {
            Ok::<_, String>(MockLdapProvider::new("{user}@corp"))
        })
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    let removed = request.remove_ldap_as(&admin).await.unwrap();
    assert_eq!(removed.kind, ProviderChangeKind::Removed);
    assert!(!service.has_ldap());
    assert_rows(&identity.events(), &FactorKind::LdapBind);

    request
        .reload_ldap_as(&admin, async {
            Ok::<_, String>(MockLdapProvider::new("{user}@corp"))
        })
        .await
        .unwrap();
    identity.arm_record_event_failure();
    let refused = request
        .remove_ldap_as(&admin)
        .await
        .expect_err("a removal nobody can account for does not stand");
    assert!(
        matches!(refused, ProviderChangeError::Audit { .. }),
        "{refused}"
    );
    assert!(service.has_ldap(), "the removal was undone");
}

// ── What a follower applies from its source ──────────────────────────────────

#[cfg(feature = "fido2")]
mod follower {
    use super::*;
    use axess_core::authn::event::AuthFailureReason;
    use axess_core::authn::service::{
        BuiltProvider, PROVIDER_SOURCE_REASON, ProviderEntry, ProviderKey, ProviderSource,
        ProviderSourceError,
    };
    use axess_core::reload::{InProcessCoordinator, ReloadCoordinator, ReloadFuture};
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A source that lists FIDO2 at a revision the test sets, or nothing.
    /// The revision the source lists FIDO2 at (none: not listed), and how
    /// many times the follower asked it to build.
    struct Fido2Source(Mutex<Option<String>>, std::sync::atomic::AtomicUsize);

    impl Fido2Source {
        fn listing(revision: &str) -> Arc<Self> {
            Arc::new(Self(
                Mutex::new(Some(revision.into())),
                std::sync::atomic::AtomicUsize::new(0),
            ))
        }

        fn builds(&self) -> usize {
            self.1.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ProviderSource for Fido2Source {
        fn desired(&self) -> ReloadFuture<'_, Result<Vec<ProviderEntry>, ProviderSourceError>> {
            let listed = self.0.lock().unwrap().clone();
            Box::pin(async move {
                Ok(listed
                    .map(|revision| ProviderEntry {
                        key: ProviderKey::Fido2,
                        revision,
                    })
                    .into_iter()
                    .collect())
            })
        }

        fn build<'a>(
            &'a self,
            _: &'a ProviderKey,
        ) -> ReloadFuture<'a, Result<BuiltProvider, ProviderSourceError>> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok(BuiltProvider::Fido2(Arc::new(
                    axess_factors::fido2::MockFido2Provider::new(),
                )))
            })
        }
    }

    async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
        for _ in 0..400 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    fn source_rows(identity: &MockIdentityStore) -> Vec<AuthEvent> {
        identity
            .events()
            .into_iter()
            .filter(|e| e.factor_kind == Some(FactorKind::Fido2))
            .collect()
    }

    /// A change the follower applies is recorded as the source's: one row
    /// per change, no administrator, the reason naming the source.
    #[tokio::test]
    async fn a_change_the_follower_applies_writes_a_row_attributed_to_the_source() {
        let clock = common::test_clock();
        let bus: Arc<InProcessCoordinator> =
            Arc::new(InProcessCoordinator::new(NonZeroUsize::new(16).unwrap()));
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant());
        let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_provider_coordinator(bus.clone())
            .build();
        let source = Fido2Source::listing("r1");
        let follower = service
            .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
            .await
            .unwrap();
        eventually("the follower installs FIDO2", || service.has_fido2()).await;

        *source.0.lock().unwrap() = None;
        bus.announce("fido2").await.unwrap();
        eventually("the follower withdraws FIDO2", || !service.has_fido2()).await;

        let rows = source_rows(&identity);
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (row, event_type) in rows
            .iter()
            .zip([AuthEventType::MethodEnabled, AuthEventType::MethodDisabled])
        {
            assert_eq!(row.event_type, event_type);
            assert_eq!(row.event_status, AuthEventStatus::Success);
            assert_eq!(row.actor_id, None, "no administrator made it");
            assert_eq!(
                row.error,
                Some(AuthFailureReason::from(PROVIDER_SOURCE_REASON)),
                "the row names the source as the cause"
            );
        }
        drop(follower);
    }

    /// A change the follower cannot record does not stand, and is tried
    /// again at the next read.
    #[tokio::test]
    async fn a_change_the_follower_cannot_record_is_undone_and_retried() {
        let clock = common::test_clock();
        let bus: Arc<InProcessCoordinator> =
            Arc::new(InProcessCoordinator::new(NonZeroUsize::new(16).unwrap()));
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant());
        identity.arm_record_event_failure();
        let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_provider_coordinator(bus.clone())
            .build();
        let source = Fido2Source::listing("r1");
        let follower = service
            .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
            .await
            .unwrap();
        eventually("the start read", || {
            follower.reads(axess_core::authn::service::ReadCause::Start) == 1
        })
        .await;
        // The follower reads one notice at a time and counts a read when it
        // begins, so the notice read counted means the start read is over.
        // The source lists nothing for it, so it changes nothing itself.
        *source.0.lock().unwrap() = None;
        bus.announce("fido2").await.unwrap();
        eventually("the notice read after the start read", || {
            follower.reads(axess_core::authn::service::ReadCause::Notice) == 1
        })
        .await;
        assert_eq!(source.builds(), 1, "the start read built FIDO2");
        assert!(!service.has_fido2(), "an unrecorded install was undone");
        assert!(source_rows(&identity).is_empty());

        identity.disarm_record_event_failure();
        *source.0.lock().unwrap() = Some("r1".into());
        bus.announce("fido2").await.unwrap();
        eventually("the retry installs FIDO2", || service.has_fido2()).await;
        assert_eq!(source.builds(), 2, "the change was tried again");
        assert_eq!(source_rows(&identity).len(), 1);
    }

    /// A withdrawal the follower cannot record does not stand either: the
    /// provider is put back and the withdrawal is tried again at the next
    /// read, so the provider does not stay installed once the source has
    /// stopped listing it.
    #[tokio::test]
    async fn a_withdrawal_the_follower_cannot_record_is_undone_and_retried() {
        let clock = common::test_clock();
        let bus: Arc<InProcessCoordinator> =
            Arc::new(InProcessCoordinator::new(NonZeroUsize::new(16).unwrap()));
        let identity = MockIdentityStore::new()
            .with_clock(clock.clone())
            .with_tenant(test_tenant());
        let service = AuthnService::builder(identity.clone(), MockFactorStore::new())
            .with_clock(clock.clone())
            .with_provider_coordinator(bus.clone())
            .build();
        let source = Fido2Source::listing("r1");
        let follower = service
            .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
            .await
            .unwrap();
        eventually("the follower installs FIDO2", || service.has_fido2()).await;

        identity.arm_record_event_failure();
        *source.0.lock().unwrap() = None;
        bus.announce("fido2").await.unwrap();
        eventually("the first notice read", || {
            follower.reads(axess_core::authn::service::ReadCause::Notice) == 1
        })
        .await;
        // A read is counted when it begins and the follower reads one notice
        // at a time, so the second read counted means the first is over.
        bus.announce("fido2").await.unwrap();
        eventually("the second notice read", || {
            follower.reads(axess_core::authn::service::ReadCause::Notice) == 2
        })
        .await;
        assert!(service.has_fido2(), "an unrecorded withdrawal was undone");

        identity.disarm_record_event_failure();
        bus.announce("fido2").await.unwrap();
        eventually("the retry withdraws FIDO2", || !service.has_fido2()).await;
        let rows = source_rows(&identity);
        assert_eq!(rows.len(), 2, "the install and the withdrawal: {rows:?}");
        assert_eq!(rows[1].event_type, AuthEventType::MethodDisabled);
    }
}
