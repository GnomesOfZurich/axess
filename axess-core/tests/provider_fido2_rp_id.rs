//! A FIDO2 reload cannot silently change the relying-party id: a passkey is
//! bound to the id it was registered under, so a changed id is refused by
//! name unless the caller acknowledges it, and an acknowledged change is
//! counted.
//!
//! Run with: `cargo test -p axess-core --features testing,jwt-aws-lc,fido2 --test provider_fido2_rp_id`

#![cfg(feature = "fido2")]

mod common;

use axess_core::authn::service::{
    AuthnService, BuiltProvider, ProviderChangeKind, ProviderEntry, ProviderKey,
    ProviderReloadError, ProviderSource, ProviderSourceError, ReloadFido2,
};
use axess_core::metrics::MetricSinks;
use axess_core::reload::{InProcessCoordinator, ReloadCoordinator, ReloadFuture};
use axess_core::testing::{
    RecordingMetrics,
    mock_authn::{MockFactorStore, MockIdentityStore},
};
use axess_factors::fido2::{DefaultFido2Provider, Fido2Provider, MockFido2Provider};
use common::test_tenant;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use webauthn_rs::prelude::{Url, WebauthnBuilder};

fn service(
    metrics: &Arc<RecordingMetrics>,
    first: impl Fido2Provider,
) -> AuthnService<MockIdentityStore, MockFactorStore> {
    AuthnService::builder(
        MockIdentityStore::new().with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_metrics(MetricSinks::all(metrics.clone()))
    .with_fido2(first)
    .build()
}

fn mock(rp_id: &str) -> MockFido2Provider {
    MockFido2Provider::new().with_relying_party_id(rp_id)
}

#[tokio::test]
async fn the_same_relying_party_id_swaps() {
    let metrics = Arc::new(RecordingMetrics::default());
    let service = service(&metrics, mock("example.com"));
    let change = service
        .reload_fido2(async { Ok::<_, String>(mock("example.com")) })
        .await
        .expect("a like-for-like swap is accepted");
    assert_eq!(change.kind, ProviderChangeKind::Replaced);
    assert_eq!(metrics.count("fido2_rp_id_changed"), 0);
}

#[tokio::test]
async fn a_changed_relying_party_id_is_refused_by_name_and_the_old_provider_stays() {
    let metrics = Arc::new(RecordingMetrics::default());
    let service = service(&metrics, mock("example.com"));
    let refused = service
        .reload_fido2(async { Ok::<_, String>(mock("example.org")) })
        .await
        .expect_err("a changed relying-party id is refused");
    match &refused {
        ProviderReloadError::RpIdChanged { current, candidate } => {
            assert_eq!(current, "example.com");
            assert_eq!(candidate, "example.org");
        }
        other => panic!("expected RpIdChanged, got {other}"),
    }
    assert!(service.has_fido2());
    assert_eq!(metrics.count("provider_reload_refused:fido2"), 1);
    assert_eq!(metrics.count("provider_reloaded:fido2"), 0);
    assert_eq!(metrics.count("fido2_rp_id_changed"), 0);

    // The provider in force is still the first one: a like-for-like reload
    // to its id is accepted, one to the refused id is refused again.
    assert!(
        service
            .reload_fido2(async { Ok::<_, String>(mock("example.com")) })
            .await
            .is_ok()
    );
    assert!(
        service
            .reload_fido2(async { Ok::<_, String>(mock("example.org")) })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_changed_relying_party_id_with_the_acknowledgement_swaps_and_is_recorded() {
    let metrics = Arc::new(RecordingMetrics::default());
    let service = service(&metrics, mock("example.com"));
    let change = service
        .reload_fido2_with(
            async { Ok::<_, String>(mock("example.org")) },
            ReloadFido2::allow_rp_id_change(),
        )
        .await
        .expect("an acknowledged change is accepted");
    assert_eq!(change.kind, ProviderChangeKind::Replaced);
    assert_eq!(metrics.count("fido2_rp_id_changed"), 1);
    assert_eq!(metrics.count("provider_reloaded:fido2"), 1);

    // The new id is the one in force now: the old id is a change again.
    let back = service
        .reload_fido2(async { Ok::<_, String>(mock("example.com")) })
        .await;
    assert!(matches!(back, Err(ProviderReloadError::RpIdChanged { .. })));
}

#[tokio::test]
async fn adding_the_first_provider_has_no_id_to_change() {
    let metrics = Arc::new(RecordingMetrics::default());
    let service = AuthnService::builder(
        MockIdentityStore::new().with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_metrics(MetricSinks::all(metrics.clone()))
    .build();
    let added = service
        .reload_fido2(async { Ok::<_, String>(mock("example.com")) })
        .await
        .unwrap();
    assert_eq!(added.kind, ProviderChangeKind::Added);
    assert_eq!(metrics.count("fido2_rp_id_changed"), 0);
}

#[tokio::test]
async fn the_default_provider_reports_the_id_its_webauthn_instance_carries() {
    let origin = Url::parse("https://login.example.com").unwrap();
    let webauthn = WebauthnBuilder::new("example.com", &origin)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        DefaultFido2Provider::new(webauthn).relying_party_id(),
        "example.com"
    );
}

/// A source that lists FIDO2 at a revision and builds it with an id, plainly
/// or with the acknowledgement, as the test sets.
struct FidoSource {
    state: Mutex<(String, &'static str, bool)>,
}

impl ProviderSource for FidoSource {
    fn desired(&self) -> ReloadFuture<'_, Result<Vec<ProviderEntry>, ProviderSourceError>> {
        Box::pin(async move {
            Ok(vec![ProviderEntry {
                key: ProviderKey::Fido2,
                revision: self.state.lock().unwrap().0.clone(),
            }])
        })
    }

    fn build<'a>(
        &'a self,
        _key: &'a ProviderKey,
    ) -> ReloadFuture<'a, Result<BuiltProvider, ProviderSourceError>> {
        Box::pin(async move {
            let (_, rp_id, acknowledged) = self.state.lock().unwrap().clone();
            let provider = Arc::new(mock(rp_id));
            Ok(if acknowledged {
                BuiltProvider::Fido2AllowingRpIdChange(provider)
            } else {
                BuiltProvider::Fido2(provider)
            })
        })
    }
}

async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("did not happen within 2s: {what}");
}

#[tokio::test]
async fn a_follower_refuses_a_source_that_changes_the_id_unless_the_source_says_so() {
    let metrics = Arc::new(RecordingMetrics::default());
    let bus = Arc::new(InProcessCoordinator::new(NonZeroUsize::new(8).unwrap()));
    let service = AuthnService::builder(
        MockIdentityStore::new().with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_metrics(MetricSinks::all(metrics.clone()))
    .with_provider_coordinator(bus.clone())
    .with_fido2(mock("example.com"))
    .build();
    let source = Arc::new(FidoSource {
        state: Mutex::new(("r1".into(), "example.org", false)),
    });
    let _follower = service
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .unwrap();

    eventually("the plain change is refused", || {
        metrics.count("provider_reload_refused:fido2") >= 1
    })
    .await;
    assert_eq!(metrics.count("provider_reloaded:fido2"), 0);

    *source.state.lock().unwrap() = ("r2".into(), "example.org", true);
    bus.announce("fido2").await.unwrap();
    eventually("the acknowledged change is applied", || {
        metrics.count("fido2_rp_id_changed") == 1
    })
    .await;
    assert_eq!(metrics.count("provider_reloaded:fido2"), 1);
}
