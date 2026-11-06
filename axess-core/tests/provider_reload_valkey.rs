#![cfg(all(feature = "testing", feature = "oauth", feature = "valkey"))]
//! The provider channel over Valkey: a provider reload announced on
//! `{prefix}:provider-reloaded` reaches a second service in the process, which
//! re-reads its own source, and the provider channel and the policy channel do
//! not cross.
//!
//! Run with `VALKEY_URL=redis://127.0.0.1:6390 cargo test -p axess-core
//! --features testing,oauth,valkey,jwt-aws-lc --test provider_reload_valkey -- --ignored`.

mod common;

use axess_core::authn::service::{
    AuthnService, BuiltProvider, ProviderEntry, ProviderKey, ProviderSource, ProviderSourceError,
    ReadCause,
};
use axess_core::reload::{ReloadCoordinator, ReloadFuture, ValkeyReloadCoordinator};
use axess_core::testing::mock_authn::{MockFactorStore, MockIdentityStore};
use axess_factors::oauth::MockOAuthProvider;
use common::test_tenant;
use fred::clients::SubscriberClient;
use fred::prelude::*;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

type Service = AuthnService<MockIdentityStore, MockFactorStore>;

fn url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

/// A coordinator on `{prefix}:{name}`, with clients of its own.
async fn coordinator(prefix: &str, name: &str) -> Arc<ValkeyReloadCoordinator> {
    let config = Config::from_url(&url()).expect("url");
    let publisher = Client::new(config.clone(), None, None, None);
    publisher.init().await.expect("connect publisher");
    let subscriber = SubscriberClient::new(config, None, None, None);
    subscriber.init().await.expect("connect subscriber");
    Arc::new(
        ValkeyReloadCoordinator::start_named(
            publisher,
            subscriber,
            prefix,
            name,
            NonZeroUsize::new(16).unwrap(),
        )
        .await
        .expect("start"),
    )
}

fn service(coordinator: Arc<ValkeyReloadCoordinator>) -> Service {
    AuthnService::builder(
        MockIdentityStore::new().with_tenant(test_tenant()),
        MockFactorStore::new(),
    )
    .with_provider_coordinator(coordinator)
    .build()
}

/// A source that lists one OAuth provider and counts how often it is read.
struct Source {
    reads: AtomicUsize,
}

fn key() -> ProviderKey {
    ProviderKey::OAuth {
        tenant: None,
        name: Arc::from("sso"),
    }
}

impl ProviderSource for Source {
    fn desired(&self) -> ReloadFuture<'_, Result<Vec<ProviderEntry>, ProviderSourceError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(vec![ProviderEntry {
                key: key(),
                revision: "r1".into(),
            }])
        })
    }

    fn build<'a>(
        &'a self,
        _key: &'a ProviderKey,
    ) -> ReloadFuture<'a, Result<BuiltProvider, ProviderSourceError>> {
        Box::pin(async {
            Ok(BuiltProvider::OAuth(Arc::new(MockOAuthProvider::new(
                "sso",
            ))))
        })
    }
}

/// Wait up to three seconds, in 10 ms steps.
async fn within_three_seconds(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..300 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not happen within 3s: {what}");
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_provider_reload_on_one_service_reaches_a_second_service_through_valkey() {
    // A prefix per run keeps concurrent test runs on one server apart.
    let prefix = format!("axess_provider_test_{}", uuid::Uuid::new_v4().simple());
    let a = service(coordinator(&prefix, "provider-reloaded").await);
    let b = service(coordinator(&prefix, "provider-reloaded").await);
    let source = Arc::new(Source {
        reads: AtomicUsize::new(0),
    });
    // A long poll: only the notice can make B read again within the test.
    let follower = b
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .expect("follow");
    within_three_seconds("B read its source at start", || {
        follower.reads(ReadCause::Start) == 1
    })
    .await;
    within_three_seconds("B installed what the source lists", || {
        b.has_oauth_providers()
    })
    .await;
    let reads_before = source.reads.load(Ordering::SeqCst);

    let change = a
        .reload_oauth_provider("other", async {
            Ok::<_, String>(MockOAuthProvider::new("other"))
        })
        .await
        .expect("reload");
    assert!(change.announced, "the notice was published");

    within_three_seconds("B read its source on the notice", || {
        follower.reads(ReadCause::Notice) >= 1
    })
    .await;
    assert!(source.reads.load(Ordering::SeqCst) > reads_before);
    assert_eq!(
        follower.reads(ReadCause::Poll),
        0,
        "the hour-long poll did not fire"
    );
    // B built from its source, not from A's reload: A's "other" is not B's.
    let names: Vec<String> = b
        .oauth_providers()
        .provider_names()
        .iter()
        .map(|n| n.to_string())
        .collect();
    assert_eq!(names, vec!["sso".to_string()]);
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn the_policy_channel_and_the_provider_channel_do_not_cross() {
    let prefix = format!("axess_provider_test_{}", uuid::Uuid::new_v4().simple());
    let providers = coordinator(&prefix, "provider-reloaded").await;
    let policies = coordinator(&prefix, "authz-policy-reloaded").await;
    let b = service(providers.clone());
    let source = Arc::new(Source {
        reads: AtomicUsize::new(0),
    });
    let follower = b
        .follow_provider_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .expect("follow");
    within_three_seconds("B read its source at start", || {
        follower.reads(ReadCause::Start) == 1
    })
    .await;
    let mut policy_notices = policies.subscribe().await.expect("subscribe");

    // A policy notice: the provider follower does not read.
    policies.announce("policy-digest").await.expect("announce");
    let policy_seen = tokio::time::timeout(Duration::from_secs(3), policy_notices.recv())
        .await
        .expect("the policy subscriber got its own notice in time")
        .expect("open");
    assert_eq!(policy_seen.digest, "policy-digest");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        follower.reads(ReadCause::Notice),
        0,
        "a policy notice does not make a provider follower read"
    );

    // A provider notice: the policy subscriber does not hear it, and the
    // follower does (so the quiet above was not a dead channel).
    providers.announce("oauth:-:sso").await.expect("announce");
    within_three_seconds("the provider follower read on its own notice", || {
        follower.reads(ReadCause::Notice) == 1
    })
    .await;
    let silence = tokio::time::timeout(Duration::from_millis(300), policy_notices.recv()).await;
    assert!(
        silence.is_err(),
        "a provider notice does not reach a policy subscriber: {silence:?}"
    );
}
