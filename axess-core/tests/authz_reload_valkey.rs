#![cfg(all(feature = "testing", feature = "authz", feature = "valkey-cache"))]
//! The Valkey reload coordinator: a reload on one store reaches a second
//! store through pub/sub, and the second store re-reads its own source.
//!
//! Run with `VALKEY_URL=redis://127.0.0.1:6390 cargo test -p axess-core
//! --features testing,valkey-cache --test authz_reload_valkey -- --ignored`.

use axess_core::authz::{
    AuthzEntityProvider, AuthzError, AuthzStore, PolicyStore, make_entity_uid,
    reload::{PolicyBundle, PolicySource, ReloadFuture, ValkeyReloadCoordinator},
};
use cedar_policy::{Entities, EntityUid, Schema};
use fred::clients::SubscriberClient;
use fred::prelude::*;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SCHEMA: &str = r#"{
    "App": {
        "entityTypes": {
            "User": { "memberOfTypes": [] },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}"#;

fn permit(doc: &str) -> String {
    format!(
        r#"permit(principal == App::User::"alice", action == App::Action::"View", resource == App::Resource::"{doc}");"#
    )
}

struct Provider;

impl AuthzEntityProvider for Provider {
    type ResourceId = String;
    type Error = std::convert::Infallible;

    async fn entities_for(
        &self,
        _: &EntityUid,
        _: &String,
        _: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        Ok(Entities::empty())
    }

    async fn entities_for_tenant(
        &self,
        _: &EntityUid,
        _: Option<&str>,
        _: &String,
        _: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        Ok(Entities::empty())
    }

    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        make_entity_uid("App", "Resource", id)
    }

    fn validate_schema(&self, _: &Schema) -> Result<(), AuthzError> {
        Ok(())
    }
}

struct Source(Mutex<String>);

impl PolicySource for Source {
    fn load(&self) -> ReloadFuture<'_, Result<PolicyBundle, AuthzError>> {
        Box::pin(async move {
            Ok(PolicyBundle {
                policy_text: self.0.lock().unwrap().clone(),
                schema_json: SCHEMA.to_string(),
            })
        })
    }
}

async fn coordinator(url: &str, prefix: &str) -> Arc<ValkeyReloadCoordinator> {
    let config = Config::from_url(url).expect("url");
    let publisher = Client::new(config.clone(), None, None, None);
    publisher.init().await.expect("connect publisher");
    let subscriber = SubscriberClient::new(config, None, None, None);
    subscriber.init().await.expect("connect subscriber");
    Arc::new(
        ValkeyReloadCoordinator::start(
            publisher,
            subscriber,
            prefix,
            NonZeroUsize::new(16).unwrap(),
        )
        .await
        .expect("start"),
    )
}

fn store(doc: &str, coordinator: Arc<ValkeyReloadCoordinator>) -> Arc<AuthzStore<Provider>> {
    let policies = Arc::new(PolicyStore::from_text(&permit(doc), SCHEMA).unwrap());
    Arc::new(
        AuthzStore::try_new(policies, Arc::new(Provider), "App")
            .unwrap()
            .with_coordinator(coordinator),
    )
}

async fn allowed(store: &Arc<AuthzStore<Provider>>, doc: &str) -> bool {
    store
        .for_user_id("alice")
        .unwrap()
        .is_permitted("View", &doc.to_string())
        .await
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_reload_on_one_store_reaches_a_second_store_through_valkey() {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    // A prefix per run keeps concurrent test runs on one server apart.
    let prefix = format!("axess_reload_test_{}", uuid::Uuid::new_v4().simple());

    let a = store("doc1", coordinator(&url, &prefix).await);
    let b = store("doc1", coordinator(&url, &prefix).await);
    let source = Arc::new(Source(Mutex::new(permit("doc1"))));
    // A long poll: only the notice can make B move within the test.
    let _follower = b
        .follow_reloads(source.clone(), Duration::from_secs(3600))
        .await
        .expect("follow");

    *source.0.lock().unwrap() = permit("doc2");
    let reloaded = a
        .reload_policies(&permit("doc2"), SCHEMA)
        .await
        .expect("reload");
    assert!(reloaded.announced, "the notice was published");

    for _ in 0..300 {
        if allowed(&b, "doc2").await {
            assert!(!allowed(&b, "doc1").await);
            assert_eq!(a.policy_digest(), b.policy_digest());
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the second store did not follow the notice within 3s");
}
