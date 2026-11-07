//! A refresh in flight does not bring back a credential that was revoked.

use super::*;
use crate::delegated::error::DelegatedError;
use axess_clock::testing::MockClock;
use axess_identity::{TenantId, UserId};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use url::Url;

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("fixed t0")
}

/// A token endpoint that reads the request, tells the test it arrived, and
/// answers only after the test releases it.
async fn held_token_endpoint() -> (String, Arc<Notify>, Arc<Notify>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (a, r) = (Arc::clone(&arrived), Arc::clone(&release));
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 8192];
        let _ = sock.read(&mut buf).await;
        a.notify_one();
        r.notified().await;
        let body = r#"{"access_token":"fresh-access","refresh_token":"rotated","expires_in":3600,"token_type":"Bearer"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes()).await;
    });
    (format!("http://{addr}/token"), arrived, release)
}

#[tokio::test]
async fn a_refresh_in_flight_does_not_revive_a_revoked_credential() {
    let (token_url, arrived, release) = held_token_endpoint().await;
    let provider = Arc::new(DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(&token_url).unwrap(),
        "client",
        "secret",
        Url::parse("https://gnomes.local/callback").unwrap(),
    ));
    let store = Arc::new(MemoryDelegatedCredentialStore::new());
    let (tenant, user) = (TenantId::from_bytes([1; 16]), UserId::from_bytes([2; 16]));
    store
        .save(
            &tenant,
            &user,
            StoredDelegation {
                provider: provider.name.clone(),
                access_token: "stale".into(),
                refresh_token: Some("old-refresh".into()),
                expires_at: Some(t0() - chrono::Duration::seconds(60)),
                scopes: vec![],
                token_type: "Bearer".to_string(),
            },
        )
        .await
        .expect("save");
    let session = Arc::new(
        StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
            .expect("the default client builds")
            .with_clock(Arc::new(MockClock::at(t0()))),
    );

    let refreshing = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.get_access_token().await })
    };
    tokio::time::timeout(Duration::from_secs(5), arrived.notified())
        .await
        .expect("the refresh reached the token endpoint");

    let revoking = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.revoke().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    release.notify_one();

    let _ = tokio::time::timeout(Duration::from_secs(5), refreshing).await;
    tokio::time::timeout(Duration::from_secs(5), revoking)
        .await
        .expect("revoke finishes")
        .expect("join")
        .expect("revoke");

    assert!(
        matches!(
            session.get_access_token().await,
            Err(DelegatedError::NotConnected)
        ),
        "no token comes back after revoke returned"
    );
}

/// A refresh is held at the token endpoint while another process revokes: the
/// store is touched directly, so no lock of this process orders it. Whatever
/// the store, the revoke holds once the refresh ends.
#[cfg(feature = "delegated-stored-encrypted")]
#[tokio::test]
async fn a_revoke_from_another_process_survives_a_refresh_over_the_encrypted_store() {
    use crate::delegated::stored::encrypted::{
        EncryptedDelegatedCredentialStore, MemoryKeyProvider,
    };

    let (token_url, arrived, release) = held_token_endpoint().await;
    let provider = Arc::new(DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(&token_url).unwrap(),
        "client",
        "secret",
        Url::parse("https://gnomes.local/callback").unwrap(),
    ));
    let keys = MemoryKeyProvider::new("k1", std::array::from_fn(|i| 7u8.wrapping_add(i as u8)))
        .expect("key");
    let store = Arc::new(EncryptedDelegatedCredentialStore::new(
        MemoryDelegatedCredentialStore::new(),
        keys,
    ));
    let (tenant, user) = (TenantId::from_bytes([1; 16]), UserId::from_bytes([2; 16]));
    store
        .save(
            &tenant,
            &user,
            StoredDelegation {
                provider: provider.name.clone(),
                access_token: "stale".into(),
                refresh_token: Some("old-refresh".into()),
                expires_at: Some(t0() - chrono::Duration::seconds(60)),
                scopes: vec![],
                token_type: "Bearer".to_string(),
            },
        )
        .await
        .expect("save");
    let session = Arc::new(
        StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
            .expect("the default client builds")
            .with_clock(Arc::new(MockClock::at(t0()))),
    );

    let refreshing = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.get_access_token().await })
    };
    tokio::time::timeout(Duration::from_secs(5), arrived.notified())
        .await
        .expect("the refresh reached the token endpoint");

    // The other process: straight to the store.
    store
        .revoke(&tenant, &user, &provider.name)
        .await
        .expect("revoke");
    release.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(5), refreshing).await;

    assert!(
        matches!(
            session.get_access_token().await,
            Err(DelegatedError::NotConnected)
        ),
        "the refresh did not write the row back over the revoke"
    );
}

/// A store that answers `Unsupported` explicitly still has its refresh
/// written, by the unconditional save.
struct NoSwap(MemoryDelegatedCredentialStore);

impl DelegatedCredentialStore for NoSwap {
    async fn load(
        &self,
        t: &TenantId,
        u: &UserId,
        p: &str,
    ) -> Result<Option<StoredDelegation>, String> {
        self.0.load(t, u, p).await
    }
    async fn save(&self, t: &TenantId, u: &UserId, c: StoredDelegation) -> Result<(), String> {
        self.0.save(t, u, c).await
    }
    async fn save_if_unchanged(
        &self,
        _: &TenantId,
        _: &UserId,
        _: &StoredDelegation,
        _: StoredDelegation,
    ) -> Result<CredentialSwap, String> {
        Ok(CredentialSwap::Unsupported)
    }
    async fn revoke(&self, t: &TenantId, u: &UserId, p: &str) -> Result<(), String> {
        self.0.revoke(t, u, p).await
    }
}

#[tokio::test]
async fn a_store_that_answers_unsupported_still_has_its_refresh_saved() {
    let (token_url, arrived, release) = held_token_endpoint().await;
    let provider = Arc::new(DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(&token_url).unwrap(),
        "client",
        "secret",
        Url::parse("https://gnomes.local/callback").unwrap(),
    ));
    let store = Arc::new(NoSwap(MemoryDelegatedCredentialStore::new()));
    let (tenant, user) = (TenantId::from_bytes([1; 16]), UserId::from_bytes([2; 16]));
    store
        .save(
            &tenant,
            &user,
            StoredDelegation {
                provider: provider.name.clone(),
                access_token: "stale".into(),
                refresh_token: Some("old-refresh".into()),
                expires_at: Some(t0() - chrono::Duration::seconds(60)),
                scopes: vec![],
                token_type: "Bearer".to_string(),
            },
        )
        .await
        .expect("save");
    let session = Arc::new(
        StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
            .expect("the default client builds")
            .with_clock(Arc::new(MockClock::at(t0()))),
    );
    let refreshing = {
        let session = Arc::clone(&session);
        tokio::spawn(async move { session.get_access_token().await })
    };
    tokio::time::timeout(Duration::from_secs(5), arrived.notified())
        .await
        .expect("the refresh reached the token endpoint");
    release.notify_one();
    let token = refreshing.await.expect("join").expect("refresh");
    assert_eq!(token, "fresh-access");
    let stored = store
        .load(&tenant, &user, &provider.name)
        .await
        .expect("load")
        .expect("present");
    assert_eq!(stored.refresh_token.as_deref(), Some("rotated"));
}
