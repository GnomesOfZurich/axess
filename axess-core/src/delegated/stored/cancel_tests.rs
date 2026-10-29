//! A cancelled refresh does not lose the rotated refresh token.

use super::*;
use axess_clock::testing::MockClock;
use axess_identity::{TenantId, UserId};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn t0() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("fixed t0")
}

/// The IdP redeems the token (and rotates it) after the caller has gone: the
/// stored credential still ends up holding the new refresh token, because
/// the redeem-and-save step does not run on the caller's future.
#[tokio::test]
async fn a_dropped_refresh_still_saves_the_rotated_token() {
    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(400))
                .set_body_json(json!({
                    "access_token": "fresh-access",
                    "refresh_token": "rotated-refresh",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                })),
        )
        .expect(1)
        .mount(&idp)
        .await;

    let provider = Arc::new(DelegatedProvider::new(
        "p",
        Url::parse("https://idp.example/authorize").unwrap(),
        Url::parse(&format!("{}/token", idp.uri())).unwrap(),
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
                refresh_token: Some("spent-on-redeem".into()),
                expires_at: Some(t0() - chrono::Duration::seconds(60)),
                scopes: vec![],
                token_type: "Bearer".to_string(),
            },
        )
        .await
        .expect("save");

    let session = StoredDelegationSession::new(provider.clone(), store.clone(), tenant, user)
        .with_clock(Arc::new(MockClock::at(t0())));
    // The caller gives up long before the IdP answers; its future is dropped.
    let outcome = tokio::time::timeout(Duration::from_millis(50), session.get_access_token()).await;
    assert!(outcome.is_err(), "the caller timed out");

    let mut stored = None;
    for _ in 0..100 {
        let cred = store
            .load(&tenant, &user, &provider.name)
            .await
            .expect("load")
            .expect("present");
        if cred.refresh_token.as_deref() == Some("rotated-refresh") {
            stored = Some(cred);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stored = stored.expect("the rotated refresh token was saved after the caller left");
    assert_eq!(&*stored.access_token, "fresh-access");

    // The next caller finds the fresh credential and asks the IdP for nothing.
    let next = session.get_access_token().await.expect("fresh token");
    assert_eq!(next, "fresh-access");
}
