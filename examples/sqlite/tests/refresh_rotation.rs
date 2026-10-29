//! Refresh-token rotation against the real SQL path: one parent rotates
//! once. The second rotation of the same parent finds it revoked, stores
//! nothing and answers `ParentAlreadyRevoked`, which the session layer
//! treats as a reuse. Before the conditional UPDATE both rotations
//! succeeded and two live children existed for one presented token.

use axess::authn::{TenantId, UserId};
use axess::session::{RefreshToken, RefreshTokenId, RefreshTokenStore, RotationOutcome};
use axess::{Clock, SystemClock};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const TENANT: &str = "00000000-0000-0000-0000-000000000001";

async fn backend() -> OurBackend {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("in-memory url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    seed(&SystemClock, &pool).await.expect("seed");
    OurBackend::new(pool)
}

fn token(suffix: &str) -> RefreshToken {
    let now = SystemClock.now();
    RefreshToken {
        id: RefreshTokenId::try_new(format!("00000000-0000-0000-0000-0000000000{suffix}"))
            .expect("token id"),
        user_id: UserId::try_new(ALICE).expect("user id"),
        tenant_id: TenantId::try_new(TENANT).expect("tenant id"),
        token_hash: format!("hash-{suffix}"),
        issued_at: now,
        expires_at: now + chrono::Duration::days(30),
        revoked: false,
        device_info: None,
        family_id: None,
        device_id: None,
        authn_time: None,
        revoked_reason: None,
        revoked_at: None,
    }
}

#[tokio::test]
async fn a_parent_rotates_once_and_a_second_rotation_is_a_lost_race() {
    let store = backend().await;
    let parent = token("a0");
    store.store_token(&parent).await.expect("store parent");

    let first = store
        .rotate_token(&parent.id, &token("a1"))
        .await
        .expect("first rotation");
    assert_eq!(first, RotationOutcome::Rotated);

    let second = store
        .rotate_token(&parent.id, &token("a2"))
        .await
        .expect("second rotation runs");
    assert_eq!(
        second,
        RotationOutcome::ParentAlreadyRevoked,
        "the parent was already revoked"
    );

    let active = store
        .active_tokens(&parent.user_id)
        .await
        .expect("active tokens");
    let ids: Vec<String> = active.iter().map(|t| t.id.to_string()).collect();
    assert_eq!(
        ids,
        vec![token("a1").id.to_string()],
        "exactly the first child is live: {ids:?}"
    );
}

/// Each way of revoking a token records its own reason, and a later sweep
/// never rewrites it: only a `Rotated` token's reuse is a theft signal.
#[tokio::test]
async fn revocation_reasons_are_persisted_and_not_overwritten() {
    use axess::session::RevocationReason;
    let store = backend().await;
    let user = UserId::try_new(ALICE).expect("user id");

    let rotated = token("b0");
    store.store_token(&rotated).await.expect("store");
    let mut child = token("b1");
    child.family_id = rotated.family_id;
    assert_eq!(
        store
            .rotate_token(&rotated.id, &child)
            .await
            .expect("rotate"),
        RotationOutcome::Rotated
    );
    let logged_out = token("b2");
    store.store_token(&logged_out).await.expect("store");
    store.revoke_token(&logged_out.id).await.expect("revoke");

    let family = axess::session::TokenFamilyId::try_new("00000000-0000-0000-0000-0000000000f1")
        .expect("family id");
    let mut swept = token("b3");
    swept.family_id = Some(family);
    store.store_token(&swept).await.expect("store");
    store.revoke_family(&user, &family).await.expect("family");
    store.revoke_user_tokens(&user).await.expect("all");

    let reason = |hash: &str| {
        let hash = hash.to_string();
        let store = &store;
        async move {
            store
                .find_token(&hash)
                .await
                .expect("find")
                .expect("row")
                .revoked_reason
        }
    };
    assert_eq!(reason("hash-b0").await, Some(RevocationReason::Rotated));
    assert_eq!(reason("hash-b2").await, Some(RevocationReason::Explicit));
    assert_eq!(reason("hash-b3").await, Some(RevocationReason::Compromise));
    assert!(
        store
            .find_token("hash-b0")
            .await
            .expect("find")
            .expect("row")
            .revoked_at
            .is_some()
    );
}
