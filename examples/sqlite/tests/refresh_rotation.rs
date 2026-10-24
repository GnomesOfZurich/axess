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
