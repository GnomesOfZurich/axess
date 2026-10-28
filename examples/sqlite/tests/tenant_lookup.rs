//! `IdentityLookup::get_user_tenant` against the real SQL path: it selects the
//! tenant column alone, which is all the session validator's per-request
//! cross-check needs.

use axess::SystemClock;
use axess::authn::{IdentityLookup, TenantId, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const ALICE: &str = "00000000-0000-0000-0000-000000000010";
const TENANT: &str = "00000000-0000-0000-0000-000000000001";

async fn pool() -> sqlx::SqlitePool {
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
    pool
}

#[tokio::test]
async fn the_tenant_is_read_without_loading_the_user() {
    let pool = pool().await;
    let backend = OurBackend::new(pool.clone());
    let alice = UserId::try_new(ALICE).expect("user id");
    let tenant = TenantId::try_new(TENANT).expect("tenant id");

    assert_eq!(
        backend.get_user_tenant(&alice).await.expect("lookup"),
        Some(tenant)
    );

    // A column the full user row needs and the tenant lookup does not. The
    // full read would panic decoding it; the narrow one never touches it.
    sqlx::query("UPDATE users SET created_by = 'not a user id' WHERE id = ?1")
        .bind(ALICE)
        .execute(&pool)
        .await
        .expect("corrupt an unrelated column");
    assert_eq!(
        backend.get_user_tenant(&alice).await.expect("lookup"),
        Some(TenantId::try_new(TENANT).expect("tenant id")),
        "only users.tenant_id is read"
    );

    let nobody = UserId::try_new("00000000-0000-0000-0000-0000000000ff").expect("user id");
    assert_eq!(
        backend.get_user_tenant(&nobody).await.expect("lookup"),
        None
    );
}
