//! A user-scoped auth method belongs to the tenant it was saved in. Asking
//! for a user's methods in one tenant never lists a row saved for the same
//! user id in another tenant.

use axess::SystemClock;
use axess::authn::{AuthMethod, AuthnScope, FactorKind, FactorStore, TenantId, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const OTHER_TENANT: &str = "00000000-0000-0000-0000-000000000000";
const ALICE: &str = "00000000-0000-0000-0000-000000000010";

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
    seed(
        &SystemClock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");
    pool
}

#[tokio::test]
async fn a_users_method_in_another_tenant_is_not_listed() {
    let backend = OurBackend::new(pool().await);
    let alice = UserId::try_new(ALICE).expect("user");
    let other = TenantId::try_new(OTHER_TENANT).expect("tenant");
    backend
        .save_method(
            &AuthnScope::User {
                user_id: alice,
                tenant_id: other,
            },
            AuthMethod::sequential("elsewhere", vec![FactorKind::Password], AuthnScope::System),
        )
        .await
        .expect("save");

    let here = TenantId::try_new(TENANT).expect("tenant");
    let names: Vec<String> = backend
        .available_methods(&alice, &here)
        .await
        .expect("methods")
        .iter()
        .map(|m| m.name.to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n == "elsewhere"),
        "another tenant's method was listed: {names:?}"
    );
}
