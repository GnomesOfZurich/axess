//! The throttle entry is a row per tenant, user and address: recorded in one
//! statement so parallel failures all count, read back as the library
//! expects it, cleared by a right guess, and forgotten once stale.

use axess::Clock;
use axess::authn::{IdentityAuthnLog, TenantId, Throttle, ThrottleSubject, UserId};
use axess_example_sqlite::models::backend::{OurBackend, seed};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

/// A clock the test moves by hand.
#[derive(Clone)]
struct MockClock(Arc<Mutex<DateTime<Utc>>>);

impl MockClock {
    fn advance(&self, by: chrono::Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for MockClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

async fn backend() -> (OurBackend, MockClock, UserId, TenantId) {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("in-memory url")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!().run(&pool).await.expect("migrations");
    let clock = MockClock(Arc::new(Mutex::new(
        DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    )));
    seed(
        &clock,
        &pool,
        &axess::authn::FactorSecretCipher::new(*b"0123456789abcdef0123456789abcdeF"),
    )
    .await
    .expect("seed");
    let (id, tenant): (String, String) = sqlx::query_as("SELECT id, tenant_id FROM users LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a seeded user");
    (
        OurBackend::new(pool).with_clock(Arc::new(clock.clone())),
        clock,
        UserId::try_new(&id).expect("a user id"),
        TenantId::try_new(&tenant).expect("a tenant id"),
    )
}

fn subject(tenant: &TenantId, user: &UserId, last: u8) -> ThrottleSubject {
    Throttle::default().subject(
        tenant,
        user,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))),
    )
}

#[tokio::test]
async fn a_failure_is_recorded_under_its_key_and_read_back() {
    let (backend, clock, user, tenant) = backend().await;
    let throttle = Throttle::default();
    let key = subject(&tenant, &user, 1);
    assert_eq!(backend.throttle_state(&key).await.unwrap(), None);
    backend
        .record_throttle_failure(&key, &throttle)
        .await
        .unwrap();
    backend
        .record_throttle_failure(&key, &throttle)
        .await
        .unwrap();
    let state = backend.throttle_state(&key).await.unwrap().unwrap();
    assert_eq!((state.failures, state.last_failure_at), (2, clock.now()));
    assert_eq!(
        backend
            .throttle_state(&subject(&tenant, &user, 2))
            .await
            .unwrap(),
        None,
        "another address is another key"
    );
    assert_eq!(
        backend
            .throttle_state(&Throttle::default().subject(&tenant, &user, None))
            .await
            .unwrap(),
        None,
        "the account-only key is a key of its own"
    );
}

#[tokio::test]
async fn parallel_failures_are_all_counted() {
    let (backend, _clock, user, tenant) = backend().await;
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let backend = backend.clone();
        let key = subject(&tenant, &user, 1);
        set.spawn(async move {
            backend
                .record_throttle_failure(&key, &Throttle::default())
                .await
                .unwrap()
        });
    }
    while let Some(done) = set.join_next().await {
        done.unwrap();
    }
    let state = backend
        .throttle_state(&subject(&tenant, &user, 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.failures, 12);
}

#[tokio::test]
async fn a_right_guess_clears_the_key() {
    let (backend, _clock, user, tenant) = backend().await;
    let key = subject(&tenant, &user, 1);
    backend
        .record_throttle_failure(&key, &Throttle::default())
        .await
        .unwrap();
    backend.clear_throttle(&key).await.unwrap();
    assert_eq!(backend.throttle_state(&key).await.unwrap(), None);
    assert!(
        backend.clear_throttle(&key).await.is_ok(),
        "clearing nothing is fine"
    );
}

#[tokio::test]
async fn a_stale_key_starts_over_and_stale_rows_are_deleted() {
    let (backend, clock, user, tenant) = backend().await;
    let throttle = Throttle::default();
    let key = subject(&tenant, &user, 1);
    let other = subject(&tenant, &user, 2);
    for _ in 0..3 {
        backend
            .record_throttle_failure(&key, &throttle)
            .await
            .unwrap();
    }
    backend
        .record_throttle_failure(&other, &throttle)
        .await
        .unwrap();
    // Older than twice max_delay (128 s): as good as absent.
    clock.advance(chrono::Duration::seconds(129));
    backend
        .record_throttle_failure(&key, &throttle)
        .await
        .unwrap();
    let state = backend.throttle_state(&key).await.unwrap().unwrap();
    assert_eq!((state.failures, state.last_failure_at), (1, clock.now()));
    assert_eq!(
        backend.throttle_state(&other).await.unwrap(),
        None,
        "every stale row went with the record"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM login_throttle")
        .fetch_one(backend.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1);
}
