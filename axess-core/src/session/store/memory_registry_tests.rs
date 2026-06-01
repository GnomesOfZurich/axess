use super::*;
use axess_rng::SystemRng;

fn uid(s: &str) -> crate::authn::ids::UserId {
    axess_identity::testing::user(s)
}

/// `active_sessions` returns sessions in registration order, oldest
/// first. The `max_sessions_per_user` eviction loop in
/// `complete_factor_step` takes from the head and depends on this
/// ordering to evict the oldest session, so the Vec representation
/// in `MemorySessionRegistry` is load-bearing.
#[tokio::test]
async fn active_sessions_returns_oldest_first() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionId::new(&rng);
    let s2 = SessionId::new(&rng);
    let s3 = SessionId::new(&rng);

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    registry.register(&user, &s3).await.unwrap();

    let active = registry.active_sessions(&user).await.unwrap();
    assert_eq!(
        active,
        vec![s1, s2, s3],
        "registration order must be preserved (oldest first)"
    );
}

/// Re-registering an already-present session id is a no-op,
/// not an append. Otherwise concurrent legitimate session-touches
/// would each push a duplicate, breaking the FIFO eviction contract
/// (the duplicate would advance the id to the tail, making it look
/// "newest" relative to its earlier siblings).
#[tokio::test]
async fn active_sessions_dedup_on_reregister() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionId::new(&rng);
    let s2 = SessionId::new(&rng);

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    registry.register(&user, &s1).await.unwrap();

    let active = registry.active_sessions(&user).await.unwrap();
    assert_eq!(
        active,
        vec![s1, s2],
        "re-register of s1 must keep the original FIFO position, not push a duplicate"
    );
}

/// Invalidating a single session removes it from the order,
/// leaving the rest intact and re-`active_sessions` reflects the
/// shorter list.
#[tokio::test]
async fn invalidate_session_removes_from_order() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionId::new(&rng);
    let s2 = SessionId::new(&rng);
    let s3 = SessionId::new(&rng);

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    registry.register(&user, &s3).await.unwrap();

    registry.invalidate_session(&user, &s2).await.unwrap();

    let active = registry.active_sessions(&user).await.unwrap();
    assert_eq!(
        active,
        vec![s1, s3],
        "invalidate_session removes the named id while preserving the rest in order"
    );
    assert!(!registry.is_valid(&user, &s2).await.unwrap());
}

/// `active_sessions` for an unknown user returns the empty vec, not
/// an error; the eviction loop should treat "no registered
/// sessions" as a fresh slate.
#[tokio::test]
async fn active_sessions_unknown_user_returns_empty() {
    let registry = MemorySessionRegistry::new();
    let active = registry.active_sessions(&uid("ghost")).await.unwrap();
    assert!(active.is_empty());
}

/// `invalidate_user` removes ALL sessions for the user.
#[tokio::test]
async fn invalidate_user_removes_all_sessions() {
    let registry = MemorySessionRegistry::new();
    let user = uid("u1");
    let rng = SystemRng;
    let s1 = SessionId::new(&rng);
    let s2 = SessionId::new(&rng);

    registry.register(&user, &s1).await.unwrap();
    registry.register(&user, &s2).await.unwrap();
    assert!(registry.is_valid(&user, &s1).await.unwrap());
    assert!(registry.is_valid(&user, &s2).await.unwrap());

    registry.invalidate_user(&user).await.unwrap();

    assert!(
        !registry.is_valid(&user, &s1).await.unwrap(),
        "invalidate_user must remove s1"
    );
    assert!(
        !registry.is_valid(&user, &s2).await.unwrap(),
        "invalidate_user must remove s2"
    );
    assert!(
        registry.active_sessions(&user).await.unwrap().is_empty(),
        "active_sessions must be empty after invalidate_user"
    );
}

/// `invalidate_user` for one user must not affect another.
#[tokio::test]
async fn invalidate_user_does_not_affect_other_users() {
    let registry = MemorySessionRegistry::new();
    let alice = uid("alice");
    let bob = uid("bob");
    let rng = SystemRng;
    let s_alice = SessionId::new(&rng);
    let s_bob = SessionId::new(&rng);

    registry.register(&alice, &s_alice).await.unwrap();
    registry.register(&bob, &s_bob).await.unwrap();

    registry.invalidate_user(&alice).await.unwrap();

    assert!(!registry.is_valid(&alice, &s_alice).await.unwrap());
    assert!(
        registry.is_valid(&bob, &s_bob).await.unwrap(),
        "bob's session must survive alice's invalidate_user"
    );
}

/// MemorySessionStore HealthCheck returns Healthy.
#[tokio::test]
async fn memory_store_health_check_returns_healthy() {
    use crate::health::HealthCheck;
    let store = MemorySessionStore::new();
    let status = store.check().await;
    assert_eq!(status, HealthStatus::Healthy);
}

/// MemorySessionRegistry HealthCheck returns Healthy.
#[tokio::test]
async fn memory_registry_health_check_returns_healthy() {
    use crate::health::HealthCheck;
    let registry = MemorySessionRegistry::new();
    let status = registry.check().await;
    assert_eq!(status, HealthStatus::Healthy);
}

/// Cycle atomically moves session data to a new id.
#[tokio::test]
async fn cycle_moves_data_to_new_id() {
    let store = MemorySessionStore::new();
    let rng = SystemRng;
    let old_id = SessionId::new(&rng);
    let new_id = SessionId::new(&rng);
    let data = SessionData::default();

    store
        .save(&old_id, &data, Duration::from_secs(60))
        .await
        .unwrap();
    store
        .cycle(&old_id, &new_id, &data, Duration::from_secs(60))
        .await
        .unwrap();

    assert!(
        store.load(&old_id).await.unwrap().is_none(),
        "old id must be gone after cycle"
    );
    assert!(
        store.load(&new_id).await.unwrap().is_some(),
        "new id must have the data after cycle"
    );
}
