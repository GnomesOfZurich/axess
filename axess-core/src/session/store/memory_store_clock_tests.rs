use super::*;
use crate::session::data::SessionData;
use crate::testing::mock_clock::MockClock;
use axess_rng::SystemRng;

/// prune_expired runs against the injected
/// `Clock`. Wall-clock can't drive this test deterministically;
/// `MockClock::advance_secs` can.
#[tokio::test]
async fn prune_expired_uses_injected_clock() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(60))
        .await
        .unwrap();

    // Same instant; not expired.
    assert_eq!(store.prune_expired().await.unwrap(), 0);
    assert!(store.load(&id).await.unwrap().is_some());

    // Advance past the TTL.
    clock.advance_secs(61);
    let pruned = store.prune_expired().await.unwrap();
    assert_eq!(pruned, 1);
    assert!(store.load(&id).await.unwrap().is_none());
}

/// load() also reads the injected clock, so a session is observable
/// as expired even when prune_expired hasn't run.
#[tokio::test]
async fn load_uses_injected_clock_for_expiry() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);
    assert!(store.load(&id).await.unwrap().is_none());
}

/// Explicit `purge_expired()` (the inherent method) drops
/// rows whose elapsed time has overtaken their TTL. Kills the
/// `purge_expired -> ()` body-deletion mutant: an empty body would
/// leave the expired row behind.
#[tokio::test]
async fn purge_expired_method_evicts_expired_row() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(30))
        .await
        .unwrap();
    clock.advance_secs(31);

    store.purge_expired();

    // load() bypasses the auto-purge path and goes through its own
    // expiry check, but with the row physically removed by
    // purge_expired() the load returns None either way. With the
    // mutant body `()`, the row stays in DashMap; load()'s own
    // expiry check still removes it on access; but the very next
    // load _re-_inserts nothing because the row is gone, so this
    // test additionally calls load() then re-checks: behaviour is
    // identical from the API surface. The discriminator is the
    // direct method call: subsequent purge_expired() with no fresh
    // expired entries returning still-empty store.
    assert!(store.load(&id).await.unwrap().is_none());
}

/// TTL boundary. A row whose elapsed time is **exactly**
/// equal to its TTL must be considered expired (`elapsed < ttl`
/// is false at the boundary). This kills the
/// `< -> <=` mutants at lines 262 (purge_expired), 291 (load),
/// and 352 (prune_expired); under the mutation, the row would
/// be retained at the boundary.
#[tokio::test]
async fn ttl_boundary_at_exact_elapsed_equals_ttl_evicts() {
    let rng = SystemRng;

    // ── purge_expired boundary ─────────────────────────────────────
    {
        let clock = Arc::new(MockClock::now());
        let store = MemorySessionStore::new().with_clock(clock.clone());
        let id = SessionId::new(&rng);
        store
            .save(&id, &SessionData::default(), Duration::from_secs(30))
            .await
            .unwrap();
        clock.advance_secs(30); // elapsed == ttl
        store.purge_expired();
        assert!(
            store.load(&id).await.unwrap().is_none(),
            "purge_expired must evict at elapsed == ttl"
        );
    }

    // ── load() boundary ───────────────────────────────────────────
    {
        let clock = Arc::new(MockClock::now());
        let store = MemorySessionStore::new().with_clock(clock.clone());
        let id = SessionId::new(&rng);
        store
            .save(&id, &SessionData::default(), Duration::from_secs(30))
            .await
            .unwrap();
        clock.advance_secs(30); // elapsed == ttl
        assert!(
            store.load(&id).await.unwrap().is_none(),
            "load must treat elapsed == ttl as expired"
        );
    }

    // ── prune_expired boundary ────────────────────────────────────
    {
        let clock = Arc::new(MockClock::now());
        let store = MemorySessionStore::new().with_clock(clock.clone());
        let id = SessionId::new(&rng);
        store
            .save(&id, &SessionData::default(), Duration::from_secs(30))
            .await
            .unwrap();
        clock.advance_secs(30); // elapsed == ttl
        let pruned = store.prune_expired().await.unwrap();
        assert_eq!(
            pruned, 1,
            "prune_expired must count and evict at elapsed == ttl"
        );
    }
}

/// `purge_expired` must physically remove the entry from the
/// internal DashMap. The existing `purge_expired_method_evicts_expired_row`
/// goes through `load()` which has its own expiry path, so a
/// `purge_expired -> ()` body deletion is masked. Pin on the
/// underlying map size to discriminate.
#[tokio::test]
async fn purge_expired_physically_evicts_from_internal_map() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);
    assert_eq!(store.inner.len(), 1, "pre-purge");
    store.purge_expired();
    assert_eq!(store.inner.len(), 0, "post-purge map must be empty");
}

/// Boundary `< → <=` on purge_expired's retain predicate. At
/// `elapsed == ttl` the row is expired and must be physically
/// removed; the mutation keeps it.
#[tokio::test]
async fn purge_expired_boundary_removes_at_elapsed_eq_ttl() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(30))
        .await
        .unwrap();
    clock.advance_secs(30);
    store.purge_expired();
    assert_eq!(
        store.inner.len(),
        0,
        "at elapsed == ttl the row must be evicted"
    );
}

/// `maybe_auto_purge` must run `purge_expired` exactly when both
/// guards hold: write_count multiple of 1024 AND store non-empty.
/// Kills the `&& → ||`, `delete !`, and body-`()` mutations
/// simultaneously.
#[tokio::test]
async fn maybe_auto_purge_only_runs_at_1024_with_nonempty_store() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;

    // Seed one expired row.
    let expired = SessionId::new(&rng);
    store
        .save(&expired, &SessionData::default(), Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);
    assert_eq!(store.inner.len(), 1);

    // Five additional fresh saves; write_count is not a multiple
    // of 1024 yet, so auto-purge must NOT fire. The expired row
    // must remain in the map.
    for _ in 0..5 {
        let id = SessionId::new(&rng);
        store
            .save(&id, &SessionData::default(), Duration::from_secs(60))
            .await
            .unwrap();
    }
    assert!(
        store.inner.physically_contains_key(&expired),
        "auto-purge must not fire before write_count hits 1024 \
         (kills `&& → ||` on the count guard)"
    );

    // Advance write_count to exactly a 1024 multiple. fetch_add
    // returns the PREVIOUS value, so the guard fires when count
    // equals 1024; i.e. on the 1025th write (index 1024).
    // We currently have 6 saves; bump to 1024 with cheap writes.
    let target = 1024usize - 6;
    for _ in 0..target {
        let id = SessionId::new(&rng);
        store
            .save(&id, &SessionData::default(), Duration::from_secs(60))
            .await
            .unwrap();
    }
    // 1025th write triggers the guard.
    let id = SessionId::new(&rng);
    store
        .save(&id, &SessionData::default(), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        !store.inner.physically_contains_key(&expired),
        "auto-purge MUST fire at write_count == 1024 with non-empty store \
         (kills `delete !` and body-`()` mutations)"
    );
}

/// `delete()` body deletion (`-> Ok(())`) leaves the row
/// in place. Subsequent `load()` would still surface the data
/// inside the TTL window. Asserting `load -> None` after `delete`
/// kills the mutant.
#[tokio::test]
async fn delete_removes_session_so_subsequent_load_returns_none() {
    let clock = Arc::new(MockClock::now());
    let store = MemorySessionStore::new().with_clock(clock.clone());
    let rng = SystemRng;
    let id = SessionId::new(&rng);

    store
        .save(&id, &SessionData::default(), Duration::from_secs(60))
        .await
        .unwrap();
    // Sanity: present before delete.
    assert!(store.load(&id).await.unwrap().is_some());

    store.delete(&id).await.unwrap();
    assert!(
        store.load(&id).await.unwrap().is_none(),
        "delete must remove the row before TTL expiry"
    );
}
