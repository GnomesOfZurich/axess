//! `tests`: extracted from `memory.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use axess_clock::testing::MockClock;
use chrono::TimeZone;

type S = MemoryStore<String, u32>;

fn anchor() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

fn store_with_clock() -> (S, Arc<MockClock>) {
    let clock = Arc::new(MockClock::at(anchor()));
    let store = S::new().with_clock(clock.clone() as Arc<dyn Clock>);
    (store, clock)
}

#[tokio::test]
async fn put_then_get_returns_value() {
    let (s, _clock) = store_with_clock();
    s.put(&"k".to_string(), &42, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(s.get(&"k".to_string()).await.unwrap(), Some(42));
}

#[tokio::test]
async fn get_missing_returns_none() {
    let (s, _clock) = store_with_clock();
    assert_eq!(s.get(&"missing".to_string()).await.unwrap(), None);
}

#[tokio::test]
async fn put_overwrites_existing_value() {
    let (s, _clock) = store_with_clock();
    s.put(&"k".to_string(), &1, Duration::from_secs(60))
        .await
        .unwrap();
    s.put(&"k".to_string(), &2, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(s.get(&"k".to_string()).await.unwrap(), Some(2));
}

#[tokio::test]
async fn delete_removes_entry() {
    let (s, _clock) = store_with_clock();
    s.put(&"k".to_string(), &1, Duration::from_secs(60))
        .await
        .unwrap();
    s.delete(&"k".to_string()).await.unwrap();
    assert_eq!(s.get(&"k".to_string()).await.unwrap(), None);
}

#[tokio::test]
async fn delete_missing_is_idempotent() {
    let (s, _clock) = store_with_clock();
    s.delete(&"never-existed".to_string()).await.unwrap();
}

#[tokio::test]
async fn get_returns_none_after_ttl_expiry() {
    let (s, clock) = store_with_clock();
    s.put(&"k".to_string(), &1, Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);
    assert_eq!(
        s.get(&"k".to_string()).await.unwrap(),
        None,
        "expired entry must not be returned by get"
    );
}

#[tokio::test]
async fn prune_expired_reclaims_only_expired_entries() {
    let (s, clock) = store_with_clock();
    s.put(&"short".to_string(), &1, Duration::from_secs(10))
        .await
        .unwrap();
    s.put(&"long".to_string(), &2, Duration::from_secs(3600))
        .await
        .unwrap();
    clock.advance_secs(11);
    let removed = s.prune_expired().await.unwrap();
    assert_eq!(removed, 1, "only the short-TTL entry must be reclaimed");
    assert_eq!(s.get(&"long".to_string()).await.unwrap(), Some(2));
}

#[tokio::test]
async fn prune_expired_returns_zero_when_nothing_expired() {
    let (s, _clock) = store_with_clock();
    s.put(&"k".to_string(), &1, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(s.prune_expired().await.unwrap(), 0);
}

#[tokio::test]
async fn duration_max_treated_as_never_expire_without_panic() {
    let (s, clock) = store_with_clock();
    s.put(&"forever".to_string(), &1, Duration::MAX)
        .await
        .unwrap();
    // Even after a century, the never-expire entry is still readable.
    clock.advance_secs(60 * 60 * 24 * 365 * 100);
    assert_eq!(s.get(&"forever".to_string()).await.unwrap(), Some(1));
}

#[tokio::test]
async fn snapshot_returns_live_entries_only() {
    let (s, clock) = store_with_clock();
    s.put(&"alive".to_string(), &1, Duration::from_secs(3600))
        .await
        .unwrap();
    s.put(&"dead".to_string(), &2, Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);
    let snap = s.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0], ("alive".to_string(), 1));
}

#[tokio::test]
async fn snapshot_excludes_entry_at_exact_expiry_time() {
    // Pins the `expires_at > now` comparison in `snapshot` against the
    // `>=` mutation. At `now == expires_at` the entry must be treated
    // as expired (not visible). With `>=`, the same instant would
    // count as still-live and the entry would surface.
    let (s, clock) = store_with_clock();
    s.put(&"boundary".to_string(), &7, Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(10);
    let snap = s.snapshot();
    assert!(
        snap.is_empty(),
        "entry at `expires_at == now` must be expired, not live; got {snap:?}"
    );
}

#[tokio::test]
async fn update_returns_false_at_exact_expiry_time() {
    // Pins the `expires_at > now` comparison in `update` against the
    // `>=` mutation. Same logic as snapshot: the entry must be
    // considered absent at the exact expiry instant.
    let (s, clock) = store_with_clock();
    s.put(&"boundary".to_string(), &7, Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(10);
    let updated = s.update(&"boundary".to_string(), |v| *v += 1);
    assert!(
        !updated,
        "update at `expires_at == now` must be a no-op (entry expired)"
    );
}

#[tokio::test]
async fn update_mutates_existing_entry() {
    let (s, _clock) = store_with_clock();
    s.put(&"k".to_string(), &10, Duration::from_secs(60))
        .await
        .unwrap();
    let updated = s.update(&"k".to_string(), |v| *v += 5);
    assert!(updated);
    assert_eq!(s.get(&"k".to_string()).await.unwrap(), Some(15));
}

#[tokio::test]
async fn update_returns_false_for_missing_key() {
    let (s, _clock) = store_with_clock();
    let updated = s.update(&"never-existed".to_string(), |v| *v += 1);
    assert!(!updated);
}

#[tokio::test]
async fn update_returns_false_for_expired_entry() {
    let (s, clock) = store_with_clock();
    s.put(&"k".to_string(), &1, Duration::from_secs(10))
        .await
        .unwrap();
    clock.advance_secs(11);
    let updated = s.update(&"k".to_string(), |v| *v += 1);
    assert!(!updated, "expired entry must be treated as absent");
}

#[tokio::test]
async fn clone_shares_state_via_arc() {
    let (s1, _clock) = store_with_clock();
    let s2 = s1.clone();
    s1.put(&"k".to_string(), &42, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(s2.get(&"k".to_string()).await.unwrap(), Some(42));
}

#[tokio::test]
async fn len_and_is_empty_track_size() {
    let (s, _clock) = store_with_clock();
    assert!(s.is_empty());
    s.put(&"a".to_string(), &1, Duration::from_secs(60))
        .await
        .unwrap();
    s.put(&"b".to_string(), &2, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(s.len(), 2);
    assert!(!s.is_empty());
}

#[tokio::test]
async fn default_clock_is_system_clock() {
    // Default `new()` uses SystemClock; verified by `now()` falling
    // within ~5s of std `Utc::now()`. (Not 0; SystemClock is
    // wall-clock-driven; we just confirm the value is plausibly
    // current.)
    let s = S::new();
    let now_via_clock = s.clock().now();
    let now_via_std = Utc::now();
    let drift = (now_via_std - now_via_clock).num_seconds().abs();
    assert!(drift < 5, "SystemClock drift {drift}s exceeds tolerance");
}
