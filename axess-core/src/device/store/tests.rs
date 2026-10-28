use super::*;
use crate::device::types::DeviceBinding;

fn t() -> TenantId {
    axess_identity::testing::tenant("tenant-1")
}

fn u() -> UserId {
    axess_identity::testing::user("user-1")
}

fn d(id: &str, fp: u8, last_seen: DateTime<Utc>) -> Device {
    Device {
        id: axess_identity::testing::device(id),
        tenant_id: t(),
        user_id: Some(u()),
        trust_level: DeviceTrustLevel::Unknown,
        fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
        first_seen_at: last_seen,
        last_seen_at: last_seen,
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::<DeviceBinding>::new(),
    }
}

#[tokio::test]
async fn save_then_load_round_trips() {
    let store = MemoryDeviceStore::new();
    let device = d("dev-1", 0xaa, Utc::now());
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    let loaded = store.load(&t(), &device.id).await.unwrap();
    assert_eq!(loaded, Some(device));
}

#[tokio::test]
async fn find_by_fingerprint_is_tenant_scoped() {
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    store
        .save(&d("dev-1", 0xaa, now), crate::device::test_now())
        .await
        .unwrap();

    let other_tenant = axess_identity::testing::tenant("tenant-2");
    let hit_same = store
        .find_by_fingerprint(&t(), &FingerprintHash::from_bytes([0xaa; 32]))
        .await
        .unwrap();
    let hit_other = store
        .find_by_fingerprint(&other_tenant, &FingerprintHash::from_bytes([0xaa; 32]))
        .await
        .unwrap();

    assert!(hit_same.is_some(), "same-tenant fingerprint hit expected");
    assert!(
        hit_other.is_none(),
        "cross-tenant fingerprint match must NOT cross the tenant boundary"
    );
}

#[tokio::test]
async fn find_for_user_returns_newest_first_and_respects_limit() {
    let store = MemoryDeviceStore::new();
    let t0 = Utc::now();
    let older = d("dev-old", 0x11, t0 - chrono::Duration::days(2));
    let newer = d("dev-new", 0x22, t0 - chrono::Duration::hours(1));
    store.save(&older, crate::device::test_now()).await.unwrap();
    store.save(&newer, crate::device::test_now()).await.unwrap();

    let listed = store.find_for_user(&t(), &u(), 10).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, newer.id, "newest-sighted first");

    let capped = store.find_for_user(&t(), &u(), 1).await.unwrap();
    assert_eq!(capped.len(), 1);
    assert_eq!(capped[0].id, newer.id);
}

#[tokio::test]
async fn record_sighting_touches_last_seen() {
    let store = MemoryDeviceStore::new();
    let initial = Utc::now();
    let device = d("dev-1", 0xaa, initial);
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    let later = initial + chrono::Duration::hours(1);
    store
        .record_sighting(&t(), &device.id, later)
        .await
        .unwrap();

    let loaded = store.load(&t(), &device.id).await.unwrap().unwrap();
    assert_eq!(loaded.last_seen_at, later);
    assert_eq!(loaded.first_seen_at, initial);
}

#[tokio::test]
async fn set_trust_level_to_revoked_stamps_revoked_at() {
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    let device = d("dev-1", 0xaa, now);
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    let revoked_at = now + chrono::Duration::minutes(5);
    store
        .set_trust_level(&t(), &device.id, DeviceTrustLevel::Revoked, revoked_at)
        .await
        .unwrap();

    let loaded = store.load(&t(), &device.id).await.unwrap().unwrap();
    assert_eq!(loaded.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(loaded.revoked_at, Some(revoked_at));
}

#[tokio::test]
async fn set_trust_level_to_non_revoked_clears_revoked_at() {
    // Re-trusting a previously-revoked device must clear revoked_at;
    // otherwise a stale timestamp lingers and downstream filters
    // ("active devices = revoked_at IS NULL") quietly miss the row.
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    let device = d("dev-1", 0xaa, now);
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    store
        .set_trust_level(&t(), &device.id, DeviceTrustLevel::Revoked, now)
        .await
        .unwrap();
    store
        .set_trust_level(&t(), &device.id, DeviceTrustLevel::Trusted, now)
        .await
        .unwrap();

    let loaded = store.load(&t(), &device.id).await.unwrap().unwrap();
    assert_eq!(loaded.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(loaded.revoked_at, None);
}

#[tokio::test]
async fn delete_removes_both_primary_and_fingerprint_index() {
    let store = MemoryDeviceStore::new();
    let device = d("dev-1", 0xaa, Utc::now());
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    store.delete(&t(), &device.id).await.unwrap();

    assert!(store.load(&t(), &device.id).await.unwrap().is_none());
    let by_fp = store
        .find_by_fingerprint(&t(), &FingerprintHash::from_bytes([0xaa; 32]))
        .await
        .unwrap();
    assert!(
        by_fp.is_none(),
        "fingerprint index must be cleared on delete"
    );
}

#[tokio::test]
async fn len_and_is_empty_track_save_and_delete() {
    // pins `len -> 0` / `len -> 1` and
    // `is_empty -> true` / `is_empty -> false` mutants.
    let store = MemoryDeviceStore::new();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());

    let now = Utc::now();
    store
        .save(&d("dev-1", 0xaa, now), crate::device::test_now())
        .await
        .unwrap();
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());

    store
        .save(&d("dev-2", 0xbb, now), crate::device::test_now())
        .await
        .unwrap();
    assert_eq!(store.len(), 2);
    assert!(!store.is_empty());

    store
        .delete(&t(), &axess_identity::testing::device("dev-1"))
        .await
        .unwrap();
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());

    store
        .delete(&t(), &axess_identity::testing::device("dev-2"))
        .await
        .unwrap();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

#[tokio::test]
async fn find_for_user_filters_out_cross_tenant_rows_for_same_user_id() {
    // pins `find_for_user same_tenant && owned_by_user`
    // → `||` mutant. The mutation widens the filter to "either
    // matches", letting a tenant-2 device owned by u leak into a
    // query for tenant-1. The existing tenant-scoping test only
    // covers the fingerprint index; this asserts the tenant
    // boundary on the `find_for_user` listing path.
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    let other_tenant = axess_identity::testing::tenant("tenant-2");

    // tenant-1: real device for u.
    store
        .save(&d("dev-mine", 0xaa, now), crate::device::test_now())
        .await
        .unwrap();
    // tenant-2: same user_id, different tenant. The && guard
    // must exclude this from a tenant-1 listing.
    let mut foreign = d("dev-foreign", 0xbb, now);
    foreign.tenant_id = other_tenant;
    store
        .save(&foreign, crate::device::test_now())
        .await
        .unwrap();

    let listed = store.find_for_user(&t(), &u(), 10).await.unwrap();
    assert_eq!(
        listed.len(),
        1,
        "tenant-1 listing must NOT include tenant-2 rows"
    );
    // DeviceId is a Uuid newtype now; `testing::device` derives a stable
    // v5 Uuid from the label, so we compare against the same derivation.
    assert_eq!(listed[0].id, axess_identity::testing::device("dev-mine"));

    let foreign_listed = store.find_for_user(&other_tenant, &u(), 10).await.unwrap();
    assert_eq!(foreign_listed.len(), 1);
    assert_eq!(
        foreign_listed[0].id,
        axess_identity::testing::device("dev-foreign")
    );
}

#[tokio::test]
async fn sweep_default_returns_zero_counts() {
    // The trait default is intentionally a no-op (backends override).
    let store = MemoryDeviceStore::new();
    let counts = store.sweep(&t(), Utc::now()).await.unwrap();
    assert_eq!(counts, SweepCounts::default());
}

/// `find_active_for_user` filters out `Revoked` devices. Pins
/// `!= → ==` on the `retain` predicate. With the mutation the
/// filter would invert and surface only revoked devices, hiding
/// every active one (catastrophic for the
/// "show me my active devices" UI it backs).
#[tokio::test]
async fn find_active_for_user_excludes_revoked_devices() {
    let store = MemoryDeviceStore::new();
    let now = Utc::now();

    let mut trusted = d("dev-trusted", 0xaa, now);
    trusted.trust_level = DeviceTrustLevel::Trusted;
    store
        .save(&trusted, crate::device::test_now())
        .await
        .unwrap();

    let mut revoked = d("dev-revoked", 0xbb, now);
    revoked.trust_level = DeviceTrustLevel::Revoked;
    revoked.revoked_at = Some(now);
    store
        .save(&revoked, crate::device::test_now())
        .await
        .unwrap();

    let active = store.find_active_for_user(&t(), &u(), 10).await.unwrap();
    let ids: Vec<_> = active.iter().map(|d| d.id).collect();
    assert!(
        ids.contains(&trusted.id),
        "active set must include the Trusted device"
    );
    assert!(
        !ids.contains(&revoked.id),
        "active set must exclude the Revoked device; `!= → ==` would invert this"
    );
    assert_eq!(active.len(), 1);
}

/// `SweepConfig::builder` returns a `SweepConfigBuilder`, and
/// each setter mutates the corresponding field. `build()`
/// produces the configured `SweepConfig`. Pins:
/// - `builder -> SweepConfigBuilder with Default::default()`
/// - `trusted_idle/seen_idle/revoked_grace -> Self with Default::default()`
/// - `build -> SweepConfig with Default::default()`
#[test]
fn sweep_config_builder_carries_setters_into_build() {
    let cfg = SweepConfig::builder()
        .trusted_idle(chrono::Duration::days(7))
        .seen_idle(chrono::Duration::days(3))
        .revoked_grace(chrono::Duration::days(1))
        .build()
        .unwrap();
    assert_eq!(cfg.trusted_idle, chrono::Duration::days(7));
    assert_eq!(cfg.seen_idle, chrono::Duration::days(3));
    assert_eq!(cfg.revoked_grace, chrono::Duration::days(1));
    assert_ne!(
        cfg,
        SweepConfig::default(),
        "configured sweep windows must NOT equal the default; \
         body-replace `Default::default()` mutation would silently \
         ignore the builder calls"
    );
}

/// `MemoryDeviceStore::with_sweep_config` actually swaps in the
/// supplied [`SweepConfig`] so `sweep` honours its windows. Without
/// this test the `with_sweep_config -> Self with Default::default()`
/// mutation would silently fall back to the 90/30/7 defaults.
#[tokio::test]
async fn with_sweep_config_overrides_default_windows() {
    // Build a config with a 1-second trusted window; much tighter
    // than the 90-day default. A device idle for 2 seconds must
    // demote Trusted→Seen under the custom config; under the
    // default it would not.
    let tight = SweepConfig::builder()
        .trusted_idle(chrono::Duration::seconds(1))
        .seen_idle(chrono::Duration::days(30))
        .revoked_grace(chrono::Duration::days(7))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(tight);

    let t0 = Utc::now();
    let mut device = d("dev-trusted", 0xaa, t0);
    device.trust_level = DeviceTrustLevel::Trusted;
    store
        .save(&device, crate::device::test_now())
        .await
        .unwrap();

    // Sweep 2s later; past the 1s trusted window.
    let counts = store
        .sweep(&t(), t0 + chrono::Duration::seconds(2))
        .await
        .unwrap();
    assert_eq!(
        counts.trusted_to_seen, 1,
        "custom 1s trusted_idle must fire a demotion at t+2s; \
         `with_sweep_config -> Default::default()` would keep the \
         90-day default and report 0 demotions"
    );
}

/// `sweep` walks the Trusted → Seen → Revoked → Purge ladder
/// and returns the right `SweepCounts`. Pins the comparison
/// boundaries (`>` and `==` mutations), the `+=` counter
/// arithmetic, the trust-level guards, and the tenant-scoping
/// `!=` predicate at line 479.
#[tokio::test]
async fn sweep_walks_retention_ladder_and_counts_transitions() {
    let cfg = SweepConfig::builder()
        .trusted_idle(chrono::Duration::days(1))
        .seen_idle(chrono::Duration::days(1))
        .revoked_grace(chrono::Duration::days(1))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(cfg);
    let t0 = Utc::now();
    let other_tenant = axess_identity::testing::tenant("tenant-other");

    // Trusted, idle 3 days → demote to Seen, and no further: a row moves
    // one level per sweep even though 3 days > trusted_idle + seen_idle.
    let mut trusted = d("dev-trusted", 0xaa, t0 - chrono::Duration::days(3));
    trusted.trust_level = DeviceTrustLevel::Trusted;
    store
        .save(&trusted, crate::device::test_now())
        .await
        .unwrap();

    // Seen, idle 3 days → demote to Revoked.
    let mut seen = d("dev-seen", 0xbb, t0 - chrono::Duration::days(3));
    seen.trust_level = DeviceTrustLevel::Seen;
    store.save(&seen, crate::device::test_now()).await.unwrap();

    // Revoked 2 days ago → past the 1-day grace → purge.
    let mut revoked_old = d("dev-revoked-old", 0xcc, t0);
    revoked_old.trust_level = DeviceTrustLevel::Revoked;
    revoked_old.revoked_at = Some(t0 - chrono::Duration::days(2));
    store
        .save(&revoked_old, crate::device::test_now())
        .await
        .unwrap();

    // Revoked just now → still in grace → keep.
    let mut revoked_fresh = d("dev-revoked-fresh", 0xdd, t0);
    revoked_fresh.trust_level = DeviceTrustLevel::Revoked;
    revoked_fresh.revoked_at = Some(t0);
    store
        .save(&revoked_fresh, crate::device::test_now())
        .await
        .unwrap();

    // Different tenant, would-be-demoted; must be skipped by
    // the `device.tenant_id != *tenant_id` guard on line 479.
    let mut foreign = d("dev-foreign", 0xee, t0 - chrono::Duration::days(3));
    foreign.tenant_id = other_tenant;
    foreign.trust_level = DeviceTrustLevel::Trusted;
    store
        .save(&foreign, crate::device::test_now())
        .await
        .unwrap();

    let counts = store.sweep(&t(), t0).await.unwrap();

    // Trusted → Seen (1); Seen → Revoked (1: only the originally-Seen
    // one, the freshly-demoted row starts its Seen window now).
    assert_eq!(
        counts.trusted_to_seen, 1,
        "exactly one device crossed the Trusted window in this tenant; \
         tenant-scope `!= → ==` would flip the count by including the \
         foreign device or excluding the in-scope one"
    );
    assert_eq!(
        counts.seen_to_revoked, 1,
        "only the originally-Seen device is revoked; the demoted one waits"
    );
    let demoted = store.load(&t(), &trusted.id).await.unwrap().unwrap();
    assert_eq!(demoted.trust_level, DeviceTrustLevel::Seen);
    assert_eq!(demoted.demoted_at, Some(t0));
    assert_eq!(
        counts.revoked_purged, 1,
        "only the 2-day-old Revoked is past the 1-day grace; fresh stays"
    );

    // Foreign device unchanged.
    let foreign_after = store
        .load(&other_tenant, &foreign.id)
        .await
        .unwrap()
        .expect("foreign device still present");
    assert_eq!(
        foreign_after.trust_level,
        DeviceTrustLevel::Trusted,
        "cross-tenant device must be untouched by another tenant's sweep"
    );

    // Fresh revoked device unchanged.
    let fresh_after = store
        .load(&t(), &revoked_fresh.id)
        .await
        .unwrap()
        .expect("fresh-revoked still present");
    assert_eq!(fresh_after.trust_level, DeviceTrustLevel::Revoked);

    // Purged device gone.
    assert!(
        store.load(&t(), &revoked_old.id).await.unwrap().is_none(),
        "purged device must be absent after sweep"
    );
}

/// Boundary: at exactly the window threshold the device is NOT
/// transitioned. The predicate is strict `>`, not `>=`. Pins
/// every `>` mutation on line 486 (trusted_idle window).
#[tokio::test]
async fn sweep_window_boundary_is_strict_greater() {
    let cfg = SweepConfig::builder()
        .trusted_idle(chrono::Duration::seconds(60))
        .seen_idle(chrono::Duration::seconds(60))
        .revoked_grace(chrono::Duration::seconds(60))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(cfg);
    let t0 = Utc::now();

    // Last seen exactly 60s ago; sit right on the boundary.
    let mut trusted = d("dev-edge", 0xab, t0 - chrono::Duration::seconds(60));
    trusted.trust_level = DeviceTrustLevel::Trusted;
    store
        .save(&trusted, crate::device::test_now())
        .await
        .unwrap();

    let counts = store.sweep(&t(), t0).await.unwrap();
    assert_eq!(
        counts.trusted_to_seen, 0,
        "exactly-at-threshold device must NOT demote; `> → >=` would flip this"
    );

    // One second past (the comparison is on whole seconds); must demote.
    let counts = store
        .sweep(&t(), t0 + chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(
        counts.trusted_to_seen, 1,
        "one-second-past-threshold must demote; `> → ==` would never fire"
    );
}

/// Strict-`>` boundary on the Seen→Revoked window. Pins
/// `> → >=` on line 495. The cascade test above masks this
/// because cascaded devices have already transitioned through
/// Seen, so the `&&` arm is always satisfied. This test isolates
/// the Seen-window boundary by starting the device already in
/// Seen with a wide Trusted-idle window.
#[tokio::test]
async fn sweep_seen_idle_boundary_is_strict_greater() {
    // A never-trusted Seen row is revoked past `seen_idle` = 60 s.
    let cfg = SweepConfig::builder()
        .trusted_idle(chrono::Duration::seconds(1))
        .seen_idle(chrono::Duration::seconds(60))
        .revoked_grace(chrono::Duration::days(7))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(cfg);
    let t0 = Utc::now();

    let mut seen = d("dev-seen-edge", 0xcd, t0 - chrono::Duration::seconds(60));
    seen.trust_level = DeviceTrustLevel::Seen;
    store.save(&seen, crate::device::test_now()).await.unwrap();

    let counts = store.sweep(&t(), t0).await.unwrap();
    assert_eq!(
        counts.seen_to_revoked, 0,
        "Seen device at exact seen_idle threshold must NOT revoke; `> → >=` would flip"
    );

    let counts = store
        .sweep(&t(), t0 + chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.seen_to_revoked, 1);
}

/// Strict-`>` boundary on the Revoked→Purge grace window.
/// Pins `> → >=` on line 506.
#[tokio::test]
async fn sweep_revoked_grace_boundary_is_strict_greater() {
    let cfg = SweepConfig::builder()
        .trusted_idle(chrono::Duration::days(365))
        .seen_idle(chrono::Duration::days(365))
        .revoked_grace(chrono::Duration::seconds(60))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(cfg);
    let t0 = Utc::now();

    let mut revoked = d("dev-revoked-edge", 0xef, t0);
    revoked.trust_level = DeviceTrustLevel::Revoked;
    revoked.revoked_at = Some(t0 - chrono::Duration::seconds(60));
    store
        .save(&revoked, crate::device::test_now())
        .await
        .unwrap();

    let counts = store.sweep(&t(), t0).await.unwrap();
    assert_eq!(
        counts.revoked_purged, 0,
        "exactly-at-grace Revoked must NOT purge; `> → >=` would flip"
    );
    assert!(store.load(&t(), &revoked.id).await.unwrap().is_some());

    let counts = store
        .sweep(&t(), t0 + chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
    assert!(store.load(&t(), &revoked.id).await.unwrap().is_none());
}

/// The Seen→Revoked guard is `current_level == Seen &&
/// elapsed > seen_idle`: both conditions must hold. With
/// `&& → ||` an already-Revoked device with stale last_seen
/// would falsely re-enter the demote branch and inflate
/// `seen_to_revoked`. Pin by sweeping a Revoked device that
/// satisfies the elapsed predicate but NOT the level predicate.
#[tokio::test]
async fn sweep_seen_revoked_guard_requires_both_conditions() {
    let cfg = SweepConfig::builder()
        .trusted_idle(chrono::Duration::days(365))
        .seen_idle(chrono::Duration::seconds(60))
        .revoked_grace(chrono::Duration::days(365))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(cfg);
    let t0 = Utc::now();

    // Already-Revoked device with stale last_seen. Elapsed
    // predicate is satisfied; level predicate is not.
    let mut revoked = d("dev-stale-revoked", 0x99, t0 - chrono::Duration::days(2));
    revoked.trust_level = DeviceTrustLevel::Revoked;
    revoked.revoked_at = Some(t0);
    store
        .save(&revoked, crate::device::test_now())
        .await
        .unwrap();

    let counts = store.sweep(&t(), t0).await.unwrap();
    assert_eq!(
        counts.seen_to_revoked, 0,
        "already-Revoked device must NOT count in seen_to_revoked; \
         `&& → ||` would inflate the count by entering the demote branch \
         solely on the elapsed predicate"
    );
}

/// Re-saving a device under a new fingerprint must drop the old
/// fingerprint's index entry, or a lookup by the old fingerprint keeps
/// returning a device that no longer carries it.
#[tokio::test]
async fn resave_with_new_fingerprint_drops_old_index_entry() {
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    store
        .save(&d("dev-1", 0xaa, now), crate::device::test_now())
        .await
        .unwrap();
    store
        .save(&d("dev-1", 0xbb, now), crate::device::test_now())
        .await
        .unwrap();

    let old = FingerprintHash::from_bytes([0xaa; 32]);
    assert!(
        store
            .find_by_fingerprint(&t(), &old)
            .await
            .unwrap()
            .is_none()
    );
    let new = FingerprintHash::from_bytes([0xbb; 32]);
    assert!(
        store
            .find_by_fingerprint(&t(), &new)
            .await
            .unwrap()
            .is_some()
    );
}

/// Deleting a device must not remove an index entry that now points at a
/// different device with the same fingerprint.
#[tokio::test]
async fn delete_keeps_index_entry_owned_by_another_device() {
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    store
        .save(&d("dev-1", 0xaa, now), crate::device::test_now())
        .await
        .unwrap();
    store
        .save(&d("dev-2", 0xaa, now), crate::device::test_now())
        .await
        .unwrap();
    store.delete(&t(), &d("dev-1", 0xaa, now).id).await.unwrap();

    let fp = FingerprintHash::from_bytes([0xaa; 32]);
    let found = store.find_by_fingerprint(&t(), &fp).await.unwrap();
    assert_eq!(found.map(|x| x.id), Some(d("dev-2", 0xaa, now).id));
}

/// A purge in the sweep must not remove an index entry that points at
/// another device sharing the fingerprint.
#[tokio::test]
async fn sweep_purge_keeps_index_entry_owned_by_another_device() {
    let cfg = SweepConfig::builder()
        .revoked_grace(chrono::Duration::seconds(1))
        .build()
        .unwrap();
    let store = MemoryDeviceStore::new().with_sweep_config(cfg);
    let t0 = Utc::now();
    let mut old = d("dev-old", 0xcc, t0 - chrono::Duration::days(1));
    old.trust_level = DeviceTrustLevel::Revoked;
    old.revoked_at = Some(t0 - chrono::Duration::days(1));
    store.save(&old, crate::device::test_now()).await.unwrap();
    store
        .save(&d("dev-live", 0xcc, t0), crate::device::test_now())
        .await
        .unwrap();

    let counts = store.sweep(&t(), t0).await.unwrap();
    assert_eq!(counts.revoked_purged, 1);
    let fp = FingerprintHash::from_bytes([0xcc; 32]);
    let found = store.find_by_fingerprint(&t(), &fp).await.unwrap();
    assert_eq!(found.map(|x| x.id), Some(d("dev-live", 0xcc, t0).id));
}

/// Revoked devices must not use up the limit: with two newer revoked
/// devices and one older active one, a limit of 1 still returns the
/// active device.
#[tokio::test]
async fn find_active_for_user_applies_limit_after_dropping_revoked() {
    let store = MemoryDeviceStore::new();
    let now = Utc::now();
    store
        .save(
            &d("active", 0x01, now - chrono::Duration::days(3)),
            crate::device::test_now(),
        )
        .await
        .unwrap();
    for (name, fp, age) in [("rev-1", 0x02, 1), ("rev-2", 0x03, 2)] {
        let mut dev = d(name, fp, now - chrono::Duration::days(age));
        dev.trust_level = DeviceTrustLevel::Revoked;
        store.save(&dev, crate::device::test_now()).await.unwrap();
    }
    let got = store.find_active_for_user(&t(), &u(), 1).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, d("active", 0x01, now).id);
    assert!(
        store
            .find_active_for_user(&t(), &u(), 0)
            .await
            .unwrap()
            .is_empty()
    );
    let all = store.find_active_for_user(&t(), &u(), 10).await.unwrap();
    assert_eq!(all.len(), 1);
}
