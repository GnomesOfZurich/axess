//! Backend-independent checks of the device-store contract, run against every
//! backend that can be stood up in a test (memory, SQLite, and Valkey when a
//! server is available): tie order, monotonic sightings, revoked rows that
//! stay revoked, revoked rows that can be purged, sweep decisions that agree
//! to the second, a sweep that walks the retention ladder one level per call
//! and counts what it wrote, and the three conditional writes (a bindings
//! swap, a trust change from an expected level, an owner claim), each of
//! which two concurrent callers cannot both win.
//!
//! The three race cases run their two calls at once on one task. A store
//! with real I/O interleaves them by itself; the in-memory stores are run
//! through `interleaving::Interleaved`, which makes every call a point
//! where the other can run, and `interleaving::ReadThenWrite` is the control
//! each case must refuse.

use axess_clock::testing::Shift;
use std::fmt::Debug;

use axess_clock::{SignedDuration, Timestamp};

use crate::authn::ids::{DeviceId, TenantId, UserId, testing};
use crate::device::store::{BindingsUpdate, DeviceStore, OwnerClaim, SweepConfig, TrustTransition};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};

/// A fixed instant, `secs` seconds after 2027-01-15.
pub(crate) fn at(secs: i64) -> Timestamp {
    Timestamp::from_utc(2027, 1, 15, 0, 0, 0)
        .unwrap()
        .plus(SignedDuration::seconds(secs))
}

pub(crate) fn tenant() -> TenantId {
    testing::tenant("consistency-tenant")
}

pub(crate) fn user() -> UserId {
    testing::user("consistency-user")
}

pub(crate) fn dev_id(label: &str) -> DeviceId {
    testing::device(label)
}

pub(crate) fn device(label: &str, fp: u8, level: DeviceTrustLevel, last_seen: Timestamp) -> Device {
    Device {
        id: dev_id(label),
        tenant_id: tenant(),
        user_id: Some(user()),
        trust_level: level,
        fingerprint_hash: FingerprintHash::from_bytes([fp; 32]),
        first_seen_at: last_seen,
        last_seen_at: last_seen,
        revoked_at: (level == DeviceTrustLevel::Revoked).then_some(last_seen),
        demoted_at: None,
        bindings: Vec::new(),
    }
}

fn refresh(family: &str, now: Timestamp) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: now,
        last_used_at: now,
    }
}

async fn last_seen<S: DeviceStore>(store: &S, label: &str) -> Timestamp {
    store
        .load(&tenant(), &dev_id(label))
        .await
        .unwrap()
        .unwrap()
        .last_seen_at
}

/// Two devices with one `last_seen_at` are returned smaller id first by
/// every finder, whatever the backend's internal order.
pub(crate) async fn ties_are_broken_by_the_smaller_id<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let seen = at(0);
    let mut a = device("tie-a", 0x31, DeviceTrustLevel::Seen, seen);
    let mut b = device("tie-b", 0x31, DeviceTrustLevel::Seen, seen);
    a.bindings = vec![refresh("tie-family", seen)];
    b.bindings = vec![refresh("tie-family", seen)];
    // Saved in the order that would favour the larger id if order leaked.
    let smaller = a.id.min(b.id);
    let (first, second) = if a.id < b.id { (&b, &a) } else { (&a, &b) };
    store.save(first, seen).await.unwrap();
    store.save(second, seen).await.unwrap();

    let (t, u) = (tenant(), user());
    let listed = store.find_for_user(&t, &u, 10).await.unwrap();
    assert_eq!(listed.first().map(|d| d.id), Some(smaller), "find_for_user");
    let own = store
        .find_by_fingerprint_for_user(&t, &u, &a.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(
        own.map(|d| d.id),
        Some(smaller),
        "find_by_fingerprint_for_user"
    );
    let family = store
        .find_by_refresh_family(&t, "tie-family")
        .await
        .unwrap();
    assert_eq!(
        family.first().map(|d| d.id),
        Some(smaller),
        "find_by_refresh_family"
    );
}

/// The family lookup answers the devices of the asked tenant that are bound
/// to the asked refresh family, and no others: not a device of that tenant
/// bound to another family or to none, and not another tenant's device bound
/// to a family of the same name. A family revocation acts on what this
/// lookup returns, so a row of another tenant here is a device of another
/// tenant revoked.
pub(crate) async fn the_family_lookup_is_by_family_and_by_tenant<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let seen = at(80_000);
    let (here, elsewhere) = (tenant(), testing::tenant("consistency-other-tenant"));
    let mut bound = device("family-bound", 0xb1, DeviceTrustLevel::Seen, seen);
    bound.bindings = vec![refresh("family-shared", seen)];
    let mut other_family = device("family-other", 0xb2, DeviceTrustLevel::Seen, seen);
    other_family.bindings = vec![refresh("family-else", seen)];
    let unbound = device("family-unbound", 0xb3, DeviceTrustLevel::Seen, seen);
    let mut other_tenant = device("family-elsewhere", 0xb4, DeviceTrustLevel::Seen, seen);
    other_tenant.tenant_id = elsewhere;
    other_tenant.bindings = vec![refresh("family-shared", seen)];
    for d in [&bound, &other_family, &unbound, &other_tenant] {
        store.save(d, seen).await.unwrap();
    }

    let found = async |tenant_id: TenantId, family: &str| -> Vec<DeviceId> {
        let devices = store
            .find_by_refresh_family(&tenant_id, family)
            .await
            .unwrap();
        devices.into_iter().map(|d| d.id).collect()
    };
    assert_eq!(
        found(here, "family-shared").await,
        vec![bound.id],
        "the asked tenant's device of the asked family, and nobody else's"
    );
    assert_eq!(
        found(elsewhere, "family-shared").await,
        vec![other_tenant.id],
        "the other tenant's device of the family of the same name"
    );
    assert_eq!(found(here, "family-else").await, vec![other_family.id]);
    assert_eq!(found(elsewhere, "family-else").await, Vec::new());
    assert_eq!(found(here, "family-nobody").await, Vec::new());
}

/// Devices of one tenant that share a fingerprint and have no owner stay
/// findable by that fingerprint until the last of them is gone: the finder
/// answers with the newest sighting (the smaller id on a tie), and neither
/// the lifecycle nor the finder loses the others when one is deleted.
pub(crate) async fn a_shared_fingerprint_stays_findable_while_any_device_carries_it<S>(store: S)
where
    S: DeviceStore + Clone,
    S::Error: Debug,
{
    use crate::device::lifecycle::DeviceLifecycleService;

    let t = tenant();
    let fingerprint = FingerprintHash::from_bytes([0x32; 32]);
    let mut older = device("share-old", 0x32, DeviceTrustLevel::Seen, at(10));
    let mut twin_x = device("share-x", 0x32, DeviceTrustLevel::Seen, at(30));
    let mut twin_y = device("share-y", 0x32, DeviceTrustLevel::Seen, at(30));
    for d in [&mut older, &mut twin_x, &mut twin_y] {
        d.user_id = None;
    }
    // The tied pair, smaller id first, then the older one.
    let (first, second) = if twin_x.id < twin_y.id {
        (twin_x.clone(), twin_y.clone())
    } else {
        (twin_y.clone(), twin_x.clone())
    };
    // Saved so that the device a "last writer wins" index would name is the
    // one that is deleted first.
    for d in [&older, &second, &first] {
        store.save(d, at(30)).await.unwrap();
    }

    let found = |store: S| async move {
        store
            .find_by_fingerprint(&t, &fingerprint)
            .await
            .unwrap()
            .map(|d| d.id)
    };
    assert_eq!(found(store.clone()).await, Some(first.id), "tie order");

    // The lifecycle recognises the guest device instead of minting one. The
    // sighting time is before every `last_seen_at`, so it moves nothing.
    let service = DeviceLifecycleService::new(store.clone());
    let id = service
        .ensure_device(&t, None, fingerprint, at(0), || {
            dev_id("must-not-be-minted")
        })
        .await
        .unwrap();
    assert_eq!(id, first.id);

    store.delete(&t, &first.id).await.unwrap();
    assert_eq!(
        found(store.clone()).await,
        Some(second.id),
        "after the first is deleted"
    );
    let id = service
        .ensure_device(&t, None, fingerprint, at(0), || {
            dev_id("must-not-be-minted")
        })
        .await
        .unwrap();
    assert_eq!(id, second.id, "the lifecycle does not mint a new device");

    store.delete(&t, &second.id).await.unwrap();
    assert_eq!(found(store.clone()).await, Some(older.id), "the last one");
    store.delete(&t, &older.id).await.unwrap();
    assert_eq!(found(store.clone()).await, None, "none left");
}

/// A sighting moves `last_seen_at` forward only, and never touches a
/// revoked row.
pub(crate) async fn a_sighting_never_rewinds_and_skips_a_revoked_row<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("sight"));
    let base = at(10_000);
    store
        .save(&device("sight", 0x41, DeviceTrustLevel::Seen, base), base)
        .await
        .unwrap();

    store
        .record_sighting(&t, &id, base.minus(SignedDuration::hours(1)))
        .await
        .unwrap();
    assert_eq!(
        last_seen(&store, "sight").await,
        base,
        "an older sighting is ignored"
    );
    store
        .record_sighting(&t, &id, base.plus(SignedDuration::hours(1)))
        .await
        .unwrap();
    assert_eq!(
        last_seen(&store, "sight").await,
        base.plus(SignedDuration::hours(1))
    );

    store
        .set_trust_level(
            &t,
            &id,
            DeviceTrustLevel::Revoked,
            base.plus(SignedDuration::hours(2)),
        )
        .await
        .unwrap();
    store
        .record_sighting(&t, &id, base.plus(SignedDuration::hours(3)))
        .await
        .unwrap();
    assert_eq!(
        last_seen(&store, "sight").await,
        base.plus(SignedDuration::hours(1)),
        "a revoked row is not touched"
    );
    assert!(
        store
            .record_sighting(&t, &dev_id("absent"), base)
            .await
            .is_err(),
        "a missing device is still an error"
    );
}

/// A save of a device that was loaded before a revocation leaves the row
/// revoked; reinstating takes an explicit trust change.
pub(crate) async fn a_save_never_un_revokes<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("stale"));
    let base = at(20_000);
    let stale = device("stale", 0x51, DeviceTrustLevel::Trusted, base);
    store.save(&stale, base).await.unwrap();
    let revoked_at = base.plus(SignedDuration::minutes(5));
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, revoked_at)
        .await
        .unwrap();

    store
        .save(&stale, base.plus(SignedDuration::minutes(6)))
        .await
        .unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(
        row.revoked_at.map(|r| r.unix_seconds()),
        Some(revoked_at.unix_seconds())
    );

    store
        .set_trust_level(
            &t,
            &id,
            DeviceTrustLevel::Seen,
            base.plus(SignedDuration::minutes(7)),
        )
        .await
        .unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        row.trust_level,
        DeviceTrustLevel::Seen,
        "explicit reinstatement works"
    );
}

/// A revoked device is never live again unless an administrator reinstates
/// it: whatever the other write paths do afterwards (stale saves, sightings,
/// conditional trust changes, binding swaps, ownership claims, retention
/// sweeps, a repeated revocation), the row is `Revoked` or gone. Deterministic pseudo-random
/// sequences, so a failure repeats; `make_store` gives each its own store.
pub(crate) async fn a_revoked_device_never_comes_back<S, F, Fut>(make_store: F)
where
    S: DeviceStore,
    S::Error: Debug,
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = S>,
{
    use DeviceTrustLevel::{Revoked, Seen, Trusted, Unknown};
    const LEVELS: [DeviceTrustLevel; 3] = [Trusted, Seen, Unknown];
    let (t, id) = (tenant(), dev_id("never-back"));
    let base = at(40_000);
    for seed in 1u64..=6 {
        let store = make_store().await;
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let original = device("never-back", 0x61, Trusted, base);
        store.save(&original, base).await.unwrap();
        let revoked_at = base.plus(SignedDuration::minutes(5));
        store
            .set_trust_level(&t, &id, Revoked, revoked_at)
            .await
            .unwrap();

        for step in 0..30 {
            let now = revoked_at.plus(SignedDuration::seconds(1 + step));
            let level = LEVELS[next(3)];
            let op = next(7);
            match op {
                0 => {
                    let mut stale = original.clone();
                    stale.trust_level = level;
                    stale.user_id = [None, Some(user())][next(2)];
                    store.save(&stale, now).await.unwrap();
                }
                1 => {
                    store.record_sighting(&t, &id, now).await.unwrap();
                }
                2 => {
                    let to = LEVELS[next(3)];
                    let _ = store
                        .set_trust_level_if(&t, &id, level, to, now)
                        .await
                        .unwrap();
                }
                3 => {
                    let new = [refresh(&format!("fam-{seed}-{step}"), now)];
                    let _ = store
                        .replace_bindings(&t, &id, &[], &new, now)
                        .await
                        .unwrap();
                }
                4 => {
                    let before = store.load(&t, &id).await.unwrap();
                    let claim = store.claim_owner(&t, &id, &user(), now).await.unwrap();
                    if before.is_some_and(|row| row.user_id.is_none()) {
                        assert_eq!(
                            claim,
                            OwnerClaim::OwnedByOther,
                            "seed {seed} step {step}: a revoked device was claimed"
                        );
                    }
                }
                5 => {
                    store.sweep(&t, now).await.unwrap();
                }
                _ => {
                    // Revoking again is not a reinstatement.
                    store.set_trust_level(&t, &id, Revoked, now).await.unwrap();
                }
            }
            if let Some(row) = store.load(&t, &id).await.unwrap() {
                assert_eq!(
                    row.trust_level, Revoked,
                    "seed {seed} step {step} op {op}: a revoked device came back as {:?}",
                    row.trust_level
                );
            }
        }
    }
}

/// A revoked device saved with no revocation time is stamped with the
/// write time and is purged once the grace has passed.
pub(crate) async fn a_revoked_save_without_a_time_is_stamped_and_purged<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("unstamped"));
    let saved = at(30_000);
    let mut d = device("unstamped", 0x61, DeviceTrustLevel::Revoked, saved);
    d.revoked_at = None;
    store.save(&d, saved).await.unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        row.revoked_at.map(|r| r.unix_seconds()),
        Some(saved.unix_seconds())
    );

    let grace =
        axess_clock::SignedDuration::try_from(SweepConfig::default().revoked_grace).unwrap();
    let early = store.sweep(&t, saved.plus(grace)).await.unwrap();
    assert_eq!(
        early.revoked_purged, 0,
        "not purged until the grace has passed"
    );
    let counts = store
        .sweep(
            &t,
            saved.plus(
                grace
                    .checked_add(axess_clock::SignedDuration::seconds(1))
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(counts.revoked_purged, 1);
    assert!(store.load(&t, &id).await.unwrap().is_none());
}

/// The sweep configuration [`sweep_decisions_agree_to_the_second`] needs: a
/// trusted-idle window of ten seconds.
pub(crate) fn tight_config() -> SweepConfig {
    SweepConfig::builder()
        .trusted_idle(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

/// A trusted-idle window of ten seconds: a row last seen at 0.9 s and swept
/// at 10.95 s is not yet due (whole seconds: 10 is not more than 10), on
/// every backend; at 11.0 s it is.
///
/// `store` must have been built with [`tight_config`].
pub(crate) async fn sweep_decisions_agree_to_the_second<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let cfg = tight_config();
    let t = tenant();
    let base = at(40_000);
    let last = base.plus(SignedDuration::milliseconds(900));
    store
        .save(
            &device("subsec", 0x71, DeviceTrustLevel::Trusted, last),
            base,
        )
        .await
        .unwrap();

    let not_yet = base.plus(SignedDuration::milliseconds(10_950));
    assert_eq!(
        cfg.level_after(DeviceTrustLevel::Trusted, last, None, not_yet),
        DeviceTrustLevel::Trusted
    );
    let counts = store.sweep(&t, not_yet).await.unwrap();
    assert_eq!(
        counts.trusted_to_seen, 0,
        "10 whole seconds is not more than 10"
    );
    let counts = store
        .sweep(&t, base.plus(SignedDuration::seconds(11)))
        .await
        .unwrap();
    assert_eq!(counts.trusted_to_seen, 1);
}

/// The sweep configuration [`a_sweep_walks_the_ladder_and_counts_what_it_wrote`]
/// needs: every window ten seconds.
pub(crate) fn ladder_config() -> SweepConfig {
    let window = std::time::Duration::from_secs(10);
    SweepConfig::builder()
        .trusted_idle(window)
        .seen_idle(window)
        .revoked_grace(window)
        .build()
        .unwrap()
}

async fn level<S: DeviceStore>(store: &S, t: &TenantId, label: &str) -> Option<DeviceTrustLevel>
where
    S::Error: Debug,
{
    store
        .load(t, &dev_id(label))
        .await
        .unwrap()
        .map(|d| d.trust_level)
}

/// What every backend's sweep does, in three calls: a row moves one level
/// per call (`Trusted` to `Seen`, `Seen` to `Revoked`, a `Revoked` row
/// purged), each window counted from the stamp the step before wrote; the
/// counts are the rows written and nothing else; a row that is not due, an
/// `Unknown` row and another tenant's rows are left alone; and a sweep with
/// nothing due answers zero counts, which is an answer and not a refusal.
///
/// `store` must have been built with [`ladder_config`].
pub(crate) async fn a_sweep_walks_the_ladder_and_counts_what_it_wrote<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    use crate::device::store::SweepCounts;
    use DeviceTrustLevel::{Revoked, Seen, Trusted, Unknown};

    let t = tenant();
    let elsewhere = testing::tenant("consistency-other-tenant");
    let t0 = at(50_000);
    let secs = SignedDuration::seconds;
    // Idle since t0: a trusted row, a row that was never trusted, and a row
    // nobody promoted. One trusted row was sighted twenty seconds later.
    for (label, fp, trust, seen) in [
        ("ladder", 0xa1, Trusted, t0),
        ("never-trusted", 0xa2, Seen, t0),
        ("unknown", 0xa3, Unknown, t0),
        ("recent", 0xa4, Trusted, t0.plus(secs(20))),
    ] {
        store
            .save(&device(label, fp, trust, seen), seen)
            .await
            .unwrap();
    }
    let mut foreign = device("foreign", 0xa5, Trusted, t0);
    foreign.tenant_id = elsewhere;
    store.save(&foreign, t0).await.unwrap();

    // Twenty-five seconds on, both windows have passed for the rows idle
    // since t0, and each moves one level only.
    let first = store.sweep(&t, t0.plus(secs(25))).await.unwrap();
    assert_eq!(
        first,
        SweepCounts {
            trusted_to_seen: 1,
            seen_to_revoked: 1,
            revoked_purged: 0,
            skipped: 0,
        }
    );
    assert_eq!(level(&store, &t, "ladder").await, Some(Seen), "one level");
    assert_eq!(level(&store, &t, "never-trusted").await, Some(Revoked));
    assert_eq!(level(&store, &t, "recent").await, Some(Trusted), "not due");
    assert_eq!(level(&store, &t, "unknown").await, Some(Unknown));
    assert_eq!(level(&store, &elsewhere, "foreign").await, Some(Trusted));

    // The same instant again: every window restarted at the step just
    // taken, so nothing is due and nothing is counted.
    let again = store.sweep(&t, t0.plus(secs(25))).await.unwrap();
    assert_eq!(
        again,
        SweepCounts::default(),
        "nothing due, nothing written"
    );

    // Eleven seconds later each row is one window past its last step.
    let second = store.sweep(&t, t0.plus(secs(36))).await.unwrap();
    assert_eq!(
        second,
        SweepCounts {
            trusted_to_seen: 1,
            seen_to_revoked: 1,
            revoked_purged: 1,
            skipped: 0,
        }
    );
    assert_eq!(level(&store, &t, "ladder").await, Some(Revoked));
    assert_eq!(level(&store, &t, "never-trusted").await, None, "purged");
    assert_eq!(level(&store, &t, "recent").await, Some(Seen));

    let third = store.sweep(&t, t0.plus(secs(47))).await.unwrap();
    assert_eq!(
        third,
        SweepCounts {
            trusted_to_seen: 0,
            seen_to_revoked: 1,
            revoked_purged: 1,
            skipped: 0,
        }
    );
    assert_eq!(level(&store, &t, "ladder").await, None, "purged");
    assert_eq!(level(&store, &t, "recent").await, Some(Revoked));

    // Three sweeps of one tenant never touched the other's row or the row
    // nobody promoted; the other tenant's own sweep moves its row.
    assert_eq!(level(&store, &t, "unknown").await, Some(Unknown));
    assert_eq!(level(&store, &elsewhere, "foreign").await, Some(Trusted));
    let theirs = store.sweep(&elsewhere, t0.plus(secs(47))).await.unwrap();
    assert_eq!(
        theirs,
        SweepCounts {
            trusted_to_seen: 1,
            ..SweepCounts::default()
        }
    );
    assert_eq!(level(&store, &elsewhere, "foreign").await, Some(Seen));
}

/// The fingerprint lookup returns the newest-sighted device among those that
/// share the fingerprint, on every backend: saving an older sighting later
/// does not take the lookup over, and a later sighting of that older device
/// does.
pub(crate) async fn the_fingerprint_lookup_follows_the_newest_sighting<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let fp = FingerprintHash::from_bytes([0x81; 32]);
    let mut newer = device("seen-new", 0x81, DeviceTrustLevel::Seen, at(50_030));
    let mut older = device("seen-old", 0x81, DeviceTrustLevel::Seen, at(50_010));
    newer.user_id = None;
    older.user_id = None;
    store.save(&newer, at(50_030)).await.unwrap();
    store.save(&older, at(50_030)).await.unwrap();

    let found = store.find_by_fingerprint(&t, &fp).await.unwrap();
    assert_eq!(
        found.map(|d| d.id),
        Some(newer.id),
        "the device written last is not the one returned"
    );

    store
        .record_sighting(&t, &older.id, at(50_050))
        .await
        .unwrap();
    let found = store.find_by_fingerprint(&t, &fp).await.unwrap();
    assert_eq!(
        found.map(|d| d.id),
        Some(older.id),
        "a later sighting takes the lookup over"
    );
}

/// Sub-second instants compare as whole seconds on every backend: two
/// sightings within one second tie and the smaller id wins, a sighting within
/// the stored second moves nothing, and the stored time is the whole second.
pub(crate) async fn sub_second_instants_compare_as_whole_seconds<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let fp = FingerprintHash::from_bytes([0x91; 32]);
    let (first, second) = if dev_id("frac-a") < dev_id("frac-b") {
        ("frac-a", "frac-b")
    } else {
        ("frac-b", "frac-a")
    };
    let tenth = SignedDuration::milliseconds(100);
    let mut smaller = device(
        first,
        0x91,
        DeviceTrustLevel::Seen,
        at(60_010).plus(tenth.checked_mul(2).unwrap()),
    );
    let mut larger = device(
        second,
        0x91,
        DeviceTrustLevel::Seen,
        at(60_010).plus(tenth.checked_mul(7).unwrap()),
    );
    smaller.user_id = None;
    larger.user_id = None;
    store
        .save(&smaller, at(60_010).plus(tenth.checked_mul(2).unwrap()))
        .await
        .unwrap();
    store
        .save(&larger, at(60_010).plus(tenth.checked_mul(7).unwrap()))
        .await
        .unwrap();

    assert_eq!(
        last_seen(&store, first).await,
        at(60_010),
        "the stored sighting is the whole second"
    );
    let found = store.find_by_fingerprint(&t, &fp).await.unwrap();
    assert_eq!(
        found.map(|d| d.id),
        Some(smaller.id),
        "sightings within one second tie, and the smaller id wins"
    );

    let level = store
        .record_sighting(
            &t,
            &larger.id,
            at(60_010).plus(tenth.checked_mul(9).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(level, DeviceTrustLevel::Seen);
    assert_eq!(
        last_seen(&store, second).await,
        at(60_010),
        "a sighting within the stored second moves nothing"
    );
    let found = store.find_by_fingerprint(&t, &fp).await.unwrap();
    assert_eq!(found.map(|d| d.id), Some(smaller.id));

    store
        .record_sighting(&t, &larger.id, at(60_011).plus(tenth))
        .await
        .unwrap();
    assert_eq!(last_seen(&store, second).await, at(60_011));
    let found = store.find_by_fingerprint(&t, &fp).await.unwrap();
    assert_eq!(
        found.map(|d| d.id),
        Some(larger.id),
        "a sighting in a later second takes the lookup over"
    );
}

/// Revoking a revoked device again keeps the first revocation time, and a
/// save of a revoked copy rewrites nothing, so neither restarts the purge
/// grace clock or brings back older bindings.
pub(crate) async fn a_revoked_row_keeps_its_revocation_time<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    use crate::device::store::TrustTransition;

    let (t, id) = (tenant(), dev_id("revoked-twice"));
    let base = at(60_000);
    let mut d = device("revoked-twice", 0x91, DeviceTrustLevel::Seen, base);
    d.bindings = vec![refresh("keep-family", base)];
    store.save(&d, base).await.unwrap();
    let first = base.plus(SignedDuration::minutes(5));
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, first)
        .await
        .unwrap();

    let again = base.plus(SignedDuration::minutes(50));
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, again)
        .await
        .unwrap();
    assert_eq!(
        store
            .set_trust_level_if(
                &t,
                &id,
                DeviceTrustLevel::Revoked,
                DeviceTrustLevel::Revoked,
                again.plus(SignedDuration::minutes(1))
            )
            .await
            .unwrap(),
        TrustTransition::Applied
    );
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        row.revoked_at.map(|r| r.unix_seconds()),
        Some(first.unix_seconds()),
        "repeating a revocation keeps the first revocation time"
    );

    // A stale revoked copy, with its own time and no bindings.
    let mut copy = d.clone();
    copy.trust_level = DeviceTrustLevel::Revoked;
    copy.revoked_at = Some(base.plus(SignedDuration::hours(3)));
    copy.bindings = Vec::new();
    store
        .save(&copy, base.plus(SignedDuration::hours(3)))
        .await
        .unwrap();
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        row.revoked_at.map(|r| r.unix_seconds()),
        Some(first.unix_seconds()),
        "a save of a revoked copy does not restart the grace clock"
    );
    assert_eq!(row.bindings, d.bindings, "nor replace the bindings");
}

/// A sighting reports the trust level the row has: the level of a live
/// row, `Revoked` for a revoked one (whose `last_seen_at` it leaves alone).
pub(crate) async fn a_sighting_reports_the_level_it_found<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("reports"));
    let base = at(70_000);
    store
        .save(
            &device("reports", 0xa1, DeviceTrustLevel::Trusted, base),
            base,
        )
        .await
        .unwrap();
    let level = store
        .record_sighting(&t, &id, base.plus(SignedDuration::hours(1)))
        .await
        .unwrap();
    assert_eq!(level, DeviceTrustLevel::Trusted);

    store
        .set_trust_level(
            &t,
            &id,
            DeviceTrustLevel::Revoked,
            base.plus(SignedDuration::hours(2)),
        )
        .await
        .unwrap();
    let level = store
        .record_sighting(&t, &id, base.plus(SignedDuration::hours(3)))
        .await
        .unwrap();
    assert_eq!(level, DeviceTrustLevel::Revoked);
    assert_eq!(
        last_seen(&store, "reports").await,
        base.plus(SignedDuration::hours(1)),
        "the revoked row's last_seen_at is unchanged"
    );
}

/// Two swaps that start from the same bindings: exactly one is written, the
/// other is answered `Conflict`, and the row and the family index hold the
/// winner's bindings and nothing of the loser's. Repeated, each round from
/// the bindings the last one left. A store whose swap is a read and a write
/// in two steps answers `Written` twice once its steps interleave.
pub(crate) async fn two_swaps_from_one_read_have_one_winner<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("two-swaps"));
    let base = at(80_000);
    let mut current = vec![refresh("swap-start", base)];
    let mut d = device("two-swaps", 0xb1, DeviceTrustLevel::Seen, base);
    d.bindings = current.clone();
    store.save(&d, base).await.unwrap();

    for round in 0..8i64 {
        let now = base.plus(SignedDuration::seconds(round + 1));
        let (left, right) = (format!("swap-{round}-left"), format!("swap-{round}-right"));
        let (to_left, to_right) = (vec![refresh(&left, now)], vec![refresh(&right, now)]);
        let (first, second) = tokio::join!(
            store.replace_bindings(&t, &id, &current, &to_left, now),
            store.replace_bindings(&t, &id, &current, &to_right, now),
        );
        let (won, winner, loser) = match (first.unwrap(), second.unwrap()) {
            (BindingsUpdate::Written, BindingsUpdate::Conflict) => (to_left, left, right),
            (BindingsUpdate::Conflict, BindingsUpdate::Written) => (to_right, right, left),
            other => panic!("round {round}: one swap is written and one conflicts: {other:?}"),
        };

        let row = store.load_fresh(&t, &id).await.unwrap().unwrap();
        assert_eq!(row.bindings, won, "round {round}: the winner's bindings");
        assert_eq!(row.trust_level, DeviceTrustLevel::Seen, "round {round}");
        for (family, holders) in [(&winner, 1), (&loser, 0)] {
            assert_eq!(
                store
                    .find_by_refresh_family(&t, family)
                    .await
                    .unwrap()
                    .len(),
                holders,
                "round {round}: {family} in the family index"
            );
        }
        current = won;
    }
}

/// Two trust changes decided from the same level: exactly one is applied,
/// the other is refused with the level the winner wrote, and the row holds
/// the winner's level. One of the two is a revocation, so a store whose
/// conditional change is a read and a write in two steps is seen writing a
/// promotion over it (or it over the promotion) and answering `Applied`
/// twice.
pub(crate) async fn two_trust_changes_from_one_level_have_one_winner<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let base = at(81_000);
    for round in 0..4i64 {
        let label = format!("two-levels-{round}");
        let id = dev_id(&label);
        let now = base.plus(SignedDuration::seconds(round + 1));
        store
            .save(&device(&label, 0xb2, DeviceTrustLevel::Seen, base), base)
            .await
            .unwrap();

        let (promote, revoke) = tokio::join!(
            store.set_trust_level_if(
                &t,
                &id,
                DeviceTrustLevel::Seen,
                DeviceTrustLevel::Trusted,
                now
            ),
            store.set_trust_level_if(
                &t,
                &id,
                DeviceTrustLevel::Seen,
                DeviceTrustLevel::Revoked,
                now
            ),
        );
        let winner = match (promote.unwrap(), revoke.unwrap()) {
            (TrustTransition::Applied, TrustTransition::Refused { current }) => {
                assert_eq!(current, DeviceTrustLevel::Trusted, "round {round}");
                DeviceTrustLevel::Trusted
            }
            (TrustTransition::Refused { current }, TrustTransition::Applied) => {
                assert_eq!(current, DeviceTrustLevel::Revoked, "round {round}");
                DeviceTrustLevel::Revoked
            }
            other => panic!("round {round}: one change is applied and one refused: {other:?}"),
        };
        let row = store.load_fresh(&t, &id).await.unwrap().unwrap();
        assert_eq!(row.trust_level, winner, "round {round}: the winner's level");
        assert_eq!(
            row.revoked_at.is_some(),
            winner == DeviceTrustLevel::Revoked,
            "round {round}: a revocation is stamped, a promotion is not"
        );
    }
}

/// Two users claiming one unowned device at once: exactly one is answered
/// `Claimed`, the other `OwnedByOther`, and the row names the winner. A
/// store whose claim is a read and a write in two steps answers `Claimed`
/// to both.
pub(crate) async fn two_claims_of_one_unowned_device_have_one_winner<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let base = at(82_000);
    let (a, b) = (testing::user("claimant-a"), testing::user("claimant-b"));
    for round in 0..4i64 {
        let label = format!("two-claims-{round}");
        let now = base.plus(SignedDuration::seconds(round + 1));
        let mut unowned = device(&label, 0xb3, DeviceTrustLevel::Seen, base);
        unowned.user_id = None;
        store.save(&unowned, base).await.unwrap();

        let (first, second) = tokio::join!(
            store.claim_owner(&t, &unowned.id, &a, now),
            store.claim_owner(&t, &unowned.id, &b, now),
        );
        let winner = match (first.unwrap(), second.unwrap()) {
            (OwnerClaim::Claimed, OwnerClaim::OwnedByOther) => a,
            (OwnerClaim::OwnedByOther, OwnerClaim::Claimed) => b,
            other => panic!("round {round}: one claim wins and one is refused: {other:?}"),
        };
        let row = store.load_fresh(&t, &unowned.id).await.unwrap().unwrap();
        assert_eq!(
            row.user_id,
            Some(winner),
            "round {round}: the winner owns it"
        );
    }
}
