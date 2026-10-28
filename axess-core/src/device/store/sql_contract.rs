//! Checks of the device-store contract that run against a real SQL server.
//!
//! Each function takes a store on an empty database and uses only the
//! [`DeviceStore`] interface, so the Postgres and MySQL stores run the same
//! checks. The raw-SQL checks that are particular to one dialect sit beside
//! each store instead. Times are whole seconds because the stores keep
//! seconds.

use std::fmt::Debug;

use chrono::Duration;

use super::DeviceStore;
use super::consistency::{at, dev_id, device, tenant, user};
use super::ladder::LADDER;
use super::{BindingsUpdate, OwnerClaim, TrustTransition};
use crate::device::types::{DeviceBinding, DeviceTrustLevel};

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: at(0),
        last_used_at: at(0),
    }
}

async fn row<S>(store: &S) -> crate::device::types::Device
where
    S: DeviceStore,
    S::Error: Debug,
{
    store
        .load(&tenant(), &dev_id("stamp"))
        .await
        .unwrap()
        .unwrap()
}

async fn trust<S>(store: &S, label: &str) -> DeviceTrustLevel
where
    S: DeviceStore,
    S::Error: Debug,
{
    store
        .load(&tenant(), &dev_id(label))
        .await
        .unwrap()
        .unwrap()
        .trust_level
}

/// Every trust level, a binding of each kind of field, and the optional
/// fields come back exactly as they went in.
pub(crate) async fn records_round_trip<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    for (i, level) in [
        DeviceTrustLevel::Unknown,
        DeviceTrustLevel::Seen,
        DeviceTrustLevel::Trusted,
        DeviceTrustLevel::Revoked,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("rt-{i}");
        let mut d = device(&label, 0xa0 + i as u8, level, at(100));
        d.bindings = vec![
            DeviceBinding::Cookie {
                token_hash: crate::device::types::FingerprintHash::from_bytes([0xcd; 32]),
                issued_at: at(90),
                last_used_at: at(95),
            },
            refresh(&format!("fam-{i}")),
        ];
        if level == DeviceTrustLevel::Trusted {
            d.demoted_at = None;
        }
        store.save(&d, at(100)).await.unwrap();
        let got = store.load(&t, &d.id).await.unwrap().expect("present");
        assert_eq!(got, d, "{level:?}");
    }
    assert!(store.load(&t, &dev_id("nobody")).await.unwrap().is_none());
}

/// A second save replaces the row and its family index; a device of another
/// tenant is neither found nor changed.
pub(crate) async fn save_upserts_and_lookups_are_tenant_scoped<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, u) = (tenant(), user());
    let mut d = device("up", 0x01, DeviceTrustLevel::Seen, at(10));
    d.bindings = vec![refresh("old-family")];
    store.save(&d, at(10)).await.unwrap();
    d.trust_level = DeviceTrustLevel::Trusted;
    d.last_seen_at = at(20);
    d.fingerprint_hash = crate::device::types::FingerprintHash::from_bytes([0x02; 32]);
    d.bindings = vec![refresh("new-family")];
    store.save(&d, at(20)).await.unwrap();

    assert_eq!(store.load(&t, &d.id).await.unwrap().unwrap(), d);
    assert!(
        store
            .find_by_refresh_family(&t, "old-family")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .find_by_refresh_family(&t, "new-family")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .find_by_fingerprint(
                &t,
                &crate::device::types::FingerprintHash::from_bytes([0x01; 32])
            )
            .await
            .unwrap()
            .is_none(),
        "the old fingerprint no longer resolves"
    );

    let other = crate::authn::ids::testing::tenant("other-tenant");
    assert!(store.load(&other, &d.id).await.unwrap().is_none());
    assert!(
        store
            .find_by_fingerprint(&other, &d.fingerprint_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .find_for_user(&other, &u, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .find_by_refresh_family(&other, "new-family")
            .await
            .unwrap()
            .is_empty()
    );

    // Newest first, and the limit applies.
    for (i, label) in ["a", "b", "c"].into_iter().enumerate() {
        let n = device(
            label,
            0x10 + i as u8,
            DeviceTrustLevel::Seen,
            at(100 + i as i64),
        );
        store.save(&n, at(100)).await.unwrap();
    }
    let listed = store.find_for_user(&t, &u, 2).await.unwrap();
    let times: Vec<_> = listed.iter().map(|d| d.last_seen_at).collect();
    assert_eq!(times, vec![at(102), at(101)]);

    // Deleting removes the row and its index rows.
    store.delete(&t, &d.id).await.unwrap();
    assert!(store.load(&t, &d.id).await.unwrap().is_none());
    assert!(
        store
            .find_by_refresh_family(&t, "new-family")
            .await
            .unwrap()
            .is_empty()
    );
}

/// Revoked rows never use up the limit of `find_active_for_user`.
pub(crate) async fn revoked_devices_never_use_up_the_active_limit<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, u) = (tenant(), user());
    for i in 0..8i64 {
        let level = if i < 5 {
            DeviceTrustLevel::Revoked
        } else {
            DeviceTrustLevel::Seen
        };
        let seen = if i < 5 { at(1_000 + i) } else { at(100 + i) };
        store
            .save(&device(&format!("act-{i}"), i as u8, level, seen), at(0))
            .await
            .unwrap();
    }
    let got = store.find_active_for_user(&t, &u, 2).await.unwrap();
    assert_eq!(got.len(), 2, "two active devices, not zero");
    assert!(
        got.iter()
            .all(|d| d.trust_level != DeviceTrustLevel::Revoked)
    );
    assert_eq!(got[0].last_seen_at, at(107), "newest active first");
    assert_eq!(
        store.find_active_for_user(&t, &u, 10).await.unwrap().len(),
        3
    );
    assert_eq!(store.find_for_user(&t, &u, 10).await.unwrap().len(), 8);
}

/// A duplicated family in the bindings does not poison this or a later save.
pub(crate) async fn a_duplicated_refresh_family_does_not_poison_later_saves<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let mut d = device("dup", 0x22, DeviceTrustLevel::Seen, at(10));
    d.bindings = vec![refresh("fam"), refresh("fam"), refresh("other")];
    store.save(&d, at(10)).await.unwrap();
    store
        .save(&d, at(11))
        .await
        .expect("second save of the same device");
    store
        .set_trust_level(&t, &d.id, DeviceTrustLevel::Trusted, at(12))
        .await
        .unwrap();
    let mut changed = store.load(&t, &d.id).await.unwrap().unwrap();
    changed.last_seen_at = at(13);
    store.save(&changed, at(13)).await.unwrap();
    for family in ["fam", "other"] {
        assert_eq!(
            store
                .find_by_refresh_family(&t, family)
                .await
                .unwrap()
                .len(),
            1,
            "{family}"
        );
    }
}

/// Writes to a device that is not stored are errors, and the same second
/// twice is a match and not a miss.
pub(crate) async fn writes_to_a_missing_device_are_errors<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, ghost) = (tenant(), dev_id("ghost"));
    assert!(store.record_sighting(&t, &ghost, at(5)).await.is_err());
    assert!(
        store
            .set_trust_level(&t, &ghost, DeviceTrustLevel::Revoked, at(5))
            .await
            .is_err()
    );
    assert_eq!(
        store
            .replace_bindings(&t, &ghost, &[], &[], at(5))
            .await
            .unwrap(),
        BindingsUpdate::Missing
    );
    assert_eq!(
        store
            .set_trust_level_if(
                &t,
                &ghost,
                DeviceTrustLevel::Unknown,
                DeviceTrustLevel::Seen,
                at(5)
            )
            .await
            .unwrap(),
        TrustTransition::Missing
    );
    assert_eq!(
        store.claim_owner(&t, &ghost, &user(), at(5)).await.unwrap(),
        OwnerClaim::Missing
    );

    store
        .save(&device("real", 1, DeviceTrustLevel::Seen, at(10)), at(10))
        .await
        .unwrap();
    store
        .record_sighting(&t, &dev_id("real"), at(10))
        .await
        .expect("an unchanged value is still a match");
}

/// The stamps `set_trust_level` and `set_trust_level_if` write: the
/// revocation time, and the demotion that a Trusted row gets on the way down.
pub(crate) async fn trust_changes_stamp_and_clear_the_times<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let id = dev_id("stamp");
    store
        .save(
            &device("stamp", 1, DeviceTrustLevel::Trusted, at(10)),
            at(10),
        )
        .await
        .unwrap();

    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Seen, at(110))
        .await
        .unwrap();
    assert_eq!(row(&store).await.demoted_at, Some(at(110)));
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Seen, at(120))
        .await
        .unwrap();
    assert_eq!(
        row(&store).await.demoted_at,
        Some(at(110)),
        "Seen to Seen keeps it"
    );
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Trusted, at(130))
        .await
        .unwrap();
    assert_eq!(row(&store).await.demoted_at, None, "a promotion clears it");

    let got = store
        .set_trust_level_if(
            &t,
            &id,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Seen,
            at(140),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(row(&store).await.demoted_at, Some(at(140)));
    let got = store
        .set_trust_level_if(
            &t,
            &id,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Seen,
            at(150),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(row(&store).await.demoted_at, Some(at(140)));
    let got = store
        .set_trust_level_if(
            &t,
            &id,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            at(160),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(row(&store).await.demoted_at, None);

    // Revoking stamps the time, and a non-revoked level clears it.
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, at(170))
        .await
        .unwrap();
    assert_eq!(row(&store).await.revoked_at, Some(at(170)));
    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Seen, at(180))
        .await
        .unwrap();
    assert_eq!(row(&store).await.revoked_at, None);
}

/// A conditional change applies only from the expected level and never over a
/// revocation.
pub(crate) async fn a_conditional_change_never_overwrites_a_revocation<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("cond"));
    store
        .save(
            &device("cond", 1, DeviceTrustLevel::Unknown, at(10)),
            at(10),
        )
        .await
        .unwrap();
    let got = store
        .set_trust_level_if(
            &t,
            &id,
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            at(11),
        )
        .await
        .unwrap();
    assert_eq!(got, TrustTransition::Applied);
    assert_eq!(trust(&store, "cond").await, DeviceTrustLevel::Seen);

    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, at(12))
        .await
        .unwrap();
    let got = store
        .set_trust_level_if(
            &t,
            &id,
            DeviceTrustLevel::Seen,
            DeviceTrustLevel::Trusted,
            at(13),
        )
        .await
        .unwrap();
    assert_eq!(
        got,
        TrustTransition::Refused {
            current: DeviceTrustLevel::Revoked
        }
    );
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.revoked_at, Some(at(12)));
}

/// A bindings swap writes only the bindings, refuses a revoked device, and
/// refuses a swap based on bindings that have since changed.
pub(crate) async fn bindings_swaps_are_conditional<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let (t, id) = (tenant(), dev_id("swap"));
    store
        .save(
            &device("swap", 1, DeviceTrustLevel::Trusted, at(10)),
            at(10),
        )
        .await
        .unwrap();
    let written = store
        .replace_bindings(&t, &id, &[], &[refresh("fam-1")], at(11))
        .await
        .unwrap();
    assert_eq!(written, BindingsUpdate::Written);
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Trusted);
    assert_eq!(row.bindings, vec![refresh("fam-1")]);
    assert_eq!(
        store
            .find_by_refresh_family(&t, "fam-1")
            .await
            .unwrap()
            .len(),
        1
    );

    let stale = store
        .replace_bindings(&t, &id, &[], &[refresh("fam-2")], at(12))
        .await
        .unwrap();
    assert_eq!(stale, BindingsUpdate::Conflict);
    assert!(
        store
            .find_by_refresh_family(&t, "fam-2")
            .await
            .unwrap()
            .is_empty()
    );
    let retry = store
        .replace_bindings(
            &t,
            &id,
            &[refresh("fam-1")],
            &[refresh("fam-1"), refresh("fam-2")],
            at(13),
        )
        .await
        .unwrap();
    assert_eq!(retry, BindingsUpdate::Written);
    assert_eq!(
        store
            .find_by_refresh_family(&t, "fam-2")
            .await
            .unwrap()
            .len(),
        1
    );

    store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, at(20))
        .await
        .unwrap();
    let refused = store
        .replace_bindings(
            &t,
            &id,
            &[refresh("fam-1"), refresh("fam-2")],
            &[refresh("fam-3")],
            at(21),
        )
        .await
        .unwrap();
    assert_eq!(refused, BindingsUpdate::Revoked);
    let row = store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(row.revoked_at, Some(at(20)));
    assert_eq!(row.bindings, vec![refresh("fam-1"), refresh("fam-2")]);
    assert!(
        store
            .find_by_refresh_family(&t, "fam-3")
            .await
            .unwrap()
            .is_empty()
    );
}

/// Two users racing for one unowned device: exactly one claims it, and the
/// stored owner is that one. Two swaps that read the same bindings: exactly
/// one is written.
pub(crate) async fn races_have_one_winner<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let mut unowned = device("claim", 1, DeviceTrustLevel::Seen, at(10));
    unowned.user_id = None;
    store.save(&unowned, at(10)).await.unwrap();
    let (a, b) = (
        crate::authn::ids::testing::user("a"),
        crate::authn::ids::testing::user("b"),
    );
    let (ra, rb) = tokio::join!(
        store.claim_owner(&t, &unowned.id, &a, at(11)),
        store.claim_owner(&t, &unowned.id, &b, at(11))
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(
        [ra, rb]
            .iter()
            .filter(|c| **c == OwnerClaim::Claimed)
            .count(),
        1,
        "{ra:?} {rb:?}"
    );
    let winner = if ra == OwnerClaim::Claimed { a } else { b };
    assert_eq!(
        store.load(&t, &unowned.id).await.unwrap().unwrap().user_id,
        Some(winner)
    );

    let id = dev_id("race-swap");
    let before = vec![refresh("fam-a")];
    let mut d = device("race-swap", 2, DeviceTrustLevel::Seen, at(10));
    d.bindings = before.clone();
    store.save(&d, at(10)).await.unwrap();
    let (to_b, to_c) = ([refresh("fam-b")], [refresh("fam-c")]);
    let (first, second) = tokio::join!(
        store.replace_bindings(&t, &id, &before, &to_b, at(11)),
        store.replace_bindings(&t, &id, &before, &to_c, at(11)),
    );
    let mut outcomes = vec![first.unwrap(), second.unwrap()];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(
        outcomes,
        vec![BindingsUpdate::Conflict, BindingsUpdate::Written]
    );
}

/// The retention ladder, one level per call, tenant scoping, and the demotion
/// stamp that starts a device's Seen window.
pub(crate) async fn the_sweep_follows_the_ladder<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let now = at(50_000_000);
    for (i, r) in LADDER.iter().enumerate() {
        let mut d = device(&format!("row-{i}"), i as u8, r.level, r.last_seen(now));
        d.demoted_at = r.demoted_at(now);
        store.save(&d, now).await.unwrap();
    }
    store.sweep(&t, now).await.unwrap();
    for (i, r) in LADDER.iter().enumerate() {
        assert_eq!(
            trust(&store, &format!("row-{i}")).await,
            r.want,
            "{:?} idle {}d demoted {:?}d ago",
            r.level,
            r.idle_days,
            r.demoted_days_ago
        );
    }
}

/// A long-idle Trusted device is demoted by one sweep and revoked by a later
/// one; the second window counts from the demotion stamp; another tenant and
/// Unknown rows are left alone.
pub(crate) async fn the_sweep_moves_one_level_and_counts_from_the_demotion<S>(store: S)
where
    S: DeviceStore,
    S::Error: Debug,
{
    let t = tenant();
    let now = at(60_000_000);
    let mut idle = device(
        "idle",
        1,
        DeviceTrustLevel::Trusted,
        now - Duration::days(200),
    );
    idle.first_seen_at = idle.last_seen_at;
    store.save(&idle, now).await.unwrap();
    let mut unknown = device(
        "unknown",
        2,
        DeviceTrustLevel::Unknown,
        now - Duration::days(365),
    );
    unknown.first_seen_at = unknown.last_seen_at;
    store.save(&unknown, now).await.unwrap();
    let mut foreign = device(
        "foreign",
        3,
        DeviceTrustLevel::Trusted,
        now - Duration::days(200),
    );
    foreign.tenant_id = crate::authn::ids::testing::tenant("t-foreign");
    store.save(&foreign, now).await.unwrap();

    let counts = store.sweep(&t, now).await.unwrap();
    assert_eq!(
        (
            counts.trusted_to_seen,
            counts.seen_to_revoked,
            counts.revoked_purged
        ),
        (1, 0, 0)
    );
    let row = store.load(&t, &idle.id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Seen);
    assert_eq!(row.demoted_at, Some(now));
    assert_eq!(trust(&store, "unknown").await, DeviceTrustLevel::Unknown);
    let foreign_row = store
        .load(&foreign.tenant_id, &foreign.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(foreign_row.trust_level, DeviceTrustLevel::Trusted);

    let counts = store.sweep(&t, now + Duration::days(29)).await.unwrap();
    assert_eq!(counts.seen_to_revoked, 0);
    let later = now + Duration::days(31);
    let counts = store.sweep(&t, later).await.unwrap();
    assert_eq!(
        (
            counts.trusted_to_seen,
            counts.seen_to_revoked,
            counts.revoked_purged
        ),
        (0, 1, 0)
    );
    let row = store.load(&t, &idle.id).await.unwrap().unwrap();
    assert_eq!(row.trust_level, DeviceTrustLevel::Revoked);
    assert_eq!(row.revoked_at, Some(later));
    assert_eq!(row.demoted_at, None, "a revoked row carries no demotion");
}
