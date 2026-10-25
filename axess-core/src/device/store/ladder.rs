//! The retention ladder and the conditional writes, on the in-memory store.

use super::*;
use chrono::TimeZone;

/// One row of the retention ladder: a device at `level`, un-sighted for
/// `idle_days`, demoted from Trusted `demoted_days_ago` days before the
/// sweep (`None` for a device that was never Trusted), and the level it has
/// after one sweep with the default 90 / 30 windows.
#[derive(Clone, Copy)]
pub(crate) struct LadderRow {
    pub level: DeviceTrustLevel,
    pub idle_days: i64,
    pub demoted_days_ago: Option<i64>,
    pub want: DeviceTrustLevel,
}

impl LadderRow {
    pub(crate) fn last_seen(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now - chrono::Duration::days(self.idle_days)
    }

    pub(crate) fn demoted_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.demoted_days_ago
            .map(|d| now - chrono::Duration::days(d))
    }
}

const fn row(
    level: DeviceTrustLevel,
    idle_days: i64,
    demoted_days_ago: Option<i64>,
    want: DeviceTrustLevel,
) -> LadderRow {
    LadderRow {
        level,
        idle_days,
        demoted_days_ago,
        want,
    }
}

/// The retention ladder, row by row, shared by every backend's sweep test.
/// A never-Trusted `Seen` device is revoked after 30 idle days; a demoted
/// one 30 days after its demotion (120 days from the last sighting when it
/// was demoted at 90); a Trusted device is demoted at 90 and never revoked
/// in the same sweep; a sighting after the demotion restarts the Seen window.
pub(crate) const LADDER: &[LadderRow] = &[
    row(
        DeviceTrustLevel::Trusted,
        89,
        None,
        DeviceTrustLevel::Trusted,
    ),
    row(DeviceTrustLevel::Trusted, 91, None, DeviceTrustLevel::Seen),
    row(DeviceTrustLevel::Trusted, 121, None, DeviceTrustLevel::Seen),
    row(DeviceTrustLevel::Trusted, 400, None, DeviceTrustLevel::Seen),
    row(DeviceTrustLevel::Seen, 29, None, DeviceTrustLevel::Seen),
    row(DeviceTrustLevel::Seen, 31, None, DeviceTrustLevel::Revoked),
    row(DeviceTrustLevel::Seen, 119, None, DeviceTrustLevel::Revoked),
    row(
        DeviceTrustLevel::Seen,
        100,
        Some(10),
        DeviceTrustLevel::Seen,
    ),
    row(
        DeviceTrustLevel::Seen,
        119,
        Some(29),
        DeviceTrustLevel::Seen,
    ),
    row(
        DeviceTrustLevel::Seen,
        121,
        Some(31),
        DeviceTrustLevel::Revoked,
    ),
    row(DeviceTrustLevel::Seen, 5, Some(40), DeviceTrustLevel::Seen),
    row(
        DeviceTrustLevel::Seen,
        35,
        Some(40),
        DeviceTrustLevel::Revoked,
    ),
    row(
        DeviceTrustLevel::Unknown,
        400,
        None,
        DeviceTrustLevel::Unknown,
    ),
];

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("tenant-1")
}

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap()
}

fn device(name: &str, byte: u8, level: DeviceTrustLevel, last_seen: DateTime<Utc>) -> Device {
    Device {
        id: crate::authn::ids::testing::device(name),
        tenant_id: tenant(),
        user_id: Some(crate::authn::ids::testing::user("user-1")),
        trust_level: level,
        fingerprint_hash: FingerprintHash::from_bytes([byte; 32]),
        first_seen_at: last_seen,
        last_seen_at: last_seen,
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    }
}

#[test]
fn the_ladder_function_matches_the_table() {
    let cfg = SweepConfig::default();
    for r in LADDER {
        assert_eq!(
            cfg.level_after(r.level, r.last_seen(at()), r.demoted_at(at()), at()),
            r.want,
            "{:?} idle {}d demoted {:?}d ago",
            r.level,
            r.idle_days,
            r.demoted_days_ago
        );
    }
}

#[tokio::test]
async fn memory_sweep_follows_the_ladder_table() {
    let store = MemoryDeviceStore::new();
    for (i, r) in LADDER.iter().enumerate() {
        let mut d = device(&format!("row-{i}"), i as u8, r.level, r.last_seen(at()));
        d.demoted_at = r.demoted_at(at());
        store.save(&d, crate::device::test_now()).await.unwrap();
    }
    store.sweep(&tenant(), at()).await.unwrap();
    for (i, r) in LADDER.iter().enumerate() {
        let id = crate::authn::ids::testing::device(&format!("row-{i}"));
        let got = store.load(&tenant(), &id).await.unwrap().unwrap();
        assert_eq!(
            got.trust_level, r.want,
            "{:?} idle {}d demoted {:?}d ago",
            r.level, r.idle_days, r.demoted_days_ago
        );
    }
}

/// A Trusted device demoted by the sweep at day 100 is stamped, keeps its
/// whole Seen window from that demotion, and is revoked only after it.
#[tokio::test]
async fn a_demoted_trusted_device_keeps_its_seen_window() {
    let store = MemoryDeviceStore::new();
    let seen_last = at() - chrono::Duration::days(100);
    let d = device("row", 1, DeviceTrustLevel::Trusted, seen_last);
    store.save(&d, crate::device::test_now()).await.unwrap();
    let row = |s: &MemoryDeviceStore| {
        let s = s.clone();
        let id = d.id;
        async move { s.load(&tenant(), &id).await.unwrap().unwrap() }
    };
    let day = |n: i64| at() + chrono::Duration::days(n);

    store.sweep(&tenant(), at()).await.unwrap();
    let demoted = row(&store).await;
    assert_eq!(demoted.trust_level, DeviceTrustLevel::Seen);
    assert_eq!(demoted.demoted_at, Some(at()));
    store.sweep(&tenant(), day(29)).await.unwrap();
    assert_eq!(row(&store).await.trust_level, DeviceTrustLevel::Seen);
    store.sweep(&tenant(), day(31)).await.unwrap();
    assert_eq!(row(&store).await.trust_level, DeviceTrustLevel::Revoked);
}

/// A sighting after the demotion restarts the Seen window, so an active
/// device is not revoked for having once been demoted.
#[tokio::test]
async fn a_sighting_restarts_a_demoted_devices_seen_window() {
    let store = MemoryDeviceStore::new();
    let mut d = device("row", 1, DeviceTrustLevel::Seen, at());
    d.demoted_at = Some(at() - chrono::Duration::days(40));
    d.last_seen_at = at() - chrono::Duration::days(5);
    store.save(&d, crate::device::test_now()).await.unwrap();
    store.sweep(&tenant(), at()).await.unwrap();
    let got = store.load(&tenant(), &d.id).await.unwrap().unwrap();
    assert_eq!(got.trust_level, DeviceTrustLevel::Seen);
}

/// The stamp follows the transition on every explicit write: Trusted to
/// Seen stamps, Seen to Seen keeps, Unknown to Seen leaves none, and a
/// promotion to Trusted clears it.
#[tokio::test]
async fn explicit_transitions_stamp_and_clear_the_demotion() {
    let store = MemoryDeviceStore::new();
    let d = device("row", 1, DeviceTrustLevel::Trusted, at());
    store.save(&d, crate::device::test_now()).await.unwrap();
    let demoted_at = |s: &MemoryDeviceStore| {
        let s = s.clone();
        let id = d.id;
        async move { s.load(&tenant(), &id).await.unwrap().unwrap().demoted_at }
    };
    let t1 = at() + chrono::Duration::hours(1);
    let t2 = at() + chrono::Duration::hours(2);

    store
        .set_trust_level(&tenant(), &d.id, DeviceTrustLevel::Seen, t1)
        .await
        .unwrap();
    assert_eq!(demoted_at(&store).await, Some(t1));
    store
        .set_trust_level(&tenant(), &d.id, DeviceTrustLevel::Seen, t2)
        .await
        .unwrap();
    assert_eq!(demoted_at(&store).await, Some(t1), "Seen to Seen keeps it");
    store
        .set_trust_level(&tenant(), &d.id, DeviceTrustLevel::Trusted, t2)
        .await
        .unwrap();
    assert_eq!(demoted_at(&store).await, None, "promotion clears it");

    let applied = store
        .set_trust_level_if(
            &tenant(),
            &d.id,
            DeviceTrustLevel::Trusted,
            DeviceTrustLevel::Seen,
            t2,
        )
        .await
        .unwrap();
    assert_eq!(applied, TrustTransition::Applied);
    assert_eq!(demoted_at(&store).await, Some(t2));

    let never = device("never", 2, DeviceTrustLevel::Unknown, at());
    store.save(&never, crate::device::test_now()).await.unwrap();
    store
        .set_trust_level(&tenant(), &never.id, DeviceTrustLevel::Seen, t1)
        .await
        .unwrap();
    let got = store.load(&tenant(), &never.id).await.unwrap().unwrap();
    assert_eq!(got.demoted_at, None, "never trusted stays unstamped");
}

#[tokio::test]
async fn memory_conditional_writes_refuse_a_revoked_device() {
    let store = MemoryDeviceStore::new();
    let d = device("row", 1, DeviceTrustLevel::Unknown, at());
    store.save(&d, crate::device::test_now()).await.unwrap();
    store
        .set_trust_level(&tenant(), &d.id, DeviceTrustLevel::Revoked, at())
        .await
        .unwrap();

    let got = store
        .set_trust_level_if(
            &tenant(),
            &d.id,
            DeviceTrustLevel::Unknown,
            DeviceTrustLevel::Seen,
            at(),
        )
        .await
        .unwrap();
    assert_eq!(
        got,
        TrustTransition::Refused {
            current: DeviceTrustLevel::Revoked
        }
    );
    let binding = crate::device::types::DeviceBinding::Refresh {
        family_id: "f".into(),
        issued_at: at(),
        last_used_at: at(),
    };
    assert_eq!(
        store
            .replace_bindings(&tenant(), &d.id, &[], &[binding], crate::device::test_now())
            .await
            .unwrap(),
        BindingsUpdate::Revoked
    );
    let row = store.load(&tenant(), &d.id).await.unwrap().unwrap();
    assert!(row.bindings.is_empty());
    assert_eq!(row.revoked_at, Some(at()));

    let ghost = crate::authn::ids::testing::device("ghost");
    assert_eq!(
        store
            .set_trust_level_if(
                &tenant(),
                &ghost,
                DeviceTrustLevel::Unknown,
                DeviceTrustLevel::Seen,
                at()
            )
            .await
            .unwrap(),
        TrustTransition::Missing
    );
}
