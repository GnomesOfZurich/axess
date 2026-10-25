//! Owner claims and the bindings compare-and-swap on the in-memory store.

use super::*;
use crate::device::types::DeviceBinding;
use chrono::TimeZone;

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("tenant-1")
}

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap()
}

fn unowned() -> Device {
    Device {
        id: crate::authn::ids::testing::device("dev"),
        tenant_id: tenant(),
        user_id: None,
        trust_level: DeviceTrustLevel::Unknown,
        fingerprint_hash: FingerprintHash::from_bytes([1; 32]),
        first_seen_at: at(),
        last_seen_at: at(),
        revoked_at: None,
        demoted_at: None,
        bindings: Vec::new(),
    }
}

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.into(),
        issued_at: at(),
        last_used_at: at(),
    }
}

#[tokio::test]
async fn the_first_claim_wins_and_the_second_user_is_refused() {
    let store = MemoryDeviceStore::new();
    let d = unowned();
    store.save(&d, crate::device::test_now()).await.unwrap();
    let (a, b) = (
        crate::authn::ids::testing::user("a"),
        crate::authn::ids::testing::user("b"),
    );
    assert_eq!(
        store
            .claim_owner(&tenant(), &d.id, &a, crate::device::test_now())
            .await
            .unwrap(),
        OwnerClaim::Claimed
    );
    assert_eq!(
        store
            .claim_owner(&tenant(), &d.id, &b, crate::device::test_now())
            .await
            .unwrap(),
        OwnerClaim::OwnedByOther
    );
    assert_eq!(
        store
            .claim_owner(&tenant(), &d.id, &a, crate::device::test_now())
            .await
            .unwrap(),
        OwnerClaim::Claimed,
        "claiming again as the owner is idempotent"
    );
    let ghost = crate::authn::ids::testing::device("ghost");
    assert_eq!(
        store
            .claim_owner(&tenant(), &ghost, &a, crate::device::test_now())
            .await
            .unwrap(),
        OwnerClaim::Missing
    );
    let row = store.load(&tenant(), &d.id).await.unwrap().unwrap();
    assert_eq!(row.user_id, Some(a));
}

#[tokio::test]
async fn a_stale_bindings_write_conflicts_and_keeps_the_other_edit() {
    let store = MemoryDeviceStore::new();
    let d = unowned();
    store.save(&d, crate::device::test_now()).await.unwrap();
    // Two editors read the empty bindings; the first writes.
    let first = store
        .replace_bindings(
            &tenant(),
            &d.id,
            &[],
            &[refresh("fam-1")],
            crate::device::test_now(),
        )
        .await
        .unwrap();
    assert_eq!(first, BindingsUpdate::Written);
    let second = store
        .replace_bindings(
            &tenant(),
            &d.id,
            &[],
            &[refresh("fam-2")],
            crate::device::test_now(),
        )
        .await
        .unwrap();
    assert_eq!(second, BindingsUpdate::Conflict);
    let row = store.load(&tenant(), &d.id).await.unwrap().unwrap();
    assert_eq!(row.bindings, vec![refresh("fam-1")]);
}
