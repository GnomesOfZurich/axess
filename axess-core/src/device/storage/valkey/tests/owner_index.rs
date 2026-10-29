//! The per-(tenant, fingerprint, user) set: a user's lookup by fingerprint
//! reads only the devices it lists. Live-server tests, ignored by default
//! (`VALKEY_URL=redis://127.0.0.1:56382`).

use super::super::row::fingerprint_user_key;
use super::*;
use crate::device::store::consistency::{self as shared, at, tenant};

async fn store(tag: &str) -> ValkeyDeviceStore {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    live_store(&format!("axo_{tag}_{nanos}")).await
}

fn owned_key(s: &ValkeyDeviceStore, d: &Device) -> String {
    fingerprint_user_key(
        &s.prefix,
        &d.tenant_id.to_string(),
        &fingerprint_hex(&d.fingerprint_hash),
        &d.user_id.expect("owned").to_string(),
    )
}

async fn members(s: &ValkeyDeviceStore, key: &str) -> Vec<String> {
    s.client.smembers(key).await.unwrap()
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_save_lists_the_device_under_its_owner_and_fingerprint() {
    let s = store("save").await;
    let d = shared::device("mine", 0x31, DeviceTrustLevel::Seen, at(0));
    s.save(&d, at(0)).await.unwrap();

    assert_eq!(
        members(&s, &owned_key(&s, &d)).await,
        vec![d.id.to_string()]
    );
    let user = d.user_id.unwrap();
    let found = s
        .find_by_fingerprint_for_user(&tenant(), &user, &d.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(found.map(|f| f.id), Some(d.id));
}

/// The lookup does not read the user's other devices: one with another
/// fingerprint is not in the set, so a row that cannot be decoded among them
/// does not fail it. (Reading the user's whole index would.)
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn the_lookup_does_not_read_the_users_other_devices() {
    let s = store("narrow").await;
    let mine = shared::device("mine", 0x31, DeviceTrustLevel::Seen, at(0));
    let other = shared::device("other-fp", 0x32, DeviceTrustLevel::Seen, at(0));
    s.save(&mine, at(0)).await.unwrap();
    s.save(&other, at(0)).await.unwrap();
    let key = device_key(
        &s.prefix,
        &other.tenant_id.to_string(),
        &other.id.to_string(),
    );
    let _: () = s
        .client
        .set(key, "not a device row", None, None, false)
        .await
        .unwrap();

    let found = s
        .find_by_fingerprint_for_user(&tenant(), &mine.user_id.unwrap(), &mine.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(found.map(|f| f.id), Some(mine.id));
}

/// A row written before the set existed is found through the user's index
/// and added to the set, so the next lookup does not need the fallback.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_row_the_set_does_not_list_is_found_and_backfilled() {
    let s = store("backfill").await;
    let d = shared::device("old", 0x33, DeviceTrustLevel::Trusted, at(0));
    s.save(&d, at(0)).await.unwrap();
    let key = owned_key(&s, &d);
    let _: i64 = s.client.del(&key).await.unwrap();

    let user = d.user_id.unwrap();
    let found = s
        .find_by_fingerprint_for_user(&tenant(), &user, &d.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(found.map(|f| f.id), Some(d.id));
    assert_eq!(members(&s, &key).await, vec![d.id.to_string()]);
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_delete_and_a_fingerprint_change_move_the_entry() {
    let s = store("move").await;
    let d = shared::device("moving", 0x34, DeviceTrustLevel::Seen, at(0));
    s.save(&d, at(0)).await.unwrap();
    let before = owned_key(&s, &d);

    let mut changed = d.clone();
    changed.fingerprint_hash = FingerprintHash::from_bytes([0x35; 32]);
    s.save(&changed, at(1)).await.unwrap();
    assert!(members(&s, &before).await.is_empty());
    assert_eq!(
        members(&s, &owned_key(&s, &changed)).await,
        vec![d.id.to_string()]
    );

    s.delete(&d.tenant_id, &d.id).await.unwrap();
    assert!(members(&s, &owned_key(&s, &changed)).await.is_empty());
}
