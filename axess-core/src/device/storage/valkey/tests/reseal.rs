//! A read that finds a device row in an older sealed format writes it back
//! in the current one, conditional on the bytes it read and keeping the
//! key's expiry. Live-server tests, ignored by default
//! (`VALKEY_URL=redis://127.0.0.1:56381`).

use super::*;
use crate::session::crypto::{BoundFormat, device_row_id_v1};

async fn sealing_store(tag: &str) -> ValkeyDeviceStore {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = Client::new(Config::from_url(&url).expect("url"), None, None, None);
    client.init().await.expect("connect");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // These tests read rows of the earlier formats on purpose, so the store
    // runs inside the accepting window; the default refuses them, which the
    // offline tests in `super` cover.
    ValkeyDeviceStore::new(client, [7u8; 32])
        .with_prefix(format!("axr_{tag}_{nanos}"))
        .with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept)
}

fn unbound_row(s: &ValkeyDeviceStore, d: &Device) -> Vec<u8> {
    s.crypto
        .as_ref()
        .unwrap()
        .encrypt_unbound(&rmp_serde::to_vec_named(d).unwrap())
        .unwrap()
}

fn v1_row(s: &ValkeyDeviceStore, d: &Device) -> Vec<u8> {
    let (tenant, id) = (d.tenant_id.to_string(), d.id.to_string());
    let body = s
        .crypto
        .as_ref()
        .unwrap()
        .encrypt_with_aad(
            &BoundFormat::DEVICE_ROW_V1.aad(&device_row_id_v1(&tenant, &id)),
            &rmp_serde::to_vec_named(d).unwrap(),
        )
        .unwrap();
    let mut row = b"AXR\x01".to_vec();
    row.extend_from_slice(&body);
    row
}

fn row_key(s: &ValkeyDeviceStore, d: &Device) -> String {
    device_key(&s.prefix, &d.tenant_id.to_string(), &d.id.to_string())
}

async fn stored(s: &ValkeyDeviceStore, d: &Device) -> Vec<u8> {
    s.client.get(row_key(s, d)).await.unwrap()
}

async fn ttl(s: &ValkeyDeviceStore, d: &Device) -> i64 {
    s.client.ttl(row_key(s, d)).await.unwrap()
}

/// Overwrite the row's bytes without touching its expiry.
async fn overwrite(s: &ValkeyDeviceStore, d: &Device, bytes: Vec<u8>) {
    let _: String = s
        .client
        .eval(
            "return redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')",
            vec![row_key(s, d)],
            vec![Value::Bytes(Bytes::from(bytes))],
        )
        .await
        .unwrap();
}

fn is_current(bytes: &[u8]) -> bool {
    bytes.starts_with(b"AXR\x82")
}

/// Save a Seen device, then swap its stored bytes for `old(store, device)`.
async fn seeded(
    tag: &str,
    old: fn(&ValkeyDeviceStore, &Device) -> Vec<u8>,
) -> (ValkeyDeviceStore, Device, i64) {
    let s = sealing_store(tag).await;
    let d = device(DeviceTrustLevel::Seen, Utc::now());
    s.save(&d, Utc::now()).await.unwrap();
    let before = ttl(&s, &d).await;
    assert!(before > 0, "a Seen row carries an expiry");
    let bytes = old(&s, &d);
    assert!(!is_current(&bytes));
    overwrite(&s, &d, bytes).await;
    (s, d, before)
}

fn kept(before: i64, after: i64) {
    assert!(
        after > 0 && after <= before && before - after <= 5,
        "ttl {before} -> {after}"
    );
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn load_reseals_an_unbound_row_and_keeps_its_expiry() {
    let (s, d, before) = seeded("unb", unbound_row).await;
    assert_eq!(s.load(&d.tenant_id, &d.id).await.unwrap().unwrap(), d);
    assert!(is_current(&stored(&s, &d).await));
    kept(before, ttl(&s, &d).await);
    assert_eq!(s.load(&d.tenant_id, &d.id).await.unwrap().unwrap(), d);
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn load_reseals_a_row_of_the_previous_format_and_keeps_its_expiry() {
    let (s, d, before) = seeded("v1", v1_row).await;
    assert_eq!(s.load(&d.tenant_id, &d.id).await.unwrap().unwrap(), d);
    assert!(is_current(&stored(&s, &d).await));
    kept(before, ttl(&s, &d).await);
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn the_finders_and_the_sweep_reseal() {
    let (s, d, before) = seeded("find", unbound_row).await;
    let user = d.user_id.unwrap();
    let found = s
        .find_by_fingerprint(&d.tenant_id, &d.fingerprint_hash)
        .await
        .unwrap();
    assert_eq!(found.unwrap(), d);
    assert!(is_current(&stored(&s, &d).await));
    kept(before, ttl(&s, &d).await);

    overwrite(&s, &d, v1_row(&s, &d)).await;
    let found = s.find_for_user(&d.tenant_id, &user, 10).await.unwrap();
    assert_eq!(found, vec![d.clone()]);
    assert!(is_current(&stored(&s, &d).await));

    overwrite(&s, &d, unbound_row(&s, &d)).await;
    s.sweep(&d.tenant_id, Utc::now()).await.unwrap();
    assert!(is_current(&stored(&s, &d).await));
    kept(before, ttl(&s, &d).await);
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_current_row_is_left_alone_by_a_read() {
    let s = sealing_store("cur").await;
    let d = device(DeviceTrustLevel::Seen, Utc::now());
    s.save(&d, Utc::now()).await.unwrap();
    let before = stored(&s, &d).await;
    s.load(&d.tenant_id, &d.id).await.unwrap().unwrap();
    assert_eq!(stored(&s, &d).await, before);
}

/// A save that lands between the read and the re-seal keeps its bytes: the
/// race is placed by hand between the two halves of what `load` does.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_reseal_never_overwrites_a_save_that_landed_meanwhile() {
    let (s, d, _) = seeded("race", unbound_row).await;
    let (tenant, id) = (d.tenant_id.to_string(), d.id.to_string());
    let (read, raw, stale) = s.get_row_checked(&tenant, &id).await.unwrap().unwrap();
    assert!(stale);

    let mut newer = d.clone();
    newer.last_seen_at = d.last_seen_at + Duration::seconds(30);
    s.save(&newer, Utc::now()).await.unwrap();
    let saved = stored(&s, &d).await;

    s.reseal_row(&read, &raw).await;
    assert_eq!(stored(&s, &d).await, saved);
    assert_eq!(s.load(&d.tenant_id, &d.id).await.unwrap().unwrap(), newer);
}

/// A row sealed by a store on key one is read by a store on key two with key
/// one as the previous key, the read re-seals it under key two, and a store
/// on key two alone then reads it.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_store_with_a_previous_key_reads_and_reseals_rows_of_the_old_key() {
    let old = sealing_store("rot").await;
    let d = device(DeviceTrustLevel::Seen, Utc::now());
    old.save(&d, Utc::now()).await.unwrap();
    let before = stored(&old, &d).await;

    let rotated = ValkeyDeviceStore::with_crypto(
        old.client.clone(),
        SessionCrypto::new([9u8; 32]).with_previous_key([7u8; 32]),
    )
    .with_prefix(old.prefix.to_string());
    assert_eq!(rotated.load(&d.tenant_id, &d.id).await.unwrap().unwrap(), d);
    assert_ne!(stored(&old, &d).await, before, "the read re-sealed the row");

    let new_only =
        ValkeyDeviceStore::new(old.client.clone(), [9u8; 32]).with_prefix(old.prefix.to_string());
    assert_eq!(
        new_only.load(&d.tenant_id, &d.id).await.unwrap().unwrap(),
        d
    );
}

/// A stored row that no configured key opens does not stop the device from
/// being saved again: the save replaces it.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_save_replaces_a_row_that_cannot_be_decoded() {
    let s = sealing_store("undec").await;
    let d = device(DeviceTrustLevel::Seen, Utc::now());
    s.save(&d, Utc::now()).await.unwrap();
    overwrite(&s, &d, b"not a sealed row at all, but long enough".to_vec()).await;
    assert!(s.load(&d.tenant_id, &d.id).await.is_err());

    s.save(&d, Utc::now()).await.unwrap();
    assert_eq!(s.load(&d.tenant_id, &d.id).await.unwrap().unwrap(), d);
}

/// The sweep skips a row it can read in the chunk read and not when the
/// swap reads it again, instead of aborting the tenant.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn the_sweep_skips_a_damaged_row_and_finishes_the_tenant() {
    let s = sealing_store("sweepdmg").await;
    let t0 = Utc::now() - chrono::Duration::days(200);
    let mut bad = device(DeviceTrustLevel::Trusted, t0);
    bad.id = axess_identity::testing::device("damaged");
    let mut good = device(DeviceTrustLevel::Trusted, t0);
    good.id = axess_identity::testing::device("healthy");
    good.fingerprint_hash = FingerprintHash::from_bytes([0xbb; 32]);
    s.save(&bad, t0).await.unwrap();
    s.save(&good, t0).await.unwrap();
    overwrite(&s, &bad, b"damaged damaged damaged damaged".to_vec()).await;

    let counts = s.sweep(&good.tenant_id, Utc::now()).await.unwrap();
    assert_eq!(counts.trusted_to_seen, 1, "the healthy row was demoted");
}

/// A legacy single-id fingerprint key whose row expired is removed by the
/// lookup that finds the row gone.
#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn a_lookup_removes_a_legacy_fingerprint_key_whose_row_expired() {
    let s = sealing_store("legacyfp").await;
    let d = device(DeviceTrustLevel::Seen, Utc::now());
    let (tenant, id) = (d.tenant_id.to_string(), d.id.to_string());
    let legacy = fingerprint_key(&s.prefix, &tenant, &fingerprint_hex(&d.fingerprint_hash));
    let _: () = s.client.set(&legacy, &id, None, None, false).await.unwrap();

    assert!(
        s.find_by_fingerprint(&d.tenant_id, &d.fingerprint_hash)
            .await
            .unwrap()
            .is_none()
    );
    let left: Option<String> = s.client.get(&legacy).await.unwrap();
    assert_eq!(left, None, "the key of an expired row is gone");
}
