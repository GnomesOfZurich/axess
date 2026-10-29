//! Re-seal of stale bindings blobs against a real Postgres server, ignored by
//! default (`POSTGRES_URL`): a read that finds a blob in an older format writes it
//! back in the current one, conditional on the bytes it read.

use super::*;
use crate::device::store::consistency::{at, dev_id, device, tenant, user};
use crate::session::crypto::{BoundFormat, device_row_id_v1};
use crate::testing::sql_live;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const KEY: [u8; 32] = [0x42; 32];

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: at(0),
        last_used_at: at(0),
    }
}

fn fingerprint() -> FingerprintHash {
    FingerprintHash::from_bytes([7; 32])
}

async fn encrypted_store() -> PostgresDeviceStore {
    let store = PostgresDeviceStore::new(
        sql_live::postgres_pool(4).await,
        SessionCrypto::new(KEY).with_legacy_blobs(crate::session::crypto::LegacyBlobs::Accept),
    );
    store.init_schema().await.unwrap();
    store
}

/// A bindings blob without any format marker, as stored before binding.
fn unbound_blob(bindings: &[DeviceBinding]) -> String {
    let body = SessionCrypto::new(KEY)
        .encrypt_unbound(&rmp_serde::to_vec_named(bindings).unwrap())
        .unwrap();
    BASE64.encode(body)
}

/// A bindings blob in the 0.11.0 format.
fn v1_blob(tenant: &str, device: &str, bindings: &[DeviceBinding]) -> String {
    let body = SessionCrypto::new(KEY)
        .encrypt_with_aad(
            &BoundFormat::DEVICE_BINDINGS_V1.aad(&device_row_id_v1(tenant, device)),
            &rmp_serde::to_vec_named(bindings).unwrap(),
        )
        .unwrap();
    let mut blob = b"AXD\x01".to_vec();
    blob.extend_from_slice(&body);
    BASE64.encode(blob)
}

async fn stored_blob(store: &PostgresDeviceStore, device: &DeviceId) -> String {
    sqlx::query_scalar("SELECT bindings FROM devices WHERE id = $1")
        .bind(device.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

async fn overwrite_blob(store: &PostgresDeviceStore, device: &DeviceId, blob: &str) {
    sqlx::query("UPDATE devices SET bindings = $1 WHERE id = $2")
        .bind(blob)
        .bind(device.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
}

fn is_current_format(stored: &str) -> bool {
    BASE64.decode(stored).unwrap().starts_with(b"AXD\x82")
}

fn unbound(_: &str, _: &str, b: &[DeviceBinding]) -> String {
    unbound_blob(b)
}

/// Save a device, then replace its stored blob with `old(tenant, device)`.
async fn seeded(
    old: impl Fn(&str, &str, &[DeviceBinding]) -> String,
) -> (
    PostgresDeviceStore,
    TenantId,
    UserId,
    DeviceId,
    Vec<DeviceBinding>,
) {
    let store = encrypted_store().await;
    let (t, u, id) = (tenant(), user(), dev_id("sealed"));
    let bindings = vec![refresh("fam-1")];
    let mut d = device("sealed", 7, DeviceTrustLevel::Seen, at(10));
    d.bindings = bindings.clone();
    store.save(&d, at(10)).await.unwrap();
    let blob = old(&t.to_string(), &id.to_string(), &bindings);
    assert!(!is_current_format(&blob));
    overwrite_blob(&store, &id, &blob).await;
    (store, t, u, id, bindings)
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn load_reseals_an_unbound_blob() {
    let (store, t, _, d, bindings) = seeded(unbound).await;
    assert_eq!(
        store.load(&t, &d).await.unwrap().unwrap().bindings,
        bindings
    );
    assert!(is_current_format(&stored_blob(&store, &d).await));
    assert_eq!(
        store.load(&t, &d).await.unwrap().unwrap().bindings,
        bindings
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn load_reseals_a_blob_of_the_previous_format() {
    let (store, t, _, d, bindings) = seeded(v1_blob).await;
    assert_eq!(
        store.load(&t, &d).await.unwrap().unwrap().bindings,
        bindings
    );
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_current_blob_is_left_alone_by_a_read() {
    let store = encrypted_store().await;
    let mut d = device("current", 7, DeviceTrustLevel::Seen, at(10));
    d.bindings = vec![refresh("f")];
    store.save(&d, at(10)).await.unwrap();
    let before = stored_blob(&store, &d.id).await;
    store.load(&tenant(), &d.id).await.unwrap().unwrap();
    store.find_for_user(&tenant(), &user(), 10).await.unwrap();
    assert_eq!(stored_blob(&store, &d.id).await, before);
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn find_by_fingerprint_reseals() {
    let (store, t, _, d, bindings) = seeded(unbound).await;
    let found = store.find_by_fingerprint(&t, &fingerprint()).await.unwrap();
    assert_eq!(found.unwrap().bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn find_for_user_and_refresh_family_reseal() {
    let (store, t, u, d, bindings) = seeded(v1_blob).await;
    let found = store.find_for_user(&t, &u, 10).await.unwrap();
    assert_eq!(found[0].bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));

    overwrite_blob(&store, &d, &unbound_blob(&bindings)).await;
    let found = store.find_by_refresh_family(&t, "fam-1").await.unwrap();
    assert_eq!(found[0].bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));

    let old = v1_blob(&t.to_string(), &d.to_string(), &bindings);
    overwrite_blob(&store, &d, &old).await;
    let found = store.find_active_for_user(&t, &u, 10).await.unwrap();
    assert_eq!(found[0].bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn find_by_fingerprint_for_user_reseals() {
    let (store, t, u, d, bindings) = seeded(unbound).await;
    let found = store
        .find_by_fingerprint_for_user(&t, &u, &fingerprint())
        .await
        .unwrap();
    assert_eq!(found.unwrap().bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

/// A save that lands between the read and the re-seal keeps its bytes: the
/// re-seal matches no row. The race is placed by hand, between the two
/// halves of what `load` does.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_reseal_never_overwrites_a_save_that_landed_meanwhile() {
    let (store, t, _, d, _) = seeded(unbound).await;
    let row: DeviceRow = sqlx::query_as(select_devices!("WHERE tenant_id = $1 AND id = $2"))
        .bind(t.to_string())
        .bind(d.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let (read, reseal) = row.into_device(&store.codec).unwrap();
    assert!(reseal.is_some(), "the unbound blob must be reported stale");

    let newer = vec![refresh("fam-2")];
    let mut saved = device("sealed", 7, DeviceTrustLevel::Seen, at(10));
    saved.bindings = newer.clone();
    store.save(&saved, at(15)).await.unwrap();
    let kept = stored_blob(&store, &d).await;

    reseal_rows(&store.pool, reseal).await;
    assert_eq!(stored_blob(&store, &d).await, kept);
    assert_ne!(read.bindings, newer);
    assert_eq!(store.load(&t, &d).await.unwrap().unwrap().bindings, newer);
}

/// A failing re-seal does not fail the read.
#[tokio::test]
#[ignore = "requires a running Postgres (POSTGRES_URL)"]
async fn a_failed_reseal_still_returns_the_device() {
    let (store, t, _, d, bindings) = seeded(unbound).await;
    // Refuses any blob in the current format (`AXD\x82` in base64).
    sqlx::query("ALTER TABLE devices ADD CONSTRAINT refuse_current CHECK (bindings NOT LIKE 'QVhE%') NOT VALID")
        .execute(&store.pool)
        .await
        .unwrap();
    let loaded = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded.bindings, bindings);
    assert!(!is_current_format(&stored_blob(&store, &d).await));
}
