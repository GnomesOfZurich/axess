//! A read that finds a bindings blob in an older format writes it back in
//! the current one, conditional on the bytes it read.

use super::*;
use crate::session::crypto::{BoundFormat, device_row_id_v1};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const KEY: [u8; 32] = [0x42; 32];

fn refresh(family: &str) -> DeviceBinding {
    DeviceBinding::Refresh {
        family_id: family.to_string(),
        issued_at: now_at(10, 0),
        last_used_at: now_at(10, 0),
    }
}

async fn encrypted_store() -> SqliteDeviceStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteDeviceStore::new(
        pool,
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

async fn stored_blob(store: &SqliteDeviceStore, device: &DeviceId) -> String {
    sqlx::query_scalar("SELECT bindings FROM devices WHERE id = ?1")
        .bind(device.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

async fn overwrite_blob(store: &SqliteDeviceStore, device: &DeviceId, blob: &str) {
    sqlx::query("UPDATE devices SET bindings = ?1 WHERE id = ?2")
        .bind(blob)
        .bind(device.to_string())
        .execute(&store.pool)
        .await
        .unwrap();
}

fn is_current_format(stored: &str) -> bool {
    BASE64.decode(stored).unwrap().starts_with(b"AXD\x82")
}

/// Save a device, then replace its stored blob with `old(tenant, device)`.
async fn seeded(
    old: impl Fn(&str, &str, &[DeviceBinding]) -> String,
) -> (
    SqliteDeviceStore,
    TenantId,
    UserId,
    DeviceId,
    Vec<DeviceBinding>,
) {
    let store = encrypted_store().await;
    let (t, u, d) = ids();
    let bindings = vec![refresh("fam-1")];
    store
        .save(
            &build_device(&t, Some(&u), &d, 7, bindings.clone()),
            now_at(10, 0),
        )
        .await
        .unwrap();
    let blob = old(&t.to_string(), &d.to_string(), &bindings);
    assert!(!is_current_format(&blob));
    overwrite_blob(&store, &d, &blob).await;
    (store, t, u, d, bindings)
}

fn unbound(_: &str, _: &str, b: &[DeviceBinding]) -> String {
    unbound_blob(b)
}

#[tokio::test]
async fn load_reseals_an_unbound_blob() {
    let (store, t, _, d, bindings) = seeded(unbound).await;
    let loaded = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded.bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
    assert_eq!(
        store.load(&t, &d).await.unwrap().unwrap().bindings,
        bindings
    );
}

#[tokio::test]
async fn load_reseals_a_blob_of_the_previous_format() {
    let (store, t, _, d, bindings) = seeded(v1_blob).await;
    let loaded = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded.bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

#[tokio::test]
async fn a_current_blob_is_left_alone_by_a_read() {
    let store = encrypted_store().await;
    let (t, u, d) = ids();
    store
        .save(
            &build_device(&t, Some(&u), &d, 7, vec![refresh("f")]),
            now_at(10, 0),
        )
        .await
        .unwrap();
    let before = stored_blob(&store, &d).await;
    store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(stored_blob(&store, &d).await, before);
}

#[tokio::test]
async fn find_by_fingerprint_reseals() {
    let (store, t, _, d, bindings) = seeded(unbound).await;
    let found = store
        .find_by_fingerprint(&t, &fingerprint(7))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

#[tokio::test]
async fn find_for_user_and_refresh_family_reseal() {
    let (store, t, u, d, bindings) = seeded(v1_blob).await;
    let found = store.find_for_user(&t, &u, 10).await.unwrap();
    assert_eq!(found[0].bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));

    overwrite_blob(&store, &d, &unbound_blob(&bindings)).await;
    let found = store.find_by_refresh_family(&t, "fam-1").await.unwrap();
    assert_eq!(found[0].bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));

    overwrite_blob(
        &store,
        &d,
        &v1_blob(&t.to_string(), &d.to_string(), &bindings),
    )
    .await;
    let found = store.find_active_for_user(&t, &u, 10).await.unwrap();
    assert_eq!(found[0].bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

#[tokio::test]
async fn find_by_fingerprint_for_user_reseals() {
    let (store, t, u, d, bindings) = seeded(unbound).await;
    let found = store
        .find_by_fingerprint_for_user(&t, &u, &fingerprint(7))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.bindings, bindings);
    assert!(is_current_format(&stored_blob(&store, &d).await));
}

/// A save that lands between the read and the re-seal keeps its bytes: the
/// re-seal matches no row. The race is placed by hand, between the two
/// halves of what `load` does.
#[tokio::test]
async fn a_reseal_never_overwrites_a_save_that_landed_meanwhile() {
    let (store, t, u, d, _) = seeded(unbound).await;
    let row: DeviceRow = sqlx::query_as(select_devices!("WHERE tenant_id = ?1 AND id = ?2"))
        .bind(t.to_string())
        .bind(d.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let (read, reseal) = row.into_device(&store.codec).unwrap();
    assert!(reseal.is_some(), "the unbound blob must be reported stale");

    let newer = vec![refresh("fam-2")];
    store
        .save(
            &build_device(&t, Some(&u), &d, 7, newer.clone()),
            now_at(10, 5),
        )
        .await
        .unwrap();
    let saved = stored_blob(&store, &d).await;

    reseal_rows(&store.pool, reseal).await;
    assert_eq!(stored_blob(&store, &d).await, saved);
    assert_ne!(read.bindings, newer);
    assert_eq!(store.load(&t, &d).await.unwrap().unwrap().bindings, newer);
}

/// A failing re-seal does not fail the read.
#[tokio::test]
async fn a_failed_reseal_still_returns_the_device() {
    let (store, t, _, d, bindings) = seeded(unbound).await;
    sqlx::query(
        "CREATE TRIGGER refuse_update BEFORE UPDATE ON devices \
         BEGIN SELECT RAISE(ABORT, 'no'); END",
    )
    .execute(&store.pool)
    .await
    .unwrap();
    let loaded = store.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded.bindings, bindings);
    assert!(!is_current_format(&stored_blob(&store, &d).await));
}

/// A blob in the current format that only the previous key opens is
/// re-sealed under the current key by the read that found it, so the
/// previous key can be dropped without leaving unreadable rows.
#[tokio::test]
async fn a_read_reseals_a_current_format_blob_sealed_under_the_previous_key() {
    const NEW_KEY: [u8; 32] = [0x99; 32];
    let old_store = encrypted_store().await;
    let (t, u, d) = ids();
    let bindings = vec![refresh("fam-rotate")];
    old_store
        .save(
            &build_device(&t, Some(&u), &d, 7, bindings.clone()),
            now_at(10, 0),
        )
        .await
        .unwrap();
    let before = stored_blob(&old_store, &d).await;

    let rotated = SqliteDeviceStore::new(
        old_store.pool.clone(),
        SessionCrypto::new(NEW_KEY).with_previous_key(KEY),
    );
    let loaded = rotated.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(loaded.bindings, bindings);
    assert_ne!(
        stored_blob(&old_store, &d).await,
        before,
        "the read wrote the row back under the current key"
    );

    // The previous key is gone: the row must still open.
    let only_new = SqliteDeviceStore::new(old_store.pool.clone(), SessionCrypto::new(NEW_KEY));
    let again = only_new.load(&t, &d).await.unwrap().unwrap();
    assert_eq!(again.bindings, bindings);
}
