//! `tests`: extracted from `encrypted.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use chrono::{TimeZone, Utc};

fn sample_tenant() -> TenantId {
    TenantId::from_bytes([1u8; 16])
}

fn sample_user() -> UserId {
    UserId::from_bytes([2u8; 16])
}

fn sample_credential() -> StoredDelegation {
    StoredDelegation {
        provider: "gmail".to_string(),
        access_token: ZeroizedString::from("at-plaintext"),
        refresh_token: Some(ZeroizedString::from("rt-plaintext")),
        expires_at: Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        scopes: vec!["gmail.send".to_string()],
        token_type: "Bearer".to_string(),
    }
}

fn store_with_key(
    key: [u8; 32],
) -> EncryptedDelegatedCredentialStore<MemoryDelegatedCredentialStore, MemoryKeyProvider> {
    let keys = MemoryKeyProvider::new("k1", key).expect("valid key id");
    EncryptedDelegatedCredentialStore::new(MemoryDelegatedCredentialStore::new(), keys)
}

#[tokio::test]
async fn save_then_load_roundtrips_plaintext() {
    let store = store_with_key([7u8; 32]);
    let tenant = sample_tenant();
    let user = sample_user();
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");
    let loaded = store
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    assert_eq!(&*loaded.access_token, "at-plaintext");
    assert_eq!(loaded.refresh_token.as_deref(), Some("rt-plaintext"));
    assert_eq!(loaded.provider, "gmail");
    assert_eq!(loaded.scopes, vec!["gmail.send".to_string()]);
}

/// Inner store never sees the plaintext token; what's written
/// must be an envelope, not the original string.
#[tokio::test]
async fn inner_store_holds_ciphertext_not_plaintext() {
    let inner = MemoryDelegatedCredentialStore::new();
    let keys = MemoryKeyProvider::new("k1", [9u8; 32]).expect("valid key");
    let store = EncryptedDelegatedCredentialStore::new(inner, keys);
    let tenant = sample_tenant();
    let user = sample_user();
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");

    // Reach back into the wrapper's inner store via the
    // `inner()` accessor and observe the stored row directly.
    let raw = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("inner load")
        .expect("present");
    assert!(
        (*raw.access_token).starts_with("v1.k1."),
        "expected envelope prefix, got: {:?}",
        &*raw.access_token
    );
    assert_ne!(&*raw.access_token, "at-plaintext");
    let rt = raw.refresh_token.as_deref().expect("refresh present");
    assert!(rt.starts_with("v1.k1."));
    assert_ne!(rt, "rt-plaintext");
}

/// Each encryption uses a fresh random nonce, so two saves of
/// the same plaintext produce distinct ciphertexts.
#[tokio::test]
async fn ciphertext_differs_across_saves_with_same_plaintext() {
    let store = store_with_key([3u8; 32]);
    let tenant = sample_tenant();
    let user = sample_user();
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("first save");
    let first = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("second save");
    let second = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    assert_ne!(
        &*first.access_token, &*second.access_token,
        "two saves with same plaintext must yield different ciphertexts (random nonce)"
    );
}

/// AAD binding: moving a row's ciphertext into a different
/// `(tenant, user, provider)` triple breaks decrypt.
#[tokio::test]
async fn row_swap_attack_fails_on_decrypt() {
    let inner = MemoryDelegatedCredentialStore::new();
    let keys = MemoryKeyProvider::new("k1", [11u8; 32]).expect("valid key");
    let store = EncryptedDelegatedCredentialStore::new(inner, keys);

    let tenant_a = TenantId::from_bytes([1u8; 16]);
    let tenant_b = TenantId::from_bytes([2u8; 16]);
    let user = sample_user();

    // Save user-A's credential, then read the raw row.
    store
        .save(&tenant_a, &user, sample_credential())
        .await
        .expect("save A");
    let stolen_row = store
        .inner()
        .load(&tenant_a, &user, "gmail")
        .await
        .expect("load A")
        .expect("present");

    // Plant user-A's ciphertext into user-B's row.
    store
        .inner()
        .save(&tenant_b, &user, stolen_row)
        .await
        .expect("inner save B");

    // Loading via the wrapper for tenant_b must FAIL; the AAD
    // for B doesn't match what A was encrypted under.
    let result = store.load(&tenant_b, &user, "gmail").await;
    assert!(
        result.is_err(),
        "row-swap from tenant_a to tenant_b should not decrypt: {result:?}"
    );
}

/// Cross-field swap (access ↔ refresh within the same row) is
/// also AAD-rejected because field_tag differentiates them.
#[tokio::test]
async fn field_swap_attack_fails_on_decrypt() {
    let inner = MemoryDelegatedCredentialStore::new();
    let keys = MemoryKeyProvider::new("k1", [13u8; 32]).expect("valid key");
    let store = EncryptedDelegatedCredentialStore::new(inner, keys);
    let tenant = sample_tenant();
    let user = sample_user();
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");

    let row = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("inner load")
        .expect("present");
    // Swap access and refresh ciphertexts.
    let swapped = StoredDelegation {
        access_token: row.refresh_token.clone().expect("rt"),
        refresh_token: Some(row.access_token.clone()),
        ..row
    };
    store
        .inner()
        .save(&tenant, &user, swapped)
        .await
        .expect("inner save");

    // Wrapper-level load must fail because each field's AAD
    // bound to the slot it sits in.
    let result = store.load(&tenant, &user, "gmail").await;
    assert!(result.is_err(), "field-swap should not decrypt: {result:?}");
}

/// Decrypt under a key not held by the provider fails cleanly.
#[tokio::test]
async fn decrypt_fails_when_key_id_unknown() {
    let tenant = sample_tenant();
    let user = sample_user();

    // Save under one key, then construct a fresh wrapper with a
    // provider that doesn't know that key id.
    let inner = MemoryDelegatedCredentialStore::new();
    let writer_keys = MemoryKeyProvider::new("k1", [21u8; 32]).expect("valid");
    let writer = EncryptedDelegatedCredentialStore::new(inner, writer_keys);
    writer
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");

    // Move inner storage into a wrapper with a different
    // provider id only.
    let raw = writer
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    let fresh_inner = MemoryDelegatedCredentialStore::new();
    fresh_inner.save(&tenant, &user, raw).await.expect("plant");
    let reader_keys = MemoryKeyProvider::new("k2", [99u8; 32]).expect("valid");
    let reader = EncryptedDelegatedCredentialStore::new(fresh_inner, reader_keys);

    let result = reader.load(&tenant, &user, "gmail").await;
    assert!(result.is_err(), "unknown key id must surface as error");
}

/// Rotation: writes use the current key, but a historical key
/// stays valid for decrypt of pre-rotation rows.
#[tokio::test]
async fn historical_key_decrypts_pre_rotation_rows() {
    let tenant = sample_tenant();
    let user = sample_user();
    let old_key = [4u8; 32];
    let new_key = [5u8; 32];

    // Write under old key.
    let inner = MemoryDelegatedCredentialStore::new();
    let old_keys = MemoryKeyProvider::new("k1", old_key).expect("valid");
    let writer = EncryptedDelegatedCredentialStore::new(inner, old_keys);
    writer
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");

    // Move the encrypted row into a new wrapper whose CURRENT
    // key is new but which still resolves k1 historically.
    let raw = writer
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    let fresh_inner = MemoryDelegatedCredentialStore::new();
    fresh_inner.save(&tenant, &user, raw).await.expect("plant");
    let rotated_keys = MemoryKeyProvider::new("k2", new_key)
        .expect("valid")
        .with_historical("k1", old_key)
        .expect("valid");
    let store = EncryptedDelegatedCredentialStore::new(fresh_inner, rotated_keys);

    // Load surfaces plaintext via the historical key.
    let loaded = store
        .load(&tenant, &user, "gmail")
        .await
        .expect("decrypt with historical k1")
        .expect("present");
    assert_eq!(&*loaded.access_token, "at-plaintext");

    // Subsequent save re-encrypts under the new current (k2).
    store
        .save(&tenant, &user, loaded)
        .await
        .expect("save under k2");
    let rewritten = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    assert!(
        (*rewritten.access_token).starts_with("v1.k2."),
        "after re-save, row should be under new current key, got: {:?}",
        &*rewritten.access_token
    );
}

#[tokio::test]
async fn load_missing_credential_returns_none() {
    let store = store_with_key([1u8; 32]);
    let tenant = sample_tenant();
    let user = sample_user();
    let result = store.load(&tenant, &user, "gmail").await.expect("load");
    assert!(result.is_none());
}

#[tokio::test]
async fn revoke_removes_credential() {
    let store = store_with_key([6u8; 32]);
    let tenant = sample_tenant();
    let user = sample_user();
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");
    store.revoke(&tenant, &user, "gmail").await.expect("revoke");
    let result = store.load(&tenant, &user, "gmail").await.expect("load");
    assert!(result.is_none());
}

/// `None` `refresh_token` round-trips without spurious envelope
/// allocation (no refresh ciphertext to encode/decode).
#[tokio::test]
async fn missing_refresh_token_roundtrips_as_none() {
    let store = store_with_key([8u8; 32]);
    let tenant = sample_tenant();
    let user = sample_user();
    let mut cred = sample_credential();
    cred.refresh_token = None;
    store.save(&tenant, &user, cred).await.expect("save");
    let loaded = store
        .load(&tenant, &user, "gmail")
        .await
        .expect("load")
        .expect("present");
    assert!(loaded.refresh_token.is_none());
    assert_eq!(&*loaded.access_token, "at-plaintext");
}

#[test]
fn memory_key_provider_rejects_dot_in_key_id() {
    let err = MemoryKeyProvider::new("has.dot", [0u8; 32]).unwrap_err();
    assert!(matches!(err, KeyProviderError::InvalidKeyId(_)));
}

#[test]
fn memory_key_provider_rejects_empty_key_id() {
    let err = MemoryKeyProvider::new("", [0u8; 32]).unwrap_err();
    assert!(matches!(err, KeyProviderError::InvalidKeyId(_)));
}

/// Future-proofing: an envelope with an unknown version tag
/// surfaces a distinct error variant rather than a generic
/// decrypt failure. This pins forward-compat behaviour against
/// regressions that silently treat unknown versions as
/// corrupted.
#[tokio::test]
async fn unknown_envelope_version_rejects_cleanly() {
    let keys = MemoryKeyProvider::new("k1", [0u8; 32]).expect("valid");

    // Craft an envelope with version "v99". Body content
    // doesn't matter; decode must short-circuit on the
    // version check.
    let fake_envelope = format!("v99.k1.{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
    let aad = build_aad("gmail", &sample_tenant(), &sample_user(), FIELD_ACCESS);
    let err = decrypt_envelope(&keys, &fake_envelope, &aad).unwrap_err();
    assert!(
        matches!(err, EnvelopeError::UnknownVersion(ref v) if v == "v99"),
        "expected UnknownVersion, got {err:?}"
    );
}

/// Truncating an envelope's body to ≤ NONCE_LEN bytes (no room
/// for ciphertext+tag) must surface as `Malformed` rather than
/// reaching the AEAD primitive with a degenerate input.
#[tokio::test]
async fn short_envelope_body_rejects_as_malformed() {
    let keys = MemoryKeyProvider::new("k1", [0u8; 32]).expect("valid");
    let short = format!("v1.k1.{}", URL_SAFE_NO_PAD.encode([0u8; NONCE_LEN]));
    let aad = build_aad("gmail", &sample_tenant(), &sample_user(), FIELD_ACCESS);
    let err = decrypt_envelope(&keys, &short, &aad).unwrap_err();
    assert!(matches!(err, EnvelopeError::Malformed(_)));
}
