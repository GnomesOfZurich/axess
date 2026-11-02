//! `tests`: extracted from `encrypted.rs` per the
//! 200-LoC inline-test rule in AGENTS.md.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::envelope::decrypt_envelope;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use crate::session::crypto::LegacyBlobs;
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
    let store = store_with_key(test_key(7));
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
    let keys = MemoryKeyProvider::new("k1", test_key(9)).expect("valid key");
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
        (*raw.access_token).starts_with("v3.k1."),
        "expected envelope prefix, got: {:?}",
        &*raw.access_token
    );
    assert_ne!(&*raw.access_token, "at-plaintext");
    let rt = raw.refresh_token.as_deref().expect("refresh present");
    assert!(rt.starts_with("v3.k1."));
    assert_ne!(rt, "rt-plaintext");
}

/// Each encryption uses a fresh random nonce, so two saves of
/// the same plaintext produce distinct ciphertexts.
#[tokio::test]
async fn ciphertext_differs_across_saves_with_same_plaintext() {
    let store = store_with_key(test_key(3));
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
    let keys = MemoryKeyProvider::new("k1", test_key(11)).expect("valid key");
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
    let keys = MemoryKeyProvider::new("k1", test_key(13)).expect("valid key");
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
    let writer_keys = MemoryKeyProvider::new("k1", test_key(21)).expect("valid");
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
    let reader_keys = MemoryKeyProvider::new("k2", test_key(99)).expect("valid");
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
    let old_key = test_key(4);
    let new_key = test_key(5);

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
        (*rewritten.access_token).starts_with("v3.k2."),
        "after re-save, row should be under new current key, got: {:?}",
        &*rewritten.access_token
    );
}

#[tokio::test]
async fn load_missing_credential_returns_none() {
    let store = store_with_key(test_key(1));
    let tenant = sample_tenant();
    let user = sample_user();
    let result = store.load(&tenant, &user, "gmail").await.expect("load");
    assert!(result.is_none());
}

#[tokio::test]
async fn revoke_removes_credential() {
    let store = store_with_key(test_key(6));
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
    let store = store_with_key(test_key(8));
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
    let err = MemoryKeyProvider::new("has.dot", test_key(0)).unwrap_err();
    assert!(matches!(err, KeyProviderError::InvalidKeyId(_)));
}

#[test]
fn memory_key_provider_rejects_empty_key_id() {
    let err = MemoryKeyProvider::new("", test_key(0)).unwrap_err();
    assert!(matches!(err, KeyProviderError::InvalidKeyId(_)));
}

/// Future-proofing: an envelope with an unknown version tag
/// surfaces a distinct error variant rather than a generic
/// decrypt failure. This pins forward-compat behaviour against
/// regressions that silently treat unknown versions as
/// corrupted.
#[tokio::test]
async fn unknown_envelope_version_rejects_cleanly() {
    let keys = MemoryKeyProvider::new("k1", test_key(0)).expect("valid");

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
    let keys = MemoryKeyProvider::new("k1", test_key(0)).expect("valid");
    let short = format!("v1.k1.{}", URL_SAFE_NO_PAD.encode([0u8; NONCE_LEN]));
    let aad = build_aad("gmail", &sample_tenant(), &sample_user(), FIELD_ACCESS);
    let err = decrypt_envelope(&keys, &short, &aad).unwrap_err();
    assert!(matches!(err, EnvelopeError::Malformed(_)));
}

/// The v2 AAD covers `scopes` and `token_type`: a store that widens the
/// granted scopes or changes the token type under the ciphertext makes the
/// row fail to open.
#[tokio::test]
async fn rewriting_scopes_or_token_type_in_the_inner_store_fails_authentication() {
    let store = store_with_key(test_key(5));
    let (tenant, user) = (sample_tenant(), sample_user());
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");
    let mut raw = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .unwrap()
        .unwrap();

    let mut widened = raw.clone();
    widened.scopes.push("gmail.admin".to_string());
    store.inner().save(&tenant, &user, widened).await.unwrap();
    let err = store.load(&tenant, &user, "gmail").await.unwrap_err();
    assert!(err.contains("decrypt"), "{err}");

    raw.token_type = "MAC".to_string();
    store.inner().save(&tenant, &user, raw).await.unwrap();
    assert!(store.load(&tenant, &user, "gmail").await.is_err());
}

/// Reordering the same scope set does not break authentication.
#[tokio::test]
async fn reordering_scopes_does_not_break_authentication() {
    let store = store_with_key(test_key(6));
    let (tenant, user) = (sample_tenant(), sample_user());
    let mut cred = sample_credential();
    cred.scopes = vec!["a".into(), "b".into()];
    store.save(&tenant, &user, cred).await.unwrap();
    let mut raw = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .unwrap()
        .unwrap();
    raw.scopes = vec!["b".into(), "a".into()];
    store.inner().save(&tenant, &user, raw).await.unwrap();
    assert!(store.load(&tenant, &user, "gmail").await.unwrap().is_some());
}

/// A row written two releases ago (v1, AAD without scopes) still opens
/// under the legacy policy, and the read re-seals it as v3 under the
/// current key.
#[tokio::test]
async fn a_v1_row_under_a_retired_key_is_read_and_resealed() {
    let (tenant, user) = (sample_tenant(), sample_user());
    let old_key = test_key(1);
    let new_key = test_key(2);
    let cred = sample_credential();

    let old = CurrentKey {
        key_id: Arc::from("k1"),
        key: Arc::new(EncryptionKey::from_bytes(old_key)),
    };
    let aad_a = build_aad("gmail", &tenant, &user, FIELD_ACCESS);
    let aad_r = build_aad("gmail", &tenant, &user, FIELD_REFRESH);
    let rng = axess_rng::SystemRng;
    let v1 = |env: String| env.replacen("v3.", "v1.", 1);
    let legacy = StoredDelegation {
        access_token: ZeroizedString::from(v1(encrypt_envelope(
            &old,
            &rng,
            "at-plaintext",
            &aad_a,
        )
        .unwrap())),
        refresh_token: Some(ZeroizedString::from(v1(encrypt_envelope(
            &old,
            &rng,
            "rt-plaintext",
            &aad_r,
        )
        .unwrap()))),
        ..cred
    };
    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant, &user, legacy).await.unwrap();
    let keys = MemoryKeyProvider::new("k2", new_key)
        .unwrap()
        .with_historical("k1", old_key)
        .unwrap();

    let store = EncryptedDelegatedCredentialStore::new(inner, keys)
        .with_legacy_envelopes(LegacyBlobs::Accept);
    let loaded = store.load(&tenant, &user, "gmail").await.unwrap().unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");

    let raw = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .unwrap()
        .unwrap();
    assert!(
        (*raw.access_token).starts_with("v3.k2."),
        "{:?}",
        &*raw.access_token
    );
    assert!(raw.refresh_token.as_deref().unwrap().starts_with("v3.k2."));
}

#[tokio::test]
async fn seals_counts_every_envelope_written() {
    let store = store_with_key(test_key(8));
    let (tenant, user) = (sample_tenant(), sample_user());
    assert_eq!(store.seals(), 0);
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");
    assert_eq!(store.seals(), 2, "access + refresh");
    let mut no_refresh = sample_credential();
    no_refresh.refresh_token = None;
    store.save(&tenant, &user, no_refresh).await.expect("save");
    assert_eq!(store.seals(), 3);
}

/// A store writer who moves `expires_at` would make an expired token look
/// fresh (refresh skipped) or a fresh one look expired. The expiry is bound
/// into the AAD, so a row whose only change is `expires_at` fails to open.
#[tokio::test]
async fn changing_only_expires_at_on_the_stored_row_fails_the_load() {
    let store = store_with_key(test_key(5));
    let (tenant, user) = (sample_tenant(), sample_user());
    store
        .save(&tenant, &user, sample_credential())
        .await
        .expect("save");
    let raw = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .expect("inner load")
        .expect("present");
    assert_eq!(
        raw.expires_at,
        sample_credential().expires_at,
        "the case exists"
    );

    // Forward-dated: the token would look fresh past its real expiry.
    let mut moved = raw.clone();
    moved.expires_at = Some(Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap());
    store.inner().save(&tenant, &user, moved).await.unwrap();
    let err = store
        .load(&tenant, &user, "gmail")
        .await
        .expect_err("a moved expiry is a tampered row");
    assert!(err.contains("decrypt access_token"), "{err}");

    // Cleared: an unknown expiry is a different statement from a known one.
    let mut cleared = raw.clone();
    cleared.expires_at = None;
    store.inner().save(&tenant, &user, cleared).await.unwrap();
    store
        .load(&tenant, &user, "gmail")
        .await
        .expect_err("a cleared expiry is a tampered row");

    // The row as written still opens.
    store.inner().save(&tenant, &user, raw).await.unwrap();
    let loaded = store.load(&tenant, &user, "gmail").await.unwrap().unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");
}

/// A row written by the previous release (v2, AAD without `expires_at`)
/// opens without any legacy setting, and the read re-seals it as v3.
#[tokio::test]
async fn a_v2_row_is_read_by_default_and_resealed_as_v3() {
    let (tenant, user) = (sample_tenant(), sample_user());
    let cred = sample_credential();
    let current = CurrentKey {
        key_id: Arc::from("k1"),
        key: Arc::new(EncryptionKey::from_bytes(test_key(3))),
    };
    let rng = axess_rng::SystemRng;
    let v2 = |env: String| env.replacen("v3.", "v2.", 1);
    let aad_a = build_aad_v2(
        "gmail",
        &tenant,
        &user,
        FIELD_ACCESS,
        &cred.scopes,
        "Bearer",
    );
    let aad_r = build_aad_v2(
        "gmail",
        &tenant,
        &user,
        FIELD_REFRESH,
        &cred.scopes,
        "Bearer",
    );
    let previous = StoredDelegation {
        access_token: ZeroizedString::from(v2(encrypt_envelope(
            &current,
            &rng,
            "at-plaintext",
            &aad_a,
        )
        .unwrap())),
        refresh_token: Some(ZeroizedString::from(v2(encrypt_envelope(
            &current,
            &rng,
            "rt-plaintext",
            &aad_r,
        )
        .unwrap()))),
        ..cred
    };
    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant, &user, previous).await.unwrap();
    assert!(
        (*inner
            .load(&tenant, &user, "gmail")
            .await
            .unwrap()
            .unwrap()
            .access_token)
            .starts_with("v2.k1."),
        "the case exists"
    );

    let store = EncryptedDelegatedCredentialStore::new(inner, store_with_key(test_key(3)).keys);
    let loaded = store.load(&tenant, &user, "gmail").await.unwrap().unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");
    assert_eq!(loaded.refresh_token.as_deref(), Some("rt-plaintext"));

    let raw = store
        .inner()
        .load(&tenant, &user, "gmail")
        .await
        .unwrap()
        .unwrap();
    assert!(
        (*raw.access_token).starts_with("v3.k1."),
        "{:?}",
        &*raw.access_token
    );
    assert!(raw.refresh_token.as_deref().unwrap().starts_with("v3.k1."));

    // The re-sealed row now binds its expiry: moving it fails the next load.
    let mut moved = raw;
    moved.expires_at = None;
    store.inner().save(&tenant, &user, moved).await.unwrap();
    store
        .load(&tenant, &user, "gmail")
        .await
        .expect_err("the re-sealed row binds expires_at");
}

/// A current key that is a single repeated byte is a placeholder that
/// reached production; the provider refuses it rather than sealing
/// credentials under it.
#[test]
fn memory_key_provider_refuses_a_constant_current_key() {
    let placeholder = [0u8; 32];
    assert!(crate::session::is_constant_key(&placeholder));
    let err = MemoryKeyProvider::new("k", placeholder).unwrap_err();
    assert!(
        matches!(err, KeyProviderError::WeakKey(_)),
        "expected WeakKey, got {err:?}"
    );
    assert!(MemoryKeyProvider::new("k", test_key(0)).is_ok());
}

/// A historical key only opens rows already sealed under it, so a
/// constant one is logged at error rather than refused.
#[test]
fn a_constant_historical_key_is_logged_at_error() {
    let capture = crate::testing::mock_tracing::TracingCapture::install();
    let keys = MemoryKeyProvider::new("k2", test_key(1))
        .expect("random key")
        .with_historical("k1", [1u8; 32])
        .expect("historical key id");
    assert!(keys.resolve("k1").expect("resolves").is_some());
    assert!(
        capture.contains_at_level(tracing::Level::ERROR, "single repeated byte"),
        "events: {:?}",
        capture.events()
    );
}
