//! Reading `v1` envelopes, and re-sealing a row on load without overwriting a
//! rotation that landed in between.

use super::*;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use crate::session::crypto::LegacyBlobs;
use chrono::{TimeZone, Utc};
use std::sync::Mutex;

fn tenant() -> TenantId {
    TenantId::from_bytes([1u8; 16])
}

fn user() -> UserId {
    UserId::from_bytes([2u8; 16])
}

fn credential() -> StoredDelegation {
    StoredDelegation {
        provider: "gmail".to_string(),
        access_token: ZeroizedString::from("at-plaintext"),
        refresh_token: Some(ZeroizedString::from("rt-plaintext")),
        expires_at: Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        scopes: vec!["gmail.send".to_string()],
        token_type: "Bearer".to_string(),
    }
}

fn keys() -> MemoryKeyProvider {
    MemoryKeyProvider::new("k2", [2u8; 32])
        .unwrap()
        .with_historical("k1", [1u8; 32])
        .unwrap()
}

/// A row as the previous release wrote it: `v1`, sealed under the retired key.
fn v1_row() -> StoredDelegation {
    let old = CurrentKey {
        key_id: Arc::from("k1"),
        key: Arc::new(EncryptionKey::from_bytes([1u8; 32])),
    };
    let rng = axess_rng::SystemRng;
    let v1 = |env: String| env.replacen("v2.", "v1.", 1);
    let aad_a = build_aad("gmail", &tenant(), &user(), FIELD_ACCESS);
    let aad_r = build_aad("gmail", &tenant(), &user(), FIELD_REFRESH);
    StoredDelegation {
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
        ..credential()
    }
}

async fn raw(inner: &impl DelegatedCredentialStore) -> StoredDelegation {
    inner
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn a_v1_envelope_is_refused_by_default_and_read_under_accept() {
    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant(), &user(), v1_row()).await.unwrap();
    let open = EncryptedDelegatedCredentialStore::new(inner, keys())
        .with_legacy_envelopes(LegacyBlobs::Accept)
        .without_reseal_on_load();
    let loaded = open
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");

    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant(), &user(), v1_row()).await.unwrap();
    let strict = EncryptedDelegatedCredentialStore::new(inner, keys())
        .with_legacy_envelopes(LegacyBlobs::Reject);
    let err = strict.load(&tenant(), &user(), "gmail").await.unwrap_err();
    assert!(err.contains("v1 envelope is refused"), "{err}");
}

/// Rejecting v1 does not touch a v2 row.
#[tokio::test]
async fn rejecting_legacy_envelopes_still_reads_v2() {
    let store =
        EncryptedDelegatedCredentialStore::new(MemoryDelegatedCredentialStore::new(), keys())
            .with_legacy_envelopes(LegacyBlobs::Reject);
    store.save(&tenant(), &user(), credential()).await.unwrap();
    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");
}

#[tokio::test]
async fn reseal_on_load_can_be_turned_off() {
    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant(), &user(), v1_row()).await.unwrap();
    let store = EncryptedDelegatedCredentialStore::new(inner, keys())
        .with_legacy_envelopes(LegacyBlobs::Accept)
        .without_reseal_on_load();
    store.load(&tenant(), &user(), "gmail").await.unwrap();
    assert!((*raw(store.inner()).await.access_token).starts_with("v1.k1."));
}

/// Wraps a memory store and, on the first `load`, plays another request that
/// rotates the credential after the loader has read it.
struct RotatesAfterLoad {
    inner: MemoryDelegatedCredentialStore,
    rotate_to: Mutex<Option<StoredDelegation>>,
}

impl DelegatedCredentialStore for RotatesAfterLoad {
    async fn load(
        &self,
        tenant: &TenantId,
        user: &UserId,
        provider: &str,
    ) -> Result<Option<StoredDelegation>, String> {
        let read = self.inner.load(tenant, user, provider).await?;
        let rotated = self.rotate_to.lock().unwrap().take();
        if let Some(rotated) = rotated {
            self.inner.save(tenant, user, rotated).await?;
        }
        Ok(read)
    }
    async fn save(&self, t: &TenantId, u: &UserId, c: StoredDelegation) -> Result<(), String> {
        self.inner.save(t, u, c).await
    }
    async fn save_if_unchanged(
        &self,
        t: &TenantId,
        u: &UserId,
        expected: &StoredDelegation,
        replacement: StoredDelegation,
    ) -> Result<CredentialSwap, String> {
        self.inner
            .save_if_unchanged(t, u, expected, replacement)
            .await
    }
    async fn revoke(&self, t: &TenantId, u: &UserId, p: &str) -> Result<(), String> {
        self.inner.revoke(t, u, p).await
    }
}

/// The re-seal is a compare-and-swap: a refresh token another request wrote
/// between the load and the re-seal survives, instead of being replaced by
/// the older token the load held.
#[tokio::test]
async fn a_reseal_does_not_overwrite_a_token_rotated_since_the_load() {
    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant(), &user(), v1_row()).await.unwrap();
    let rotated = StoredDelegation {
        refresh_token: Some(ZeroizedString::from("v2.k2.rotated-by-another-request")),
        ..v1_row()
    };
    let racing = RotatesAfterLoad {
        inner,
        rotate_to: Mutex::new(Some(rotated)),
    };
    let store = EncryptedDelegatedCredentialStore::new(racing, keys())
        .with_legacy_envelopes(LegacyBlobs::Accept);

    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.refresh_token.as_deref(), Some("rt-plaintext"));

    let stored = raw(store.inner()).await;
    assert_eq!(
        stored.refresh_token.as_deref(),
        Some("v2.k2.rotated-by-another-request"),
        "the rotation that landed after the load must not be overwritten"
    );
}

/// A store without a compare-and-swap is never re-sealed.
struct NoSwap(MemoryDelegatedCredentialStore);

impl DelegatedCredentialStore for NoSwap {
    async fn load(
        &self,
        t: &TenantId,
        u: &UserId,
        p: &str,
    ) -> Result<Option<StoredDelegation>, String> {
        self.0.load(t, u, p).await
    }
    async fn save(&self, t: &TenantId, u: &UserId, c: StoredDelegation) -> Result<(), String> {
        self.0.save(t, u, c).await
    }
    async fn revoke(&self, t: &TenantId, u: &UserId, p: &str) -> Result<(), String> {
        self.0.revoke(t, u, p).await
    }
}

#[tokio::test]
async fn a_store_without_a_swap_is_not_resealed() {
    let inner = NoSwap(MemoryDelegatedCredentialStore::new());
    inner.save(&tenant(), &user(), v1_row()).await.unwrap();
    let store = EncryptedDelegatedCredentialStore::new(inner, keys())
        .with_legacy_envelopes(LegacyBlobs::Accept);
    store.load(&tenant(), &user(), "gmail").await.unwrap();
    assert!((*raw(store.inner()).await.access_token).starts_with("v1.k1."));
}
