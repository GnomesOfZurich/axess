//! Reading `v1` envelopes, re-sealing a row on load without overwriting a
//! rotation that landed in between, and rows whose two fields are sealed
//! under different keys or envelope versions.

use super::*;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use crate::session::crypto::LegacyBlobs;
use axess_clock::Timestamp;
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
        registration: Some(crate::delegated::stored::GrantRegistration {
            provider: "gmail".to_string(),
            fingerprint: "gmail-registration".to_string(),
        }),
        access_token: ZeroizedString::from("at-plaintext"),
        refresh_token: Some(ZeroizedString::from("rt-plaintext")),
        expires_at: Some(Timestamp::from_utc(2030, 1, 1, 0, 0, 0).unwrap()),
        scopes: vec!["gmail.send".to_string()],
        token_type: "Bearer".to_string(),
    }
}

fn keys() -> MemoryKeyProvider {
    MemoryKeyProvider::new("k2", test_key(2))
        .unwrap()
        .with_historical("k1", test_key(1))
        .unwrap()
}

/// A row as the previous release wrote it: `v1`, sealed under the retired key.
fn v1_row() -> StoredDelegation {
    let old = CurrentKey {
        key_id: Arc::from("k1"),
        key: Arc::new(EncryptionKey::from_bytes(test_key(1))),
    };
    let rng = axess_rng::SystemRng;
    let v1 = |env: String| env.replacen("v4.", "v1.", 1);
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
    async fn save_if_unchanged(
        &self,
        _: &TenantId,
        _: &UserId,
        _: &StoredDelegation,
        _: StoredDelegation,
    ) -> Result<CredentialSwap, String> {
        Ok(CredentialSwap::Unsupported)
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

/// A provider that resolves every stored key but cannot name a current one:
/// the KMS answers reads and refuses the call that picks the key for writes.
struct CurrentFails(MemoryKeyProvider);

impl KeyProvider for CurrentFails {
    fn current(&self) -> Result<CurrentKey, KeyProviderError> {
        Err(KeyProviderError::Failed("no current key".into()))
    }
    fn resolve(&self, key_id: &str) -> Result<Option<Arc<EncryptionKey>>, KeyProviderError> {
        self.0.resolve(key_id)
    }
}

/// A load needs the key the row was sealed under, not the current one; the
/// current key is wanted only for the re-seal, which is skipped when it
/// cannot be had.
#[tokio::test]
async fn a_load_decrypts_under_the_stored_key_when_no_current_key_can_be_had() {
    let sealed_as =
        EncryptedDelegatedCredentialStore::new(MemoryDelegatedCredentialStore::new(), keys())
            .seal(&tenant(), &user(), credential())
            .unwrap();
    let inner = MemoryDelegatedCredentialStore::new();
    inner
        .save(&tenant(), &user(), sealed_as.clone())
        .await
        .unwrap();

    let reader = EncryptedDelegatedCredentialStore::new(inner, CurrentFails(keys()));
    let loaded = reader
        .load(&tenant(), &user(), "gmail")
        .await
        .expect("the stored key id still decrypts")
        .expect("row present");
    assert_eq!(&*loaded.access_token, "at-plaintext");
    assert_eq!(
        &*raw(reader.inner()).await.access_token,
        &*sealed_as.access_token,
        "no re-seal without a current key"
    );
}

/// A row as the previous release wrote it: `v2`, whose AAD does not cover
/// `expires_at`, with the expiry far in the future.
fn v2_row_with_far_expiry() -> StoredDelegation {
    let current = CurrentKey {
        key_id: Arc::from("k2"),
        key: Arc::new(EncryptionKey::from_bytes(test_key(2))),
    };
    let rng = axess_rng::SystemRng;
    let v2 = |env: String| env.replacen("v4.", "v2.", 1);
    let cred = credential();
    let aad =
        |field: &[u8]| build_aad_v2("gmail", &tenant(), &user(), field, &cred.scopes, "Bearer");
    StoredDelegation {
        access_token: ZeroizedString::from(v2(encrypt_envelope(
            &current,
            &rng,
            "at-plaintext",
            &aad(FIELD_ACCESS),
        )
        .unwrap())),
        refresh_token: Some(ZeroizedString::from(v2(encrypt_envelope(
            &current,
            &rng,
            "rt-plaintext",
            &aad(FIELD_REFRESH),
        )
        .unwrap()))),
        expires_at: Some(Timestamp::from_utc(2999, 1, 1, 0, 0, 0).unwrap()),
        ..cred
    }
}

/// A `v2` row's expiry is not authenticated, so a store writer could have
/// moved it. The row loads as expired (and as granted through no
/// registration, so the user grants again) and is not re-sealed, which would have
/// vouched for the unauthenticated value.
#[tokio::test]
async fn a_v2_row_loads_as_expired_and_is_not_resealed() {
    let inner = MemoryDelegatedCredentialStore::new();
    inner
        .save(&tenant(), &user(), v2_row_with_far_expiry())
        .await
        .unwrap();
    let store = EncryptedDelegatedCredentialStore::new(inner, keys());

    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");
    assert!(
        !loaded.is_fresh(
            axess_clock::testing::MockClock::reference_time(),
            std::time::Duration::ZERO
        ),
        "an unauthenticated expiry must not read as fresh: {:?}",
        loaded.expires_at
    );
    assert!(
        (*raw(store.inner()).await.access_token).starts_with("v2.k2."),
        "the v2 row is left as it was"
    );

    let mut refreshed = loaded;
    refreshed.expires_at = Some(Timestamp::from_utc(2030, 1, 1, 0, 0, 0).unwrap());
    store.save(&tenant(), &user(), refreshed).await.unwrap();
    assert!((*raw(store.inner()).await.access_token).starts_with("v4.k2."));
}

// ── Rows whose two fields are sealed apart ───────────────────────────────────

/// An expiry far in the future, as a store writer would move it to.
fn far_expiry() -> Option<Timestamp> {
    Some(Timestamp::from_utc(2999, 1, 1, 0, 0, 0).unwrap())
}

/// One field as the current envelope version seals it, bound to
/// `expires_at` and the fixture's registration, under the key `id`
/// (`test_key(seed)`).
fn current_field(
    id: &str,
    seed: u8,
    field: &[u8],
    plain: &str,
    expires_at: Option<Timestamp>,
) -> ZeroizedString {
    let key = CurrentKey {
        key_id: Arc::from(id),
        key: Arc::new(EncryptionKey::from_bytes(test_key(seed))),
    };
    let row = StoredDelegation {
        expires_at,
        ..credential()
    };
    let aad = build_aad_v4("gmail", &tenant(), &user(), field, &row);
    ZeroizedString::from(encrypt_envelope(&key, &axess_rng::SystemRng, plain, &aad).unwrap())
}

async fn store_holding(
    row: StoredDelegation,
) -> EncryptedDelegatedCredentialStore<MemoryDelegatedCredentialStore, MemoryKeyProvider> {
    let inner = MemoryDelegatedCredentialStore::new();
    inner.save(&tenant(), &user(), row).await.unwrap();
    EncryptedDelegatedCredentialStore::new(inner, keys())
}

fn reads_as_fresh(row: &StoredDelegation) -> bool {
    row.is_fresh(
        axess_clock::testing::MockClock::reference_time(),
        std::time::Duration::ZERO,
    )
}

/// A row with no refresh token, sealed under a retired key, is re-sealed
/// under the current key on load: the access token alone makes it stale.
#[tokio::test]
async fn an_access_token_alone_under_a_retired_key_is_resealed_on_load() {
    let expires_at = credential().expires_at;
    let store = store_holding(StoredDelegation {
        access_token: current_field("k1", 1, FIELD_ACCESS, "at-plaintext", expires_at),
        refresh_token: None,
        ..credential()
    })
    .await;

    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");
    assert!(reads_as_fresh(&loaded), "{:?}", loaded.expires_at);
    assert!((*raw(store.inner()).await.access_token).starts_with("v4.k2."));
}

/// One field under a retired key is enough: a refresh token sealed under it,
/// beside an access token under the current key, is re-sealed on load.
#[tokio::test]
async fn a_refresh_token_under_a_retired_key_is_resealed_on_load() {
    let expires_at = credential().expires_at;
    let store = store_holding(StoredDelegation {
        access_token: current_field("k2", 2, FIELD_ACCESS, "at-plaintext", expires_at),
        refresh_token: Some(current_field(
            "k1",
            1,
            FIELD_REFRESH,
            "rt-plaintext",
            expires_at,
        )),
        ..credential()
    })
    .await;

    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.refresh_token.as_deref(), Some("rt-plaintext"));
    let stored = raw(store.inner()).await;
    assert!(
        stored
            .refresh_token
            .as_deref()
            .is_some_and(|sealed| sealed.starts_with("v4.k2.")),
        "the refresh token is still under the retired key"
    );
}

/// A `v2` access token with no refresh token beside it: the expiry is not
/// authenticated, so the row reads as expired and is left as it was.
#[tokio::test]
async fn a_v2_access_token_alone_reads_as_expired_and_is_not_resealed() {
    let store = store_holding(StoredDelegation {
        refresh_token: None,
        ..v2_row_with_far_expiry()
    })
    .await;

    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*loaded.access_token, "at-plaintext");
    assert!(!reads_as_fresh(&loaded), "{:?}", loaded.expires_at);
    assert!((*raw(store.inner()).await.access_token).starts_with("v2.k2."));
}

/// Every field has to cover the expiry: a `v2` refresh token beside an
/// access token that does cover it still reads as expired, and the row is
/// left as it was.
#[tokio::test]
async fn a_v2_refresh_token_beside_a_current_access_token_reads_as_expired() {
    let store = store_holding(StoredDelegation {
        access_token: current_field("k2", 2, FIELD_ACCESS, "at-plaintext", far_expiry()),
        ..v2_row_with_far_expiry()
    })
    .await;

    let loaded = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.refresh_token.as_deref(), Some("rt-plaintext"));
    assert!(!reads_as_fresh(&loaded), "{:?}", loaded.expires_at);
    let stored = raw(store.inner()).await;
    assert!(
        stored
            .refresh_token
            .as_deref()
            .is_some_and(|sealed| sealed.starts_with("v2.k2.")),
        "the row was re-sealed, which vouches for an expiry nobody authenticated"
    );
}

/// The swap through the encrypting store compares what the rows open to: it
/// saves over the row the caller read, and leaves a row that has changed
/// since, or that is gone.
#[tokio::test]
async fn a_swap_saves_over_the_row_the_caller_read_and_leaves_a_changed_one() {
    let store =
        EncryptedDelegatedCredentialStore::new(MemoryDelegatedCredentialStore::new(), keys());
    let with_access = |token: &str| StoredDelegation {
        access_token: ZeroizedString::from(token),
        ..credential()
    };

    let gone = store
        .save_if_unchanged(&tenant(), &user(), &credential(), with_access("at-first"))
        .await
        .unwrap();
    assert_eq!(gone, CredentialSwap::Changed, "no row to swap against");
    assert!(
        store
            .load(&tenant(), &user(), "gmail")
            .await
            .unwrap()
            .is_none()
    );

    store.save(&tenant(), &user(), credential()).await.unwrap();
    let read = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    let saved = store
        .save_if_unchanged(&tenant(), &user(), &read, with_access("at-rotated"))
        .await
        .unwrap();
    assert_eq!(saved, CredentialSwap::Saved);

    let late = store
        .save_if_unchanged(&tenant(), &user(), &read, with_access("at-late"))
        .await
        .unwrap();
    assert_eq!(late, CredentialSwap::Changed);
    let held = store
        .load(&tenant(), &user(), "gmail")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&*held.access_token, "at-rotated");
}
