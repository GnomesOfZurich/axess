//! A key provider of the adopter's own is checked on the save path, not only
//! in [`MemoryKeyProvider`].

use super::*;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use chrono::{TimeZone, Utc};

struct FixedKeys {
    id: &'static str,
    key: [u8; 32],
}

impl KeyProvider for FixedKeys {
    fn current(&self) -> Result<CurrentKey, KeyProviderError> {
        Ok(CurrentKey {
            key_id: Arc::from(self.id),
            key: Arc::new(EncryptionKey::from_bytes(self.key)),
        })
    }

    fn resolve(&self, key_id: &str) -> Result<Option<Arc<EncryptionKey>>, KeyProviderError> {
        Ok((key_id == self.id).then(|| Arc::new(EncryptionKey::from_bytes(self.key))))
    }
}

fn credential() -> StoredDelegation {
    StoredDelegation {
        provider: "gmail".to_string(),
        access_token: ZeroizedString::from("at-plaintext"),
        refresh_token: None,
        expires_at: Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        scopes: vec!["gmail.send".to_string()],
        token_type: "Bearer".to_string(),
    }
}

async fn save_under(id: &'static str, key: [u8; 32]) -> Result<(), String> {
    let store = EncryptedDelegatedCredentialStore::new(
        MemoryDelegatedCredentialStore::new(),
        FixedKeys { id, key },
    );
    store
        .save(
            &TenantId::from_bytes([1u8; 16]),
            &UserId::from_bytes([2u8; 16]),
            credential(),
        )
        .await
}

#[tokio::test]
async fn a_key_id_with_a_dot_is_refused_when_saving() {
    let saved = save_under("2026.05", test_key(4)).await;
    assert!(saved.is_err(), "saved an envelope that cannot be read back");
}

#[tokio::test]
async fn an_empty_key_id_is_refused_when_saving() {
    assert!(save_under("", test_key(4)).await.is_err());
}

#[tokio::test]
async fn a_constant_key_is_refused_when_saving() {
    assert!(save_under("k1", [7u8; 32]).await.is_err());
}

#[tokio::test]
async fn an_ordinary_key_still_saves() {
    save_under("2026-05", test_key(4)).await.unwrap();
}
