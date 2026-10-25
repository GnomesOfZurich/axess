//! Envelope nonces come from the injected RNG.

use super::*;
use crate::delegated::stored::credential::MemoryDelegatedCredentialStore;
use axess_rng::testing::MockRng;
use chrono::{TimeZone, Utc};

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

fn store(
    seed: u64,
) -> EncryptedDelegatedCredentialStore<MemoryDelegatedCredentialStore, MemoryKeyProvider> {
    let keys = MemoryKeyProvider::new("k1", [3u8; 32]).expect("key id");
    EncryptedDelegatedCredentialStore::new(MemoryDelegatedCredentialStore::new(), keys)
        .with_rng(MockRng::new(seed))
}

fn tenant() -> TenantId {
    TenantId::from_bytes([1u8; 16])
}

fn user() -> UserId {
    UserId::from_bytes([2u8; 16])
}

/// The nonce a stored envelope carries.
fn nonce_of(envelope: &str) -> [u8; NONCE_LEN] {
    let body_b64 = envelope.splitn(3, '.').nth(2).expect("body");
    let body = URL_SAFE_NO_PAD.decode(body_b64).expect("base64");
    body[..NONCE_LEN].try_into().expect("nonce")
}

async fn stored(
    s: &EncryptedDelegatedCredentialStore<MemoryDelegatedCredentialStore, MemoryKeyProvider>,
) -> StoredDelegation {
    s.inner()
        .load(&tenant(), &user(), "gmail")
        .await
        .expect("inner load")
        .expect("present")
}

#[tokio::test]
async fn nonces_are_the_injected_rngs_draws_in_order() {
    let s = store(21);
    s.save(&tenant(), &user(), credential())
        .await
        .expect("save");
    let row = stored(&s).await;

    let rng = MockRng::new(21);
    let mut first = [0u8; NONCE_LEN];
    let mut second = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut first);
    rng.fill_bytes(&mut second);

    assert_eq!(
        nonce_of(&row.access_token),
        first,
        "access token takes draw one"
    );
    assert_eq!(
        nonce_of(row.refresh_token.as_deref().expect("refresh")),
        second,
        "refresh token takes draw two"
    );
}

#[tokio::test]
async fn a_second_save_uses_a_fresh_nonce_and_equal_seeds_give_equal_bytes() {
    let a = store(5);
    a.save(&tenant(), &user(), credential())
        .await
        .expect("save");
    let first = stored(&a).await;
    a.save(&tenant(), &user(), credential())
        .await
        .expect("save");
    let second = stored(&a).await;
    assert_ne!(
        nonce_of(&first.access_token),
        nonce_of(&second.access_token),
        "the same plaintext must not be sealed twice under one nonce"
    );

    let b = store(5);
    b.save(&tenant(), &user(), credential())
        .await
        .expect("save");
    let twin = stored(&b).await;
    assert_eq!(&*first.access_token, &*twin.access_token);
    assert_eq!(
        first.refresh_token.as_deref(),
        twin.refresh_token.as_deref(),
        "same seed, same key, same plaintext: byte-identical envelopes"
    );
}
