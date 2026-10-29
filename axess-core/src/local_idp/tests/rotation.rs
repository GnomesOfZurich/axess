//! Signing-key rotation tests for the production `LocalIdp`.
//!
//! Covers `rotate_signing_key` semantics: demotion of the previous
//! current key, persistence through the key store, error propagation
//! without state mutation, post-rotation minting under the new kid,
//! cross-algorithm rotation, snapshot semantics of `jwks_handle`, and
//! clone-state visibility across handles.

use std::sync::Arc;

use super::super::*;
use super::support::CustomClaims;
use axess_factors::jwt::verifier::JwtVerifier;
use chrono::{Duration, Utc};

/// Key store that loads cleanly but always errors on `rotate`. Used
/// to confirm `rotate_signing_key` returns `IssuanceError::KeyStore`
/// and leaves the in-memory state intact when persistence fails.
#[derive(Clone)]
struct RotateFailingKeyStore {
    initial: LocalIdpSigningKey,
}

#[derive(Debug, thiserror::Error)]
#[error("intentional rotate failure for test")]
struct RotateFailure;

impl LocalIdpKeyStore for RotateFailingKeyStore {
    type Error = RotateFailure;

    async fn load_all(&self) -> Result<LoadedKeys, Self::Error> {
        Ok(LoadedKeys {
            current: self.initial.clone(),
            historical: Vec::new(),
        })
    }

    async fn rotate(&self, new_current: LocalIdpSigningKey) -> Result<(), Self::Error> {
        drop(new_current);
        Err(RotateFailure)
    }

    async fn retire(&self, _key_id: &str) -> Result<bool, Self::Error> {
        Err(RotateFailure)
    }
}

#[tokio::test]
async fn rotate_signing_key_demotes_previous_current_to_historical() {
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let store = MemoryLocalIdpKeyStore::with_current(k1);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    idp.rotate_signing_key(k2).await.expect("rotate");

    let jwks = idp.jwks().await;
    let kids: Vec<_> = jwks
        .keys
        .iter()
        .filter_map(|k| k.common.key_id.as_deref())
        .collect();
    assert_eq!(
        kids,
        vec!["rsa-2", "rsa-1"],
        "JWKS must list new current first, then demoted historical"
    );
}

#[tokio::test]
async fn rotate_signing_key_persists_through_key_store() {
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let store = MemoryLocalIdpKeyStore::with_current(k1);
    let idp = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load");

    idp.rotate_signing_key(k2).await.expect("rotate");

    // Independently re-load the store snapshot: the rotation must be
    // visible to a future `from_key_store` over the same backend.
    let reloaded = store.load_all().await.expect("reload");
    assert_eq!(reloaded.current.key_id(), "rsa-2");
    assert_eq!(reloaded.historical.len(), 1);
    assert_eq!(reloaded.historical[0].key_id(), "rsa-1");
}

#[tokio::test]
async fn rotate_signing_key_propagates_key_store_error_without_mutating_state() {
    let initial = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-original");
    let store = RotateFailingKeyStore {
        initial: initial.clone(),
    };
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    let new_key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-new");
    let err = idp
        .rotate_signing_key(new_key)
        .await
        .expect_err("rotate must fail");
    assert!(
        matches!(err, IssuanceError::KeyStore(RotateFailure)),
        "expected IssuanceError::KeyStore(RotateFailure), got {err:?}"
    );

    // State must be unchanged: JWKS still lists only the original key,
    // and a subsequent mint still signs under the original kid.
    let jwks = idp.jwks().await;
    assert_eq!(jwks.keys.len(), 1, "JWKS must not grow on failed rotation");
    assert_eq!(
        jwks.keys[0].common.key_id.as_deref(),
        Some("rsa-original"),
        "current key must still be the original"
    );

    let now = Utc::now();
    let token = idp
        .mint(
            &MintClaims::new("worker-1", now + Duration::hours(1))
                .with_audience("https://api")
                .with_issued_at(now),
        )
        .await
        .expect("mint after failed rotate still works under original key");
    let header = jsonwebtoken::decode_header(&token).expect("decode");
    assert_eq!(header.kid.as_deref(), Some("rsa-original"));
}

#[tokio::test]
async fn mint_after_successful_rotation_uses_new_kid() {
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let recorder = Arc::new(MockIssuanceListener::new());
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(k1),
    )
    .await
    .expect("load")
    .with_issuance_listener(recorder.clone());

    let now = Utc::now();
    let claims = MintClaims::new("worker-1", now + Duration::hours(1))
        .with_audience("https://api")
        .with_issued_at(now);
    idp.mint(&claims).await.expect("pre-rotation mint");
    idp.rotate_signing_key(k2).await.expect("rotate");
    idp.mint(&claims).await.expect("post-rotation mint");

    let events = recorder.events();
    assert_eq!(events.len(), 2, "listener captures both mints");
    assert_eq!(events[0].key_id, "rsa-1", "first mint uses original key");
    assert_eq!(events[1].key_id, "rsa-2", "second mint uses rotated key");
}

#[tokio::test]
async fn verifier_algorithms_after_cross_alg_rotation_lists_both() {
    let rsa = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(rsa),
    )
    .await
    .expect("load");

    idp.rotate_signing_key(ec)
        .await
        .expect("rotate RSA → ES256");

    let algs = idp.verifier_algorithms().await;
    assert_eq!(algs[0], Algorithm::ES256, "new current first");
    assert!(
        algs.contains(&Algorithm::RS256),
        "demoted historical RSA must remain verifier-eligible"
    );
}

#[tokio::test]
async fn rotated_idp_verifies_tokens_minted_before_and_after_rotation() {
    // End-to-end: a token minted under the old key still verifies via
    // the post-rotation JWKS (because the old key is in historical),
    // and a token minted under the new key also verifies.
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(k1),
    )
    .await
    .expect("load");

    let now = Utc::now();
    let claims = MintClaims::new("worker-1", now + Duration::hours(1))
        .with_audience("https://api")
        .with_issued_at(now);
    let token_old = idp.mint(&claims).await.expect("pre-rotation mint");

    idp.rotate_signing_key(k2).await.expect("rotate");
    let token_new = idp.mint(&claims).await.expect("post-rotation mint");

    let verifier = JwtVerifier::new(idp.jwks_handle().await)
        .with_issuer("https://idp.local")
        .with_audience("https://api")
        .with_algorithms(idp.verifier_algorithms().await);
    verifier
        .verify::<CustomClaims>(&token_old)
        .await
        .expect("token signed under historical key still verifies");
    verifier
        .verify::<CustomClaims>(&token_new)
        .await
        .expect("token signed under new current key verifies");
}

#[tokio::test]
async fn clone_after_rotation_sees_new_state_through_both_handles() {
    // LocalIdp shares state via Arc<AsyncRwLock<...>>, so a rotation on
    // one clone must be visible to subsequent mints on every other clone.
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let idp_a = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(k1),
    )
    .await
    .expect("load");
    let idp_b = idp_a.clone();

    idp_a.rotate_signing_key(k2).await.expect("rotate via A");

    let now = Utc::now();
    let token = idp_b
        .mint(
            &MintClaims::new("worker-1", now + Duration::hours(1))
                .with_audience("https://api")
                .with_issued_at(now),
        )
        .await
        .expect("mint via B");
    let header = jsonwebtoken::decode_header(&token).expect("decode");
    assert_eq!(
        header.kid.as_deref(),
        Some("rsa-2"),
        "clone must observe rotation performed on sibling handle"
    );
}

#[tokio::test]
async fn jwks_handle_taken_before_rotation_is_a_snapshot() {
    // jwks_handle hands out a *snapshot*: a handle obtained before
    // rotation continues to reflect the pre-rotation JWKS. Adopters
    // who need live propagation should re-call jwks_handle after
    // rotating; the discovery/handler module documents this.
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(k1),
    )
    .await
    .expect("load");

    let stale_handle = idp.jwks_handle().await;
    idp.rotate_signing_key(k2).await.expect("rotate");

    let stale_kids: Vec<String> = {
        let stale = stale_handle.read().unwrap();
        stale
            .keys
            .iter()
            .filter_map(|k| k.common.key_id.as_deref().map(str::to_owned))
            .collect()
    };
    assert_eq!(
        stale_kids,
        vec!["rsa-1"],
        "handle taken before rotation must remain the pre-rotation snapshot"
    );

    let fresh = idp.jwks_handle().await;
    let fresh_kids: Vec<String> = {
        let fresh = fresh.read().unwrap();
        fresh
            .keys
            .iter()
            .filter_map(|k| k.common.key_id.as_deref().map(str::to_owned))
            .collect()
    };
    assert_eq!(
        fresh_kids,
        vec!["rsa-2", "rsa-1"],
        "handle taken after rotation reflects current + historical"
    );
}

fn es(kid: &str) -> LocalIdpSigningKey {
    LocalIdpSigningKey::generate_es256().with_key_id(kid)
}

fn kids(set: &jsonwebtoken::jwk::JwkSet) -> Vec<String> {
    set.keys
        .iter()
        .filter_map(|k| k.common.key_id.clone())
        .collect()
}

#[tokio::test]
async fn retiring_a_historical_key_removes_it_from_the_jwks_and_the_store() {
    let store = MemoryLocalIdpKeyStore::with_current(es("k1"));
    let idp = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load");
    idp.rotate_signing_key(es("k2")).await.expect("rotate");
    assert_eq!(kids(&idp.jwks().await), vec!["k2", "k1"]);

    assert!(idp.retire_historical_key("k1").await.expect("retire"));
    assert_eq!(kids(&idp.jwks().await), vec!["k2"]);
    assert!(store.load_all().await.expect("load").historical.is_empty());

    // Unknown kid: nothing removed.
    assert!(!idp.retire_historical_key("k1").await.expect("retire again"));
}

#[tokio::test]
async fn the_current_key_cannot_be_retired() {
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(es("k1")),
    )
    .await
    .expect("load");
    assert!(matches!(
        idp.retire_historical_key("k1").await,
        Err(IssuanceError::RetireCurrentKey)
    ));
    assert_eq!(kids(&idp.jwks().await), vec!["k1"]);
}

/// Two replicas over one store, each rotating in turn: the second rotation
/// is rebuilt from the store, so it keeps the first replica's key in the
/// JWKS instead of dropping it, and `reload` brings the first replica level.
#[tokio::test]
async fn replicas_rotating_in_turn_converge_on_the_stores_key_set() {
    let store = MemoryLocalIdpKeyStore::with_current(es("k1"));
    let a = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load a");
    let b = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load b");

    a.rotate_signing_key(es("ka")).await.expect("a rotates");
    b.rotate_signing_key(es("kb")).await.expect("b rotates");

    // Without the re-read, b would publish [kb, k1] and lose ka, so tokens
    // minted by a (kid ka) would not verify against b's JWKS.
    assert_eq!(kids(&b.jwks().await), vec!["kb", "k1", "ka"]);
    assert_eq!(kids(&a.jwks().await), vec!["ka", "k1"], "a is behind");
    a.reload().await.expect("reload");
    assert_eq!(kids(&a.jwks().await), vec!["kb", "k1", "ka"]);
}

#[tokio::test]
async fn rotating_to_a_kid_already_in_the_jwks_is_refused() {
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("same");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("same");
    let store = MemoryLocalIdpKeyStore::with_current(k1);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");

    let err = idp.rotate_signing_key(k2).await.expect_err("duplicate kid");
    assert!(matches!(err, IssuanceError::DuplicateKeyId { ref kid } if kid == "same"));
    assert_eq!(idp.jwks().await.keys.len(), 1, "state is unchanged");
}

#[test]
fn generated_keys_get_distinct_kids() {
    let a = LocalIdpSigningKey::generate_es256();
    let b = LocalIdpSigningKey::generate_es256();
    assert_ne!(a.key_id(), b.key_id());
    let r = LocalIdpSigningKey::generate_rsa();
    let s = LocalIdpSigningKey::generate_rsa();
    assert_ne!(r.key_id(), s.key_id());
}
