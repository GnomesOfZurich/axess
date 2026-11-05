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

/// A store whose `retire` is durable but whose next `load_all` fails: the
/// re-read a replica makes after it retires a key.
#[derive(Clone)]
struct ReloadFailsAfterRetire {
    inner: MemoryLocalIdpKeyStore,
    fail_loads: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug, thiserror::Error)]
#[error("intentional load failure after retire")]
struct ReloadFailure;

impl LocalIdpKeyStore for ReloadFailsAfterRetire {
    type Error = ReloadFailure;

    async fn load_all(&self) -> Result<LoadedKeys, Self::Error> {
        if self.fail_loads.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ReloadFailure);
        }
        self.inner.load_all().await.map_err(|_| ReloadFailure)
    }

    async fn rotate(&self, new_current: LocalIdpSigningKey) -> Result<(), Self::Error> {
        self.inner
            .rotate(new_current)
            .await
            .map_err(|_| ReloadFailure)
    }

    async fn retire(&self, key_id: &str) -> Result<bool, Self::Error> {
        let removed = self.inner.retire(key_id).await.map_err(|_| ReloadFailure)?;
        self.fail_loads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(removed)
    }
}

/// The store retired the key, so the JWKS must not carry it whether or not
/// the re-read that follows succeeds: a key the store no longer holds is
/// never served from memory.
#[tokio::test]
async fn a_key_retired_in_the_store_leaves_the_jwks_even_when_the_reread_fails() {
    let store = ReloadFailsAfterRetire {
        inner: MemoryLocalIdpKeyStore::with_current(es("k1")),
        fail_loads: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let idp = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load");
    idp.rotate_signing_key(es("k2")).await.expect("rotate");
    assert_eq!(kids(&idp.jwks().await), vec!["k2", "k1"]);

    let outcome = idp.retire_historical_key("k1").await;
    assert!(
        store
            .inner
            .load_all()
            .await
            .expect("store")
            .historical
            .is_empty(),
        "the store retired the key"
    );
    assert_eq!(
        kids(&idp.jwks().await),
        vec!["k2"],
        "a key the store retired is still served (outcome {outcome:?})"
    );
    assert!(
        !idp.verifier_algorithms().await.is_empty(),
        "the current key is still there"
    );
    assert!(
        matches!(outcome, Ok(true)),
        "the retirement is durable: {outcome:?}"
    );
}

/// Two replicas over one store: the first rotates to a kid, the second,
/// which has not reloaded, rotates to the same kid. The in-memory check on
/// the second replica cannot see the first's key, so the store itself must
/// refuse, or the JWKS carries two keys under one kid.
#[tokio::test]
async fn a_kid_another_replica_rotated_to_is_refused_by_the_store() {
    let store = MemoryLocalIdpKeyStore::with_current(es("k1"));
    let a = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load a");
    let b = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load b");

    a.rotate_signing_key(es("dup")).await.expect("a rotates");
    let outcome = b.rotate_signing_key(es("dup")).await;
    assert!(
        outcome.is_err(),
        "a kid the store already holds must be refused: {outcome:?}"
    );
    let loaded = store.load_all().await.expect("store");
    let mut all: Vec<&str> = std::iter::once(loaded.current.key_id())
        .chain(loaded.historical.iter().map(|k| k.key_id()))
        .collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all, vec!["dup", "k1"], "one key per kid in the store");
    assert_eq!(kids(&b.jwks().await), vec!["k1"], "b is unchanged");
    b.reload().await.expect("reload");
    assert_eq!(
        kids(&b.jwks().await),
        vec!["dup", "k1"],
        "one key under the kid once b has caught up"
    );
}

/// A store whose whole key set can be swapped, standing in for another
/// replica (or a hand edit) changing what the store holds between reads.
#[derive(Clone)]
struct SwappableKeyStore {
    inner: Arc<std::sync::Mutex<MemoryLocalIdpKeyStore>>,
}

impl SwappableKeyStore {
    fn new(current: LocalIdpSigningKey, historical: Vec<LocalIdpSigningKey>) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(MemoryLocalIdpKeyStore::with_keys(
                current, historical,
            ))),
        }
    }

    fn swap(&self, current: LocalIdpSigningKey, historical: Vec<LocalIdpSigningKey>) {
        *self.inner.lock().expect("store lock") =
            MemoryLocalIdpKeyStore::with_keys(current, historical);
    }

    fn snapshot(&self) -> MemoryLocalIdpKeyStore {
        self.inner.lock().expect("store lock").clone()
    }
}

impl LocalIdpKeyStore for SwappableKeyStore {
    type Error = MemoryLocalIdpKeyStoreError;

    async fn load_all(&self) -> Result<LoadedKeys, Self::Error> {
        self.snapshot().load_all().await
    }

    async fn rotate(&self, new_current: LocalIdpSigningKey) -> Result<(), Self::Error> {
        self.snapshot().rotate(new_current).await
    }

    async fn retire(&self, key_id: &str) -> Result<bool, Self::Error> {
        self.snapshot().retire(key_id).await
    }
}

/// Two keys under one `kid` make a verifier pick either, so a stored key
/// set that repeats one is refused when it is loaded, whether the repeat
/// is between the current key and a historical one or among the historical.
#[tokio::test]
async fn a_stored_key_set_that_repeats_a_kid_is_refused_on_load() {
    for (current, historical) in [
        (es("k1"), vec![es("k2"), es("k1")]),
        (es("k3"), vec![es("k1"), es("k2"), es("k1")]),
    ] {
        let store = MemoryLocalIdpKeyStore::with_keys(current, historical);
        match LocalIdp::from_key_store("https://idp.local", store).await {
            Err(IssuanceError::DuplicateKeyId { kid }) => assert_eq!(kid, "k1"),
            Err(e) => panic!("refused for the wrong reason: {e}"),
            Ok(_) => panic!("a key set repeating a kid was loaded"),
        }
    }
}

/// A key with an empty `kid` cannot be named by a token header, so a key set
/// carrying one is refused on load.
#[tokio::test]
async fn a_stored_key_with_an_empty_kid_is_refused_on_load() {
    for store in [
        MemoryLocalIdpKeyStore::with_current(es("")),
        MemoryLocalIdpKeyStore::with_keys(es("k1"), vec![es("")]),
    ] {
        assert!(
            matches!(
                LocalIdp::from_key_store("https://idp.local", store).await,
                Err(IssuanceError::EmptyKeyId)
            ),
            "a key set with an empty kid was loaded"
        );
    }
}

/// A reload that reads a key set it would refuse on load keeps the keys it
/// had: the JWKS is unchanged and mints still sign under the old key.
#[tokio::test]
async fn a_reload_that_reads_a_repeated_or_empty_kid_keeps_the_keys_it_had() {
    let store = SwappableKeyStore::new(es("k2"), vec![es("k1")]);
    let idp = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load");
    for (current, historical, repeated) in [
        (es("k3"), vec![es("k3")], true),
        (es(""), vec![es("k2")], false),
        (es("k3"), vec![es("")], false),
    ] {
        store.swap(current, historical);
        match idp.reload().await {
            Err(IssuanceError::DuplicateKeyId { kid }) if repeated => assert_eq!(kid, "k3"),
            Err(IssuanceError::EmptyKeyId) if !repeated => {}
            other => panic!("the bad key set was not refused for its reason: {other:?}"),
        }
        assert_eq!(kids(&idp.jwks().await), vec!["k2", "k1"]);
    }
}

/// A rotation to a key with an empty `kid` is refused before the store is
/// touched, on the same terms as a repeated one.
#[tokio::test]
async fn a_rotation_to_an_empty_kid_is_refused() {
    let store = MemoryLocalIdpKeyStore::with_current(es("k1"));
    let idp = LocalIdp::from_key_store("https://idp.local", store.clone())
        .await
        .expect("load");
    assert!(matches!(
        idp.rotate_signing_key(es("")).await,
        Err(IssuanceError::EmptyKeyId)
    ));
    assert_eq!(kids(&idp.jwks().await), vec!["k1"]);
    assert_eq!(store.load_all().await.expect("load").current.key_id(), "k1");
}
