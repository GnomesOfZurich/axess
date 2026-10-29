//! Replay window at skew zero, and the size bounds on a proof and its `jti`.

use super::*;
use crate::oauth::types::DpopKey;
use axess_clock::Clock as _;
use axess_clock::testing::MockClock;
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::pkcs8::EncodePrivateKey;
use std::sync::atomic::{AtomicUsize, Ordering};

const HTU: &str = "https://rs.example/x";

/// A proof signed by `key` over exactly `claims`.
fn proof_over(key: &DpopKey, claims: &serde_json::Value) -> String {
    use base64::Engine as _;
    crate::jwt::ensure_crypto_provider();
    let b64 = &URL_SAFE_NO_PAD;
    let (x, y) = key.public_coordinates().unwrap();
    let header = serde_json::json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y },
    });
    let der = key.secret_key().unwrap().to_pkcs8_der().unwrap();
    let signing_input = format!(
        "{}.{}",
        b64.encode(header.to_string()),
        b64.encode(claims.to_string())
    );
    let sig = jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        &EncodingKey::from_ec_der(der.as_bytes()),
        Algorithm::ES256,
    )
    .unwrap();
    format!("{signing_input}.{sig}")
}

fn claims(iat: i64, jti: &str) -> serde_json::Value {
    serde_json::json!({ "htm": "POST", "htu": HTU, "iat": iat, "jti": jti })
}

fn verify(
    proof: &str,
    cache: &dyn DpopJtiCache,
    skew: i64,
    now: DateTime<Utc>,
) -> Result<DpopVerified, OAuthError> {
    verify_dpop_proof(
        DpopVerifyRequest {
            proof_jwt: proof,
            htm: "POST",
            htu: HTU,
            access_token: None,
            max_iat_skew_secs: skew,
            jti_cache: cache,
        },
        now,
    )
}

/// With a skew of zero the same proof is accepted at T + 200 ms and is a
/// replay at T + 900 ms. Before, its `jti` entry expired at `iat` and the same
/// proof was accepted again for the rest of that second.
#[test]
fn at_skew_zero_a_proof_cannot_replay_within_its_second() {
    let t = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let clock = Arc::new(MockClock::at(t));
    let cache = MemoryJtiCache::new().with_clock(clock.clone());
    let key = DpopKey::from_seed([5; 32]);
    let proof = proof_over(&key, &claims(t.timestamp(), "jti-1"));

    clock.set(t + chrono::Duration::milliseconds(200));
    verify(&proof, &cache, 0, clock.now()).expect("fresh at T+200ms");

    clock.set(t + chrono::Duration::milliseconds(900));
    let err = verify(&proof, &cache, 0, clock.now()).expect_err("replay at T+900ms");
    assert!(format!("{err}").contains("replayed"), "{err}");
}

struct Counting(AtomicUsize);

impl DpopJtiCache for Counting {
    fn try_insert(&self, _jti: &str, _expires_at: DateTime<Utc>) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        true
    }
}

/// A 300-byte `jti` and a proof over the size cap are refused without the
/// cache being touched, and a replay error does not repeat the `jti`.
#[test]
fn oversized_proofs_and_jtis_are_refused_before_the_cache() {
    let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let key = DpopKey::from_seed([6; 32]);
    let cache = Counting(AtomicUsize::new(0));

    let long_jti = "j".repeat(300);
    let proof = proof_over(&key, &claims(now.timestamp(), &long_jti));
    assert!(verify(&proof, &cache, 60, now).is_err());

    let empty = proof_over(&key, &claims(now.timestamp(), ""));
    assert!(verify(&empty, &cache, 60, now).is_err());

    let mut big = claims(now.timestamp(), "ok");
    big["pad"] = serde_json::json!("p".repeat(MAX_PROOF_BYTES));
    let proof = proof_over(&key, &big);
    assert!(proof.len() > MAX_PROOF_BYTES);
    assert!(verify(&proof, &cache, 60, now).is_err());

    assert_eq!(cache.0.load(Ordering::SeqCst), 0, "no try_insert call");

    let real = MemoryJtiCache::new().with_clock(Arc::new(MockClock::at(now)));
    let good = proof_over(&key, &claims(now.timestamp(), "secret-looking-jti"));
    verify(&good, &real, 60, now).unwrap();
    let err = verify(&good, &real, 60, now).unwrap_err();
    assert!(!format!("{err}").contains("secret-looking-jti"), "{err}");
}

/// The store keys entries by a fixed-size digest, so a long `jti` costs no
/// more than a short one in either structure.
#[test]
fn the_store_keys_entries_by_digest() {
    let mut store = JtiStore::default();
    let at = |s: i64| DateTime::from_timestamp(1_700_000_000 + s, 0).unwrap();
    assert!(try_insert_at(
        &mut store,
        &"x".repeat(256),
        at(60),
        at(0),
        10
    ));
    let (digest, _) = store.live.iter().next().unwrap();
    assert_eq!(digest.len(), 32);
}
