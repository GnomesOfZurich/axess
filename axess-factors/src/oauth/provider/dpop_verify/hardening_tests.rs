//! Replay window at skew zero, and the size bounds on a proof and its `jti`.

use super::*;
use crate::oauth::types::DpopKey;
use axess_clock::Clock as _;
use axess_clock::testing::{MockClock, Shift};
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::pkcs8::EncodePrivateKey;
use std::sync::atomic::{AtomicUsize, Ordering};

const HTU: &str = "https://rs.example/x";

/// A proof signed by `key` over exactly `claims`.
fn proof_over(key: &DpopKey, claims: &serde_json::Value) -> String {
    use base64::Engine as _;
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
    let sig = crate::jwt::sign(
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
    skew: u64,
    now: Timestamp,
) -> Result<DpopVerified, OAuthError> {
    verify_dpop_proof(
        DpopVerifyRequest {
            proof_jwt: proof,
            htm: "POST",
            htu: HTU,
            access_token: None,
            max_iat_skew: Duration::from_secs(skew),
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
    let t = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let clock = Arc::new(MockClock::at(t));
    let cache = MemoryJtiCache::new().with_clock(clock.clone());
    let key = DpopKey::from_seed([5; 32]);
    let proof = proof_over(&key, &claims(t.unix_seconds(), "jti-1"));

    clock.set(t.plus(SignedDuration::milliseconds(200)));
    verify(&proof, &cache, 0, clock.now()).expect("fresh at T+200ms");

    clock.set(t.plus(SignedDuration::milliseconds(900)));
    let err = verify(&proof, &cache, 0, clock.now()).expect_err("replay at T+900ms");
    assert!(format!("{err}").contains("replayed"), "{err}");
}

struct Counting(AtomicUsize);

impl DpopJtiCache for Counting {
    fn try_insert(&self, _: &str, _: Timestamp) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        true
    }
}

/// A 300-byte `jti` and a proof over the size cap are refused without the
/// cache being touched, and a replay error does not repeat the `jti`.
#[test]
fn oversized_proofs_and_jtis_are_refused_before_the_cache() {
    let now = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let key = DpopKey::from_seed([6; 32]);
    let cache = Counting(AtomicUsize::new(0));

    let long_jti = "j".repeat(300);
    let proof = proof_over(&key, &claims(now.unix_seconds(), &long_jti));
    assert!(verify(&proof, &cache, 60, now).is_err());

    let empty = proof_over(&key, &claims(now.unix_seconds(), ""));
    assert!(verify(&empty, &cache, 60, now).is_err());

    let mut big = claims(now.unix_seconds(), "ok");
    big["pad"] = serde_json::json!("p".repeat(MAX_PROOF_BYTES));
    let proof = proof_over(&key, &big);
    assert!(proof.len() > MAX_PROOF_BYTES);
    assert!(verify(&proof, &cache, 60, now).is_err());

    assert_eq!(cache.0.load(Ordering::SeqCst), 0, "no try_insert call");

    let real = MemoryJtiCache::new().with_clock(Arc::new(MockClock::at(now)));
    let good = proof_over(&key, &claims(now.unix_seconds(), "secret-looking-jti"));
    verify(&good, &real, 60, now).unwrap();
    let err = verify(&good, &real, 60, now).unwrap_err();
    assert!(!format!("{err}").contains("secret-looking-jti"), "{err}");
}

/// The store keys entries by a fixed-size digest, so a long `jti` costs no
/// more than a short one in either structure.
#[test]
fn the_store_keys_entries_by_digest() {
    let mut store = JtiStore::default();
    let at = |s: i64| Timestamp::from_unix_seconds(1_700_000_000 + s).unwrap();
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

// ── The proof's key ──────────────────────────────────────────────────────

/// A proof signed by `key` whose header carries `jwk` instead of the key's
/// own public JWK.
fn proof_with_jwk(key: &DpopKey, jwk: &serde_json::Value, claims: &serde_json::Value) -> String {
    use base64::Engine as _;
    let b64 = &URL_SAFE_NO_PAD;
    let header = serde_json::json!({ "alg": "ES256", "typ": "dpop+jwt", "jwk": jwk });
    let der = key.secret_key().unwrap().to_pkcs8_der().unwrap();
    let signing_input = format!(
        "{}.{}",
        b64.encode(header.to_string()),
        b64.encode(claims.to_string())
    );
    let sig = crate::jwt::sign(
        signing_input.as_bytes(),
        &EncodingKey::from_ec_der(der.as_bytes()),
        Algorithm::ES256,
    )
    .unwrap();
    format!("{signing_input}.{sig}")
}

fn refusal_of(jwk: serde_json::Value) -> String {
    let t = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let key = DpopKey::from_seed([6; 32]);
    let proof = proof_with_jwk(&key, &jwk, &claims(t.unix_seconds(), "jti-key"));
    let cache = MemoryJtiCache::new();
    verify(&proof, &cache, 60, t)
        .expect_err("a key that is not P-256 is refused")
        .to_string()
}

/// The verifier signs over ES256 only, so the key must be an EC key on
/// P-256 with 32-byte coordinates, said in so many words, before a key is
/// built from it.
#[test]
fn a_key_that_is_not_a_p256_ec_key_is_refused_by_name() {
    let key = DpopKey::from_seed([6; 32]);
    let (x, y) = key.public_coordinates().unwrap();
    let short = URL_SAFE_NO_PAD.encode([7u8; 31]);
    let long = URL_SAFE_NO_PAD.encode([7u8; 33]);

    for (jwk, member) in [
        (
            serde_json::json!({"kty": "RSA", "crv": "P-256", "x": x, "y": y}),
            "kty",
        ),
        (
            serde_json::json!({"kty": "OKP", "crv": "P-256", "x": x, "y": y}),
            "kty",
        ),
        (serde_json::json!({"crv": "P-256", "x": x, "y": y}), "kty"),
        (
            serde_json::json!({"kty": "EC", "crv": "P-384", "x": x, "y": y}),
            "crv",
        ),
        (
            serde_json::json!({"kty": "EC", "crv": "secp256k1", "x": x, "y": y}),
            "crv",
        ),
        (serde_json::json!({"kty": "EC", "x": x, "y": y}), "crv"),
        (
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": short, "y": y}),
            "x",
        ),
        (
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": long}),
            "y",
        ),
        (
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": format!("{x}="), "y": y}),
            "x",
        ),
        (
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": x}),
            "y",
        ),
        (
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": 5, "y": y}),
            "x",
        ),
    ] {
        let text = refusal_of(jwk.clone());
        assert!(
            text.contains(&format!("`{member}`")),
            "{jwk}: the refusal does not name `{member}`: {text}"
        );
    }
}

/// The thumbprint is RFC 7638's: the SHA-256 of the key's required members as
/// canonical JSON, whatever else the header's JWK carries.
#[test]
fn the_thumbprint_is_the_rfc_7638_digest_whatever_else_the_jwk_carries() {
    use sha2::{Digest, Sha256};
    let t = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let key = DpopKey::from_seed([8; 32]);
    let (x, y) = key.public_coordinates().unwrap();
    let canonical = serde_json::to_string(&serde_json::json!({
        "crv": "P-256", "kty": "EC", "x": x, "y": y,
    }))
    .unwrap();
    let want = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));

    for (n, jwk) in [
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}),
        serde_json::json!({"y": y, "x": x, "crv": "P-256", "kty": "EC", "use": "sig", "kid": "k"}),
    ]
    .into_iter()
    .enumerate()
    {
        let proof = proof_with_jwk(&key, &jwk, &claims(t.unix_seconds(), &format!("jti-{n}")));
        let verified = verify(&proof, &MemoryJtiCache::new(), 60, t).expect("a valid proof");
        assert_eq!(verified.thumbprint, want, "{jwk}");
    }
}

/// A proof whose header the sender wrote whole: `edit` changes the header
/// of an otherwise valid proof by `key`.
fn proof_with_header(key: &DpopKey, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    use base64::Engine as _;
    let b64 = &URL_SAFE_NO_PAD;
    let (x, y) = key.public_coordinates().unwrap();
    let mut header = serde_json::json!({
        "alg": "ES256", "typ": "dpop+jwt",
        "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y },
    });
    edit(&mut header);
    let der = key.secret_key().unwrap().to_pkcs8_der().unwrap();
    let signing_input = format!(
        "{}.{}",
        b64.encode(header.to_string()),
        b64.encode(claims(1_700_000_000, "jti-long").to_string())
    );
    let sig = crate::jwt::sign(
        signing_input.as_bytes(),
        &EncodingKey::from_ec_der(der.as_bytes()),
        Algorithm::ES256,
    )
    .unwrap();
    format!("{signing_input}.{sig}")
}

/// What the sender put in a proof's header reaches the refusal cut: a long
/// `typ` or `alg` is quoted to 64 bytes, and a key member of the wrong kind
/// in `jwk` is reported with serde's message cut at 256 bytes, not with the
/// value whole.
#[test]
fn a_long_header_value_is_quoted_cut() {
    let t = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let key = DpopKey::from_seed([6; 32]);
    let long = "A".repeat(3000);
    // The header member the long value goes in, and the key member within
    // it for `jwk`.
    for (member, within) in [("typ", None), ("alg", None), ("jwk", Some("x5c"))] {
        let proof = proof_with_header(&key, |h| match within {
            Some(inner) => h[member][inner] = serde_json::json!(long),
            None => h[member] = serde_json::json!(long),
        });
        assert!(proof.len() <= MAX_PROOF_BYTES, "{member}: the proof fits");
        let err = verify(&proof, &MemoryJtiCache::new(), 60, t)
            .expect_err("the header is refused")
            .to_string();
        assert!(
            err.len() <= 512,
            "{member}: {} bytes in one error",
            err.len()
        );
        assert!(
            !err.contains(&"A".repeat(300)),
            "{member}: the value is quoted whole"
        );
    }
}

/// A proof by `key` whose `htm` and `htu` claims the sender wrote.
fn proof_claiming(key: &DpopKey, htm: &str, htu: &str) -> String {
    proof_over(
        key,
        &serde_json::json!({ "htm": htm, "htu": htu, "iat": 1_700_000_000, "jti": "jti-claims" }),
    )
}

/// A mismatched `htm` or `htu` claim is the sender's text, and so is the
/// request it is compared with: the refusal quotes each side cut to 64
/// bytes with control characters and the Unicode line separators escaped,
/// so one proof neither fills an error nor forges a log line.
#[test]
fn a_mismatched_htm_or_htu_is_quoted_cut_and_escaped() {
    let t = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let key = DpopKey::from_seed([7; 32]);
    let forged = format!(
        "GET\nWARN forged line\r\u{1b}[31m\u{2028}{}",
        "A".repeat(3000)
    );

    for (htm, htu) in [(forged.as_str(), HTU), ("POST", forged.as_str())] {
        let proof = proof_claiming(&key, htm, htu);
        assert!(proof.len() <= MAX_PROOF_BYTES, "the proof fits");
        let err = verify(&proof, &MemoryJtiCache::new(), 60, t)
            .expect_err("the claim is refused")
            .to_string();
        assert!(err.contains("mismatch"), "{err}");
        assert!(err.len() <= 256, "{} bytes in one error", err.len());
        assert!(!err.contains(&"A".repeat(64)), "quoted whole: {err}");
        assert!(
            !err.chars()
                .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
            "{err:?}"
        );
        assert!(err.contains("GET\\nWARN forged line\\r"), "{err}");
    }
}

/// The method and the URL of the request are the sender's too: a mismatch
/// quotes them under the same cut and the same escapes as the claim. The
/// escaped head of each is in the error, so the value is quoted, and quoted
/// escaped, rather than left out.
#[test]
fn the_request_side_of_a_mismatch_is_quoted_cut_and_escaped() {
    let t = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let key = DpopKey::from_seed([8; 32]);
    let proof = proof_claiming(&key, "POST", HTU);
    let long_url = format!("https://rs.example/x\n{}", "B".repeat(3000));
    let long_method = format!("PO\rST\u{2028}{}", "B".repeat(3000));

    for (htm, htu, head) in [
        (
            "POST",
            long_url.as_str(),
            "request is `https://rs.example/x\\nBBB",
        ),
        (long_method.as_str(), HTU, "request is `PO\\rST\\u{2028}BBB"),
    ] {
        let err = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &proof,
                htm,
                htu,
                access_token: None,
                max_iat_skew: Duration::from_secs(60),
                jti_cache: &MemoryJtiCache::new(),
            },
            t,
        )
        .expect_err("the request does not match the proof")
        .to_string();
        assert!(err.len() <= 256, "{} bytes in one error", err.len());
        assert!(err.contains(head), "the escaped head {head:?} in {err:?}");
        assert!(err.ends_with("...`"), "the cut is marked: {err:?}");
        assert!(!err.contains(&"B".repeat(64)), "quoted whole: {err}");
        assert!(
            !err.chars()
                .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
            "{err:?}"
        );
    }
}
