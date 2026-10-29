use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use std::sync::Mutex;

fn rsa_keypair() -> (Vec<u8>, JwkSet, String) {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();
    let kid = "test-key-1".to_string();

    let private_der = private_key
        .to_pkcs1_der()
        .expect("PKCS1 DER encode")
        .as_bytes()
        .to_vec();

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwk_json = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e,
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwk_json).expect("JwkSet parse");

    (private_der, jwks, kid)
}

fn sign(claims: &serde_json::Value, kid: &str, der: &[u8]) -> String {
    // Signing needs the same crypto provider verification does, and under
    // `--all-features` `jsonwebtoken` has no default. Verification installs
    // one itself; a signer asks, and a test that signs before anything has
    // verified would otherwise panic on the order tests happened to run in.
    crate::jwt::ensure_crypto_provider();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_der(der);
    encode(&header, claims, &key).expect("JWT encode")
}

fn handle(jwks: JwkSet) -> Arc<RwLock<JwkSet>> {
    Arc::new(RwLock::new(jwks))
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Debug, Deserialize)]
struct WorkloadClaims {
    sub: String,
    #[serde(default)]
    scope: Option<String>,
}

/// Happy path: verifier deserialises into a typed claim struct and
/// surfaces the registered standard claims.
#[tokio::test]
async fn verify_typed_claims_happy_path() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "workload-42",
            "aud": "my-svc",
            "exp": now + 3600,
            "iat": now,
            "scope": "read",
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc");

    let claims = verifier
        .verify::<WorkloadClaims>(&token)
        .await
        .expect("verify ok");

    assert_eq!(claims.iss.as_deref(), Some("https://idp.example.com"));
    assert_eq!(claims.aud.as_deref(), Some(&["my-svc".to_string()][..]));
    assert_eq!(claims.custom.sub, "workload-42");
    assert_eq!(claims.custom.scope.as_deref(), Some("read"));
}

/// Issuer mismatch is rejected. Pins `with_issuer` against silent
/// no-op mutations.
#[tokio::test]
async fn issuer_mismatch_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "iss": "https://attacker.example.com",
            "sub": "x",
            "aud": "my-svc",
            "exp": now + 3600,
            "iat": now,
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc");

    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("issuer mismatch must reject");
    assert!(
        matches!(err, JwtError::VerificationFailed(_)),
        "got {err:?}"
    );
}

/// `require_nbf(true)` rejects a token without an `nbf` claim.
#[tokio::test]
async fn missing_nbf_rejected_when_required() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "sub": "x",
            "aud": "my-svc",
            "exp": now + 3600,
            "iat": now,
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_audience("my-svc")
        .require_nbf(true);

    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("missing nbf must reject");
    assert!(
        matches!(err, JwtError::VerificationFailed(_)),
        "got {err:?}"
    );
}

/// Configured `nbf` in the future is rejected even within the
/// default leeway. Pins the leeway plumbing.
#[tokio::test]
async fn nbf_in_future_beyond_leeway_rejected() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "sub": "x",
            "aud": "my-svc",
            "exp": now + 3600,
            "iat": now,
            "nbf": now + 1000, // far beyond leeway
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_audience("my-svc")
        .require_nbf(true);

    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("future nbf must reject");
    assert!(
        matches!(err, JwtError::VerificationFailed(_)),
        "got {err:?}"
    );
}

/// Replay store records the `jti` and rejects a second use of the
/// same token. Pins the replay-store wiring.
#[derive(Default)]
struct InMemReplay {
    seen: Mutex<std::collections::HashSet<String>>,
}

impl JtiReplayStore for InMemReplay {
    fn check_and_record(
        &self,
        jti: &str,
        _ttl: Duration,
    ) -> impl Future<Output = Result<(), JtiReplayError>> + Send {
        let key = jti.to_string();
        let result = {
            let mut seen = self.seen.lock().unwrap();
            if seen.contains(&key) {
                Err(JtiReplayError::AlreadyUsed(key))
            } else {
                seen.insert(key);
                Ok(())
            }
        };
        async move { result }
    }
}

#[tokio::test]
async fn replay_store_rejects_second_use() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "sub": "x",
            "aud": "my-svc",
            "exp": now + 3600,
            "iat": now,
            "jti": "tok-1",
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_audience("my-svc")
        .with_replay_store(InMemReplay::default());

    verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect("first use ok");
    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("replay must reject");
    assert!(
        matches!(err, JwtError::VerificationFailed(_)),
        "got {err:?}"
    );
}

/// Replay store with no `jti` on the token rejects. Without this
/// pin, mistakenly skipping the `jti` claim would silently
/// bypass replay protection.
#[tokio::test]
async fn replay_store_requires_jti() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "sub": "x",
            "aud": "my-svc",
            "exp": now + 3600,
            "iat": now,
            // jti intentionally omitted
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_audience("my-svc")
        .with_replay_store(InMemReplay::default());

    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("missing jti under replay store must reject");
    assert!(
        matches!(err, JwtError::VerificationFailed(_)),
        "got {err:?}"
    );
}

/// DST-driven `exp` validation. With a `MockClock` injected,
/// advancing the clock past `exp + leeway` rejects the token even
/// though wall-clock time hasn't moved. Impossible to write before
/// the injected-clock path landed because `jsonwebtoken`'s internal
/// `exp` check used `SystemTime::now()`.
#[tokio::test]
async fn exp_validation_uses_injected_clock() {
    use axess_clock::testing::MockClock;

    let (der, jwks, kid) = rsa_keypair();
    // Anchor the mock clock at a known wall-clock moment so the
    // token's `exp` claim and the clock's `now` agree.
    let t0 = chrono::Utc::now();
    let exp = t0.timestamp() + 100;
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "workload-42",
            "aud": "my-svc",
            "exp": exp,
            "iat": t0.timestamp(),
        }),
        &kid,
        &der,
    );

    let clock = Arc::new(MockClock::at(t0));
    let verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc")
        .with_clock(clock.clone());

    // At t0: valid.
    verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect("token must verify at issuance time");

    // Advance well past exp + 60s leeway (default).
    clock.advance_secs(200);
    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("expired token must reject under MockClock advance");
    match err {
        JwtError::VerificationFailed(msg) => {
            assert!(
                msg.contains("expired"),
                "expected 'expired' in error message, got: {msg}"
            );
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }

    // Rewind to t0 + 30s (within exp): valid again.
    clock.set(t0 + chrono::Duration::seconds(30));
    verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect("token must verify within exp window after clock rewind");
}

/// DST-driven `nbf` validation. A token with
/// `nbf` in the future is rejected when the MockClock is set before
/// `nbf - leeway`; advancing the clock past `nbf` makes it valid.
#[tokio::test]
async fn nbf_validation_uses_injected_clock() {
    use axess_clock::testing::MockClock;

    let (der, jwks, kid) = rsa_keypair();
    let t0 = chrono::Utc::now();
    let nbf = t0.timestamp() + 300; // not valid until t0 + 5 min
    let exp = nbf + 3600;
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "workload-42",
            "aud": "my-svc",
            "nbf": nbf,
            "exp": exp,
            "iat": t0.timestamp(),
        }),
        &kid,
        &der,
    );

    let clock = Arc::new(MockClock::at(t0));
    let verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc")
        .with_clock(clock.clone());

    // At t0: nbf is 300s in the future, leeway is 60s; reject.
    let err = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("token with future nbf must reject at issuance time");
    match err {
        JwtError::VerificationFailed(msg) => {
            assert!(
                msg.contains("not yet valid"),
                "expected 'not yet valid' in error message, got: {msg}"
            );
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }

    // Advance past nbf: valid.
    clock.advance_secs(400);
    verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect("token must verify after MockClock advance past nbf");
}

/// `PS256` is outside the conservative default but
/// `with_algorithms` opens the door for FAPI 2.0 / Entra adopters.
/// The pair of sub-tests pins both halves of the contract: default
/// rejects, opt-in accepts.
#[tokio::test]
async fn ps256_opt_in_via_with_algorithms() {
    // Build an RSA keypair, then publish it under `alg: PS256` so
    // the verifier's defense-in-depth alg-vs-JWK match passes when
    // the token header says PS256 too.
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
    let public_key = private_key.to_public_key();
    let kid = "ps256-key".to_string();
    let private_der = private_key
        .to_pkcs1_der()
        .expect("PKCS1 DER encode")
        .as_bytes()
        .to_vec();
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
    let jwk_json = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "PS256",
            "kid": kid,
            "n": n,
            "e": e,
        }]
    });
    let jwks: JwkSet = serde_json::from_value(jwk_json).expect("JwkSet parse");

    let now = now_secs();
    let claims = serde_json::json!({
        "iss": "https://idp.example.com",
        "sub": "workload-42",
        "aud": "my-svc",
        "exp": now + 3600,
        "iat": now,
    });
    let mut header = Header::new(Algorithm::PS256);
    header.kid = Some(kid.clone());
    let signing_key = EncodingKey::from_rsa_der(&private_der);
    crate::jwt::ensure_crypto_provider();
    let token = encode(&header, &claims, &signing_key).expect("PS256 JWT encode");

    // Default allowlist rejects PS256; proves the conservative
    // default still excludes it.
    let default_verifier = JwtVerifier::new(handle(jwks.clone()))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc");
    let err = default_verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("PS256 must be rejected by default");
    assert!(
        matches!(err, JwtError::DisallowedAlgorithm(Algorithm::PS256)),
        "expected DisallowedAlgorithm(PS256), got {err:?}"
    );

    // Opt in via `with_algorithms`; verification now succeeds.
    let opt_in_verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc")
        .with_algorithms([Algorithm::PS256]);
    opt_in_verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect("PS256 must verify after with_algorithms opt-in");
}

/// `aud` as a JSON Array must round-trip into `VerifiedClaims.aud`
/// preserving every string element. Pins the `Some(Value::Array(arr))`
/// match arm; without it, multi-audience tokens would silently collapse
/// to `None` and any policy that branches on `aud.contains("my-svc")`
/// would fail open or closed unexpectedly.
#[tokio::test]
async fn aud_array_round_trips_into_verified_claims() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "u",
            "aud": ["other-rp", "my-svc", "third"],
            "exp": now + 3600,
            "iat": now,
        }),
        &kid,
        &der,
    );

    let verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc");
    let claims = verifier
        .verify::<serde_json::Value>(&token)
        .await
        .expect("verify ok");
    let aud = claims.aud.expect("aud must be Some for array form");
    assert!(
        aud.contains(&"my-svc".to_string()) && aud.contains(&"other-rp".to_string()),
        "Array aud must preserve every string element (kills `delete Array arm`)"
    );
}

/// `compute_replay_ttl` holds a `jti` for as long as the verifier would
/// still take the token: `exp + skew - now`, floored at zero. Pins the
/// subtraction, the skew term, the floor, and the no-exp fallback:
/// - `replace compute_replay_ttl -> Default::default()` (Duration::ZERO),
/// - `(exp - now) → (exp + now)` (would yield ~2*now ≈ 4e9 seconds),
/// - dropping the skew (a token presented in the leeway window would be
///   forgotten while still accepted, so its replay would pass).
#[test]
fn compute_replay_ttl_covers_the_leeway_window() {
    use axess_clock::testing::MockClock;
    use chrono::{TimeZone, Utc};

    let now: i64 = 1_700_000_000;
    let clock = MockClock::at(Utc.timestamp_opt(now, 0).single().unwrap());
    let skew = Duration::from_secs(60);

    // 900 seconds in the future → TTL = 960s (exp + skew - now).
    assert_eq!(
        compute_replay_ttl(Some(now + 900), skew, &clock),
        Duration::from_secs(960),
        "TTL must equal `exp + skew - now` exactly"
    );

    // Expired 10 s ago but inside the 60 s leeway: the verifier still
    // accepts it for 50 s, so the jti must be held for 50 s, not 0.
    assert_eq!(
        compute_replay_ttl(Some(now - 10), skew, &clock),
        Duration::from_secs(50),
        "a token inside the leeway window is still replayable and must be remembered"
    );

    // Past the leeway window clamps to 0.
    assert_eq!(
        compute_replay_ttl(Some(now - 100), skew, &clock),
        Duration::ZERO,
        "exp + skew in the past must clamp TTL to zero"
    );

    // Without skew the old behaviour holds exactly.
    assert_eq!(
        compute_replay_ttl(Some(now + 900), Duration::ZERO, &clock),
        Duration::from_secs(900)
    );

    // Missing exp is held for the fallback day, never forgotten at once.
    assert_eq!(
        compute_replay_ttl(None, skew, &clock),
        Duration::from_secs(24 * 60 * 60)
    );
}

/// The pins are visible to a resolver that wants to insist on them.
#[test]
fn the_pins_are_reported() {
    let (_, jwks, _) = rsa_keypair();
    let bare = JwtVerifier::new(handle(jwks.clone()));
    assert!(!bare.has_issuer() && !bare.has_audience());
    let pinned = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("svc");
    assert!(pinned.has_issuer() && pinned.has_audience());
    // Keeping the pins across the replay-store type change.
    let with_store = pinned.with_replay_store(NoReplay);
    assert!(with_store.has_issuer() && with_store.has_audience());
}

/// A verifier with no audience pin and no waiver refuses every token, since a
/// token minted for another service of the same issuer would otherwise
/// verify; the waiver and the pin each lift the refusal.
#[tokio::test]
async fn a_missing_audience_pin_refuses_unless_waived() {
    let (der, jwks, kid) = rsa_keypair();
    let claims = serde_json::json!({
        "sub": "s",
        "exp": now_secs() + 300,
    });
    let token = sign(&claims, &kid, &der);

    let bare = JwtVerifier::new(handle(jwks.clone()));
    let err = bare
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("no audience decision, no verification");
    assert!(err.to_string().contains("audience"), "{err}");

    let waived = JwtVerifier::new(handle(jwks.clone())).allow_any_audience();
    waived.verify::<serde_json::Value>(&token).await.unwrap();

    let pinned = JwtVerifier::new(handle(jwks)).with_audience("svc");
    let mut with_aud = claims;
    with_aud["aud"] = serde_json::json!("svc");
    pinned
        .verify::<serde_json::Value>(&sign(&with_aud, &kid, &der))
        .await
        .unwrap();
}

/// A correctly signed token over the size limit is refused: the limit
/// applies to the verifier (and so to the JWT-SVID resolver built on it), not
/// only to the claim helper.
#[tokio::test]
async fn an_oversized_signed_token_is_refused() {
    let (der, jwks, kid) = rsa_keypair();
    let now = now_secs();
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "workload-42",
            "aud": "my-svc",
            "exp": now + 3600,
            "padding": "p".repeat(crate::jwt::claims::MAX_JWT_BYTES),
        }),
        &kid,
        &der,
    );
    let verifier = JwtVerifier::new(handle(jwks)).with_audience("my-svc");
    let err = verifier.verify::<WorkloadClaims>(&token).await.unwrap_err();
    assert!(matches!(err, JwtError::TooLarge { .. }), "{err:?}");
}
