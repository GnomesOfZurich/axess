use super::*;
use chrono::Utc;
use jsonwebtoken::jwk::KeyAlgorithm;
use rsa::rand_core::RngCore;

/// An imported RSA key under 2048 bits is refused.
#[test]
fn imported_rsa_key_below_2048_bits_is_refused() {
    let mut adapter = SecureRngAdapter(&axess_rng::SystemRng);
    let weak = RsaPrivateKey::new(&mut adapter, 1024).expect("1024-bit keygen");
    let der = weak.to_pkcs1_der().expect("encode");
    let err = LocalIdpSigningKey::from_rsa_pkcs1_der(der.as_bytes(), "weak", Algorithm::RS256)
        .expect_err("a 1024-bit key must be refused");
    assert!(
        matches!(
            err,
            LocalIdpKeyError::WeakKey {
                bits: 1024,
                min: 2048
            }
        ),
        "{err:?}"
    );
}

/// An unsupported algorithm is an error from every constructor that
/// already returns a `Result`, and from the `try_` generator; none panics.
#[test]
fn unsupported_algorithm_is_an_error_not_a_panic() {
    let es = LocalIdpSigningKey::generate_es256();
    let _ = es;
    let err = LocalIdpSigningKey::from_ec_pem("x", "k", Algorithm::RS256)
        .expect_err("EC constructor with RS256");
    assert!(
        matches!(err, LocalIdpKeyError::UnsupportedAlgorithm(_)),
        "{err:?}"
    );
    let err = LocalIdpSigningKey::from_rsa_pem("x", "k", Algorithm::ES256)
        .expect_err("RSA constructor with ES256");
    assert!(
        matches!(err, LocalIdpKeyError::UnsupportedAlgorithm(_)),
        "{err:?}"
    );
    let err = LocalIdpSigningKey::try_generate_rsa_with_algorithm(Algorithm::HS256)
        .expect_err("HS256 is not an RSA algorithm");
    assert!(
        matches!(err, LocalIdpKeyError::UnsupportedAlgorithm(_)),
        "{err:?}"
    );
    let err = LocalIdpSigningKey::try_generate_rsa_with_algorithm_and_rng(
        Algorithm::ES256,
        &axess_rng::SystemRng,
    )
    .expect_err("ES256 is not an RSA algorithm");
    assert!(
        matches!(err, LocalIdpKeyError::UnsupportedAlgorithm(_)),
        "{err:?}"
    );
}

/// A custom claim never overrides a registered one: a custom `exp` would
/// outlive the max-TTL check, a custom `sub` or `aud` would swap the
/// subject or audience under the signature.
#[test]
fn custom_claims_cannot_override_registered_claims() {
    let exp = Utc::now() + chrono::Duration::minutes(5);
    let claims = MintClaims::new("worker-1", exp)
        .with_custom_claim("exp", exp.timestamp() + 10 * 365 * 24 * 3600)
        .with_custom_claim("sub", "mallory")
        .with_custom_claim("aud", "other-service")
        .with_custom_claim("iss", "https://evil.example")
        .with_custom_claim("jti", "forged")
        .with_custom_claim("dept", "treasury");
    let v = build_claims_json("https://issuer.example", &claims);
    assert_eq!(v["exp"], serde_json::json!(exp.timestamp()));
    assert_eq!(v["sub"], serde_json::json!("worker-1"));
    assert_eq!(v["iss"], serde_json::json!("https://issuer.example"));
    assert!(
        v.get("aud").is_none(),
        "no audience was stated, none is minted"
    );
    assert!(v.get("jti").is_none(), "no jti was stated, none is minted");
    assert_eq!(
        v["dept"],
        serde_json::json!("treasury"),
        "a custom claim that is not registered is kept"
    );
}

/// The lifetime cap is measured from now: a future-dated `iat` cannot
/// shrink the apparent lifetime of a token that stays valid for years.
#[test]
fn max_ttl_is_measured_from_now_not_from_a_stated_iat() {
    let now = Utc::now();
    let claims = MintClaims::new("worker-1", now + chrono::Duration::days(3650))
        .with_issued_at(now + chrono::Duration::days(3649));
    assert!(
        enforce_max_ttl_fallible(&claims, chrono::Duration::hours(24), now).is_err(),
        "a ten-year token must exceed a one-day cap whatever its iat says"
    );
}

/// A cap that is not positive, a token that has already expired, and one
/// that becomes valid after it expires are refused, not minted.
#[test]
fn max_ttl_refuses_unusable_caps_and_claim_sets() {
    use crate::local_idp::LifetimeFault::{AlreadyExpired, NonPositiveCap, NotBeforeAfterExpiry};
    use chrono::Duration;
    let now = Utc::now();
    let ok = MintClaims::new("worker-1", now + Duration::minutes(5));
    assert!(enforce_max_ttl_fallible(&ok, Duration::hours(1), now).is_ok());
    for cap in [Duration::zero(), Duration::seconds(-1)] {
        let long_gone = MintClaims::new("worker-1", now - Duration::hours(1));
        assert_eq!(
            enforce_max_ttl_fallible(&long_gone, cap, now),
            Err(TtlRefusal::Invalid(NonPositiveCap)),
            "a cap of {cap} must not admit a token that expired an hour ago"
        );
        assert_eq!(
            enforce_max_ttl_fallible(&ok, cap, now),
            Err(TtlRefusal::Invalid(NonPositiveCap)),
            "a cap of {cap} admits nothing"
        );
    }
    let expired = MintClaims::new("worker-1", now);
    assert_eq!(
        enforce_max_ttl_fallible(&expired, Duration::hours(1), now),
        Err(TtlRefusal::Invalid(AlreadyExpired)),
        "exp at now is already expired"
    );
    let backwards = MintClaims::new("worker-1", now + Duration::minutes(5))
        .with_not_before(now + Duration::minutes(10));
    assert_eq!(
        enforce_max_ttl_fallible(&backwards, Duration::hours(1), now),
        Err(TtlRefusal::Invalid(NotBeforeAfterExpiry)),
        "nbf after exp is a token that is never valid"
    );
    assert!(matches!(
        enforce_max_ttl_fallible(&ok, Duration::minutes(1), now),
        Err(TtlRefusal::Exceeds { .. })
    ));
}

/// Signing reuses one `EncodingKey`: each mint used to build a new one,
/// leaving an unzeroized copy of the private key per mint.
#[test]
fn signing_reuses_one_encoding_key() {
    let key = LocalIdpSigningKey::generate_es256();
    assert!(std::ptr::eq(key.encoding_key(), key.encoding_key()));
}

/// Every JWS algorithm `LocalIdpFixture::verifier_algorithms` is
/// allowed to surface must round-trip through this mapper. Kills
/// `delete match arm "<ALG>"` for each algorithm: with the arm gone,
/// `key_algorithm_to_algorithm` falls through to `_ => None`.
#[test]
fn key_algorithm_to_algorithm_covers_every_jws_alg() {
    let cases: &[(KeyAlgorithm, Algorithm)] = &[
        (KeyAlgorithm::RS256, Algorithm::RS256),
        (KeyAlgorithm::RS384, Algorithm::RS384),
        (KeyAlgorithm::RS512, Algorithm::RS512),
        (KeyAlgorithm::ES256, Algorithm::ES256),
        (KeyAlgorithm::ES384, Algorithm::ES384),
        (KeyAlgorithm::EdDSA, Algorithm::EdDSA),
        (KeyAlgorithm::PS256, Algorithm::PS256),
        (KeyAlgorithm::PS384, Algorithm::PS384),
        (KeyAlgorithm::PS512, Algorithm::PS512),
        (KeyAlgorithm::HS256, Algorithm::HS256),
        (KeyAlgorithm::HS384, Algorithm::HS384),
        (KeyAlgorithm::HS512, Algorithm::HS512),
    ];
    for (ka, expected) in cases {
        let got = key_algorithm_to_algorithm(*ka);
        assert_eq!(
            got,
            Some(*expected),
            "key_algorithm_to_algorithm({ka:?}) must yield Some({expected:?})",
        );
    }
}

/// `SecureRngAdapter` must forward every RngCore call to its
/// underlying [`axess_rng::SecureRng`]. Kills `next_u32 -> 0/1`,
/// `next_u64 -> 0/1`, `try_fill_bytes -> Ok(())` body replacements
/// by comparing the adapter's output against a separately-seeded
/// reference `MockRng` driven through the same byte counts.
#[test]
fn secure_rng_adapter_forwards_to_inner_rng() {
    use axess_rng::SecureRng;
    use axess_rng::testing::MockRng;

    const SEED: u64 = 0xA110_CA7E_5EED_F00Du64;

    // Reference: feed bytes through MockRng the same way the adapter
    // does and compute expected outputs.
    let reference = MockRng::new(SEED);
    let mut buf = [0u8; 4];
    reference.fill_bytes(&mut buf);
    let expected_u32 = u32::from_le_bytes(buf);
    let mut buf = [0u8; 8];
    reference.fill_bytes(&mut buf);
    let expected_u64 = u64::from_le_bytes(buf);
    let mut expected_fill = [0u8; 32];
    reference.fill_bytes(&mut expected_fill);
    let mut expected_try = [0u8; 32];
    reference.fill_bytes(&mut expected_try);

    // Adapter under test: driven in the same byte order against an
    // identically-seeded MockRng.
    let inner = MockRng::new(SEED);
    let mut adapter = SecureRngAdapter(&inner as &dyn SecureRng);

    let got_u32 = adapter.next_u32();
    assert_eq!(
        got_u32, expected_u32,
        "next_u32 must forward to inner SecureRng (kills `-> 0` and `-> 1`)",
    );

    let got_u64 = adapter.next_u64();
    assert_eq!(
        got_u64, expected_u64,
        "next_u64 must forward to inner SecureRng (kills `-> 0` and `-> 1`)",
    );

    let mut fill = [0u8; 32];
    adapter.fill_bytes(&mut fill);
    assert_eq!(
        fill, expected_fill,
        "fill_bytes must forward to inner SecureRng",
    );

    let mut tried = [0u8; 32];
    adapter
        .try_fill_bytes(&mut tried)
        .expect("try_fill_bytes is infallible against MockRng");
    assert_eq!(
        tried, expected_try,
        "try_fill_bytes must forward to inner SecureRng (kills `-> Ok(())`)",
    );
}
