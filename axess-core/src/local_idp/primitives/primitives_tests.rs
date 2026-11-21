use super::*;
use axess_clock::testing::Shift;
use jsonwebtoken::jwk::KeyAlgorithm;

/// An unsupported algorithm is an error from the EC constructors, which
/// return a `Result`; none panics. The RSA constructors' half is with them.
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
}

/// A custom claim never overrides a registered one: a custom `exp` would
/// outlive the max-TTL check, a custom `sub` or `aud` would swap the
/// subject or audience under the signature.
#[test]
fn custom_claims_cannot_override_registered_claims() {
    let exp = axess_clock::testing::MockClock::reference_time()
        .plus(axess_clock::SignedDuration::minutes(5));
    let claims = MintClaims::new("worker-1", exp)
        .with_custom_claim("exp", exp.unix_seconds() + 10 * 365 * 24 * 3600)
        .with_custom_claim("sub", "mallory")
        .with_custom_claim("aud", "other-service")
        .with_custom_claim("iss", "https://evil.example")
        .with_custom_claim("jti", "forged")
        .with_custom_claim("dept", "treasury");
    let v = build_claims_json("https://issuer.example", &claims);
    assert_eq!(v["exp"], serde_json::json!(exp.unix_seconds()));
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
    let now = axess_clock::testing::MockClock::reference_time();
    let claims = MintClaims::new(
        "worker-1",
        now.plus(axess_clock::SignedDuration::days(3650)),
    )
    .with_issued_at(now.plus(axess_clock::SignedDuration::days(3649)));
    assert!(
        enforce_max_ttl_fallible(&claims, std::time::Duration::from_hours(24), now).is_err(),
        "a ten-year token must exceed a one-day cap whatever its iat says"
    );
}

/// A cap of no time, a token that has already expired, and one
/// that becomes valid after it expires are refused, not minted.
#[test]
fn max_ttl_refuses_unusable_caps_and_claim_sets() {
    use crate::local_idp::LifetimeFault::{AlreadyExpired, NotBeforeAfterExpiry, ZeroCap};
    use axess_clock::SignedDuration;
    let now = axess_clock::testing::MockClock::reference_time();
    let ok = MintClaims::new("worker-1", now.plus(SignedDuration::minutes(5)));
    assert!(enforce_max_ttl_fallible(&ok, std::time::Duration::from_hours(1), now).is_ok());
    {
        let cap = std::time::Duration::ZERO;
        let long_gone = MintClaims::new("worker-1", now.minus(SignedDuration::hours(1)));
        assert_eq!(
            enforce_max_ttl_fallible(&long_gone, cap, now),
            Err(TtlRefusal::Invalid(ZeroCap)),
            "a cap of {cap:?} must not admit a token that expired an hour ago"
        );
        assert_eq!(
            enforce_max_ttl_fallible(&ok, cap, now),
            Err(TtlRefusal::Invalid(ZeroCap)),
            "a cap of {cap:?} admits nothing"
        );
        assert_eq!(ZeroCap.to_string(), "the max-TTL cap is no time");
    }
    let expired = MintClaims::new("worker-1", now);
    assert_eq!(
        enforce_max_ttl_fallible(&expired, std::time::Duration::from_hours(1), now),
        Err(TtlRefusal::Invalid(AlreadyExpired)),
        "exp at now is already expired"
    );
    let backwards = MintClaims::new("worker-1", now.plus(SignedDuration::minutes(5)))
        .with_not_before(now.plus(SignedDuration::minutes(10)));
    assert_eq!(
        enforce_max_ttl_fallible(&backwards, std::time::Duration::from_hours(1), now),
        Err(TtlRefusal::Invalid(NotBeforeAfterExpiry)),
        "nbf after exp is a token that is never valid"
    );
    assert!(matches!(
        enforce_max_ttl_fallible(&ok, std::time::Duration::from_mins(1), now),
        Err(TtlRefusal::Exceeds { .. })
    ));
}

/// Signing reuses one `EncodingKey`: a new one for each mint would leave
/// an unzeroized copy of the private key per mint.
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

/// The `rand_core` 0.10 traits `p256` generates keys through forward to
/// the inner [`axess_rng::SecureRng`] too: each call returns the bytes an
/// identically seeded `MockRng` hands out in the same order, so a body that
/// answered a constant or filled nothing fails here.
#[test]
fn secure_rng_adapter_forwards_the_rand_core_0_10_calls() {
    use axess_rng::SecureRng;
    use axess_rng::testing::MockRng;
    use p256::elliptic_curve::rand_core::TryRng;

    const SEED: u64 = 0x0DEC_0DE5_5EED_BEEFu64;

    let reference = MockRng::new(SEED);
    let mut buf = [0u8; 4];
    reference.fill_bytes(&mut buf);
    let expected_u32 = u32::from_le_bytes(buf);
    let mut buf = [0u8; 8];
    reference.fill_bytes(&mut buf);
    let expected_u64 = u64::from_le_bytes(buf);
    let mut expected_fill = [0u8; 32];
    reference.fill_bytes(&mut expected_fill);

    let inner = MockRng::new(SEED);
    let mut adapter = SecureRngAdapter(&inner as &dyn SecureRng);
    assert_eq!(TryRng::try_next_u32(&mut adapter), Ok(expected_u32));
    assert_eq!(TryRng::try_next_u64(&mut adapter), Ok(expected_u64));
    let mut fill = [0u8; 32];
    assert_eq!(TryRng::try_fill_bytes(&mut adapter, &mut fill), Ok(()));
    assert_eq!(fill, expected_fill);
}

/// ES256 keygen is a pure function of the injected generator: two keys from
/// identically seeded generators are the same key, and another seed gives
/// another key.
#[test]
fn es256_keygen_follows_the_injected_rng() {
    use axess_rng::testing::MockRng;

    let a = LocalIdpSigningKey::generate_es256_with_rng(&MockRng::new(7));
    let b = LocalIdpSigningKey::generate_es256_with_rng(&MockRng::new(7));
    let c = LocalIdpSigningKey::generate_es256_with_rng(&MockRng::new(8));
    assert_eq!(a.key_id(), b.key_id());
    assert_ne!(a.key_id(), c.key_id());
}

/// The private key's DER bytes are held in a `Zeroizing` buffer, which
/// wipes itself when the key is dropped, whichever kind of key it is. The
/// key has no `Drop` of its own to keep in step with its bytes: taking the
/// buffer out of it compiles only while it has none.
#[test]
fn the_private_key_bytes_are_held_in_a_zeroizing_buffer() {
    let key = LocalIdpSigningKey::generate_es256_with_rng(&axess_rng::testing::MockRng::new(7));
    let LocalIdpSigningKey { private_der, .. } = key;
    let held: Zeroizing<Vec<u8>> = private_der;
    assert!(!held.is_empty());
}

/// The registered times of a minted token are whole Unix seconds, the
/// fraction dropped and rounded down before the epoch too.
#[test]
fn the_registered_times_are_whole_unix_seconds() {
    let stamp = |text: &str| {
        let row = format!(r#"{{"admin":"01010101-0101-0101-0101-010101010101","since":"{text}"}}"#);
        serde_json::from_str::<crate::session::data::Impersonation>(&row)
            .expect("reads")
            .since
    };
    let claims = MintClaims::new("svc", stamp("2026-01-01T01:00:00.999Z"))
        .with_not_before(stamp("1969-12-31T23:59:59.5Z"))
        .with_issued_at(axess_clock::testing::MockClock::reference_time());
    let json = build_claims_json("https://idp.example.org", &claims);
    assert_eq!(json["exp"], serde_json::json!(1_767_229_200));
    assert_eq!(json["nbf"], serde_json::json!(-1));
    assert_eq!(json["iat"], serde_json::json!(1_767_225_600));
}
