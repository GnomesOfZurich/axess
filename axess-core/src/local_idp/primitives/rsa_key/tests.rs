//! The RSA constructors of `LocalIdpSigningKey`, and the `rand_core` 0.6
//! half of the RNG bridge they generate keys through.

use super::*;
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

/// An unsupported algorithm is an error from every RSA constructor that
/// returns a `Result`, and from the `try_` generators; none panics.
#[test]
fn unsupported_algorithm_is_an_error_not_a_panic() {
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
