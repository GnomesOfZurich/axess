//! `provider_tests`: the first `jsonwebtoken` operation of a process, made
//! through each way into it, settles the crypto provider before it signs or
//! verifies.
//!
//! The first operation in a process fixes the provider for the rest of it,
//! so each case runs in a process of its own: the test re-runs this test
//! binary with only itself selected and a variable naming it, and the child
//! runs the case as the first thing the process does. With both backends
//! compiled in, an operation that reached `jsonwebtoken` before
//! [`ensure_crypto_provider`](super::ensure_crypto_provider) panics there.
//! After the case the child checks that the provider in place is the one
//! `ensure_crypto_provider` installs.
//!
//! A case that verifies gets what it checks from the parent, which makes it
//! through the same boundary and hands it over in a variable, so that the
//! verification is the child's first operation.

use std::process::Command;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;

use super::validation::{ALLOWED_ALGORITHMS, ValidationConfig, verify_jwt};

/// The variable that tells a re-run of the test binary which case it is.
const CASE: &str = "AXESS_JWT_PROVIDER_CASE";

/// The variable that carries a case's input from the parent to the child.
const INPUT: &str = "AXESS_JWT_PROVIDER_INPUT";

/// Run `case` as the first `jsonwebtoken` operation of a fresh process, and
/// require that afterwards the provider in place is the one
/// `ensure_crypto_provider` installs.
///
/// `module` is the caller's `module_path!()` and `test` the name of the
/// calling test, which together name it to the test harness. The parent
/// makes `input` and re-runs the binary with only that test selected; the
/// child hands the input to `case`.
pub(crate) fn first_in_process(
    module: &str,
    test: &str,
    input: impl FnOnce() -> String,
    case: impl FnOnce(&str),
) {
    // The harness names a test by its module path without the crate's name.
    let module = module.split_once("::").map_or(module, |(_, rest)| rest);
    let name = format!("{module}::{test}");
    if std::env::var(CASE).as_deref() == Ok(name.as_str()) {
        let input = std::env::var(INPUT).expect("the parent hands the input over");
        case(&input);
        assert_provider_is_the_one_ensure_installs();
        return;
    }
    let exe = std::env::current_exe().expect("the test binary's path");
    let output = Command::new(exe)
        .args([name.as_str(), "--exact", "--test-threads=1", "--nocapture"])
        .env(CASE, &name)
        .env(INPUT, input())
        .output()
        .expect("the test binary re-runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{name} failed in its own process:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The child must have run the case, not filtered it out.
    assert!(stdout.contains("1 passed"), "{name} did not run:\n{stdout}");
}

/// Where `jwt-aws-lc` is on, axess's own install of aws-lc took, which it
/// can only have done before anything else fixed a provider; and on every
/// build a provider is in place, so no later install takes.
fn assert_provider_is_the_one_ensure_installs() {
    #[cfg(feature = "jwt-aws-lc")]
    assert!(
        super::axess_installed_aws_lc(),
        "the provider in place is not the aws-lc one axess installs"
    );
    #[cfg(feature = "jwt-aws-lc")]
    let later = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    #[cfg(not(feature = "jwt-aws-lc"))]
    let later = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    assert!(later.is_err(), "no provider was in place after the case");
}

/// The HMAC key of the boundary cases, which need no key pair.
const SECRET: &[u8] = b"the provider tests' shared secret, used nowhere else";

/// What the `sign` and `verify` cases sign.
const MESSAGE: &[u8] = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3b3JrZXItMSJ9";

/// A P-256 key from `openssl ecparam -name prime256v1 -genkey | openssl
/// pkcs8 -topk8 -nocrypt`, made for these tests only, and the coordinates
/// of its public half.
const EC_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghfFK0mr/Q3XdmEKu
sS5Wtl8eLW/2FwHY/+NC/X1G1eihRANCAARjXzcuJVuR4sApi31JCn8yXHN41Cny
ILdIUfJpVaviFL4qYW7Y2DISAYy3ovm8/qy4eB3oWGjS0M4Y4iC+jcC5
-----END PRIVATE KEY-----
";
const EC_X: &str = "Y183LiVbkeLAKYt9SQp_MlxzeNQp8iC3SFHyaVWr4hQ";
const EC_Y: &str = "viphbtjYMhIBjLei-bz-rLh4HehYaNLQzhjiIL6NwLk";
const EC_KID: &str = "provider-test";

const ISSUER: &str = "https://idp.example.org";
const AUDIENCE: &str = "example-api";

fn hs256_token() -> String {
    super::encode(
        &Header::new(Algorithm::HS256),
        &json!({ "sub": "worker-1" }),
        &EncodingKey::from_secret(SECRET),
    )
    .expect("an HMAC key signs")
}

/// HS256 with no claim required, for a token that carries only `sub`.
fn hs256_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation
}

fn hs256_signature() -> String {
    super::sign(MESSAGE, &EncodingKey::from_secret(SECRET), Algorithm::HS256)
        .expect("an HMAC key signs")
}

#[test]
fn encode_settles_the_provider_before_the_first_signature() {
    first_in_process(
        module_path!(),
        "encode_settles_the_provider_before_the_first_signature",
        String::new,
        |_| {
            let token = hs256_token();
            let claims = super::decode::<serde_json::Value>(
                &token,
                &DecodingKey::from_secret(SECRET),
                &hs256_validation(),
            )
            .expect("the token verifies");
            assert_eq!(claims.claims["sub"], "worker-1");
        },
    );
}

#[test]
fn decode_settles_the_provider_before_the_first_verification() {
    first_in_process(
        module_path!(),
        "decode_settles_the_provider_before_the_first_verification",
        hs256_token,
        |token| {
            let claims = super::decode::<serde_json::Value>(
                token,
                &DecodingKey::from_secret(SECRET),
                &hs256_validation(),
            )
            .expect("the token verifies");
            assert_eq!(claims.claims["sub"], "worker-1");
        },
    );
}

#[test]
fn sign_settles_the_provider_before_the_first_signature() {
    first_in_process(
        module_path!(),
        "sign_settles_the_provider_before_the_first_signature",
        String::new,
        |_| {
            let signature = hs256_signature();
            let holds = super::verify(
                &signature,
                MESSAGE,
                &DecodingKey::from_secret(SECRET),
                Algorithm::HS256,
            );
            assert_eq!(holds.ok(), Some(true));
        },
    );
}

#[test]
fn verify_settles_the_provider_before_the_first_verification() {
    first_in_process(
        module_path!(),
        "verify_settles_the_provider_before_the_first_verification",
        hs256_signature,
        |signature| {
            let holds = super::verify(
                signature,
                MESSAGE,
                &DecodingKey::from_secret(SECRET),
                Algorithm::HS256,
            );
            assert_eq!(holds.ok(), Some(true));
            let other = super::verify(
                signature,
                b"another message",
                &DecodingKey::from_secret(SECRET),
                Algorithm::HS256,
            );
            assert_eq!(other.ok(), Some(false));
        },
    );
}

/// The token `verify_jwt` checks: ES256 under the fixed key, valid at the
/// reference time of `MockClock`.
fn es256_token() -> String {
    let now = axess_clock::testing::MockClock::reference_time().unix_seconds();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(EC_KID.to_string());
    // DER rather than PEM: `EncodingKey::from_ec_pem` sits behind
    // `jsonwebtoken`'s `use_pem` feature, which this crate leaves off.
    use base64::Engine as _;
    let body: String = EC_PKCS8
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("the PEM body is base64");
    let key = EncodingKey::from_ec_der(&der);
    super::encode(
        &header,
        &json!({
            "iss": ISSUER,
            "sub": "worker-1",
            "aud": AUDIENCE,
            "exp": now + 300,
            "iat": now,
        }),
        &key,
    )
    .expect("an EC key signs with ES256")
}

/// The verification every JWT path of the crate takes: OAuth logout and
/// JARM, bearer tokens, `JwtVerifier` and the workload resolvers.
#[test]
fn verify_jwt_settles_the_provider_before_the_first_verification() {
    first_in_process(
        module_path!(),
        "verify_jwt_settles_the_provider_before_the_first_verification",
        es256_token,
        |token| {
            let jwks: JwkSet = serde_json::from_value(json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": EC_X,
                    "y": EC_Y,
                    "kid": EC_KID,
                    "use": "sig",
                    "alg": "ES256",
                }]
            }))
            .expect("a key set");
            let mut config = ValidationConfig::new();
            config.issuer = Some(ISSUER.to_string());
            config.audience = Some(AUDIENCE.to_string());
            let claims = verify_jwt(
                token,
                &jwks,
                &config,
                ALLOWED_ALGORITHMS,
                &axess_clock::testing::MockClock::at_reference(),
            )
            .expect("the token verifies");
            assert_eq!(claims["sub"], "worker-1");
        },
    );
}

/// `ClientAssertionSigner::new` signs one assertion to try its key, so that
/// is the first operation, and `mint` the second.
#[cfg(any(feature = "oauth", feature = "outbound-oauth"))]
#[test]
fn a_client_assertion_signer_settles_the_provider_before_it_signs() {
    use crate::client_assertion::ClientAssertionSigner;
    first_in_process(
        module_path!(),
        "a_client_assertion_signer_settles_the_provider_before_it_signs",
        String::new,
        |_| {
            let signer = ClientAssertionSigner::from_pem(AUDIENCE, EC_PKCS8, Algorithm::ES256)
                .expect("an EC signer");
            let assertion = signer
                .mint(
                    "https://idp.example.org/token",
                    &axess_clock::testing::MockClock::at_reference(),
                    &axess_rng::testing::MockRng::new(7),
                )
                .expect("an assertion");
            assert_eq!(assertion.split('.').count(), 3);
        },
    );
}

#[cfg(feature = "key-proof")]
mod key_proofs {
    use super::first_in_process;
    use crate::key_proof::testing::SoftwareKey;
    use crate::key_proof::{
        KeyProofRequest, KeyProofShape, ProofKey, ProofTarget, verify_key_proof,
    };

    const TARGET: ProofTarget<'static> = ProofTarget {
        method: "POST",
        url: "https://app.example.org/axess/device-key",
    };
    const CHALLENGE: &str = "challenge-0001";

    fn key() -> SoftwareKey {
        SoftwareKey::from_seed([7; 32])
    }

    fn proof() -> String {
        key().sign(KeyProofShape::App, TARGET, CHALLENGE, true)
    }

    fn verifies(jws: &str) {
        let verified = verify_key_proof(KeyProofRequest {
            jws,
            shape: KeyProofShape::App,
            target: TARGET,
            challenge: CHALLENGE,
            key: ProofKey::Embedded,
        })
        .expect("the proof verifies");
        assert_eq!(verified.key, key().public());
    }

    /// The device-key verification of registrations, request proofs and
    /// the session's device keys.
    #[test]
    fn a_key_proof_verification_settles_the_provider_first() {
        first_in_process(
            module_path!(),
            "a_key_proof_verification_settles_the_provider_first",
            proof,
            verifies,
        );
    }

    /// The software key adopters' tests sign proofs with.
    #[test]
    fn a_software_key_settles_the_provider_before_it_signs() {
        first_in_process(
            module_path!(),
            "a_software_key_settles_the_provider_before_it_signs",
            String::new,
            |_| verifies(&proof()),
        );
    }
}
