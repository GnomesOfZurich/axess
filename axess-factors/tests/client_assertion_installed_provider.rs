//! An RSA client assertion signs only where the `jsonwebtoken` crypto
//! provider in place is the aws-lc one axess installed, or where
//! `client-assertion-rsa` chose the pure-Rust signature.
//!
//! A build with both backends compiled may have RustCrypto's provider in
//! place, installed by the application before axess installed aws-lc, and
//! that one signs RSA in `rsa` 0.9 (RUSTSEC-2023-0071). The provider is a
//! process-wide setting fixed by the first install, so each case here runs
//! in a process of its own: the test re-runs this binary with only itself
//! selected and a variable naming it, and the child runs the case as the
//! first thing the process does.

#![cfg(all(
    feature = "jwt-aws-lc",
    feature = "jwt-rust-crypto",
    any(feature = "oauth", feature = "outbound-oauth")
))]

use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_factors::client_assertion::ClientAssertionSigner;
#[cfg(not(feature = "client-assertion-rsa"))]
use axess_factors::client_assertion::{ClientAssertionError::RsaNotChosen, SignerSpec};
use axess_rng::testing::MockRng;
use jsonwebtoken::Algorithm;
use std::process::Command;

/// The variable that tells a re-run of this binary which case it is.
const CASE: &str = "AXESS_CLIENT_ASSERTION_PROVIDER_CASE";

/// Run `case` in a fresh process: in the parent, re-run this binary with
/// only `name` selected and `CASE` set to it, and require that run to pass;
/// in that child, run `case`.
fn in_own_process(name: &str, case: fn()) {
    if std::env::var(CASE).as_deref() == Ok(name) {
        case();
        return;
    }
    let exe = std::env::current_exe().expect("the test binary's path");
    let output = Command::new(exe)
        .args([name, "--exact", "--test-threads=1", "--nocapture"])
        .env(CASE, name)
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

/// A PKCS#1 RSA private key PEM, made fresh.
fn rsa_pem() -> String {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .expect("rsa key")
        .to_pkcs1_pem(Default::default())
        .expect("pkcs1")
        .to_string()
}

/// A P-256 key from `openssl ecparam -name prime256v1 -genkey | openssl
/// pkcs8 -topk8 -nocrypt`, made for this test only.
#[cfg(not(feature = "client-assertion-rsa"))]
const EC_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaIdz1CBm27c+a2Q
4lwMZOSeBZnbM1KkbBPv4xizy4WhRANCAAQZIaDN9tHlIbqHc9mOKzezhVGVY+CJ
AOvrqvniGAwR3I6EXZI5vT/mB8JRD6e+Ir1nRbrutHGH5kyENsRjhn9P
-----END PRIVATE KEY-----
";

/// Mint one assertion with `signer`, on a fixed clock and seeded RNG.
fn mints(signer: &ClientAssertionSigner) -> bool {
    let clock = MockClock::at(Timestamp::from_unix_seconds(1_700_000_000).expect("time"));
    let rng = MockRng::new(7);
    signer
        .mint("https://idp.example.org/token", &clock, &rng)
        .is_ok()
}

/// The application installs RustCrypto's provider before axess installs
/// its own: without `client-assertion-rsa`, an RSA signer is refused by
/// name through every constructor, and an EC signer still mints.
#[cfg(not(feature = "client-assertion-rsa"))]
#[test]
fn rsa_is_refused_where_the_application_installed_rust_crypto_first() {
    in_own_process(
        "rsa_is_refused_where_the_application_installed_rust_crypto_first",
        || {
            jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
                .install_default()
                .expect("the first install in this process");
            let pem = rsa_pem();
            for algorithm in [Algorithm::RS256, Algorithm::PS256] {
                assert_eq!(
                    ClientAssertionSigner::from_pem("c", &pem, algorithm).err(),
                    Some(RsaNotChosen(algorithm))
                );
                assert_eq!(
                    ClientAssertionSigner::from_spec("c", &pem, &SignerSpec::new(algorithm)).err(),
                    Some(RsaNotChosen(algorithm))
                );
                assert_eq!(
                    ClientAssertionSigner::new(
                        "c",
                        jsonwebtoken::EncodingKey::from_rsa_der(&[]),
                        algorithm
                    )
                    .err(),
                    Some(RsaNotChosen(algorithm))
                );
            }
            let message = RsaNotChosen(Algorithm::RS256).to_string();
            assert!(message.contains("client-assertion-rsa"), "{message}");
            assert!(message.contains("RUSTSEC-2023-0071"), "{message}");
            let ec = ClientAssertionSigner::from_pem("c", EC_PKCS8, Algorithm::ES256)
                .expect("an EC signer");
            assert!(mints(&ec));
        },
    );
}

/// Nothing installed a provider before axess: axess installs aws-lc, and an
/// RSA signer signs there without `client-assertion-rsa`.
#[test]
fn rsa_signs_where_axess_installed_aws_lc() {
    in_own_process("rsa_signs_where_axess_installed_aws_lc", || {
        let pem = rsa_pem();
        for algorithm in [Algorithm::RS256, Algorithm::PS256] {
            let signer =
                ClientAssertionSigner::from_pem("c", &pem, algorithm).expect("an RSA signer");
            assert!(mints(&signer));
        }
    });
}

/// With `client-assertion-rsa` the pure-Rust signature is chosen: an RSA
/// signer signs even where the application installed RustCrypto first.
#[cfg(feature = "client-assertion-rsa")]
#[test]
fn rsa_signs_on_rust_crypto_where_the_build_chose_it() {
    in_own_process("rsa_signs_on_rust_crypto_where_the_build_chose_it", || {
        jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
            .install_default()
            .expect("the first install in this process");
        let pem = rsa_pem();
        let signer =
            ClientAssertionSigner::from_pem("c", &pem, Algorithm::RS256).expect("an RSA signer");
        assert!(mints(&signer));
    });
}
