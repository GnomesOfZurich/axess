//! The local IdP settles the `jsonwebtoken` crypto provider before its first
//! signature in a process.
//!
//! The first `jsonwebtoken` operation in a process fixes the provider for
//! the rest of it, and with both backends compiled in, one that comes before
//! any install fixes the fallback that panics. So each case runs in a
//! process of its own: the test re-runs this binary with only itself
//! selected and a variable naming it, and the child mints as the first
//! thing the process does. Nothing in the child installs a provider but
//! axess, so a mint that signs shows axess settled one first; which one it
//! settles is `axess_factors::jwt::ensure_crypto_provider`'s, held there by
//! the crate's own first-operation tests.

#![cfg(feature = "local-idp")]

use std::process::Command;
use std::sync::Arc;

use axess_clock::testing::MockClock;
use axess_clock::{Clock, SignedDuration};
use axess_core::local_idp::{LocalIdp, LocalIdpSigningKey, MemoryLocalIdpKeyStore, MintClaims};
use axess_factors::jwt::validation::{ValidationConfig, verify_jwt};
use axess_rng::testing::MockRng;
use jsonwebtoken::Algorithm;
use jsonwebtoken::jwk::JwkSet;

/// The variable that tells a re-run of this binary which case it is.
const CASE: &str = "AXESS_LOCAL_IDP_PROVIDER_CASE";

const ISSUER: &str = "https://idp.example.org";
const AUDIENCE: &str = "example-api";

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

/// Claims valid at the reference time of `MockClock`.
fn claims() -> MintClaims {
    let now = MockClock::reference_time();
    let expires_at = now
        .checked_add(SignedDuration::minutes(5))
        .expect("inside the range");
    MintClaims::new("worker-1", expires_at)
        .with_audience(AUDIENCE)
        .with_issued_at(now)
}

/// `token` verifies under `jwks` at `clock`'s time, and a provider is in
/// place afterwards, so no later install takes.
fn verifies(token: &str, jwks: &JwkSet, clock: &dyn Clock) {
    let mut config = ValidationConfig::new();
    config.issuer = Some(ISSUER.to_string());
    config.audience = Some(AUDIENCE.to_string());
    let claims =
        verify_jwt(token, jwks, &config, &[Algorithm::ES256], clock).expect("the token verifies");
    assert_eq!(claims["sub"], "worker-1");
    #[cfg(feature = "jwt-aws-lc")]
    let later = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    #[cfg(not(feature = "jwt-aws-lc"))]
    let later = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    assert!(later.is_err(), "no provider was in place after the mint");
}

#[test]
fn local_idp_settles_the_provider_before_its_first_signature() {
    in_own_process(
        "local_idp_settles_the_provider_before_its_first_signature",
        || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a runtime");
            runtime.block_on(async {
                let clock = MockClock::at_reference();
                let key = LocalIdpSigningKey::generate_es256_with_rng(&MockRng::new(7));
                let idp =
                    LocalIdp::from_key_store(ISSUER, MemoryLocalIdpKeyStore::with_current(key))
                        .await
                        .expect("the keys load")
                        .with_clock(Arc::new(clock.clone()));
                let token = idp.mint(&claims()).await.expect("a token");
                verifies(&token, &idp.jwks().await, &clock);
            });
        },
    );
}

#[cfg(feature = "testing")]
#[test]
fn local_idp_fixture_settles_the_provider_before_its_first_signature() {
    use axess_core::testing::local_idp::LocalIdpFixture;
    in_own_process(
        "local_idp_fixture_settles_the_provider_before_its_first_signature",
        || {
            let clock = MockClock::at_reference();
            let key = LocalIdpSigningKey::generate_es256_with_rng(&MockRng::new(7));
            let fixture = LocalIdpFixture::with_signing_key(ISSUER, key).with_clock(clock.clone());
            let token = fixture.mint(&claims());
            verifies(&token, fixture.jwks(), &clock);
        },
    );
}
