//! The verifier a recipe test checks a token with. Every user of this
//! module uses it.

use std::sync::{Arc, RwLock};

use axess_clock::testing::MockClock;
use axess_factors::jwt::verifier::JwtVerifier;
use jsonwebtoken::jwk::JwkSet;

/// Build a `JwtVerifier` pinning `iss` + `aud` against the supplied
/// JWKS, judging `iat`/`exp`/`nbf` on `clock`, the test's [`MockClock`]
/// (set to the reference instant the tokens are stamped at), so the test
/// runs deterministically regardless of wall-clock time (e.g. on a build
/// agent in a year where the hardcoded `now`/`exp` would otherwise be
/// expired).
pub fn build_verifier(
    clock: &MockClock,
    jwks: JwkSet,
    issuer: &str,
    audience: &str,
) -> Arc<JwtVerifier> {
    Arc::new(
        JwtVerifier::new(Arc::new(RwLock::new(jwks)))
            .with_issuer(issuer)
            .with_audience(audience)
            .with_clock(Arc::new(clock.clone())),
    )
}
