//! Shared helpers for the production `LocalIdp` tests.
//!
//! `CustomClaims` is the empty claims payload used when round-tripping
//! tokens through `JwtVerifier`; it lives here so both the foundation
//! tests and the rotation tests can reuse it.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct CustomClaims {}
