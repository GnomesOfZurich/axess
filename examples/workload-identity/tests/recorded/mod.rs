//! The recorded tokens under `tests/fixtures/`. Every user of this module
//! loads one and reads each field of it.

use jsonwebtoken::jwk::JwkSet;

/// A recorded token with the JWKS that verifies it and the document its claim
/// set was taken from. See `tests/fixtures/*.json`, which
/// `examples/regenerate_fixtures.rs` writes.
#[derive(Debug, serde::Deserialize)]
pub struct Fixture {
    /// The published document the claim set follows.
    pub source: String,
    /// The date the fixture was recorded.
    pub recorded: String,
    /// `real` for a token captured from a live issuer, `constructed` for one
    /// built from the documented claim set and signed with a test key.
    pub kind: String,
    pub issuer: String,
    pub audience: String,
    pub jwks: JwkSet,
    pub token: String,
}

/// Load `tests/fixtures/<name>.json`.
pub fn fixture(name: &str) -> Fixture {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}
