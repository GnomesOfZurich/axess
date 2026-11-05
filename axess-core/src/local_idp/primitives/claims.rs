//! The claim set a mint signs: the [`MintClaims`] builder and its rendering
//! to the JWT body.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── MintClaims ───────────────────────────────────────────────────────────────

/// Builder for the claim set passed to
/// [`LocalIdpFixture::mint`](crate::testing::local_idp::LocalIdpFixture::mint).
///
/// The fixture sets `iss` automatically from its configured issuer.
/// All other claims (sub, aud, exp, nbf, iat, jti, custom) are
/// supplied by the caller via this builder.
#[derive(Debug, Clone)]
pub struct MintClaims {
    /// `sub`: required.
    pub subject: String,
    /// `aud`: empty `Vec` skips the claim; single-element renders
    /// as a string, multi-element as an array (per RFC 7519 §4.1.3).
    pub audience: Vec<String>,
    /// `exp`: required to keep tokens auto-expiring in test runs.
    pub expires_at: DateTime<Utc>,
    /// `nbf`: optional.
    pub not_before: Option<DateTime<Utc>>,
    /// `iat`: optional. Recommended; some verifiers reject tokens
    /// without `iat`. Written as given, never set or clamped by the IdP:
    /// the IdP's `max_ttl` cap measures the lifetime from its own clock,
    /// so a backdated `iat` does not stretch it, and a verifier that bounds
    /// the age of a token (as the back-channel logout handler bounds the
    /// token's `iat`) reads whatever was set here.
    pub issued_at: Option<DateTime<Utc>>,
    /// `jti`: optional. Required when feeding a
    /// [`axess_factors::jwt::verifier::JwtVerifier`] configured with a
    /// `JtiReplayStore` (replay protection).
    pub jwt_id: Option<String>,
    /// Extra claims merged into the JSON object alongside the
    /// standard fields. A key naming a registered claim (`iss`, `sub`,
    /// `aud`, `exp`, `nbf`, `iat`, `jti`) is ignored: those are set from
    /// the typed fields only, so a custom entry can never change the
    /// subject, audience, lifetime or issuer under the signature.
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl MintClaims {
    /// Build with the two required claims.
    pub fn new(subject: impl Into<String>, expires_at: DateTime<Utc>) -> Self {
        Self {
            subject: subject.into(),
            audience: Vec::new(),
            expires_at,
            not_before: None,
            issued_at: None,
            jwt_id: None,
            custom: serde_json::Map::new(),
        }
    }

    /// Set a single `aud` value.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = vec![audience.into()];
        self
    }

    /// Set multiple `aud` values (renders as a JSON array).
    pub fn with_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audience = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Set `nbf`.
    pub fn with_not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.not_before = Some(nbf);
        self
    }

    /// Set `iat`. See [`issued_at`](Self::issued_at): the value is written
    /// as given.
    pub fn with_issued_at(mut self, iat: DateTime<Utc>) -> Self {
        self.issued_at = Some(iat);
        self
    }

    /// Set `jti`.
    pub fn with_jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jwt_id = Some(jti.into());
        self
    }

    /// Add a single custom claim. Replaces any existing custom value for
    /// the same key. A registered claim name is ignored when the token is
    /// built (see [`custom`](Self::custom)).
    pub fn with_custom_claim(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StandardClaimsView {
    iss: String,
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

/// The claims RFC 7519 §4.1 registers; set from `MintClaims`' typed fields
/// only, never from its custom map.
const REGISTERED_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

pub(crate) fn build_claims_json(issuer: &str, claims: &MintClaims) -> serde_json::Value {
    let aud_value = match claims.audience.as_slice() {
        [] => None,
        [single] => Some(serde_json::Value::String(single.clone())),
        many => Some(serde_json::Value::Array(
            many.iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        )),
    };

    let view = StandardClaimsView {
        iss: issuer.to_string(),
        sub: claims.subject.clone(),
        exp: claims.expires_at.timestamp(),
        aud: aud_value,
        nbf: claims.not_before.map(|t| t.timestamp()),
        iat: claims.issued_at.map(|t| t.timestamp()),
        jti: claims.jwt_id.clone(),
    };

    let mut value = serde_json::to_value(view).expect("StandardClaimsView serialises");
    if let serde_json::Value::Object(ref mut map) = value {
        for (k, v) in &claims.custom {
            // The registered claims are the typed fields' to state. A custom
            // `exp` would outlive the max-TTL check (which reads the typed
            // `expires_at`), a custom `sub` or `aud` would swap the subject
            // or audience under the signature, and a custom `iss` would
            // break the JWKS routing; none is honoured.
            if REGISTERED_CLAIMS.contains(&k.as_str()) {
                continue;
            }
            map.insert(k.clone(), v.clone());
        }
    }
    value
}
