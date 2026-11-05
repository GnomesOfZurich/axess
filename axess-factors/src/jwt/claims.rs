//! Pure claim-level validation helpers for JWT payloads.
//!
//! These are provider-agnostic checks that operate on a decoded JWT
//! payload (`serde_json::Value`). Signature verification is handled
//! separately in [`super::validation`].

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Maximum JWT size (8 KiB). Real OIDC tokens are typically well under
/// 2 KiB; the larger limit allows headroom for unusual claim payloads
/// while still preventing memory DoS via crafted multi-megabyte JWTs.
pub const MAX_JWT_BYTES: usize = 8 * 1024;

/// Maximum age of a token's `iat` claim (5 minutes).
pub const MAX_IAT_AGE_SECS: i64 = 300;

/// Decode the payload (second segment) of a JWT without signature verification.
///
/// Returns the parsed JSON payload. This is used for claim inspection only;
/// the caller is responsible for verifying the signature separately (e.g. via
/// the provider's JWKS) before trusting any fields.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    if token.len() > MAX_JWT_BYTES {
        return Err(format!(
            "JWT too large ({} bytes, max {MAX_JWT_BYTES})",
            token.len()
        ));
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("expected 3 JWT segments, got {}", parts.len()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("base64 decode failed: {e}"))?;

    serde_json::from_slice(&payload_bytes).map_err(|e| format!("JSON parse failed: {e}"))
}

/// Check that the JWT `aud` claim contains the expected client ID. Accepts
/// either a single-string `aud` or an array of strings (both RFC 7519 forms).
pub fn aud_contains(payload: &serde_json::Value, client_id: &str) -> bool {
    match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    }
}

/// When `aud` is an array, OIDC Core §2 requires the `azp`
/// (authorized party) claim to be present and equal to the relying
/// party's client_id. Without this check, a logout token addressed to
/// `["this-client", "other-client"]` with `azp: "other-client"` would be
/// accepted as if it were intended for us, letting a colluding client
/// log our users out at will (or, in adjacent flows, escalate). Returns
/// `true` when:
///
/// * `azp` is absent and `aud` is a single value, OR
/// * `azp == client_id`.
///
/// Returns `false` (reject) when `azp` is present and is not the client,
/// whatever `aud` holds, or when `aud` is an array with several values and
/// `azp` is missing.
pub fn azp_satisfied(payload: &serde_json::Value, client_id: &str) -> bool {
    // A present `azp` must be the expected client whatever `aud` holds: a
    // token authorised for another party is not ours even when it names
    // only us in `aud`. A non-string `azp` is malformed and refused.
    if let Some(azp) = payload.get("azp")
        && azp.as_str() != Some(client_id)
    {
        return false;
    }
    match payload.get("aud") {
        // Multi-valued `aud` requires `azp` to be present (and, by the
        // check above, equal to client_id).
        Some(serde_json::Value::Array(arr)) if arr.len() > 1 => payload.get("azp").is_some(),
        // Single-valued `aud`: `azp` may be absent, already pinned by the
        // `aud` check.
        _ => true,
    }
}

/// Outcome of `iat` (issued-at) recency validation.
pub enum IatCheck {
    /// The `iat` claim is within tolerance: pre-dated by at most 60 s
    /// (clock skew) and no older than [`MAX_IAT_AGE_SECS`].
    Ok,
    /// Missing or non-integer `iat` claim: reject.
    Missing,
    /// Outside the acceptable window: too old or too far in the future.
    OutOfRange {
        /// The token's `iat` claim (Unix seconds).
        iat: i64,
        /// The reference wall-clock time used for comparison (Unix seconds).
        now: i64,
    },
}

/// Check the token's `iat` claim against the supplied wall-clock time.
/// Returns [`IatCheck`] so the caller can log the specific failure mode.
pub fn check_iat(payload: &serde_json::Value, now: i64) -> IatCheck {
    let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) else {
        return IatCheck::Missing;
    };
    if crate::iat_window::iat_within(iat, now, 60, MAX_IAT_AGE_SECS) {
        IatCheck::Ok
    } else {
        IatCheck::OutOfRange { iat, now }
    }
}

#[cfg(test)]
mod jwt_claims_tests;
