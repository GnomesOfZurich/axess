//! Claim-level validation helpers for OIDC back-channel logout tokens.
//!
//! These are pure, provider-agnostic checks that operate on a decoded JWT
//! payload (`serde_json::Value`). The signature-verification step lives in
//! the back-channel logout handler (`axess_core::federation::backchannel_logout`)
//! because it needs access to the matched provider's JWKS cache.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// The OIDC event URI that must be present in a back-channel logout token.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Maximum age of a logout token's `iat` claim (5 minutes).
pub const MAX_IAT_AGE_SECS: i64 = 300;

/// Maximum logout token size (8 KiB). Real OIDC logout tokens are typically
/// well under 2 KiB; the larger limit allows headroom for unusual claim
/// payloads while still preventing memory DoS via crafted multi-megabyte
/// JWTs aimed at the public logout endpoint.
pub const MAX_LOGOUT_TOKEN_BYTES: usize = 8 * 1024;

/// Decode the payload (second segment) of a JWT without signature verification.
///
/// Returns the parsed JSON payload. This is used for claim inspection only;
/// the caller is responsible for verifying the signature separately (e.g. via
/// the provider's JWKS) before trusting any fields.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    if token.len() > MAX_LOGOUT_TOKEN_BYTES {
        return Err(format!(
            "logout token too large ({} bytes, max {MAX_LOGOUT_TOKEN_BYTES})",
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

/// when `aud` is an array, OIDC Core §2 requires the `azp`
/// (authorized party) claim to be present and equal to the relying
/// party's client_id. Without this check, a logout token addressed to
/// `["this-client", "other-client"]` with `azp: "other-client"` would be
/// accepted as if it were intended for us, letting a colluding client
/// log our users out at will (or, in adjacent flows, escalate). Returns
/// `true` when:
///
/// * `aud` is a single string (no `azp` requirement), OR
/// * `aud` is an array AND `azp == client_id`.
///
/// Returns `false` (reject) when `aud` is an array and `azp` is missing
/// or mismatched.
pub fn azp_satisfied(payload: &serde_json::Value, client_id: &str) -> bool {
    match payload.get("aud") {
        Some(serde_json::Value::Array(arr)) if arr.len() > 1 => {
            payload.get("azp").and_then(|v| v.as_str()) == Some(client_id)
        }
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
        /// The `iat` value from the token.
        iat: i64,
        /// The wall-clock `now` value used for the comparison.
        now: i64,
    },
}

/// Check the logout token's `iat` claim against the supplied wall-clock time.
/// Returns [`IatCheck`] so the caller can log the specific failure mode.
pub fn check_iat(payload: &serde_json::Value, now: i64) -> IatCheck {
    let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) else {
        return IatCheck::Missing;
    };
    let age = now - iat;
    if (-60..=MAX_IAT_AGE_SECS).contains(&age) {
        IatCheck::Ok
    } else {
        IatCheck::OutOfRange { iat, now }
    }
}

/// Check that the JWT `events` object contains the OIDC back-channel logout URI.
pub fn events_contains_logout(payload: &serde_json::Value) -> bool {
    payload
        .get("events")
        .and_then(|v| v.as_object())
        .is_some_and(|m| m.contains_key(BACKCHANNEL_LOGOUT_EVENT))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MAX_LOGOUT_TOKEN_BYTES` is exactly 8192 (8 KiB). Pins the
    /// `8 * 1024` expression against `+` (1032) and `/` (0) mutations;
    /// both would silently change the size cap.
    #[test]
    fn max_logout_token_bytes_is_eight_kib() {
        assert_eq!(
            MAX_LOGOUT_TOKEN_BYTES, 8192,
            "MAX_LOGOUT_TOKEN_BYTES must be 8 * 1024 = 8192"
        );
    }

    /// `decode_jwt_payload` rejects with size error only when strictly
    /// above 8192 bytes. At exactly 8192 the size check passes (we then
    /// fail downstream on parts-split). Pins the `>` operator against
    /// `==`/`>=` mutations. Uses a hardcoded literal rather than
    /// `MAX_LOGOUT_TOKEN_BYTES` so the test discriminates even when the
    /// constant is mutated.
    #[test]
    fn decode_jwt_payload_size_boundary_is_strict_greater_than() {
        let at_cap = "x".repeat(8192);
        let err = decode_jwt_payload(&at_cap).expect_err("non-JWT payload still fails downstream");
        assert!(
            !err.contains("too large"),
            "at exactly 8192 bytes the size guard must pass (got: {err})"
        );

        let over_cap = "x".repeat(8193);
        let err = decode_jwt_payload(&over_cap).expect_err("oversized must reject");
        assert!(
            err.contains("too large"),
            "8193 bytes must trigger the size guard (got: {err})"
        );
    }

    /// `aud_contains` accepts an array `aud` whose elements contain the
    /// client_id. Pins both `delete match arm Array(arr)` and `== → !=`
    /// mutations; without an array-aud positive test, the array branch
    /// could be removed entirely without breaking any test.
    #[test]
    fn aud_contains_accepts_array_with_matching_client_id() {
        let payload = serde_json::json!({
            "aud": ["other-rp", "this-client", "yet-another-rp"]
        });
        assert!(
            aud_contains(&payload, "this-client"),
            "array aud containing client_id must match"
        );
        assert!(
            !aud_contains(&payload, "not-listed"),
            "array aud not containing client_id must reject"
        );
    }

    /// `azp_satisfied` skips the `azp` requirement when `aud` is a
    /// single-element array (OIDC §2 only mandates `azp` when `aud` has
    /// multiple values). Pins the match guard `arr.len() > 1` against
    /// `true`/`==`/`>=` mutations; each would force `azp` checking on a
    /// single-element array, breaking conformant IdPs that omit `azp`
    /// for single-audience tokens.
    #[test]
    fn azp_satisfied_skips_azp_for_single_element_array_aud() {
        let payload = serde_json::json!({
            "aud": ["this-client"],
        });
        assert!(
            azp_satisfied(&payload, "this-client"),
            "single-element array aud must not require azp"
        );
    }

    /// `azp_satisfied` returns `true` when `aud` is a multi-element
    /// array AND `azp` matches the relying party's client_id. Pins
    /// `== → !=`; that mutation would reject every matching `azp`,
    /// breaking the only acceptance path for multi-audience tokens.
    #[test]
    fn azp_satisfied_accepts_multi_element_aud_when_azp_matches() {
        let payload = serde_json::json!({
            "aud": ["this-client", "other-rp"],
            "azp": "this-client",
        });
        assert!(
            azp_satisfied(&payload, "this-client"),
            "multi-element aud with matching azp must be accepted"
        );
    }

    /// `azp_satisfied` returns `false` when `aud` is a multi-element
    /// array and `azp` is absent or mismatched. Pins three mutations:
    /// `azp_satisfied -> true` (would let any token through),
    /// `arr.len() > 1 -> false` (would skip the azp check entirely on
    /// multi-element arrays), and `> -> <` (same skip-on-multi-element
    /// effect). All three would silently accept logout tokens addressed
    /// to a colluding client when azp is missing; the collusion attack
    /// the OIDC Core §2 `azp` rule exists to prevent.
    #[test]
    fn azp_satisfied_rejects_multi_element_aud_without_matching_azp() {
        let missing = serde_json::json!({
            "aud": ["this-client", "other-rp"],
        });
        assert!(
            !azp_satisfied(&missing, "this-client"),
            "multi-element aud without azp must reject (OIDC Core §2)"
        );

        let mismatched = serde_json::json!({
            "aud": ["this-client", "other-rp"],
            "azp": "other-rp",
        });
        assert!(
            !azp_satisfied(&mismatched, "this-client"),
            "multi-element aud with non-matching azp must reject (OIDC Core §2)"
        );
    }
}
