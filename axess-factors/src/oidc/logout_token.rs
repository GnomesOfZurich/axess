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

/// How far in the future a logout token's `iat` may be (clock skew), in
/// seconds.
pub const MAX_IAT_FUTURE_SECS: i64 = 60;

/// How long a logout token's `jti` must be remembered to refuse a replay: a
/// token is accepted from `MAX_IAT_FUTURE_SECS` before its `iat` until
/// `MAX_IAT_AGE_SECS` after it, so the same token can arrive this many
/// seconds apart.
pub const JTI_RETENTION_SECS: i64 = MAX_IAT_AGE_SECS + MAX_IAT_FUTURE_SECS;

/// Maximum logout token size (8 KiB). Real OIDC logout tokens are typically
/// well under 2 KiB; the larger limit allows headroom for unusual claim
/// payloads while still preventing memory DoS via crafted multi-megabyte
/// JWTs aimed at the public logout endpoint.
pub const MAX_LOGOUT_TOKEN_BYTES: usize = 8 * 1024;

/// Maximum ID token size (1 MiB). An ID token from a directory-backed IdP
/// can carry hundreds of group or role claims and legitimately exceed the
/// logout-token cap; the bound only has to keep a hostile or broken IdP
/// response from driving an unbounded base64 and JSON decode.
pub const MAX_ID_TOKEN_BYTES: usize = 1024 * 1024;

/// Decode the payload (second segment) of a JWT without signature verification.
///
/// Returns the parsed JSON payload. This is used for claim inspection only;
/// the caller is responsible for verifying the signature separately (e.g. via
/// the provider's JWKS) before trusting any fields.
///
/// Refuses tokens over [`MAX_LOGOUT_TOKEN_BYTES`], because it runs on the
/// public logout endpoint. The login path reads ID tokens with
/// [`decode_id_token_payload`] instead.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    decode_payload_capped(token, MAX_LOGOUT_TOKEN_BYTES, "logout token")
}

/// Decode the payload of an ID token that the caller has already verified,
/// refusing tokens over [`MAX_ID_TOKEN_BYTES`].
pub fn decode_id_token_payload(token: &str) -> Result<serde_json::Value, String> {
    decode_payload_capped(token, MAX_ID_TOKEN_BYTES, "ID token")
}

fn decode_payload_capped(
    token: &str,
    max_bytes: usize,
    what: &str,
) -> Result<serde_json::Value, String> {
    if token.len() > max_bytes {
        return Err(format!(
            "{what} too large ({} bytes, max {max_bytes})",
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
    if (-MAX_IAT_FUTURE_SECS..=MAX_IAT_AGE_SECS).contains(&age) {
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

    fn token_with_groups(n: usize) -> String {
        let groups: Vec<String> = (0..n)
            .map(|i| format!("00000000-0000-0000-0000-{i:012}"))
            .collect();
        let payload = serde_json::json!({ "sub": "u", "groups": groups }).to_string();
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload))
    }

    /// A 9 KiB ID token with many groups decodes on the login path and is
    /// still refused by the logout-token decoder.
    #[test]
    fn id_token_over_logout_cap_decodes_on_login_path_only() {
        let token = token_with_groups(250);
        assert!(token.len() > 9 * 1024, "fixture is {} bytes", token.len());
        assert!(token.len() < MAX_ID_TOKEN_BYTES);
        let payload = decode_id_token_payload(&token).expect("login path accepts it");
        assert_eq!(payload["groups"].as_array().map(Vec::len), Some(250));
        let err = decode_jwt_payload(&token).expect_err("logout path refuses it");
        assert!(err.contains("too large"), "{err}");
    }

    /// The ID-token cap is strict greater-than and bounded.
    #[test]
    fn id_token_decoder_refuses_over_its_own_cap() {
        let err = decode_id_token_payload(&"x".repeat(MAX_ID_TOKEN_BYTES + 1)).expect_err("cap");
        assert!(err.contains("ID token too large"), "{err}");
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

    /// A present `azp` that is not the expected client is refused even when
    /// `aud` holds a single value naming us.
    #[test]
    fn azp_satisfied_rejects_foreign_azp_with_single_aud() {
        for aud in [
            serde_json::json!("this-client"),
            serde_json::json!(["this-client"]),
        ] {
            let payload = serde_json::json!({ "aud": aud, "azp": "other-rp" });
            assert!(!azp_satisfied(&payload, "this-client"));
        }
        let non_string = serde_json::json!({ "aud": "this-client", "azp": 7 });
        assert!(!azp_satisfied(&non_string, "this-client"));
        let matching = serde_json::json!({ "aud": "this-client", "azp": "this-client" });
        assert!(azp_satisfied(&matching, "this-client"));
    }
}
