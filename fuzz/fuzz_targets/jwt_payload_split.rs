// Fuzz the real token-payload decoders that run before any signature check:
// `axess_factors::oidc::logout_token::{decode_jwt_payload, decode_id_token_payload}`
// for the public back-channel-logout endpoint and the login path, and
// `axess_factors::jwt::claims::decode_jwt_payload` for bearer tokens.
//
// The target calls the library functions, not a copy of their steps, and holds
// them to an independent statement of the contract: a token is accepted only
// when it is within its size cap, has exactly three dot-separated segments and
// carries a payload segment that is URL-safe base64 of a JSON document; the
// document returned is that JSON; and the logout cap is never looser than the
// ID-token cap.

#![no_main]

use axess_factors::jwt::claims::{self, MAX_JWT_BYTES};
use axess_factors::oidc::logout_token::{
    MAX_ID_TOKEN_BYTES, MAX_LOGOUT_TOKEN_BYTES, decode_id_token_payload, decode_jwt_payload,
};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;

/// What the contract says the payload is, written without the library's code.
fn expected(token: &str, cap: usize) -> Option<serde_json::Value> {
    if token.len() > cap {
        return None;
    }
    let mut segments = token.split('.');
    let (_header, payload, _signature) = (segments.next()?, segments.next()?, segments.next()?);
    if segments.next().is_some() {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };

    let logout = decode_jwt_payload(token);
    assert_eq!(
        logout.ok(),
        expected(token, MAX_LOGOUT_TOKEN_BYTES),
        "logout decoder"
    );

    let id = decode_id_token_payload(token);
    assert_eq!(
        id.ok(),
        expected(token, MAX_ID_TOKEN_BYTES),
        "ID token decoder"
    );

    let bearer = claims::decode_jwt_payload(token);
    assert_eq!(
        bearer.ok(),
        expected(token, MAX_JWT_BYTES),
        "bearer decoder"
    );

    // A token the stricter cap accepts, the looser cap accepts with the same
    // payload.
    if let Ok(strict) = decode_jwt_payload(token) {
        assert_eq!(decode_id_token_payload(token).ok(), Some(strict));
    }
});
