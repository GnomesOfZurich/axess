//! Minting and checking of CSRF tokens: `nonce || HMAC(key, nonce || session_id)`.

use super::TOKEN_NONCE_BYTES;
use axess_rng::SecureRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use subtle::ConstantTimeEq;

pub(super) fn mint_token(session_id: &[u8], signing_key: &[u8; 32], rng: &dyn SecureRng) -> String {
    let mut nonce = [0u8; TOKEN_NONCE_BYTES];
    rng.fill_bytes(&mut nonce);
    let tag = compute_tag(&nonce, session_id, signing_key);
    let mut combined = Vec::with_capacity(TOKEN_NONCE_BYTES + tag.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(&combined)
}

fn compute_tag(nonce: &[u8], session_id: &[u8], signing_key: &[u8; 32]) -> [u8; 32] {
    // MAC over `nonce || session_id`. Binding the session id into the tag is
    // what makes a token minted under one session fail validation under
    // another: the nonce is echoed in the token but the id is not, so an
    // attacker cannot recompute the tag for a different session without the
    // key. The nonce has a fixed length (`TOKEN_NONCE_BYTES`), so the
    // concatenation is unambiguous and needs no separator.
    let mut mac = crate::hmac::new_signer(signing_key);
    mac.update(nonce);
    mac.update(session_id);
    mac.finalize().into_bytes().into()
}

pub(super) fn validate_token(token: &str, session_id: &[u8], signing_key: &[u8; 32]) -> bool {
    let bytes = match URL_SAFE_NO_PAD.decode(token) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if bytes.len() != TOKEN_NONCE_BYTES + 32 {
        return false;
    }
    let (nonce, tag) = bytes.split_at(TOKEN_NONCE_BYTES);
    let expected = compute_tag(nonce, session_id, signing_key);
    expected.ct_eq(tag).into()
}
