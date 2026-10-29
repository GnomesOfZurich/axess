//! What a refresh token's `device_info` holds, and how rotation checks it.
//!
//! The caller of a refresh supplies a device string: it should be the hex of
//! the keyed device fingerprint, but it is whatever the caller passed, and a
//! raw `User-Agent` is a header anyone can read from the victim's traffic. The
//! token therefore does not store that string. At issue it stores a keyed
//! digest of it together with the token's device id,
//!
//! ```text
//! hb1:<base64url(HMAC-SHA256(pepper, "axess.refresh-device.v1" 0x00 device id 0x00 info))>
//! ```
//!
//! so the store never holds the client string, and the stored value is only
//! valid for the device id on the same row (a row whose device id was changed
//! no longer matches what the device presents). Rotation recomputes the digest
//! from what the caller presents now and compares in constant time. Without a
//! configured pepper the digest is unkeyed; set one.
//!
//! A token issued by an earlier release stores the raw string. It is still
//! honoured, compared as before, and the token that replaces it on rotation
//! carries the keyed digest, so a chain upgrades itself.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::types::RefreshToken;
use crate::authn::ids::DeviceId;

const PREFIX: &str = "hb1:";
const DOMAIN: &[u8] = b"axess.refresh-device.v1";

/// The value a token stores for `info` presented for `device`.
pub(super) fn bind(info: &str, device: Option<&DeviceId>, pepper: Option<&[u8]>) -> String {
    let mut mac = crate::hmac::new_signer(pepper.unwrap_or(DOMAIN));
    mac.update(DOMAIN);
    mac.update(&[0]);
    if let Some(device) = device {
        mac.update(device.to_string().as_bytes());
    }
    mac.update(&[0]);
    mac.update(info.as_bytes());
    format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// Equal strings, compared as digests so the length of neither shows.
fn same(a: &str, b: &str) -> bool {
    bool::from(Sha256::digest(a.as_bytes()).ct_eq(&Sha256::digest(b.as_bytes())))
}

/// Check what the caller presents against the token's binding.
///
/// `Ok` carries the `device_info` the replacement token should store:
/// the token's own value, or the keyed digest when the token held the raw
/// string of an earlier release. `Err(())` is a mismatch (or a token that is
/// bound and a caller that presents nothing).
pub(super) fn verify(
    record: &RefreshToken,
    presented: Option<&str>,
    pepper: Option<&[u8]>,
) -> Result<Option<String>, ()> {
    let Some(stored) = record.device_info.as_deref() else {
        return Ok(None);
    };
    let Some(presented) = presented else {
        return Err(());
    };
    if stored.starts_with(PREFIX) {
        let expected = bind(presented, record.device_id.as_ref(), pepper);
        return same(stored, &expected)
            .then(|| Some(stored.to_string()))
            .ok_or(());
    }
    if same(stored, presented) {
        return Ok(Some(bind(presented, record.device_id.as_ref(), pepper)));
    }
    Err(())
}
