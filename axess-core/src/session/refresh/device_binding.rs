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
//! from what the caller presents now and compares in constant time.
//!
//! Without a configured pepper the MAC is keyed with the public domain
//! constant, so the digest is unkeyed: a reader of the store can confirm a
//! guessed device string against a row, which a `User-Agent` of little
//! entropy makes cheap. That bounds what the digest hides, never what it
//! checks: a caller still has to present the matching string. It is not
//! refused, because the default configuration has no pepper and device
//! binding has to keep working there; set `hash_pepper` wherever the device
//! string is worth hiding.
//!
//! The digest is keyed by the pepper the token's hash was computed under. A
//! token found under `previous_hash_pepper` after a pepper rotation is
//! verified under that pepper, and the token that replaces it is bound under
//! the current one, so a chain moves off a retired pepper on its next refresh
//! and keeps working once the previous pepper is dropped from the config.
//!
//! A token issued by an earlier release stores the raw string. It is still
//! honoured, compared as before, and the token that replaces it on rotation
//! carries the keyed digest, so a chain upgrades itself on its first refresh
//! after the upgrade. With rotation off nothing replaces the token, so its
//! raw string stays in the store until the token expires (`ttl` after its
//! last refresh, or `max_lifetime`); re-storing it in place under the same
//! pepper would give two rows one `token_hash`. To retire raw bindings
//! sooner, turn rotation on or revoke the user's tokens.

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

/// The peppers one verification runs under.
#[derive(Clone, Copy)]
pub(super) struct Peppers<'a> {
    /// The pepper the record's hash was found under, which is the one its
    /// binding was keyed with: the current pepper, or the previous one for a
    /// token that has not been refreshed since the rotation.
    pub(super) stored_under: Option<&'a [u8]>,
    /// The current pepper, which the replacement token is bound under.
    pub(super) current: Option<&'a [u8]>,
}

/// Check what the caller presents against the token's binding.
///
/// `Ok` carries the `device_info` the replacement token should store: the
/// digest of what was presented, keyed under the current pepper. It equals
/// the token's own value when the token was already bound under that pepper,
/// and moves a token off the previous pepper or off the raw string of an
/// earlier release otherwise. `Err(())` is a mismatch (or a token that is
/// bound and a caller that presents nothing).
pub(super) fn verify(
    record: &RefreshToken,
    presented: Option<&str>,
    peppers: Peppers<'_>,
) -> Result<Option<String>, ()> {
    let Some(stored) = record.device_info.as_deref() else {
        return Ok(None);
    };
    let Some(presented) = presented else {
        return Err(());
    };
    let device = record.device_id.as_ref();
    let matches = if stored.starts_with(PREFIX) {
        same(stored, &bind(presented, device, peppers.stored_under))
    } else {
        same(stored, presented)
    };
    if !matches {
        return Err(());
    }
    Ok(Some(bind(presented, device, peppers.current)))
}
