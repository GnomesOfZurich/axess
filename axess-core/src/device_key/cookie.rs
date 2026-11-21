//! The proof cookie and the registration offer: two values the session layer
//! mints and reads with keys derived from its signing key.
//!
//! # The proof cookie
//!
//! ```text
//! <name>_<16 hex of SHA-256(tenant.device)> = v1.<tenant>.<device>.<thumbprint>.<expires>.<mac>
//! ```
//!
//! It says "the holder of this device's key signed a challenge, and that is
//! good until `expires`". The expiry is inside the MAC, so a copy does not
//! outlive it however often the owner's client refreshes. Reading one is a
//! MAC and a comparison with the clock; no store is read. The name carries a
//! digest of the tenant and the device id so that two devices registered in
//! one browser profile keep separate cookies.
//!
//! # The offer
//!
//! ```text
//! v1.<expires>.<mac>
//! ```
//!
//! The challenge a registration proof signs. It is not stored: the MAC
//! covers the session's key, the tenant and the device it was made for, so it is
//! good for exactly those and until `expires`.

use crate::authn::ids::{DeviceId, TenantId};
use crate::device_key::{KeyThumbprint, ProvenKey};
use crate::session::id::SessionKey;
use axess_clock::{Timestamp, Until};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Longest proof cookie value read; a real one is about 180 bytes.
const MAX_PROOF_COOKIE_BYTES: usize = 320;

/// Most proof cookies read from one request: one per device registered in
/// the browser profile, and a profile shared by more accounts than this
/// proves only the first ones.
pub(crate) const MAX_PROOF_COOKIES: usize = 8;

const PROOF_DOMAIN: &[u8] = b"axess.device-key.proof.v1";
const OFFER_DOMAIN: &[u8] = b"axess.device-key.offer.v1";

/// The MAC keys of the proof cookie and the offer, under the current signing
/// key and, during a rotation, the previous one. Zeroed on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct KeyCookieKeys {
    pub(crate) current: [u8; 32],
    pub(crate) previous: Option<[u8; 32]>,
}

/// HMAC-SHA256 over a domain label and length-prefixed fields, so no two
/// different field lists share one byte string.
fn mac(key: &[u8; 32], domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut signer = crate::hmac::new_signer(key);
    signer.update(domain);
    for field in fields {
        signer.update(&(field.len() as u64).to_be_bytes());
        signer.update(field);
    }
    signer.finalize().into_bytes().into()
}

/// Whether `tag` is the MAC of the fields under the current key or, during a
/// rotation, the previous one.
fn mac_holds(keys: &KeyCookieKeys, domain: &[u8], fields: &[&[u8]], tag: &[u8]) -> bool {
    let under = |key: &[u8; 32]| bool::from(mac(key, domain, fields)[..].ct_eq(tag));
    // Both are computed when there are two, so the time taken does not say
    // which key a value was minted under.
    let current = under(&keys.current);
    let previous = keys.previous.as_ref().is_some_and(under);
    current | previous
}

/// The cookie name for the proof of `device` of `tenant` under the
/// configured base name: the base, an underscore, and the first 16 hex
/// digits of SHA-256 over the tenant and the device id. One slot per device
/// whatever shape an id scheme gives its ids (time-ordered ids share their
/// leading digits), and nothing in the name reads back as the id.
pub(crate) fn proof_cookie_name(base: &str, tenant: &TenantId, device: &DeviceId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant.to_string().as_bytes());
    hasher.update(b".");
    hasher.update(device.to_string().as_bytes());
    let digest = hasher.finalize();
    format!("{base}_{}", axess_rng::hex::encode(&digest[..8]))
}

fn proof_fields<'a>(
    tenant: &'a str,
    device: &'a str,
    thumbprint: &'a KeyThumbprint,
    expires: &'a [u8; 8],
) -> [&'a [u8]; 4] {
    [
        tenant.as_bytes(),
        device.as_bytes(),
        thumbprint.as_bytes(),
        expires,
    ]
}

/// The proof cookie value for `proven`, good until `expires_at`.
pub(crate) fn mint_proof(keys: &KeyCookieKeys, proven: &ProvenKey, expires_at: Until) -> String {
    let (tenant, device) = (proven.tenant.to_string(), proven.device.to_string());
    let expires = expires_at.unix_seconds();
    let tag = mac(
        &keys.current,
        PROOF_DOMAIN,
        &proof_fields(&tenant, &device, &proven.thumbprint, &expires.to_be_bytes()),
    );
    format!(
        "v1.{tenant}.{device}.{}.{expires}.{}",
        proven.thumbprint.to_text(),
        URL_SAFE_NO_PAD.encode(tag)
    )
}

/// The key a proof cookie value proves at `now`, `None` when the value is
/// not one this layer minted or `now` is at or past its expiry plus `grace`.
pub(crate) fn read_proof(
    keys: &KeyCookieKeys,
    value: &str,
    now: Timestamp,
    grace: std::time::Duration,
) -> Option<ProvenKey> {
    if value.len() > MAX_PROOF_COOKIE_BYTES {
        return None;
    }
    let mut parts = value.split('.');
    let (Some("v1"), Some(tenant), Some(device), Some(thumbprint), Some(expires), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    let expires_secs: i64 = expires.parse().ok()?;
    // One spelling per value: a number written another way is not ours.
    if expires_secs.to_string() != expires {
        return None;
    }
    let thumbprint_bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(thumbprint).ok()?.try_into().ok()?;
    let thumbprint = KeyThumbprint::from_bytes(thumbprint_bytes);
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    if !mac_holds(
        keys,
        PROOF_DOMAIN,
        &proof_fields(tenant, device, &thumbprint, &expires_secs.to_be_bytes()),
        &tag,
    ) {
        return None;
    }
    // A proof whose end never comes is at no reading past it, grace or
    // none, and neither is one whose grace is too long to hold: the end of
    // the grace is an end like the proof's own.
    if let Until::At(expires_at) = Until::from_unix_seconds(expires_secs)?
        && Until::At(now) >= Until::after(expires_at, grace)
    {
        return None;
    }
    Some(ProvenKey {
        tenant: TenantId::try_new(tenant).ok()?,
        device: DeviceId::try_new(device).ok()?,
        thumbprint,
    })
}

/// Every key the request's proof cookies prove at `now`: the cookies whose
/// name starts with `base` and an underscore, at most
/// [`MAX_PROOF_COOKIES`] of them.
pub(crate) fn read_proofs(
    keys: &KeyCookieKeys,
    headers: &axum::http::HeaderMap,
    base: &str,
    now: Timestamp,
    grace: std::time::Duration,
) -> Vec<ProvenKey> {
    let mut proven = Vec::new();
    let mut seen = 0usize;
    for header in headers.get_all(axum::http::header::COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            let is_proof = name
                .strip_prefix(base)
                .is_some_and(|rest| rest.starts_with('_'));
            if !is_proof {
                continue;
            }
            seen += 1;
            if seen > MAX_PROOF_COOKIES {
                return proven;
            }
            if let Some(key) = read_proof(keys, value, now, grace)
                && !proven.contains(&key)
            {
                proven.push(key);
            }
        }
    }
    proven
}

fn offer_fields<'a>(
    session: &'a SessionKey,
    tenant: &'a str,
    device: &'a str,
    expires: &'a [u8; 8],
) -> [&'a [u8]; 4] {
    [
        session.as_bytes(),
        tenant.as_bytes(),
        device.as_bytes(),
        expires,
    ]
}

/// The offer for `device` of `tenant`, made to `session`, good until
/// `expires_at`.
pub(crate) fn mint_offer(
    keys: &KeyCookieKeys,
    session: &SessionKey,
    tenant: &TenantId,
    device: &DeviceId,
    expires_at: Until,
) -> String {
    let expires = expires_at.unix_seconds();
    let tag = mac(
        &keys.current,
        OFFER_DOMAIN,
        &offer_fields(
            session,
            &tenant.to_string(),
            &device.to_string(),
            &expires.to_be_bytes(),
        ),
    );
    format!("v1.{expires}.{}", URL_SAFE_NO_PAD.encode(tag))
}

/// Whether `offer` was made to `session` for `device` of `tenant` and has
/// not expired at `now`.
pub(crate) fn offer_holds(
    keys: &KeyCookieKeys,
    offer: &str,
    session: &SessionKey,
    tenant: &TenantId,
    device: &DeviceId,
    now: Timestamp,
) -> bool {
    if offer.len() > MAX_PROOF_COOKIE_BYTES {
        return false;
    }
    let mut parts = offer.split('.');
    let (Some("v1"), Some(expires), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Ok(expires_secs) = expires.parse::<i64>() else {
        return false;
    };
    if expires_secs.to_string() != expires {
        return false;
    }
    let Ok(tag) = URL_SAFE_NO_PAD.decode(tag) else {
        return false;
    };
    let genuine = mac_holds(
        keys,
        OFFER_DOMAIN,
        &offer_fields(
            session,
            &tenant.to_string(),
            &device.to_string(),
            &expires_secs.to_be_bytes(),
        ),
        &tag,
    );
    genuine
        && Until::from_unix_seconds(expires_secs)
            .is_some_and(|expires_at| Until::At(now) < expires_at)
}

#[cfg(test)]
mod props;
#[cfg(test)]
mod tests;
