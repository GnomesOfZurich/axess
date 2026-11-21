//! The parsers of device keys that read what any client can send and are
//! private to the crate: the proof cookie, the registration offer and the
//! identifier header. The fuzz crate reaches them here, under fixed keys
//! and for one fixed session, tenant and device. Nothing here is for an
//! application.

use axess_clock::Timestamp;

use crate::authn::ids::{DeviceId, TenantId};
use crate::device_key::cookie::{self, KeyCookieKeys};
use crate::device_key::{KeyThumbprint, ProvenKey};
use crate::session::id::{SessionId, SessionKey};

/// The grace a proof cookie is read with.
pub const GRACE: std::time::Duration = std::time::Duration::from_secs(30);

fn keys() -> KeyCookieKeys {
    KeyCookieKeys {
        current: [7; 32],
        previous: Some([8; 32]),
    }
}

fn session() -> SessionKey {
    SessionKey::of(&SessionId::new(&super::MockRng::new(1)))
}

/// The one key the minted proof cookie proves, and the tenant and device
/// the minted offer is for.
pub fn proven_key() -> ProvenKey {
    ProvenKey {
        tenant: crate::authn::ids::testing::tenant("fuzz-tenant"),
        device: crate::authn::ids::testing::device("fuzz-device"),
        thumbprint: KeyThumbprint::from_bytes([5; 32]),
    }
}

/// The proof cookie value the layer mints for [`proven_key`], good until
/// `expires_unix`; `None` for a time that is no date.
pub fn mint_proof_cookie(expires_unix: i64) -> Option<String> {
    let expires_at = axess_clock::Until::from_unix_seconds(expires_unix)?;
    Some(cookie::mint_proof(&keys(), &proven_key(), expires_at))
}

/// What a proof cookie value proves at `now_unix`, read with
/// [`GRACE`] of grace.
pub fn read_proof_cookie(value: &str, now_unix: i64) -> Option<ProvenKey> {
    let now = Timestamp::from_unix_seconds(now_unix)?;
    cookie::read_proof(&keys(), value, now, GRACE)
}

/// The offer the layer mints to the fixed session for [`proven_key`]'s
/// tenant and device, good until `expires_unix`.
pub fn mint_offer(expires_unix: i64) -> Option<String> {
    let expires_at = axess_clock::Until::from_unix_seconds(expires_unix)?;
    let key = proven_key();
    Some(cookie::mint_offer(
        &keys(),
        &session(),
        &key.tenant,
        &key.device,
        expires_at,
    ))
}

/// Whether `offer` holds at `now_unix` for the fixed session, tenant and
/// device.
pub fn offer_holds(offer: &str, now_unix: i64) -> bool {
    let Some(now) = Timestamp::from_unix_seconds(now_unix) else {
        return false;
    };
    let key = proven_key();
    cookie::offer_holds(&keys(), offer, &session(), &key.tenant, &key.device, now)
}

/// The tenant and device the value of the identifier header names to the
/// session layer; `None` for a value no header can carry.
pub fn named_device(header_value: &str) -> Option<(TenantId, DeviceId)> {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::HeaderName::from_static(
            axess_factors::key_proof::browser_draft::SESSION_ID_HEADER,
        ),
        axum::http::HeaderValue::from_str(header_value).ok()?,
    );
    crate::session::layer::device_keys::named_device(&headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry points answer as the parsers behind them: what was minted
    /// reads back until it ends, and nothing else does.
    #[test]
    fn the_entry_points_reach_the_parsers() {
        let grace = i64::try_from(GRACE.as_secs()).unwrap();
        let proof = mint_proof_cookie(1_000).unwrap();
        assert_eq!(
            read_proof_cookie(&proof, 1_000 + grace - 1),
            Some(proven_key())
        );
        assert_eq!(read_proof_cookie(&proof, 1_000 + grace), None);
        assert_eq!(read_proof_cookie("v1.not.a.proof", 0), None);
        let offer = mint_offer(1_000).unwrap();
        assert!(offer_holds(&offer, 999));
        assert!(!offer_holds(&offer, 1_000));
        assert!(!offer_holds(&proof, 0));
        let key = proven_key();
        let written = format!("\"{}.{}\"", key.tenant, key.device);
        assert_eq!(named_device(&written), Some((key.tenant, key.device)));
        assert_eq!(named_device("nobody"), None);
    }
}
