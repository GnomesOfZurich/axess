//! The device token: proof that a request comes from the browser a device
//! row was issued to.
//!
//! The device fingerprint (a keyed digest of `User-Agent` and other headers)
//! is a hint, not an identity: anyone who copies a victim's headers computes
//! the same digest. A device is therefore matched by something the client
//! cannot forge. When the lifecycle creates a device for an authenticated
//! user it mints a random 32-byte token, stores only a SHA-256 digest of it on
//! the row (as a [`DeviceBinding::Cookie`]),
//! and sends the token to the browser in a cookie,
//!
//! ```text
//! __Host-axess_device = <device id>.<base64url(token)>; Secure; HttpOnly; SameSite=Strict; Path=/
//! ```
//!
//! A later request presents the cookie; the row is loaded by the id in it and
//! the token's digest is compared in constant time with the digest on the
//! row. A request without a valid token never inherits a device by matching
//! headers: it gets a new `Unknown` device when its user is authenticated, and
//! none otherwise. The digest is of a 256-bit random value, so it needs no
//! key and a leaked row does not let anyone mint a cookie.
//!
//! `SameSite=Strict` keeps the cookie off cross-site requests, so a visit that
//! arrives from another site carries the session cookie and not this one. The
//! session already names the device it was last bound to, and the lifecycle
//! keeps that device for an authenticated user instead of minting another.
//!
//! # One slot per device
//!
//! A device row has one owner, so a browser profile that several accounts
//! sign in on holds one device per account. The cookie therefore holds one
//! entry per device, newest first, joined by `~`:
//!
//! ```text
//! __Host-axess_device = <id>.<token>~<id>.<token>
//! ```
//!
//! at most [`MAX_DEVICE_COOKIE_ENTRIES`] of them. A request is resolved to the
//! first entry that proves a device its user may use, so an account switch
//! reuses that account's device instead of minting a new one, and minting a
//! device for one account keeps the other accounts' entries. A value with one
//! entry, which is what earlier releases wrote, reads as it always did.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axess_rng::SecureRng;
use axum::http::HeaderValue;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cookie::{Cookie, SameSite, time};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::types::{DeviceBinding, FingerprintHash};

/// Most device entries one cookie holds: one per account that signs in on a
/// browser profile. A request that presents more is read up to this many, and
/// a cookie written when it is full drops the oldest.
pub const MAX_DEVICE_COOKIE_ENTRIES: usize = 8;

/// Longest cookie value read; an entry is under 100 bytes.
pub(crate) const MAX_DEVICE_COOKIE_BYTES: usize = 1024;

/// What joins the entries of one cookie value. A cookie octet that neither an
/// id nor a base64url token contains.
const ENTRY_SEPARATOR: char = '~';

/// A device token: 32 random bytes, shown to the browser once.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceToken(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for DeviceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceToken(***)")
    }
}

impl DeviceToken {
    /// Draw a fresh token from `rng`.
    pub fn mint(rng: &dyn SecureRng) -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    /// The token's bytes, for a test that checks they are not stored.
    #[cfg(test)]
    pub(crate) fn raw_for_tests(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest stored on the device row in place of the token.
    pub fn digest(&self) -> FingerprintHash {
        let mut hasher = Sha256::new();
        hasher.update(b"axess.device-token.v1\0");
        hasher.update(&self.0[..]);
        FingerprintHash::from_bytes(hasher.finalize().into())
    }

    /// The binding that lets a row recognise this token.
    pub fn binding(&self, now: axess_clock::Timestamp) -> DeviceBinding {
        DeviceBinding::Cookie {
            token_hash: self.digest(),
            issued_at: now,
            last_used_at: now,
        }
    }

    /// Whether any cookie binding in `bindings` holds this token's digest.
    /// Every binding is compared, in constant time each, so the time taken
    /// does not say which one matched.
    pub fn is_listed_in(&self, bindings: &[DeviceBinding]) -> bool {
        let mine = self.digest();
        let mut found = subtle::Choice::from(0);
        for binding in bindings {
            if let DeviceBinding::Cookie { token_hash, .. } = binding {
                found |= token_hash.as_bytes().ct_eq(mine.as_bytes());
            }
        }
        bool::from(found)
    }
}

/// A device the client proved it holds: it presented the secret token on the
/// device's cookie (see [`DeviceToken`]) or, for a device that has a key
/// under a layer that enforces keys, proved that key. A fingerprint cannot
/// stand in for either.
///
/// The only way to get one is a resolution by
/// [`DeviceLifecycleService::resolve_or_keep`](crate::device::DeviceLifecycleService::resolve_or_keep)
/// or [`resolve_proven`](crate::device::DeviceLifecycleService::resolve_proven)
/// (through [`ResolvedDevice::proven`](crate::device::ResolvedDevice::proven)),
/// which yield one for a request that presents the token and for the device
/// created on that request, so an API that takes a `ProvenDevice` cannot be
/// handed a device found by fingerprint, nor one a session only kept from an
/// earlier request. A session bound to a device key is the exception to the
/// last: a request that proved the bound key has the bound device proven by
/// that key, whether or not it presented the token. The per-account
/// lockout's exemption for a device the
/// account has used is one: [`AuthSession::proven_device`](crate::session::extractor::AuthSession::proven_device)
/// answers only on a request that proved the session's device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenDevice {
    id: DeviceId,
    proof: crate::device_key::DeviceProof,
}

impl ProvenDevice {
    /// The device's id.
    pub fn id(&self) -> DeviceId {
        self.id
    }

    /// How the request proved the device: by its token, which is a bearer
    /// value, or by a signature of its key
    /// ([`DeviceProof::Key`](crate::device_key::DeviceProof::Key)), which a
    /// copy of the cookie store cannot make. Where device keys are enforced,
    /// a device that has a key is only ever proven by it.
    pub fn proof(&self) -> crate::device_key::DeviceProof {
        self.proof
    }

    /// A device proven by its token, or by being created on this request.
    pub(crate) fn new(id: DeviceId) -> Self {
        Self::by(id, crate::device_key::DeviceProof::Token)
    }

    pub(crate) fn by(id: DeviceId, proof: crate::device_key::DeviceProof) -> Self {
        Self { id, proof }
    }

    /// A token proof for a test that has no cookie to present. Not available
    /// in a production build.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests(id: DeviceId) -> Self {
        Self::new(id)
    }

    /// A key proof for a test that has no proof cookie to present. Not
    /// available in a production build.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests_by_key(id: DeviceId, thumbprint: crate::device_key::KeyThumbprint) -> Self {
        Self::by(id, crate::device_key::DeviceProof::Key(thumbprint))
    }
}

/// A device a request proved, with the user and the tenant of the session
/// that is authenticated on that request: what a trust write takes.
///
/// [`AuthSession::user_device`](crate::session::extractor::AuthSession::user_device)
/// answers one, and only for an authenticated session on a request that
/// proved a device, with the session's own user and tenant. A caller
/// therefore cannot hand a trust write a device and a user that do not
/// belong together; on the request that completes a sign-in the device is
/// the one the request proved before anyone was signed in, which may be
/// another account's, so the write still reads the row and leaves a device
/// another user owns as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserDevice {
    tenant: TenantId,
    user: UserId,
    device: ProvenDevice,
}

impl UserDevice {
    /// The tenant the session is authenticated in.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The user the session is authenticated as.
    pub fn user(&self) -> UserId {
        self.user
    }

    /// The device the request proved.
    pub fn device(&self) -> ProvenDevice {
        self.device
    }

    pub(crate) fn new(tenant: TenantId, user: UserId, device: ProvenDevice) -> Self {
        Self {
            tenant,
            user,
            device,
        }
    }

    /// A pairing for a test that has no session to ask. Not available in a
    /// production build.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_tests(tenant: TenantId, user: UserId, device: ProvenDevice) -> Self {
        Self::new(tenant, user, device)
    }
}

/// The device a request claims to be, as read from its cookie: an id and a
/// token to prove it with. Nothing here is verified yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedDevice {
    /// The device the cookie names.
    pub id: DeviceId,
    /// The token it presents for that device.
    pub token: DeviceToken,
}

impl PresentedDevice {
    /// Every entry of a cookie value that parses, newest first, at most
    /// [`MAX_DEVICE_COOKIE_ENTRIES`] of them, one per device: an entry that
    /// does not parse, and a second entry for a device, are left out.
    pub fn parse_all(value: &str) -> Vec<Self> {
        let mut entries: Vec<Self> = Vec::new();
        for entry in value.split(ENTRY_SEPARATOR).take(MAX_DEVICE_COOKIE_ENTRIES) {
            if let Some(entry) = Self::parse(entry)
                && !entries.iter().any(|kept| kept.id == entry.id)
            {
                entries.push(entry);
            }
        }
        entries
    }

    /// Parse one entry of a cookie value, `None` when it is not in the form
    /// [`cookie_value`] writes.
    pub fn parse(value: &str) -> Option<Self> {
        let (id, token) = value.split_once('.')?;
        let id = DeviceId::try_new(id).ok()?;
        // The decoded bytes are the token: they live only in buffers that
        // are zeroed when dropped, a token of the wrong length included.
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(token).ok()?);
        if decoded.len() != 32 {
            return None;
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&decoded);
        Some(Self {
            id,
            token: DeviceToken(bytes),
        })
    }
}

/// The cookie value that presents `token` for device `id`.
pub fn cookie_value(id: &DeviceId, token: &DeviceToken) -> String {
    format!("{id}.{}", URL_SAFE_NO_PAD.encode(&token.0[..]))
}

/// How the device cookie is named and sent.
///
/// The default is the strict form: a `__Host-` name (which browsers accept
/// only with `Secure`, `Path=/` and no `Domain`), `HttpOnly`,
/// `SameSite=Strict`, and a lifetime of 400 days, the longest a browser keeps
/// a cookie. A deployment on plain HTTP in development uses
/// [`insecure_for_local_development`](Self::insecure_for_local_development).
#[derive(Debug, Clone)]
pub struct DeviceCookieConfig {
    name: Arc<str>,
    secure: bool,
    max_age: Duration,
}

impl Default for DeviceCookieConfig {
    fn default() -> Self {
        Self {
            name: Arc::from("__Host-axess_device"),
            secure: true,
            max_age: Duration::from_secs(400 * 24 * 60 * 60),
        }
    }
}

impl DeviceCookieConfig {
    /// A name without the `__Host-` prefix and no `Secure` attribute, for a
    /// development server on plain HTTP (a browser drops a `Secure` cookie
    /// from one). Never use it behind HTTPS.
    pub fn insecure_for_local_development() -> Self {
        Self {
            name: Arc::from("axess_device"),
            secure: false,
            ..Self::default()
        }
    }

    /// Use another cookie name. A name that does not start with `__Host-`
    /// forgoes the browser's guarantee that the cookie was set by this exact
    /// host over HTTPS.
    pub fn with_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.name = name.into();
        self
    }

    /// Use another lifetime. The device is re-recognised for as long as the
    /// browser keeps the cookie, so this is also how long a trusted browser
    /// stays recognised without a visit.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// The cookie's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The lifetime the cookie is sent with.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// The `Set-Cookie` header value that stores `token` for device `id`
    /// first, then the entries of `kept` for other devices, up to
    /// [`MAX_DEVICE_COOKIE_ENTRIES`] in all.
    pub(crate) fn set_cookie(
        &self,
        id: &DeviceId,
        token: &DeviceToken,
        kept: &[PresentedDevice],
    ) -> Option<HeaderValue> {
        let mut value = cookie_value(id, token);
        for entry in kept
            .iter()
            .filter(|entry| entry.id != *id)
            .take(MAX_DEVICE_COOKIE_ENTRIES - 1)
        {
            value.push(ENTRY_SEPARATOR);
            value.push_str(&cookie_value(&entry.id, &entry.token));
        }
        let mut cookie = Cookie::new(self.name.to_string(), value);
        cookie.set_http_only(true);
        cookie.set_secure(self.secure);
        cookie.set_same_site(SameSite::Strict);
        cookie.set_path("/");
        cookie.set_max_age(time::Duration::seconds(
            self.max_age.as_secs().min(i64::MAX as u64) as i64,
        ));
        HeaderValue::from_str(&cookie.to_string()).ok()
    }

    /// The devices a request presents, read from its `Cookie` header, newest
    /// first.
    pub(crate) fn presented(&self, headers: &axum::http::HeaderMap) -> Vec<PresentedDevice> {
        crate::cookies::extract_named_cookie(headers, &self.name, MAX_DEVICE_COOKIE_BYTES)
            .map(|value| PresentedDevice::parse_all(&value))
            .unwrap_or_default()
    }
}

/// Where a resolver leaves the `Set-Cookie` value for a device it issued a
/// token to. The session layer puts one in the request extensions before it
/// calls the resolver and appends what is in it to the response.
#[derive(Debug, Clone, Default)]
pub struct DeviceCookieSlot(Arc<Mutex<Option<HeaderValue>>>);

impl DeviceCookieSlot {
    /// Leave `value` to be sent with the response.
    pub fn set(&self, value: HeaderValue) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(value);
        }
    }

    /// Take the value left, if any.
    pub fn take(&self) -> Option<HeaderValue> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

#[cfg(test)]
mod tests;
