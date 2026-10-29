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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axess_rng::SecureRng;
use axum::http::HeaderValue;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_cookies::cookie::{Cookie, SameSite, time};

use crate::authn::ids::DeviceId;
use crate::device::types::{DeviceBinding, FingerprintHash};

/// Longest cookie value read; a real one is under 100 bytes.
pub(crate) const MAX_DEVICE_COOKIE_BYTES: usize = 256;

/// A device token: 32 random bytes, shown to the browser once.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceToken([u8; 32]);

impl std::fmt::Debug for DeviceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceToken(***)")
    }
}

impl Drop for DeviceToken {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl DeviceToken {
    /// Draw a fresh token from `rng`.
    pub fn mint(rng: &dyn SecureRng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
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
        hasher.update(self.0);
        FingerprintHash::from_bytes(hasher.finalize().into())
    }

    /// The binding that lets a row recognise this token.
    pub fn binding(&self, now: chrono::DateTime<chrono::Utc>) -> DeviceBinding {
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
    /// Parse a cookie value, `None` when it is not in the form
    /// [`cookie_value`] writes.
    pub fn parse(value: &str) -> Option<Self> {
        let (id, token) = value.split_once('.')?;
        let id = DeviceId::try_new(id).ok()?;
        let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
        let bytes: [u8; 32] = decoded.try_into().ok()?;
        Some(Self {
            id,
            token: DeviceToken(bytes),
        })
    }
}

/// The cookie value that presents `token` for device `id`.
pub fn cookie_value(id: &DeviceId, token: &DeviceToken) -> String {
    format!("{id}.{}", URL_SAFE_NO_PAD.encode(token.0))
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

    /// The `Set-Cookie` header value that stores `token` for device `id`.
    pub(crate) fn set_cookie(&self, id: &DeviceId, token: &DeviceToken) -> Option<HeaderValue> {
        let mut cookie = Cookie::new(self.name.to_string(), cookie_value(id, token));
        cookie.set_http_only(true);
        cookie.set_secure(self.secure);
        cookie.set_same_site(SameSite::Strict);
        cookie.set_path("/");
        cookie.set_max_age(time::Duration::seconds(
            self.max_age.as_secs().min(i64::MAX as u64) as i64,
        ));
        HeaderValue::from_str(&cookie.to_string()).ok()
    }

    /// The device a request presents, read from its `Cookie` header.
    pub(crate) fn presented(&self, headers: &axum::http::HeaderMap) -> Option<PresentedDevice> {
        let value =
            crate::cookies::extract_named_cookie(headers, &self.name, MAX_DEVICE_COOKIE_BYTES)?;
        PresentedDevice::parse(&value)
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
