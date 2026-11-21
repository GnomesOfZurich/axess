//! [`DeviceFingerprintExtractor`]: pluggable computation of
//! [`FingerprintHash`] from an HTTP request.
//!
//! # Why a trait
//!
//! The choice of inputs (full UA vs UA-family-only, IPv4 /24 vs /32,
//! Accept-Language top entry vs full list, screen-class bucket vs
//! none) is a privacy/proportionality decision that varies by
//! deployment. A regulated-fintech app will want the minimum useful
//! set (data minimisation, GDPR Art 5(1)(c); see
//! [`docs/identity/device.md`], "PII tokenisation and GDPR"); a hobby
//! project may not bother with IP truncation.
//! axess ships a sensible default and lets consumers swap in their
//! own implementation.
//!
//! # The default
//!
//! [`DefaultFingerprintExtractor`] hashes
//! `User-Agent || Accept-Language top || ip_truncation(client_ip)`
//! with a tenant-scoped HMAC-SHA256 pepper. It does **not** parse the
//! User-Agent down to family/OS-family because that requires a UA
//! parser dep (`woothee` / `uap-rust`) we don't otherwise need.
//! Production deployments that care about strict data minimisation
//! should implement their own extractor with a UA parser and emit
//! only the family identifiers.
//!
//! # Tenant scoping
//!
//! The pepper is keyed per-tenant so the same physical device under
//! tenants A and B produces different `FingerprintHash` values.
//! Required for GDPR controller separation in multi-tenant SaaS
//! ([`docs/identity/device.md`], "The per-tenant pepper"). The default
//! extractor takes a closure that
//! resolves a tenant to its pepper, so applications can derive the
//! pepper however suits them (per-tenant secret in a vault, KDF over
//! a master key, …).
//!
//! [`docs/identity/device.md`]: ../../../../docs/identity/device.md

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::header;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request};
use hmac::Mac;

use crate::authn::ids::TenantId;
use crate::client_ip::network::ClientNetwork;
use crate::device::types::FingerprintHash;

/// Pluggable strategy for deriving a [`FingerprintHash`] from an HTTP
/// request and a tenant identity.
///
/// Implementors choose the input set. Output is always a 32-byte
/// keyed hash; the *contents* of those bytes are an opaque cookie
/// from the caller's perspective.
pub trait DeviceFingerprintExtractor: Send + Sync + 'static {
    /// Compute the fingerprint hash. Returns `None` when the request
    /// lacks the inputs the extractor requires (e.g. missing
    /// `User-Agent` for a UA-required extractor).
    /// [`LifecycleDeviceResolver`](crate::device::LifecycleDeviceResolver)
    /// answers such a request with no device when it is a guest's, and
    /// resolves one that carries a user by its token, its key or its
    /// session's device, as any other, creating no device for it.
    ///
    /// Takes [`Parts`] rather than the full `Request<B>` so the
    /// extractor composes cleanly with
    /// [`DeviceResolver`](super::resolver::DeviceResolver), which the
    /// session middleware drives across an `await` boundary
    /// (`axum::body::Body` is `!Sync` and cannot be borrowed there).
    /// Use [`Self::extract_from_request`] when you only have a
    /// `Request<B>` in hand.
    fn extract(
        &self,
        tenant_id: &TenantId,
        parts: &Parts,
        client_ip: Option<IpAddr>,
    ) -> Option<FingerprintHash>;

    /// Convenience: split a `Request<B>` into parts and delegate to
    /// [`Self::extract`]. Useful from non-async contexts that hold a
    /// full request and don't want to manage the
    /// parts/body split themselves. Clones headers/uri/method/version
    /// (cheap: all internally `Bytes`/`Arc`-backed); does not touch
    /// the body.
    fn extract_from_request<B>(
        &self,
        tenant_id: &TenantId,
        request: &Request<B>,
        client_ip: Option<IpAddr>,
    ) -> Option<FingerprintHash> {
        let placeholder: Request<()> = Request::new(());
        let (mut synthetic, _) = placeholder.into_parts();
        synthetic.headers = request.headers().clone();
        synthetic.uri = request.uri().clone();
        synthetic.method = request.method().clone();
        synthetic.version = request.version();
        self.extract(tenant_id, &synthetic, client_ip)
    }
}

/// Resolves a tenant to its 32-byte HMAC pepper.
///
/// The pepper should be stable for the lifetime of the tenant: after a
/// rotation no stored fingerprint hash of that tenant matches a request
/// any more, which strands every device a lookup by fingerprint would
/// find (a device found by its token is unaffected). Most deployments derive the pepper from a master key via
/// HKDF-Expand with the tenant_id as `info`.
///
/// `Arc<dyn>` so the same resolver can be cloned into the extractor
/// without moving the closure into a generic.
pub type TenantPepperResolver = Arc<dyn Fn(&TenantId) -> [u8; 32] + Send + Sync>;

/// Default [`DeviceFingerprintExtractor`] over `User-Agent`,
/// `Accept-Language` (top entry), and the truncated client IP
/// (IPv4 → /24, IPv6 → /48), keyed with a tenant-scoped pepper.
///
/// **Limitations**: see [module docs](self). Does NOT parse UA down
/// to family/OS, does NOT include screen-class. Adequate for risk-
/// scoring use; deployments under strict data-minimisation review
/// should implement their own extractor.
///
/// # The fingerprint is a hint, not an authenticator
///
/// Every input is chosen by the client: the `User-Agent` and
/// `Accept-Language` headers are copied verbatim, and the address is
/// truncated to a /24 or /48 range an attacker on the same network, or
/// anywhere when no client address is supplied, can share. Anyone who knows
/// a user's headers produces the same fingerprint, and a lookup by
/// fingerprint
/// ([`ensure_device`](crate::device::DeviceLifecycleService::ensure_device))
/// matches them to the same device row. A match therefore says "this request looks like that
/// device", never "this is that device", and nothing that grants access
/// should rest on it alone. The default
/// [`StepUpPolicy`](crate::authn::service::StepUpPolicy) asks for a factor
/// on a `Trusted` device for this reason. A device secret the client holds
/// and presents (a cookie or an app-held key, compared in constant time
/// against a stored hash) is what proves a device; the extractor does not
/// provide one, and the device token of
/// [`proof`](crate::device::proof) is the one the stock resolver uses.
pub struct DefaultFingerprintExtractor {
    pepper: TenantPepperResolver,
}

impl DefaultFingerprintExtractor {
    /// Construct with a tenant→pepper resolver.
    pub fn new(pepper: TenantPepperResolver) -> Self {
        Self { pepper }
    }
}

impl DeviceFingerprintExtractor for DefaultFingerprintExtractor {
    fn extract(
        &self,
        tenant_id: &TenantId,
        parts: &Parts,
        client_ip: Option<IpAddr>,
    ) -> Option<FingerprintHash> {
        // The inputs begin with the User-Agent: a request without one is
        // not fingerprinted, whatever its address.
        let headers = &parts.headers;
        let ua = headers.get(header::USER_AGENT)?;
        let pepper = (self.pepper)(tenant_id);

        let mut mac = crate::hmac::new_signer(&pepper);

        // Domain-separation prefix so a future change in input set
        // (e.g. adding screen-class) doesn't collide with the
        // existing fingerprints. Bump on layout changes.
        mac.update(b"axess.device.v1\0");

        // User-Agent.
        mac.update(b"ua\0");
        mac.update(ua.as_bytes());
        mac.update(b"\0");

        // Accept-Language top entry (everything before the first ';' or ',').
        if let Some(top) = accept_language_top(headers) {
            mac.update(b"al\0");
            mac.update(top.as_bytes());
            mac.update(b"\0");
        }

        // Truncated client IP. /24 for an IPv4 client, /48 for IPv6;
        // the standard "user roams within their ISP / cellular network
        // without re-fingerprinting" tolerance.
        if let Some(ip) = client_ip {
            mac.update(b"ip\0");
            mac.update(&truncate_ip(ip));
            mac.update(b"\0");
        }

        let bytes: [u8; 32] = mac.finalize().into_bytes().into();
        Some(FingerprintHash::from_bytes(bytes))
    }
}

/// Top-priority `Accept-Language` entry, in lower case.
/// `en-CH;q=0.9,en;q=0.5` → `"en-ch"`. Returns `None` when the header is
/// absent or empty.
fn accept_language_top(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::ACCEPT_LANGUAGE)?.to_str().ok()?;
    let head = raw.split(',').next()?.trim();
    let head = head.split(';').next()?.trim();
    if head.is_empty() {
        return None;
    }
    Some(head.to_ascii_lowercase())
}

/// Truncate an IP address for fingerprinting, on the network the throttle
/// and the rate limiter key it as (see `ClientNetwork`):
/// - an IPv4 client: the /24 of its address;
/// - an IPv6 address that carries an IPv4 client (IPv4-mapped, which a
///   dual-stack listener reports, IPv4-translated, IPv4-compatible, NAT64,
///   6to4, Teredo): the /24 of that client, as if it had arrived over IPv4;
/// - an address under the locally used NAT64 prefix: its /120, where an
///   IPv4 /24 sits under the common /96 translator prefix;
/// - any other IPv6 address: its /48.
///
/// Truncated as plain IPv6 addresses, the carrying forms kept only what
/// every client of one translator, relay or Teredo server shares (six zero
/// bytes for the mapped form, `64:ff9b::/48` for NAT64), and all of those
/// clients would share one fingerprint input.
///
/// Returns the raw bytes (4 or 16) with the trailing portion
/// zeroed, so a cellular user roaming within their ISP keeps one
/// fingerprint across NAT changes.
fn truncate_ip(ip: IpAddr) -> Vec<u8> {
    match ClientNetwork::of(ip) {
        ClientNetwork::V4(v4) => {
            let o = v4.octets();
            vec![o[0], o[1], o[2], 0]
        }
        ClientNetwork::Whole(v6) => (u128::from(v6) & (u128::MAX << 8)).to_be_bytes().to_vec(),
        ClientNetwork::Prefix64(net) => {
            (u128::from(net) & (u128::MAX << 80)).to_be_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests;
