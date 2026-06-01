//! [`DeviceFingerprintExtractor`]: pluggable computation of
//! [`FingerprintHash`] from an HTTP request.
//!
//! # Why a trait
//!
//! The choice of inputs (full UA vs UA-family-only, IPv4 /24 vs /32,
//! Accept-Language top entry vs full list, screen-class bucket vs
//! none) is a privacy/proportionality decision that varies by
//! deployment. A regulated-fintech app will want the minimum useful
//! set per [`docs/identity/device.md`] §4.3 (data minimisation
//! Art 5(1)(c)); a hobby project may not bother with IP truncation.
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
//! ([`docs/identity/device.md`] §10, "Cross-tenant correlation by a
//! malicious tenant"). The default extractor takes a closure that
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
    /// `User-Agent` for a UA-required extractor). Callers treat
    /// `None` as "skip device tracking for this request", never as
    /// an error.
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
/// The pepper must be stable for the lifetime of the tenant: a
/// rotation invalidates every existing fingerprint hash for that
/// tenant. Most deployments derive the pepper from a master key via
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
        // Skip when there's nothing meaningful to fingerprint;
        // a request with no UA AND no IP is too thin to identify.
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

        // Truncated client IP. /24 for IPv4, /48 for IPv6; the
        // standard "user roams within their ISP / cellular network
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

/// Top-priority `Accept-Language` entry. `en-CH;q=0.9,en;q=0.5` →
/// `"en-CH"`. Returns `None` when the header is absent or empty.
fn accept_language_top(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::ACCEPT_LANGUAGE)?.to_str().ok()?;
    let head = raw.split(',').next()?.trim();
    let head = head.split(';').next()?.trim();
    if head.is_empty() {
        return None;
    }
    Some(head.to_ascii_lowercase())
}

/// Truncate an IP address for fingerprinting:
/// - IPv4: first 3 octets (drop last), /24.
/// - IPv6: first 6 bytes (drop last 10), /48.
///
/// Returns the raw bytes (4 or 16) with the trailing portion
/// zeroed, so a cellular user roaming within their ISP doesn't
/// generate a new device row on every NAT change.
fn truncate_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            vec![o[0], o[1], o[2], 0]
        }
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            // Zero bytes 6..16 → /48.
            for byte in &mut o[6..] {
                *byte = 0;
            }
            o.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn parts(ua: Option<&str>, al: Option<&str>) -> Parts {
        let mut r: Request<()> = Request::new(());
        if let Some(v) = ua {
            r.headers_mut()
                .insert(header::USER_AGENT, HeaderValue::from_str(v).unwrap());
        }
        if let Some(v) = al {
            r.headers_mut()
                .insert(header::ACCEPT_LANGUAGE, HeaderValue::from_str(v).unwrap());
        }
        r.into_parts().0
    }

    fn tenant() -> TenantId {
        crate::authn::ids::testing::tenant("tenant-1")
    }

    fn fixed_pepper() -> TenantPepperResolver {
        Arc::new(|t: &TenantId| {
            t.as_uuid();
            [42u8; 32]
        })
    }

    fn extractor() -> DefaultFingerprintExtractor {
        DefaultFingerprintExtractor::new(fixed_pepper())
    }

    /// Pin: same inputs → same hash. The whole point of the type.
    #[test]
    fn deterministic_on_same_inputs() {
        let ext = extractor();
        let r1 = parts(Some("Mozilla/5.0"), Some("en-CH;q=0.9,en;q=0.5"));
        let r2 = parts(Some("Mozilla/5.0"), Some("en-CH;q=0.9,en;q=0.5"));
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        let f1 = ext.extract(&tenant(), &r1, ip).unwrap();
        let f2 = ext.extract(&tenant(), &r2, ip).unwrap();
        assert_eq!(f1, f2);
    }

    /// Pin: different UA → different hash.
    #[test]
    fn different_user_agents_yield_different_hashes() {
        let ext = extractor();
        let r1 = parts(Some("Mozilla/5.0 (Macintosh)"), None);
        let r2 = parts(Some("Mozilla/5.0 (Windows)"), None);
        let f1 = ext.extract(&tenant(), &r1, None).unwrap();
        let f2 = ext.extract(&tenant(), &r2, None).unwrap();
        assert_ne!(f1, f2);
    }

    /// Pin: missing UA → None (extractor refuses to fingerprint a
    /// UA-less request, mirroring the threshold in
    /// `session::binding::UserAgentBinding`).
    #[test]
    fn missing_ua_returns_none() {
        let ext = extractor();
        let r = parts(None, Some("en"));
        assert!(ext.extract(&tenant(), &r, None).is_none());
    }

    /// Pin: tenant scoping. Different tenants on the same request
    /// produce different hashes (cross-tenant correlation defence).
    #[test]
    fn different_tenants_yield_different_hashes() {
        let pepper: TenantPepperResolver = Arc::new(|t: &TenantId| {
            // Trivial differentiation: hash the tenant id as the pepper.
            // Real deployments derive via HKDF.
            let mut k = [0u8; 32];
            for (i, b) in t.as_bytes().iter().copied().enumerate().take(32) {
                k[i] = b;
            }
            k
        });
        let ext = DefaultFingerprintExtractor::new(pepper);
        let r = parts(Some("Mozilla/5.0"), None);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let t1 = crate::authn::ids::testing::tenant("acme");
        let t2 = crate::authn::ids::testing::tenant("globex");
        let f1 = ext.extract(&t1, &r, ip).unwrap();
        let f2 = ext.extract(&t2, &r, ip).unwrap();
        assert_ne!(
            f1, f2,
            "same physical device under two tenants must hash differently"
        );
    }

    /// Pin: IPv4 truncation to /24. `10.0.0.42` and `10.0.0.7`
    /// hash identically (both /24-mapped to `10.0.0.0`); but
    /// `10.0.1.42` differs.
    #[test]
    fn ipv4_truncates_to_slash_24() {
        let ext = extractor();
        let r = parts(Some("Mozilla/5.0"), None);
        let f_a = ext
            .extract(&tenant(), &r, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))))
            .unwrap();
        let f_b = ext
            .extract(&tenant(), &r, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))))
            .unwrap();
        let f_c = ext
            .extract(&tenant(), &r, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 42))))
            .unwrap();
        assert_eq!(f_a, f_b, "/24 partners must collide");
        assert_ne!(f_a, f_c, "different /24s must produce different hashes");
    }

    /// Pin: IPv6 truncation to /48.
    #[test]
    fn ipv6_truncates_to_slash_48() {
        let ext = extractor();
        let r = parts(Some("Mozilla/5.0"), None);
        let same_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x0001, 0, 0, 0, 0x42));
        let same_b = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xabcd, 0x9999, 0xffff, 0xffff, 0xffff, 0x07,
        ));
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xfeed, 0x0001, 0, 0, 0, 0x42));
        let f_a = ext.extract(&tenant(), &r, Some(same_a)).unwrap();
        let f_b = ext.extract(&tenant(), &r, Some(same_b)).unwrap();
        let f_c = ext.extract(&tenant(), &r, Some(other)).unwrap();
        assert_eq!(f_a, f_b, "/48 partners must collide");
        assert_ne!(f_a, f_c);
    }

    /// Pin: Accept-Language parsing extracts the top entry only,
    /// strips the q-value, and lowercases. `en-CH;q=0.9,en;q=0.5` →
    /// `"en-ch"`.
    #[test]
    fn accept_language_takes_top_priority_only() {
        let ext = extractor();
        let r1 = parts(Some("Mozilla/5.0"), Some("en-CH;q=0.9,en;q=0.5"));
        let r2 = parts(Some("Mozilla/5.0"), Some("en-ch"));
        let f1 = ext.extract(&tenant(), &r1, None).unwrap();
        let f2 = ext.extract(&tenant(), &r2, None).unwrap();
        assert_eq!(
            f1, f2,
            "top entry of Accept-Language with q-value must equal the bare top entry"
        );
    }

    /// mutant kill: pins `accept_language_top` against
    /// constant-replacement mutants (`-> None`, `Some("")`,
    /// `Some("xyzzy")`). Each constant-replacement mutant collapses
    /// every request to a single AL contribution, so requests with
    /// *different* AL headers would all hash identically. That's the
    /// observable difference the previous tests didn't exercise. We
    /// pin (a) presence-of-AL changes the hash vs absence-of-AL, and
    /// (b) two distinct AL values produce two distinct hashes.
    #[test]
    fn accept_language_value_actually_feeds_the_hash() {
        let ext = extractor();
        let no_al = parts(Some("Mozilla/5.0"), None);
        let with_en = parts(Some("Mozilla/5.0"), Some("en-CH"));
        let with_de = parts(Some("Mozilla/5.0"), Some("de-CH"));

        let h_none = ext.extract(&tenant(), &no_al, None).unwrap();
        let h_en = ext.extract(&tenant(), &with_en, None).unwrap();
        let h_de = ext.extract(&tenant(), &with_de, None).unwrap();

        assert_ne!(
            h_none, h_en,
            "no Accept-Language vs en-CH must hash differently; \
             a constant-`None` mutant on accept_language_top would collapse them"
        );
        assert_ne!(
            h_en, h_de,
            "two distinct Accept-Language values must hash differently; \
             a constant-`Some(\"xyzzy\")` mutant would collapse them"
        );
    }

    /// mutant kill: `extract_from_request` is the
    /// `Request<B>`-flavoured convenience wrapper; previous tests went
    /// through `extract(&Parts, …)` directly so the helper body never
    /// ran. Pin its happy path: round-trips a UA-bearing request and
    /// matches what `extract` produces from the same headers.
    #[test]
    fn extract_from_request_matches_extract_on_equivalent_inputs() {
        let ext = extractor();
        let mut req: Request<()> = Request::new(());
        req.headers_mut().insert(
            header::USER_AGENT,
            HeaderValue::from_str("Mozilla/5.0").unwrap(),
        );
        req.headers_mut().insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_str("en-CH").unwrap(),
        );
        let from_request = ext
            .extract_from_request(&tenant(), &req, None)
            .expect("UA-bearing request must produce a fingerprint");

        let p = parts(Some("Mozilla/5.0"), Some("en-CH"));
        let from_parts = ext.extract(&tenant(), &p, None).unwrap();

        assert_eq!(
            from_request, from_parts,
            "extract_from_request must agree with extract on equivalent headers"
        );
    }
}
