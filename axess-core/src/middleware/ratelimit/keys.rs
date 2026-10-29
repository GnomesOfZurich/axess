//! Bucket-key derivation for the rate limiter.
//!
//! A key is whatever the configured [`KeyExtractor`] reads from the request,
//! bounded so that neither its length nor the number of keys one identity can
//! create is under the caller's control: an over-long key is cut and suffixed
//! with a digest of the whole, a header value only selects one of
//! [`HEADER_SLOTS`] sub-buckets of its user, and an IPv6 client is keyed by
//! its /64 prefix. Every key starts with a kind (`ip:`, `user:`, `login:` ...)
//! so a value one caller chooses (a login name) can never equal a sentinel or
//! another kind's key, and a key that was cut can never equal one that was
//! not.

use super::{KeyExtractor, RateLimitLoginIdentifier, RateLimitTenantId, RateLimitUserId};
use axum::{body::Body, http::Request};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Header sub-buckets one authenticated user can hold. A header value picks
/// its slot by digest, so a user sending any number of distinct values holds
/// at most this many buckets and cannot fill the shared table.
pub(super) const HEADER_SLOTS: u64 = 16;

/// Sentinel bucket key for unauthenticated requests when the extractor is
/// scoped to an authenticated identity (`UserId` / `TenantId`). All such
/// requests share a single bucket so the per-identity rate limit cannot be
/// trivially evaded by sending unauthenticated traffic; they are
/// rate-limited collectively under this key.
pub(super) const ANONYMOUS_BUCKET: &str = "anon";

/// Bucket for requests whose origin could not be established: no peer
/// address, or no `ClientIp` because the layer is not installed. Everything
/// unattributable shares it, which limits harder rather than less.
///
/// The failure mode is worth stating plainly, because it is total. On a
/// route where nothing resolves an address, every caller shares this one
/// bucket, so a single client can exhaust the limit for everybody. That is
/// the correct trade against the alternative, which is keying on something
/// the caller chooses and so enforcing nothing at all, but it is a denial
/// of service reachable from a misconfiguration rather than from a bug.
/// Install the layer, and alert on a non-zero count of audit rows carrying
/// `ip_source = 'unknown'`, which is the same misconfiguration seen from
/// the other side.
pub(super) const UNKNOWN_BUCKET: &str = "unknown";

/// The most live buckets one address group (an IPv6 /48 or an IPv4 /24) may
/// hold. A new key past this folds into the group's shared overflow bucket,
/// so one allocation cannot fill the table with the /64s it can mint.
pub(super) const GROUP_BUCKET_CAP: usize = 1024;

/// Longest bucket key (bytes). A key over this is cut and suffixed with a
/// digest of the whole key (see [`bound_key`]), so a megabyte-sized
/// identifier cannot inflate per-bucket allocation and two long identifiers
/// that share a prefix still get different buckets. Real values (addresses,
/// UUIDs, identifiers) are far smaller than this.
pub(super) const MAX_KEY_LEN: usize = 256;

/// Bytes of the original key kept in front of the digest suffix.
const KEPT_PREFIX_LEN: usize = MAX_KEY_LEN - 65;

/// Longest key left as it is. A cut key is at least `KEPT_PREFIX_LEN - 3`
/// (the cut backs up to a character boundary) plus the separator plus 64
/// digest characters long, so every cut key is longer than every key left
/// alone: a caller cannot submit the shortened form of someone else's long
/// key and land in that bucket.
const MAX_NATURAL_KEY_LEN: usize = KEPT_PREFIX_LEN - 4;

/// Bound `key` to [`MAX_KEY_LEN`] bytes.
///
/// A key of at most `MAX_NATURAL_KEY_LEN` bytes is returned unchanged. A
/// longer one is cut at a UTF-8 boundary to `KEPT_PREFIX_LEN` bytes and
/// suffixed with `:` and the lowercase hex SHA-256 of the full key, so keys
/// that differ only after the cut stay different, and the result is longer
/// than any unchanged key, so a cut key never equals an uncut one.
pub(super) fn bound_key(key: String) -> String {
    if key.len() <= MAX_NATURAL_KEY_LEN {
        return key;
    }
    let mut cut = KEPT_PREFIX_LEN;
    while !key.is_char_boundary(cut) {
        cut -= 1;
    }
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::with_capacity(MAX_KEY_LEN);
    out.push_str(&key[..cut]);
    out.push(':');
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The sub-bucket slot a header value selects: the first eight bytes of its
/// SHA-256, modulo [`HEADER_SLOTS`].
fn header_slot(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % HEADER_SLOTS
}

/// The bucket name for a client address: the address itself for IPv4, the
/// /64 prefix for IPv6.
///
/// A single IPv6 subscriber is routinely handed a whole /64, so keying on the
/// full address would give one client 2^64 buckets. An IPv4-mapped IPv6
/// address is keyed as the IPv4 address it carries.
pub(super) fn ip_bucket(addr: IpAddr) -> String {
    match addr.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            format!("{}/64", std::net::Ipv6Addr::from(masked))
        }
    }
}

/// The group an address counts against: its IPv4 /24, or its IPv6 /48.
///
/// A /48 holds 65,536 /64s, each its own bucket, so one allocation could
/// otherwise mint enough keys to fill the table. Past [`GROUP_BUCKET_CAP`]
/// live buckets in a group, new keys of that group share the group's
/// overflow bucket. The group is also what a login-identifier overflow is
/// keyed on for an IPv6 client.
pub(super) fn ip_group(addr: IpAddr) -> String {
    match addr.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 80);
            format!("{}/48", std::net::Ipv6Addr::from(masked))
        }
    }
}

/// Where a request's tokens come from, and what to do when that bucket does
/// not exist yet and the table cannot take it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Target {
    /// The bucket key.
    pub(super) key: String,
    /// The address group this key counts against, when it is derived from an
    /// address. A new key is refused its own bucket once the group holds
    /// [`GROUP_BUCKET_CAP`].
    pub(super) group: Option<String>,
    /// The shared bucket a new key folds into when it is refused its own.
    pub(super) fold_into: Option<String>,
    /// Fold a new key into `fold_into` as soon as the table is three quarters
    /// full, not only when its group is. Set for login identifiers, which an
    /// unauthenticated caller mints freely.
    pub(super) fold_near_cap: bool,
    /// Whether other callers draw on this bucket too. The remaining count of
    /// such a bucket says something about other people, so it is not sent
    /// back in a header.
    pub(super) shared: bool,
}

impl Target {
    /// A plain bucket: no group, nothing to fold into.
    pub(super) fn plain(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            group: None,
            fold_into: None,
            fold_near_cap: false,
            shared: false,
        }
    }

    fn shared(key: &str) -> Self {
        Self {
            shared: true,
            ..Self::plain(key)
        }
    }

    fn address(addr: IpAddr, prefix: &str) -> Self {
        let group = ip_group(addr);
        Self {
            key: bound_key(format!("{prefix}{}", ip_bucket(addr))),
            fold_into: Some(format!("{group}:ovf")),
            group: Some(group),
            fold_near_cap: false,
            shared: false,
        }
    }
}

/// The bucket key for a request, as a plain string (the same key
/// [`resolve_target`] puts in [`Target::key`]).
#[cfg(test)]
pub(super) fn extract_key(req: &Request<Body>, extractor: &KeyExtractor) -> String {
    resolve_target(req, extractor).key
}

pub(super) fn resolve_target(req: &Request<Body>, extractor: &KeyExtractor) -> Target {
    match extractor {
        KeyExtractor::ClientIp => client_ip_target(req),
        KeyExtractor::PeerIp => peer_target(req, ""),
        KeyExtractor::UserId => req
            .extensions()
            .get::<RateLimitUserId>()
            .map(|u| Target::plain(bound_key(format!("user:{}", u.0))))
            .unwrap_or_else(|| Target::shared(ANONYMOUS_BUCKET)),
        KeyExtractor::TenantId => req
            .extensions()
            .get::<RateLimitTenantId>()
            .map(|t| Target {
                // Many users draw on one tenant bucket.
                shared: true,
                ..Target::plain(bound_key(format!("tenant:{}", t.0)))
            })
            .unwrap_or_else(|| Target::shared(ANONYMOUS_BUCKET)),
        KeyExtractor::LoginIdentifier => match req.extensions().get::<RateLimitLoginIdentifier>() {
            Some(id) => Target {
                key: bound_key(format!("login:{}", id.bucket_key())),
                group: None,
                // Folded by origin: the group for an IPv6 client, so the
                // overflow itself cannot be minted per /64.
                fold_into: Some(format!("login-ovf:{}", origin_group(req))),
                fold_near_cap: true,
                // Everyone who targets this account shares it.
                shared: true,
            },
            None => Target::shared(ANONYMOUS_BUCKET),
        },
        // A header value is the caller's own claim, so it only subdivides a
        // bucket the caller cannot choose: an authenticated identity. Without
        // one, every value would be a fresh bucket for the asking. The
        // identity and the `h:` prefix keep one user's header values out of
        // another user's buckets and out of the address buckets.
        KeyExtractor::Header(name) => {
            match (
                req.extensions().get::<RateLimitUserId>(),
                header_str(req, name),
            ) {
                (Some(user), Some(v)) => {
                    Target::plain(bound_key(format!("h:{}:{}", user.0, header_slot(&v))))
                }
                _ => peer_target(req, "ip:"),
            }
        }
    }
}

/// The group of the request's origin: the resolved client address when the
/// client-IP layer ran, else the TCP peer.
fn origin_group(req: &Request<Body>) -> String {
    let resolved = req
        .extensions()
        .get::<crate::client_ip::ClientIp>()
        .and_then(|ip| ip.get());
    match resolved.or_else(|| peer_addr(req)) {
        Some(addr) => ip_group(addr),
        None => UNKNOWN_BUCKET.to_owned(),
    }
}

/// Read the address `client_ip::layer` resolved for this request.
///
/// No header is consulted here. A missing `ClientIp` means the layer is
/// not installed, and the answer is the shared bucket rather than a guess:
/// a guess would be the caller's own claim, which is what this replaced.
fn client_ip_target(req: &Request<Body>) -> Target {
    match req.extensions().get::<crate::client_ip::ClientIp>() {
        Some(ip) => match ip.get() {
            Some(addr) => Target::address(addr, "ip:"),
            None => Target::shared(UNKNOWN_BUCKET),
        },
        None => {
            use std::sync::Once;
            static WARN: Once = Once::new();
            WARN.call_once(|| {
                tracing::warn!(
                    "ClientIp rate limiting: no ClientIp in request extensions; \
                     all requests share one bucket. Wrap the router in \
                     axess_core::client_ip::layer."
                );
            });
            Target::shared(UNKNOWN_BUCKET)
        }
    }
}

/// The TCP peer address in the request extensions, if any.
///
/// Looks for axum's `ConnectInfo<SocketAddr>` (populated when the server
/// is mounted via `Router::into_make_service_with_connect_info::<SocketAddr>()`),
/// then falls back to a bare `SocketAddr` (which some integrations insert
/// directly, e.g. test harnesses that wire the extension by hand).
fn peer_addr(req: &Request<Body>) -> Option<IpAddr> {
    let ext = req.extensions();
    ext.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0)
        .or_else(|| ext.get::<std::net::SocketAddr>().copied())
        .map(|addr| addr.ip())
}

/// The bucket for the TCP peer, with `prefix` in front of its address.
///
/// Falls back to a shared bucket (`"unknown"`) if no peer address is
/// available. This is fail-closed: all unknown-origin requests share one
/// bucket, meaning stricter (not weaker) rate limiting.
fn peer_target(req: &Request<Body>, prefix: &str) -> Target {
    match peer_addr(req) {
        Some(addr) => Target::address(addr, prefix_or_ip(prefix)),
        None => {
            use std::sync::Once;
            static WARN: Once = Once::new();
            WARN.call_once(|| {
                tracing::warn!(
                    "PeerIp rate limiting: no SocketAddr in request extensions; \
                     all requests will share a single bucket. Use \
                     Router::into_make_service_with_connect_info::<SocketAddr>() \
                     or, behind a proxy, client_ip::layer with \
                     KeyExtractor::ClientIp."
                );
            });
            Target::shared(&format!("{}{UNKNOWN_BUCKET}", prefix_or_ip(prefix)))
        }
    }
}

fn prefix_or_ip(prefix: &str) -> &str {
    if prefix.is_empty() { "ip:" } else { prefix }
}

fn header_str(req: &Request<Body>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

/// A short stand-in for `key` that is safe to log: the first eight bytes of
/// its HMAC-SHA256 under `secret`, in hex.
///
/// The key can be a login identifier or a user id, which a debug log should
/// not carry. A plain hash of an email address or username can be reversed
/// with a dictionary, so the hash is keyed with a per-instance random
/// `secret` that never leaves the process: two log lines of one instance for
/// one bucket still match, and nothing else can be recovered from them.
pub(super) fn fingerprint(secret: &[u8], key: &str) -> String {
    use hmac::Mac as _;
    let mut mac = crate::hmac::new_signer(secret);
    mac.update(key.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
