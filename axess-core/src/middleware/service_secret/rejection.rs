//! Why a service-secret check refused a request, and the log line it leaves.
//!
//! Every refusal is one event on the `axess::service_secret` target with a
//! `reason` field. Most are `debug`, because a wrong credential is routine;
//! a replayed signature and a full replay cache are `warn`, because the
//! first is evidence of a captured request and the second is the layer
//! refusing good traffic. An event never carries the secret, the signature
//! tag or the timestamp, only the reason, the caller's configured name
//! where one was identified, and the peer address when one is known.

use super::ServiceCaller;
use axum::http::StatusCode;
use axum::{body::Body, extract::ConnectInfo, extract::Request};
use std::net::{IpAddr, SocketAddr};

/// The tracing target of every event in this module.
pub(super) const TARGET: &str = "axess::service_secret";

/// The reason a request did not authenticate.
#[derive(Debug)]
pub(super) enum Rejection {
    /// No credential was presented.
    NoCredential,
    /// A bearer or header secret matched no configured secret.
    BadSecret,
    /// The signature header was absent, unparseable, or carried no tag of
    /// the scheme this route reads (v2 with an audience, v1 without).
    Malformed,
    /// The timestamp is outside the tolerance.
    StaleStamp,
    /// The body is over the limit.
    TooLarge,
    /// The signature matched no configured secret.
    BadSignature,
    /// The signature was valid and had been seen before.
    Replay(ServiceCaller),
    /// The replay cache is full of live entries.
    CacheFull,
}

impl Rejection {
    /// The status the request is refused with.
    pub(super) fn status(&self) -> StatusCode {
        match self {
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::CacheFull => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    /// Whether this refusal is logged at `warn` rather than `debug`.
    pub(super) fn warns(&self) -> bool {
        matches!(self, Self::Replay(_) | Self::CacheFull)
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::NoCredential => "no_credential",
            Self::BadSecret => "bad_secret",
            Self::Malformed => "malformed",
            Self::StaleStamp => "stale_stamp",
            Self::TooLarge => "too_large",
            Self::BadSignature => "bad_signature",
            Self::Replay(_) => "replay",
            Self::CacheFull => "cache_full",
        }
    }

    /// Emit the event. `warn_due` is false when the caller has already
    /// emitted a warning in this second, which demotes the event to `debug`.
    pub(super) fn log(&self, peer: Option<IpAddr>, warn_due: bool) {
        let reason = self.reason();
        let peer = peer.map(|ip| ip.to_string());
        let peer = peer.as_deref().unwrap_or("unknown");
        match self {
            Self::Replay(caller) if warn_due => tracing::warn!(
                target: TARGET,
                reason,
                caller = caller.name(),
                peer,
                "service request refused",
            ),
            Self::CacheFull if warn_due => tracing::warn!(
                target: TARGET,
                reason,
                peer,
                "service request refused",
            ),
            _ => tracing::debug!(
                target: TARGET,
                reason,
                peer,
                "service request refused",
            ),
        }
    }
}

/// The address of the peer, from the resolved client address when the
/// `client_ip` layer ran, else from the connection.
pub(super) fn peer_of(req: &Request<Body>) -> Option<IpAddr> {
    req.extensions()
        .get::<crate::client_ip::ClientIp>()
        .and_then(|ip| ip.get())
        .or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
        })
}
