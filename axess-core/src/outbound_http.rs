//! Shared policy for the HTTP clients that carry credentials to a remote
//! token or STS endpoint: the endpoint must be HTTPS (plain HTTP only to a
//! loopback host), and the default client follows no redirects and has
//! connect and request timeouts. A redirect would re-send the credentials
//! (a 307 or 308 repeats the POST body) to wherever the response points.
//!
//! The module is compiled only with one of the features that bring such a
//! client (see its declaration in the crate root), so nothing in it repeats
//! that gate.

use url::Url;

/// Connect timeout of the default client.
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Request timeout of the default client. A request that sets its own
/// timeout replaces it for that request.
pub(crate) const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why an endpoint was refused. Carries no URL: a configured endpoint can
/// embed userinfo.
pub(crate) const REFUSED: &str =
    "endpoint must be https, or http to a loopback host, with no userinfo";

/// Accept `https`, or `http` to `localhost` or a loopback address, and
/// refuse userinfo. The host decides, not a prefix: `http://localhost.evil.com`
/// and `http://localhost@evil.com` are not loopback.
pub(crate) fn require_https_or_loopback(url: &Url) -> Result<(), &'static str> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(REFUSED);
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => match url.host() {
            Some(url::Host::Domain("localhost")) => Ok(()),
            Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
            Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
            _ => Err(REFUSED),
        },
        _ => Err(REFUSED),
    }
}

/// The default HTTP client of a credential-bearing outbound client (token
/// exchange, stored delegation, the cloud STS adapters) could not be built,
/// which happens when the TLS backend fails to initialise. Nothing is sent:
/// the alternative, a stock `reqwest::Client`, follows redirects and has no
/// timeouts, so it would carry the credentials wherever a redirect points and
/// hang on a stalled endpoint. The builder's error is the source.
#[derive(Debug, thiserror::Error)]
#[error("HTTP client could not be built: {0}")]
pub struct ClientBuildError(#[source] reqwest::Error);

/// The HTTP client of a credential-bearing outbound client: built by the
/// unscreened egress policy, so it follows no redirect, with a connect and
/// a request timeout first and the caller's settings after them.
///
/// Unscreened, because these endpoints are the adopter's own configuration
/// (a cloud STS endpoint, a token endpoint it registered) and each request
/// is held to the transport rule ([`require_https_or_loopback`]): the
/// environment's proxy is followed as a plain client follows it, and no
/// address is refused. The caller's settings are a
/// [`ClientSettings`](axess_factors::egress::ClientSettings), which offers
/// nothing that restores redirects.
///
/// # Errors
///
/// [`ClientBuildError`] when the client cannot be built; it is never
/// swallowed.
pub(crate) fn hardened_client(
    configure: impl FnOnce(
        axess_factors::egress::ClientSettings,
    ) -> axess_factors::egress::ClientSettings,
) -> Result<reqwest::Client, ClientBuildError> {
    hardened_screened_client(configure).map(axess_factors::egress::ScreenedClient::into_inner)
}

/// [`hardened_client`], kept in the type that says the library built it,
/// for a function that takes its client from the caller.
///
/// # Errors
///
/// [`ClientBuildError`] when the client cannot be built.
pub(crate) fn hardened_screened_client(
    configure: impl FnOnce(
        axess_factors::egress::ClientSettings,
    ) -> axess_factors::egress::ClientSettings,
) -> Result<axess_factors::egress::ScreenedClient, ClientBuildError> {
    axess_factors::egress::EgressPolicy::unscreened()
        .build_client(|settings| {
            configure(
                settings
                    .connect_timeout(CONNECT_TIMEOUT)
                    .timeout(REQUEST_TIMEOUT),
            )
        })
        .map_err(ClientBuildError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> bool {
        require_https_or_loopback(&Url::parse(s).unwrap()).is_ok()
    }

    #[test]
    fn https_and_loopback_http_are_accepted() {
        assert!(ok("https://sts.example.com/token"));
        assert!(ok("http://localhost:8080/t"));
        assert!(ok("http://127.0.0.1:1/t"));
        assert!(ok("http://[::1]:1/t"));
    }

    #[test]
    fn remote_http_userinfo_and_other_schemes_are_refused() {
        assert!(!ok("http://sts.example.com/token"));
        assert!(!ok("http://localhost.evil.com/t"));
        assert!(!ok("http://127.0.0.1.nip.io/t"));
        assert!(!ok("https://user:pw@sts.example.com/t"));
        assert!(!ok("http://localhost@evil.com/t"));
        assert!(!ok("ftp://localhost/t"));
    }

    /// A client that cannot be built is an error, never `reqwest::Client::default()`
    /// (redirects followed, no timeouts) in its place. A `User-Agent` that is
    /// not a header value is a build failure a test can arrange whatever TLS
    /// backend the feature set resolves to.
    #[test]
    fn a_client_that_cannot_be_built_is_an_error_not_a_default_client() {
        let result = hardened_client(|settings| settings.user_agent("not a\nheader value"));
        assert!(
            result.is_err(),
            "a failed build must surface, not fall back to an unhardened client"
        );
        assert!(
            hardened_client(|settings| settings).is_ok(),
            "the default build still succeeds"
        );
    }
}
