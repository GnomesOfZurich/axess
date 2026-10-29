//! Shared policy for the HTTP clients that carry credentials to a remote
//! token or STS endpoint: the endpoint must be HTTPS (plain HTTP only to a
//! loopback host), and the default client follows no redirects and has
//! connect and request timeouts. A redirect would re-send the credentials
//! (a 307 or 308 repeats the POST body) to wherever the response points.

use std::time::Duration;

use url::Url;

/// Connect timeout of the default client.
#[cfg(feature = "delegated-exchange")]
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Request timeout of the default client.
#[cfg(feature = "delegated-exchange")]
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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

/// A client that follows no redirects and has a connect and a request timeout.
#[cfg(feature = "delegated-exchange")]
pub(crate) fn hardened_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_default()
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
}
