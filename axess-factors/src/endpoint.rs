//! The rule an endpoint that receives credentials, or that a user is sent to,
//! must meet: HTTPS, or plain HTTP to a loopback host for local development.

/// Whether `url` is HTTPS, or HTTP to `localhost`, `127.0.0.1` or `[::1]`.
///
/// Parsed, not prefix-matched: `http://localhost.attacker.com`,
/// `http://127.0.0.1.nip.io` and `http://localhost@evil.com` all start with a
/// loopback spelling and none is loopback. The host decides, and a URL
/// carrying userinfo is refused outright, since `user@host` is how a prefix
/// test is defeated. A URL that does not parse is refused.
pub(crate) fn is_https_or_loopback(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    match parsed.scheme() {
        "https" => true,
        "http" => match parsed.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        },
        _ => false,
    }
}
