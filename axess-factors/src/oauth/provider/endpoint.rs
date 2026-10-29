//! The transport rule for endpoints that receive a client secret, a token or
//! an authorization code: HTTPS, or an IETF loopback host over plain HTTP for
//! local development.
//!
//! Applied where the endpoint arrives (discovery) and again where it is used
//! (the setters take any string), so a URL typed into configuration cannot
//! send a secret in the clear however it got there.

use crate::oauth::types::OAuthError;

/// Refuse `url` unless it is HTTPS or loopback HTTP. `None` passes: an
/// endpoint that is not configured is not used. `what` names the setting in
/// the error; the URL itself is not echoed.
pub(super) fn require_secure(url: Option<&str>, what: &str) -> Result<(), OAuthError> {
    let Some(url) = url else {
        return Ok(());
    };
    crate::oidc::discovery::require_https_or_loopback(url).map_err(|_| {
        OAuthError::Config(format!(
            "{what} must use HTTPS (http is only allowed for localhost, 127.0.0.1 and [::1])"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_to_a_remote_host_is_refused_and_https_and_loopback_pass() {
        assert!(require_secure(Some("https://idp.example/token"), "t").is_ok());
        assert!(require_secure(Some("http://localhost:8080/token"), "t").is_ok());
        assert!(require_secure(Some("http://127.0.0.1/token"), "t").is_ok());
        assert!(require_secure(None, "t").is_ok());
        for bad in [
            "http://idp.example/token",
            "http://localhost.evil.test/token",
            "ftp://idp.example/token",
            "not a url",
            "",
        ] {
            let err = require_secure(Some(bad), "token_endpoint").expect_err(bad);
            let msg = err.to_string();
            assert!(msg.contains("token_endpoint"), "{msg}");
            assert!(!msg.contains(bad) || bad.is_empty(), "{msg}");
        }
    }
}
