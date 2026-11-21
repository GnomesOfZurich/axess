//! Bounded read of a discovery or JWKS response body, over
//! [`crate::http_body`], and the check that the answer came from the URL
//! that was asked.

/// Refuse an answer that is a redirect, or that came from another URL than
/// `requested`. The first is what a client the egress policy built sees,
/// since it follows no redirect; the second is what a client that followed
/// one would produce, and is checked so the rule does not rest on the
/// client's settings alone. The message names the status, never the URL the
/// answer came from.
pub(super) fn require_answered_in_place(
    response: &openidconnect::reqwest::Response,
    requested: &openidconnect::reqwest::Url,
) -> Result<(), String> {
    let status = response.status();
    if status.is_redirection() {
        return Err(format!("HTTP {status}: a redirect, which is not followed"));
    }
    if response.url() != requested {
        return Err(
            "answered from another URL than the one requested: a redirect was followed".to_owned(),
        );
    }
    Ok(())
}

/// Read `response` into memory, failing with `too_large` as soon as the body
/// passes `max` bytes, and with `read_error(e)` when the transfer fails.
pub(super) async fn read_capped<E>(
    response: &mut openidconnect::reqwest::Response,
    max: usize,
    too_large: impl Fn() -> E,
    read_error: impl Fn(String) -> E,
) -> Result<zeroize::Zeroizing<Vec<u8>>, E> {
    use crate::http_body::{BodyError, read_limited};
    read_limited(response, max).await.map_err(|e| match e {
        BodyError::TooLarge { .. } => too_large(),
        BodyError::Read(e) => read_error(e),
    })
}
