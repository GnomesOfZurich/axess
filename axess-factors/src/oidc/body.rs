//! Bounded read of a discovery or JWKS response body, over
//! [`crate::http_body`].

/// Read `response` into memory, failing with `too_large` as soon as the body
/// passes `max` bytes, and with `read_error(e)` when the transfer fails.
pub(super) async fn read_capped<E>(
    response: &mut openidconnect::reqwest::Response,
    max: usize,
    too_large: impl Fn() -> E,
    read_error: impl Fn(String) -> E,
) -> Result<Vec<u8>, E> {
    use crate::http_body::{BodyError, read_limited};
    read_limited(response, max).await.map_err(|e| match e {
        BodyError::TooLarge { .. } => too_large(),
        BodyError::Read(e) => read_error(e),
    })
}
