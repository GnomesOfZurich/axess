//! Bounded reads of token-endpoint response bodies, over
//! [`axess_factors::http_body`].
//!
//! A success body is a small JSON object and gets a 64 KiB cap; an error body
//! only feeds logs, so its first 1 KiB is kept and the rest is never read.

use axess_factors::http_body::{self, BodyError};
use zeroize::Zeroizing;

use crate::delegated::error::DelegatedError;

/// Largest success body read.
#[cfg(test)]
pub(crate) const MAX_SUCCESS_BODY_BYTES: usize = http_body::MAX_TOKEN_BODY_BYTES;

/// Read a success body, refusing one larger than the cap. The buffer is
/// zeroed on drop because it carries the tokens.
pub(crate) async fn read_success_body(
    response: &mut reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>, DelegatedError> {
    http_body::read_limited(response, http_body::MAX_TOKEN_BODY_BYTES)
        .await
        .map(Zeroizing::new)
        .map_err(|e| match e {
            BodyError::TooLarge { max } => {
                DelegatedError::MalformedResponse(format!("response body exceeds {max} bytes"))
            }
            BodyError::Read(e) => DelegatedError::MalformedResponse(e),
        })
}

/// The first 1 KiB of an error body, with a truncation suffix when cut.
pub(crate) async fn read_error_body(response: &mut reqwest::Response) -> String {
    http_body::read_error_snippet(response).await
}
