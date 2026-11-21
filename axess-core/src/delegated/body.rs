//! Bounded reads of token-endpoint response bodies, over
//! [`axess_factors::http_body`].
//!
//! A success body is a small JSON object and gets a 64 KiB cap; an error body
//! is read up to 64 KiB for its `error` code, and only its first 1 KiB
//! reaches an error message.

use axess_factors::http_body::{self, BodyError};
use zeroize::Zeroizing;

use crate::delegated::error::DelegatedError;

/// Largest success body read, for the stored grant's response tests.
#[cfg(all(test, feature = "delegated-stored"))]
pub(crate) const MAX_SUCCESS_BODY_BYTES: usize = http_body::MAX_TOKEN_BODY_BYTES;

/// Read a success body, refusing one larger than the cap. The buffer is
/// zeroed on drop because it carries the tokens.
pub(crate) async fn read_success_body(
    response: &mut reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>, DelegatedError> {
    http_body::read_limited(response, http_body::MAX_TOKEN_BODY_BYTES)
        .await
        .map_err(|e| match e {
            BodyError::TooLarge { max } => {
                DelegatedError::MalformedResponse(format!("response body exceeds {max} bytes"))
            }
            BodyError::Read(e) => DelegatedError::MalformedResponse(e),
        })
}

/// An error body, read up to 64 KiB for the error code it may carry.
pub(crate) async fn read_error_body(response: &mut reqwest::Response) -> http_body::ErrorBody {
    http_body::ErrorBody::read(response).await
}

/// The first 1 KiB of `body`, as [`read_error_body`] returned it, made safe
/// for an error message: every character
/// [`escapes`](axess_identity::log_text::escapes) names (control characters,
/// the line and paragraph separators, bidirectional controls, zero-width
/// characters, the byte order mark, the Hangul fillers) escaped, and a
/// truncation suffix when it was cut.
pub(crate) fn log_safe(body: &http_body::ErrorBody) -> String {
    http_body::log_safe_snippet(&body.snippet())
}
