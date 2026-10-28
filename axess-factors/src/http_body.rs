//! Bounded reads of HTTP response bodies from a remote party.
//!
//! Every endpoint axess calls (token, userinfo, discovery, JWKS, cloud STS) is
//! configured by the adopter but answers over the network, so a body is read
//! in chunks and stops at a cap instead of being buffered whole. A success
//! body is small JSON and gets a cap that refuses anything larger; an error
//! body only feeds logs, so its first [`ERROR_BODY_BYTES`](crate::http_body::ERROR_BODY_BYTES) are kept and the
//! rest is never read.

use std::fmt;

/// Largest token-endpoint success body read: a token response is a few hundred
/// bytes, and 64 KiB leaves room for large JWT access tokens and vendor
/// extensions.
pub const MAX_TOKEN_BODY_BYTES: usize = 64 * 1024;

/// Largest userinfo success body read. Larger than a token body because
/// userinfo can carry group and role lists (an Azure AD user in a thousand
/// groups is about 40 KiB).
pub const MAX_USERINFO_BODY_BYTES: usize = 256 * 1024;

/// Bytes of an error body kept.
pub const ERROR_BODY_BYTES: usize = 1024;

/// Appended to an error body that was cut at [`ERROR_BODY_BYTES`].
pub const TRUNCATED_SUFFIX: &str = "…[truncated]";

/// Why a bounded read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// The body is larger than the cap.
    TooLarge {
        /// The cap that was passed, in bytes.
        max: usize,
    },
    /// The transfer failed.
    Read(String),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max } => write!(f, "response body exceeds {max} bytes"),
            Self::Read(e) => write!(f, "read body: {e}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// Read a body of at most `max` bytes.
///
/// A declared `Content-Length` above the cap is refused before anything is
/// read; without one, the chunk that crosses the cap ends the read, so at most
/// the cap plus one chunk is ever held.
pub async fn read_limited(
    response: &mut reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(BodyError::TooLarge { max });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| BodyError::Read(e.to_string()))?
    {
        if body.len() + chunk.len() > max {
            return Err(BodyError::TooLarge { max });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read the first [`ERROR_BODY_BYTES`] of an error body as lossy UTF-8, with
/// [`TRUNCATED_SUFFIX`] appended when more followed. Reading stops once the
/// cap is passed; a failed read ends the body where it stood.
pub async fn read_error_snippet(response: &mut reqwest::Response) -> String {
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Ok(Some(chunk)) = response.chunk().await {
        let room = ERROR_BODY_BYTES - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let mut text = String::from_utf8_lossy(&body).into_owned();
    if truncated {
        text.push_str(TRUNCATED_SUFFIX);
    }
    text
}

/// Read a body whichever the status: a success body in full up to
/// `success_max` ([`BodyError::TooLarge`] past it), any other status as the
/// error snippet's bytes (never an error for size). For callers that format
/// the body into their own error.
pub async fn read_for_status(
    response: &mut reqwest::Response,
    success_max: usize,
) -> Result<Vec<u8>, BodyError> {
    if response.status().is_success() {
        read_limited(response, success_max).await
    } else {
        Ok(read_error_snippet(response).await.into_bytes())
    }
}
