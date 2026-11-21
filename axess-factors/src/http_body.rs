//! Bounded reads of HTTP response bodies from a remote party.
//!
//! Every endpoint axess calls (token, userinfo, discovery, JWKS, cloud STS) is
//! configured by the adopter but answers over the network, so a body is read
//! in chunks and stops at a cap instead of being buffered whole. A success
//! body is small JSON and gets a cap that refuses anything larger; an error
//! body only feeds logs, so its first [`ERROR_BODY_BYTES`](crate::http_body::ERROR_BODY_BYTES) are kept and the
//! rest is never read.

use std::fmt;
use zeroize::Zeroizing;

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

/// The most bytes [`log_safe`] writes for one byte of its input: six, the
/// `\u{1b}` of a one-byte control character. A longer character it escapes
/// is two or three bytes and writes at most eight (`\u{202e}`).
const LONGEST_ESCAPE_BYTES: usize = 6;

/// The most bytes [`log_safe_snippet`] returns: every byte of an error
/// snippet written as its longest escape, and the truncation suffix. A
/// snippet [`read_error_snippet`] read is never cut again, so the suffix it
/// carries stays.
pub const ERROR_SNIPPET_LOG_BYTES: usize =
    ERROR_BODY_BYTES * LONGEST_ESCAPE_BYTES + TRUNCATED_SUFFIX.len();

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

/// The bytes of a body read up to a cap, in memory that is wiped:
/// [`read_limited`] collects a body into one, and a body read some other
/// way can be.
///
/// A success body carries tokens and keys, and a `Vec` that grows in place
/// frees its old bytes as they were. This buffer is sized once from a
/// declared length, grows into a new buffer and wipes the old one when it
/// must grow, and wipes what it holds when it is dropped, a body refused
/// part of the way through included. The bytes are handed out in memory
/// that wipes itself.
pub struct BoundedBody {
    bytes: Zeroizing<Vec<u8>>,
    max: usize,
}

impl BoundedBody {
    /// A body of at most `max` bytes. A declared length above `max` is
    /// refused before anything is read; one at or below it sizes the buffer
    /// once.
    pub fn new(declared: Option<u64>, max: usize) -> Result<Self, BodyError> {
        match declared {
            Some(len) if len > max as u64 => Err(BodyError::TooLarge { max }),
            _ => Ok(Self::up_to(declared, max)),
        }
    }

    /// A body that keeps the first `max` bytes and refuses nothing: a
    /// declared length sizes the buffer once, at most to `max`, and
    /// [`push_up_to`](Self::push_up_to) cuts what does not fit.
    fn up_to(declared: Option<u64>, max: usize) -> Self {
        let capacity = declared.map_or(0, |len| {
            usize::try_from(len).map_or(max, |len| len.min(max))
        });
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(capacity)),
            max,
        }
    }

    /// Add the next chunk. A chunk that takes the body past the cap is
    /// refused, and the bytes held so far are wiped when the body is
    /// dropped.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        if self.bytes.len().saturating_add(chunk.len()) > self.max {
            return Err(BodyError::TooLarge { max: self.max });
        }
        self.append(chunk);
        Ok(())
    }

    /// Add as much of the next chunk as the cap leaves room for, and say
    /// whether any of it was cut off. Never over the cap, so never refused.
    fn push_up_to(&mut self, chunk: &[u8]) -> bool {
        let room = self.max.saturating_sub(self.bytes.len());
        let cut = chunk.len() > room;
        self.append(&chunk[..chunk.len().min(room)]);
        cut
    }

    /// Append `chunk`, which the caller has checked fits under the cap.
    fn append(&mut self, chunk: &[u8]) {
        let needed = self.bytes.len().saturating_add(chunk.len());
        if needed > self.bytes.capacity() {
            // Growing into a new buffer lets the old one be wiped as it is
            // dropped; `Vec` growth would free it as it was.
            let room = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.max);
            let mut grown = Zeroizing::new(Vec::with_capacity(room));
            grown.extend_from_slice(&self.bytes);
            self.bytes = grown;
        }
        self.bytes.extend_from_slice(chunk);
    }

    /// The body, in memory that wipes itself when it is dropped.
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

/// The length and the cap only: the bytes are the remote party's secret.
impl fmt::Debug for BoundedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedBody")
            .field("len", &self.bytes.len())
            .field("max", &self.max)
            .finish()
    }
}

/// Read a body of at most `max` bytes into a [`BoundedBody`], and hand it
/// back in memory that wipes itself.
///
/// A declared `Content-Length` above the cap is refused before anything is
/// read, and one within it sizes the buffer once; without one, the chunk
/// that crosses the cap ends the read, so at most the cap is ever held. A
/// refused or broken read wipes what it held. The chunks the HTTP client
/// delivered are the client's and are not within reach.
pub async fn read_limited(
    response: &mut reqwest::Response,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>, BodyError> {
    let mut body = BoundedBody::new(response.content_length(), max)?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| BodyError::Read(e.to_string()))?
    {
        body.push(&chunk)?;
    }
    Ok(body.into_bytes())
}

pub use crate::log_text::log_safe;

/// A serde error over a remote party's body, made safe for an error message
/// as [`log_safe`] makes text: serde quotes the value it could not read,
/// escaped but whole, so the message is cut at 256 bytes and the position
/// serde reported is kept after it.
pub fn log_safe_parse_error(error: &serde_json::Error) -> String {
    crate::remote_text::parse_error(error)
}

/// An error snippet [`read_error_snippet`] returned, made safe for a log line
/// as [`log_safe`] does, without a second cut: the reader bounded the text,
/// so the escapes are the only growth and the result is at most
/// [`ERROR_SNIPPET_LOG_BYTES`]. A snippet the reader cut keeps its
/// [`TRUNCATED_SUFFIX`]; `log_safe` at [`ERROR_BODY_BYTES`] would cut the
/// suffix off and mark the cut again.
pub fn log_safe_snippet(snippet: &str) -> String {
    log_safe(snippet, ERROR_SNIPPET_LOG_BYTES)
}

/// The most bytes of an upstream `error` code kept for an error or a log
/// line. RFC 6749 section 5.2 makes the code a short ASCII token; a longer
/// one is cut as [`log_safe`] cuts. Only the OAuth providers parse an error
/// body for its code, so the item exists with the `oauth` feature.
#[cfg(feature = "oauth")]
pub(crate) const ERROR_CODE_LOG_BYTES: usize = 128;

/// The `error` member of an OAuth error body, made safe for a log line as
/// [`log_safe`] does and cut at [`ERROR_CODE_LOG_BYTES`], or `HTTP <status>`
/// when the body carries none. The code is the remote party's text as much
/// as its description is, and a line break or an escape inside it forges a
/// log line the same way.
#[cfg(feature = "oauth")]
pub(crate) fn log_safe_error_code(body: &[u8], status: reqwest::StatusCode) -> String {
    let code = string_member(body, "error").unwrap_or_else(|| format!("HTTP {status}"));
    log_safe(&code, ERROR_CODE_LOG_BYTES)
}

/// The most bytes of a refusal's body read to find what it says (an OAuth
/// `error` member, an STS error document): as much as a success body may
/// hold. What reaches an error or a log line is still cut at
/// [`ERROR_BODY_BYTES`]; this bound is for the reading only, so a long
/// description before or after the code does not cost the code.
pub const ERROR_BODY_PARSE_BYTES: usize = MAX_TOKEN_BODY_BYTES;

/// A refusal's body, read to find what it says: up to
/// [`ERROR_BODY_PARSE_BYTES`] are read and the rest is not, so a code
/// placed after a long description is still found. A failed read ends the
/// body where it stood; reading it is never an error, since the body only
/// explains a status the caller already has.
///
/// A refusal may quote what the request carried, a grant or an assertion,
/// so the body is collected as a [`BoundedBody`] collects a success body:
/// every buffer it outgrows is wiped, and so is the body when this is
/// dropped.
///
/// The text is the remote party's and is not bounded for a message: take
/// [`snippet`](Self::snippet) for an error or a log line, and pass a member
/// read with [`string_member`](Self::string_member) through [`log_safe`]
/// before it reaches one.
pub struct ErrorBody {
    bytes: Zeroizing<Vec<u8>>,
}

impl ErrorBody {
    /// Read the body of `response`, up to [`ERROR_BODY_PARSE_BYTES`].
    pub async fn read(response: &mut reqwest::Response) -> Self {
        Self {
            bytes: read_error_body(response).await,
        }
    }

    /// The body as read, for a parser that reads the whole document; a body
    /// longer than [`ERROR_BODY_PARSE_BYTES`] is cut there and will not
    /// parse whole, which [`string_member`](Self::string_member) survives.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The string member `name` of the JSON object the body holds, read
    /// member by member, so a body cut after that member still yields it.
    /// `None` when the body is not a JSON object, has no such member before
    /// it ends, or the member is not a string. Raw: compare it, and pass it
    /// through [`log_safe`] where it becomes a message.
    pub fn string_member(&self, name: &str) -> Option<String> {
        string_member(&self.bytes, name)
    }

    /// The first [`ERROR_BODY_BYTES`] as lossy UTF-8, with
    /// [`TRUNCATED_SUFFIX`] when more followed: what
    /// [`read_error_snippet`] returns, for [`log_safe_snippet`].
    pub fn snippet(&self) -> String {
        error_snippet_of(&self.bytes)
    }
}

/// The length only: the body is the remote party's text.
impl fmt::Debug for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorBody")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Read an error body up to [`ERROR_BODY_PARSE_BYTES`], into memory that
/// wipes itself; the rest is not read, and a failed read ends the body
/// where it stood. Never an error: the body only explains a status the
/// caller already has.
pub(crate) async fn read_error_body(response: &mut reqwest::Response) -> Zeroizing<Vec<u8>> {
    read_up_to(response, ERROR_BODY_PARSE_BYTES).await.0
}

/// The string member `name` of the JSON object `body` holds, read entry by
/// entry, so a body cut anywhere after that member still yields it. `None`
/// when the body is not an object, has no such member before it ends, or
/// the member is not a string. The first member of the name counts.
pub(crate) fn string_member(body: &[u8], name: &str) -> Option<String> {
    use serde::Deserializer as _;
    use serde::de::{IgnoredAny, MapAccess, Visitor};

    struct Seek<'a> {
        name: &'a str,
        found: &'a mut Option<String>,
    }

    impl<'de> Visitor<'de> for Seek<'_> {
        type Value = ();

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            while let Some(key) = map.next_key::<String>()? {
                if key == self.name {
                    let value: serde_json::Value = map.next_value()?;
                    *self.found = value.as_str().map(String::from);
                    // Stop here: the rest of the body may be cut, and the
                    // error the parser then reports is not this caller's.
                    return Ok(());
                }
                map.next_value::<IgnoredAny>()?;
            }
            Ok(())
        }
    }

    let mut found = None;
    let mut parser = serde_json::Deserializer::from_slice(body);
    // The parse fails once the member is found (the object is left open) or
    // where a cut body ends; `found` holds what was read before either.
    let _ = parser.deserialize_map(Seek {
        name,
        found: &mut found,
    });
    found
}

/// The refusal text a caller keeps of an error body read for its code: the
/// first [`ERROR_BODY_BYTES`] as lossy UTF-8, with [`TRUNCATED_SUFFIX`] when
/// more followed, as [`read_error_snippet`] returns it.
pub(crate) fn error_snippet_of(body: &[u8]) -> String {
    snippet(
        &body[..body.len().min(ERROR_BODY_BYTES)],
        body.len() > ERROR_BODY_BYTES,
    )
}

/// Read the first [`ERROR_BODY_BYTES`] of an error body as lossy UTF-8, with
/// [`TRUNCATED_SUFFIX`] appended when more followed. Reading stops once the
/// cap is passed; a failed read ends the body where it stood. The text is
/// raw, since callers parse it for an error code; pass it through
/// [`log_safe`] where it becomes an error message.
pub async fn read_error_snippet(response: &mut reqwest::Response) -> String {
    let (body, truncated) = read_up_to(response, ERROR_BODY_BYTES).await;
    snippet(&body, truncated)
}

/// At most `cap` bytes of a body, in memory that wipes itself, and whether
/// more followed. Reading stops once the cap is passed; a failed read ends
/// the body where it stood.
///
/// The bytes are collected in a [`BoundedBody`], so no buffer outgrown on
/// the way is freed unwiped, and the cut is the body's own
/// ([`BoundedBody::push_up_to`]).
async fn read_up_to(response: &mut reqwest::Response, cap: usize) -> (Zeroizing<Vec<u8>>, bool) {
    let mut body = BoundedBody::up_to(response.content_length(), cap);
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.push_up_to(&chunk) {
            return (body.into_bytes(), true);
        }
    }
    (body.into_bytes(), false)
}

/// [`snippet`] written straight into memory that wipes itself: the lossy
/// UTF-8 of `body` with [`TRUNCATED_SUFFIX`] when it was cut, the same bytes
/// `snippet` returns, with no plain `String` or `Vec` between.
///
/// The length is counted first, so the buffer is allocated once and never
/// outgrown. `str::from_utf8_lossy` is defined over the same
/// `utf8_chunks` walk: each valid run as it is, and one U+FFFD for each
/// invalid sequence, so the two agree byte for byte.
fn wiped_snippet(body: &[u8], truncated: bool) -> Zeroizing<Vec<u8>> {
    const REPLACEMENT: &str = "\u{FFFD}";
    let suffix = if truncated { TRUNCATED_SUFFIX } else { "" };
    let len = body
        .utf8_chunks()
        .map(|chunk| {
            chunk.valid().len()
                + if chunk.invalid().is_empty() {
                    0
                } else {
                    REPLACEMENT.len()
                }
        })
        .sum::<usize>()
        + suffix.len();
    let mut text = Zeroizing::new(Vec::with_capacity(len));
    for chunk in body.utf8_chunks() {
        text.extend_from_slice(chunk.valid().as_bytes());
        if !chunk.invalid().is_empty() {
            text.extend_from_slice(REPLACEMENT.as_bytes());
        }
    }
    text.extend_from_slice(suffix.as_bytes());
    text
}

/// `body` as lossy UTF-8, with [`TRUNCATED_SUFFIX`] when it was cut.
fn snippet(body: &[u8], truncated: bool) -> String {
    let mut text = String::from_utf8_lossy(body).into_owned();
    if truncated {
        text.push_str(TRUNCATED_SUFFIX);
    }
    text
}

#[cfg(test)]
mod tests;

/// Read a body whichever the status: a success body in full up to
/// `success_max` ([`BodyError::TooLarge`] past it), any other status as the
/// error snippet's bytes (never an error for size). For callers that format
/// the body into their own error; a caller that parses a refusal for its
/// code reads it with [`ErrorBody`], which keeps a code a long description
/// would push past the snippet. Either body is collected and handed back
/// in memory that wipes itself, with no unwiped copy left on the way.
pub async fn read_for_status(
    response: &mut reqwest::Response,
    success_max: usize,
) -> Result<Zeroizing<Vec<u8>>, BodyError> {
    if response.status().is_success() {
        read_limited(response, success_max).await
    } else {
        let (body, truncated) = read_up_to(response, ERROR_BODY_BYTES).await;
        Ok(wiped_snippet(&body, truncated))
    }
}
