//! Text a request gave, as a span field or a log line carries it.
//!
//! A tenant identifier, a provider name or a passkey's name reaches an
//! entry point from the request, and no length is asked of it before the
//! entry point's span opens. A text formatter prints a span's fields on
//! every line written inside it, so such text is written as
//! [`log_safe`](axess_factors::log_text::log_safe) writes text from a
//! remote party: every character
//! [`escapes`](axess_identity::log_text::escapes) names (control characters,
//! the line and paragraph separators, bidirectional controls, zero-width
//! characters, the byte order mark, the Hangul fillers) as an escape, cut at
//! a bound with `...` marking the cut.

/// The most bytes of a request's text a span field or a log line keeps.
pub(crate) const REQUEST_TEXT_LOG_BYTES: usize = 128;

/// `text` escaped and cut at [`REQUEST_TEXT_LOG_BYTES`]. No more of it is
/// read than the cut can keep.
pub(crate) fn logged_request_text(text: &str) -> String {
    axess_factors::log_text::log_safe(text, REQUEST_TEXT_LOG_BYTES)
}
