//! Text a remote party wrote, made safe for an error message or a log line.
//!
//! An identity provider, a token or a proof decides what its text holds: a
//! line break or an escape sequence forges a log line or rewrites a
//! terminal, and a long value fills one error and one log line with
//! whatever it likes. Every error that carries such text goes through
//! here: every character [`escapes`](crate::log_text::escapes) names
//! (control characters, the line and paragraph separators, bidirectional
//! controls, zero-width characters, the byte order mark, the Hangul fillers)
//! is written as an escape, and the result is cut, by
//! [`log_safe`](crate::log_text::log_safe).
//!
//! A parse error is the case that is easy to miss. serde quotes the value it
//! could not read (`invalid type: string "...", expected u64`), escaped but
//! whole, so an answer that puts 60 KiB where a number belongs puts 60 KiB
//! into the error. [`parse_error`] keeps the head of that message and the
//! position serde reported.

/// The most bytes [`parse_error`] keeps of serde's message, before the
/// position it appends.
pub(crate) const PARSE_ERROR_LOG_BYTES: usize = 256;

/// A serde error over a remote party's text, made safe for an error message:
/// the message escaped and cut at [`PARSE_ERROR_LOG_BYTES`], then the
/// position serde reported, whole. A value serde quoted is kept to its head.
pub(crate) fn parse_error(error: &serde_json::Error) -> String {
    let full = error.to_string();
    let position = if error.line() == 0 {
        String::new()
    } else {
        format!(" at line {} column {}", error.line(), error.column())
    };
    let message = full.strip_suffix(&position).unwrap_or(&full);
    format!(
        "{}{position}",
        crate::log_text::log_safe(message, PARSE_ERROR_LOG_BYTES)
    )
}

/// Any error whose text may quote a remote party (a JOSE library's error
/// over a token, which wraps serde's), escaped and cut at
/// [`PARSE_ERROR_LOG_BYTES`].
#[cfg(feature = "jwt")]
pub(crate) fn error_text(error: &dyn std::fmt::Display) -> String {
    crate::log_text::log_safe(&error.to_string(), PARSE_ERROR_LOG_BYTES)
}

#[cfg(test)]
mod tests;
