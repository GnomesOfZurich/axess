//! Text from a remote party or a request, made safe for a log line.
//!
//! [`log_safe`] is always compiled: the bounded body reader of `http_body`
//! uses it for upstream error text, and a service uses it for text a request
//! gave (a tenant identifier, a provider name, a passkey's name) before that
//! text reaches a span or a log line. `http_body::log_safe` re-exports it.
//!
//! Both items are `axess_identity::log_text`'s, re-exported: the workspace
//! has one predicate for what such text must not carry raw, and it lives in
//! the crate every other one depends on.

pub use axess_identity::log_text::{escapes, log_safe};

#[cfg(test)]
mod tests;
