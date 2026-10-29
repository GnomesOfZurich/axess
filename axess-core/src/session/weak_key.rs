//! A constant key is a placeholder that reached production. These checks
//! need no backend, so they live outside the feature-gated `crypto` module
//! and the session layer can run them under every feature set.

/// Whether `key` is a single byte repeated 32 times (all zeros included).
///
/// No random key looks like this, so one is a placeholder that reached
/// production: the README example used to show an all-zero key. The check
/// cannot prove a key is strong, only that this one is not.
pub fn is_constant_key(key: &[u8; 32]) -> bool {
    key.iter().all(|byte| *byte == key[0])
}

/// A key rejected by a `try_new` constructor because it is a single repeated
/// byte (see [`is_constant_key`]).
#[derive(Debug, thiserror::Error)]
#[error("key is a single repeated byte, not random key material")]
pub struct WeakKeyError;

/// Log an error when `key` is a constant placeholder. Non-fatal so the
/// infallible constructors keep their signatures.
pub(crate) fn warn_if_constant_key(what: &str, key: &[u8; 32]) {
    if is_constant_key(key) {
        tracing::error!(
            target: "axess::session::crypto",
            "{what} is a single repeated byte (a placeholder, not random key material); \
             load a random 32-byte key from a secret store"
        );
    }
}
