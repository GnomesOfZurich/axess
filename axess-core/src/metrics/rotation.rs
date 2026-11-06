//! The rotation-window concern: how often the previous key is still needed.

/// Counters that tell an operator when a key rotation window can close.
///
/// A previous key stays configured until nothing needs it. Each method fires
/// when the previous key did work, so a rate that falls to zero is the signal
/// to drop the previous key.
pub trait RotationMetrics: Send + Sync + 'static {
    /// A session or device blob opened only under the previous encryption key
    /// (see [`SessionCrypto::with_previous_key`](crate::session::SessionCrypto::with_previous_key)).
    /// The blob is re-sealed under the current key as it is read.
    fn encryption_key_fallback(&self) {}

    /// A stored session fingerprint matched only under the previous signing
    /// key. The fingerprint is re-stored under the current key.
    fn fingerprint_key_fallback(&self) {}
}
