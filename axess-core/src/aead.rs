//! The size every AES-256-GCM layout in this crate shares: the tag that
//! closes each ciphertext. A sealed value shorter than its nonce or salt and
//! this tag was never sealed, and each open path refuses one before it tries
//! a key.

/// Length of the authentication tag AES-GCM appends to every ciphertext,
/// the empty plaintext's included.
pub(crate) const TAG_LEN: usize = 16;

#[cfg(test)]
mod tests {
    /// The cipher wipes its key schedule when it is dropped: it carries the
    /// marker only with the `zeroize` feature of `aes-gcm` on.
    #[test]
    fn the_cipher_is_zeroed_on_drop() {
        fn zeroed_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroed_on_drop::<aes_gcm::Aes256Gcm>();
    }
}
