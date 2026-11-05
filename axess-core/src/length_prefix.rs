//! The big-endian `u32` length prefix the sealed-data bindings use, so no
//! value can bleed into its neighbour.

/// `len` as a big-endian `u32`.
///
/// # Panics
///
/// When `len` does not fit a `u32` (a field over 4 GiB): a truncated prefix
/// would let two different field sets produce one binding.
pub(crate) fn length_prefix(len: usize) -> [u8; 4] {
    u32::try_from(len)
        .expect("a bound field longer than u32::MAX bytes")
        .to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_is_four_big_endian_bytes() {
        assert_eq!(length_prefix(0), [0, 0, 0, 0]);
        assert_eq!(length_prefix(258), [0, 0, 1, 2]);
        assert_eq!(length_prefix(u32::MAX as usize), [255; 4]);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic(expected = "longer than u32::MAX")]
    fn a_length_past_u32_is_refused_not_truncated() {
        length_prefix(u32::MAX as usize + 1);
    }
}
