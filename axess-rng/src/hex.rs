//! Lowercase hex encoding and strict hex decoding, the one codec the
//! workspace uses for MAC tags, trace ids and device fingerprints.

use core::fmt;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Why a hex string was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The input has an odd number of digits.
    OddLength,
    /// The input holds a byte that is not an ASCII hex digit.
    InvalidDigit,
    /// The output slice is not exactly half as long as the input.
    WrongLength,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OddLength => "hex string has an odd number of digits",
            Self::InvalidDigit => "hex string contains a non-hex character",
            Self::WrongLength => "hex string does not match the output length",
        })
    }
}

impl std::error::Error for HexError {}

/// Encode `bytes` as lowercase hex.
#[must_use]
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn nibble(digit: u8) -> Result<u8, HexError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(HexError::InvalidDigit),
    }
}

/// Decode `hex`, in either case, into `out` without allocating.
///
/// `out` must be exactly `hex.len() / 2` bytes. On an error `out` may hold
/// a partial decode and must not be used.
///
/// # Errors
///
/// [`HexError::OddLength`], [`HexError::WrongLength`] or
/// [`HexError::InvalidDigit`].
pub fn decode_to_slice(hex: &str, out: &mut [u8]) -> Result<(), HexError> {
    let hex = hex.as_bytes();
    if !hex.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    if hex.len() / 2 != out.len() {
        return Err(HexError::WrongLength);
    }
    let (pairs, _) = hex.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Ok(())
}

/// Decode `hex`, in either case, into a new vector.
///
/// # Errors
///
/// [`HexError::OddLength`] or [`HexError::InvalidDigit`].
pub fn decode(hex: &str) -> Result<Vec<u8>, HexError> {
    let mut out = vec![0u8; hex.len() / 2];
    decode_to_slice(hex, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10 test vectors, base16.
    const RFC4648: [(&str, &str); 7] = [
        ("", ""),
        ("f", "66"),
        ("fo", "666f"),
        ("foo", "666f6f"),
        ("foob", "666f6f62"),
        ("fooba", "666f6f6261"),
        ("foobar", "666f6f626172"),
    ];

    #[test]
    fn rfc_4648_vectors_encode_and_decode() {
        for (plain, hex) in RFC4648 {
            assert_eq!(encode(plain.as_bytes()), hex);
            assert_eq!(decode(hex).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn every_byte_round_trips_in_either_case() {
        let all: Vec<u8> = (0..=255).collect();
        let lower = encode(&all);
        assert_eq!(lower, lower.to_ascii_lowercase());
        assert_eq!(decode(&lower).unwrap(), all);
        assert_eq!(decode(&lower.to_ascii_uppercase()).unwrap(), all);
    }

    #[test]
    fn odd_length_is_refused() {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("a"), Err(HexError::OddLength));
    }

    #[test]
    fn a_non_hex_digit_is_refused() {
        assert_eq!(decode("zz"), Err(HexError::InvalidDigit));
        assert_eq!(decode("0g"), Err(HexError::InvalidDigit));
        assert_eq!(decode("+1"), Err(HexError::InvalidDigit));
        assert_eq!(decode("\u{e9}0"), Err(HexError::OddLength));
    }

    #[test]
    fn decode_to_slice_demands_the_exact_length() {
        let mut two = [0u8; 2];
        assert_eq!(decode_to_slice("abcd", &mut two), Ok(()));
        assert_eq!(two, [0xab, 0xcd]);
        assert_eq!(decode_to_slice("ab", &mut two), Err(HexError::WrongLength));
        assert_eq!(
            decode_to_slice("abcdef", &mut two),
            Err(HexError::WrongLength)
        );
        assert_eq!(decode_to_slice("abc", &mut two), Err(HexError::OddLength));
    }
}
