//! Whether a private key is the key of a certificate, read from the two
//! encodings.
//!
//! An SVID is a certificate and the private key that goes with it. An agent
//! that sends a key for another certificate, or bytes that are no key, has
//! sent nothing a workload can present, and admitting it would replace an
//! SVID that works. So the key is checked before the SVID is kept.
//!
//! The check here needs no cryptography: a PKCS#8 private key of the kinds
//! an agent issues carries its public key (an RSA key its modulus and public
//! exponent, an EC key the point, in the form the usual encoders write), and
//! that is compared with the certificate's. A key that carries no public key
//! cannot be decided here; with a TLS stack in the build the public key is
//! derived there instead (see `tls`), and without one the SVID is refused.
//!
//! The reader below reads DER as far as these structures need it: definite
//! lengths of up to four bytes, tag numbers below 31. Every length is checked
//! against the bytes that are left before anything is sliced.

/// `SEQUENCE`.
const SEQUENCE: u8 = 0x30;
/// `INTEGER`.
const INTEGER: u8 = 0x02;
/// `BIT STRING`.
const BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
const OCTET_STRING: u8 = 0x04;
/// `OBJECT IDENTIFIER`.
const OID: u8 = 0x06;
/// `[1]`, constructed: the public key of an `ECPrivateKey`.
const EXPLICIT_1: u8 = 0xA1;
/// `[1]`, primitive: the public key of a version 2 `PrivateKeyInfo`.
const IMPLICIT_1: u8 = 0x81;

/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// What the encodings say about a private key and a certificate's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyMatch {
    /// The public key the private key carries is the certificate's.
    Proven,
    /// The private key is of the certificate's algorithm and carries no
    /// public key to compare.
    Undecided,
}

/// Why a private key is not a certificate's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KeyMismatch {
    /// The key bytes are not a PKCS#8 `PrivateKeyInfo`.
    #[error("the private key is not PKCS#8")]
    NotPkcs8,
    /// The certificate's `SubjectPublicKeyInfo` does not read.
    #[error("the leaf certificate's public key does not read")]
    NotSpki,
    /// The key is of another algorithm, or another curve, than the
    /// certificate's.
    #[error("the private key is of another algorithm or curve than the leaf certificate's key")]
    OtherAlgorithm,
    /// The public key the private key carries is not the certificate's.
    #[error("the private key is not the leaf certificate's")]
    OtherKey,
}

/// Compare a PKCS#8 private key with a certificate's
/// `SubjectPublicKeyInfo`, both DER.
pub(crate) fn private_key_matches(pkcs8: &[u8], spki: &[u8]) -> Result<KeyMatch, KeyMismatch> {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //     algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    let mut leaf = Der::whole(spki, SEQUENCE).ok_or(KeyMismatch::NotSpki)?;
    let leaf_algorithm = leaf.expect(SEQUENCE).ok_or(KeyMismatch::NotSpki)?;
    let leaf_key = leaf
        .expect(BIT_STRING)
        .and_then(bit_string)
        .ok_or(KeyMismatch::NotSpki)?;

    // PrivateKeyInfo ::= SEQUENCE {
    //     version INTEGER, privateKeyAlgorithm AlgorithmIdentifier,
    //     privateKey OCTET STRING, attributes [0] OPTIONAL,
    //     publicKey [1] IMPLICIT BIT STRING OPTIONAL }
    let mut info = Der::whole(pkcs8, SEQUENCE).ok_or(KeyMismatch::NotPkcs8)?;
    info.expect(INTEGER).ok_or(KeyMismatch::NotPkcs8)?;
    let algorithm = info.expect(SEQUENCE).ok_or(KeyMismatch::NotPkcs8)?;
    let private_key = info.expect(OCTET_STRING).ok_or(KeyMismatch::NotPkcs8)?;
    // The identifier holds the algorithm and, for an EC key, the curve.
    if algorithm != leaf_algorithm {
        return Err(KeyMismatch::OtherAlgorithm);
    }
    let kind = Der::new(algorithm)
        .expect(OID)
        .ok_or(KeyMismatch::NotPkcs8)?;
    let carried = if kind == RSA_ENCRYPTION {
        return rsa_matches(private_key, leaf_key);
    } else if kind == EC_PUBLIC_KEY {
        ec_point(private_key).ok_or(KeyMismatch::NotPkcs8)?
    } else {
        None
    };
    // Whatever the algorithm, a version 2 structure may carry the public
    // key beside the private one.
    let carried = carried.or_else(|| info.find(IMPLICIT_1).and_then(bit_string));
    match carried {
        Some(public) if public == leaf_key => Ok(KeyMatch::Proven),
        Some(_) => Err(KeyMismatch::OtherKey),
        None => Ok(KeyMatch::Undecided),
    }
}

/// An RSA private key carries its modulus and public exponent, which are
/// the whole public key.
fn rsa_matches(private_key: &[u8], leaf_key: &[u8]) -> Result<KeyMatch, KeyMismatch> {
    // RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, ... }
    let mut key = Der::whole(private_key, SEQUENCE).ok_or(KeyMismatch::NotPkcs8)?;
    key.expect(INTEGER).ok_or(KeyMismatch::NotPkcs8)?;
    let modulus = key.expect(INTEGER).ok_or(KeyMismatch::NotPkcs8)?;
    let exponent = key.expect(INTEGER).ok_or(KeyMismatch::NotPkcs8)?;
    // RSAPublicKey ::= SEQUENCE { modulus, publicExponent }
    let mut public = Der::whole(leaf_key, SEQUENCE).ok_or(KeyMismatch::NotSpki)?;
    let leaf_modulus = public.expect(INTEGER).ok_or(KeyMismatch::NotSpki)?;
    let leaf_exponent = public.expect(INTEGER).ok_or(KeyMismatch::NotSpki)?;
    if magnitude(modulus) == magnitude(leaf_modulus)
        && magnitude(exponent) == magnitude(leaf_exponent)
    {
        Ok(KeyMatch::Proven)
    } else {
        Err(KeyMismatch::OtherKey)
    }
}

/// The public point an `ECPrivateKey` carries: `Some(None)` when it carries
/// none, `None` when the structure does not read.
fn ec_point(private_key: &[u8]) -> Option<Option<&[u8]>> {
    // ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING,
    //     parameters [0] OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
    let mut key = Der::whole(private_key, SEQUENCE)?;
    key.expect(INTEGER)?;
    key.expect(OCTET_STRING)?;
    match key.find(EXPLICIT_1) {
        Some(wrapped) => {
            let point = Der::new(wrapped).expect(BIT_STRING).and_then(bit_string)?;
            Some(Some(point))
        }
        None => Some(None),
    }
}

/// The bytes of a bit string that has no unused bits, as a key's has.
fn bit_string(content: &[u8]) -> Option<&[u8]> {
    match content.split_first() {
        Some((0, bytes)) => Some(bytes),
        _ => None,
    }
}

/// An integer's content without its leading zero bytes.
fn magnitude(integer: &[u8]) -> &[u8] {
    let zeros = integer.iter().take_while(|byte| **byte == 0).count();
    &integer[zeros..]
}

/// Reads the elements of one DER structure in order.
struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(content: &'a [u8]) -> Self {
        Self { rest: content }
    }

    /// A reader over the content of `input`, which is one element of `tag`
    /// and nothing after it.
    fn whole(input: &'a [u8], tag: u8) -> Option<Self> {
        let mut outer = Self::new(input);
        let content = outer.expect(tag)?;
        outer.rest.is_empty().then(|| Self::new(content))
    }

    /// The next element as `(tag, content)`; `None` at the end, and where
    /// the bytes are not an element this reader reads.
    fn next_element(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, after_tag) = self.rest.split_first()?;
        // A tag number of 31 or more continues in further bytes.
        if tag & 0x1F == 0x1F {
            return None;
        }
        let (&first, after_first) = after_tag.split_first()?;
        let (len, after_len) = if first < 0x80 {
            (usize::from(first), after_first)
        } else {
            // 0x80 is the indefinite form, which DER does not have.
            let count = usize::from(first & 0x7F);
            if count == 0 || count > 4 || after_first.len() < count {
                return None;
            }
            let (len_bytes, after_len) = after_first.split_at(count);
            let len = len_bytes
                .iter()
                .fold(0usize, |len, byte| (len << 8) | usize::from(*byte));
            (len, after_len)
        };
        if after_len.len() < len {
            return None;
        }
        let (content, rest) = after_len.split_at(len);
        self.rest = rest;
        Some((tag, content))
    }

    /// The content of the next element when it is of `tag`.
    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        match self.next_element()? {
            (found, content) if found == tag => Some(content),
            _ => None,
        }
    }

    /// The content of the first of the remaining elements that is of `tag`.
    fn find(&mut self, tag: u8) -> Option<&'a [u8]> {
        while let Some((found, content)) = self.next_element() {
            if found == tag {
                return Some(content);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
