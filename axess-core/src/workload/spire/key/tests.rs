//! The key check, on structures written out by hand so that each field is
//! in view, and on bytes of no structure at all.

use proptest::prelude::*;

use super::*;

/// One DER element.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        len @ 0..=0x7F => out.push(len as u8),
        len @ 0x80..=0xFF => out.extend([0x81, len as u8]),
        len => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    der(SEQUENCE, &parts.concat())
}

fn bits(content: &[u8]) -> Vec<u8> {
    der(BIT_STRING, &[&[0u8][..], content].concat())
}

const NULL: &[u8] = &[0x05, 0x00];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `secp384r1`, 1.3.132.0.34.
const P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
/// `id-Ed25519`, 1.3.101.112.
const ED25519: &[u8] = &[0x2B, 0x65, 0x70];

fn rsa_algorithm() -> Vec<u8> {
    seq(&[&der(OID, RSA_ENCRYPTION), NULL])
}

fn ec_algorithm(curve: &[u8]) -> Vec<u8> {
    seq(&[&der(OID, EC_PUBLIC_KEY), &der(OID, curve)])
}

fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let public = seq(&[&der(INTEGER, modulus), &der(INTEGER, exponent)]);
    seq(&[&rsa_algorithm(), &bits(&public)])
}

fn rsa_pkcs8(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let private = seq(&[
        &der(INTEGER, &[0]),
        &der(INTEGER, modulus),
        &der(INTEGER, exponent),
        &der(INTEGER, &[0x11, 0x22]),
    ]);
    seq(&[
        &der(INTEGER, &[0]),
        &rsa_algorithm(),
        &der(OCTET_STRING, &private),
    ])
}

fn ec_spki(curve: &[u8], point: &[u8]) -> Vec<u8> {
    seq(&[&ec_algorithm(curve), &bits(point)])
}

fn ec_pkcs8(curve: &[u8], point: Option<&[u8]>) -> Vec<u8> {
    let mut parts = vec![der(INTEGER, &[1]), der(OCTET_STRING, &[0x5A; 32])];
    if let Some(point) = point {
        parts.push(der(EXPLICIT_1, &bits(point)));
    }
    let private = der(SEQUENCE, &parts.concat());
    seq(&[
        &der(INTEGER, &[0]),
        &ec_algorithm(curve),
        &der(OCTET_STRING, &private),
    ])
}

const POINT: &[u8] = &[0x04, 1, 2, 3, 4, 5, 6, 7, 8];
const OTHER_POINT: &[u8] = &[0x04, 1, 2, 3, 4, 5, 6, 7, 9];

#[test]
fn an_rsa_key_is_proven_by_its_modulus_and_exponent() {
    let spki = rsa_spki(&[0x00, 0xC3, 0x51], &[0x01, 0x00, 0x01]);
    assert_eq!(
        private_key_matches(&rsa_pkcs8(&[0x00, 0xC3, 0x51], &[0x01, 0x00, 0x01]), &spki),
        Ok(KeyMatch::Proven)
    );
    // The same numbers with and without a leading zero byte are the same.
    assert_eq!(
        private_key_matches(&rsa_pkcs8(&[0xC3, 0x51], &[0x00, 0x01, 0x00, 0x01]), &spki),
        Ok(KeyMatch::Proven)
    );
}

#[test]
fn an_rsa_key_of_another_modulus_or_exponent_is_not_the_leafs() {
    let spki = rsa_spki(&[0x00, 0xC3, 0x51], &[0x01, 0x00, 0x01]);
    assert_eq!(
        private_key_matches(&rsa_pkcs8(&[0x00, 0xC3, 0x53], &[0x01, 0x00, 0x01]), &spki),
        Err(KeyMismatch::OtherKey)
    );
    assert_eq!(
        private_key_matches(&rsa_pkcs8(&[0x00, 0xC3, 0x51], &[0x03]), &spki),
        Err(KeyMismatch::OtherKey)
    );
}

#[test]
fn an_ec_key_is_proven_by_the_point_it_carries() {
    let spki = ec_spki(P256, POINT);
    assert_eq!(
        private_key_matches(&ec_pkcs8(P256, Some(POINT)), &spki),
        Ok(KeyMatch::Proven)
    );
    assert_eq!(
        private_key_matches(&ec_pkcs8(P256, Some(OTHER_POINT)), &spki),
        Err(KeyMismatch::OtherKey)
    );
}

#[test]
fn an_ec_key_with_parameters_before_its_point_is_read() {
    // ECPrivateKey with the optional `parameters [0]` before `publicKey [1]`.
    let private = seq(&[
        &der(INTEGER, &[1]),
        &der(OCTET_STRING, &[0x5A; 32]),
        &der(0xA0, &der(OID, P256)),
        &der(EXPLICIT_1, &bits(POINT)),
    ]);
    let pkcs8 = seq(&[
        &der(INTEGER, &[0]),
        &ec_algorithm(P256),
        &der(OCTET_STRING, &private),
    ]);
    assert_eq!(
        private_key_matches(&pkcs8, &ec_spki(P256, POINT)),
        Ok(KeyMatch::Proven)
    );
}

#[test]
fn an_ec_key_that_carries_no_point_is_undecided() {
    assert_eq!(
        private_key_matches(&ec_pkcs8(P256, None), &ec_spki(P256, POINT)),
        Ok(KeyMatch::Undecided)
    );
}

#[test]
fn a_key_of_another_algorithm_or_curve_is_refused() {
    assert_eq!(
        private_key_matches(&ec_pkcs8(P384, Some(POINT)), &ec_spki(P256, POINT)),
        Err(KeyMismatch::OtherAlgorithm)
    );
    assert_eq!(
        private_key_matches(&rsa_pkcs8(&[0xC3, 0x51], &[0x03]), &ec_spki(P256, POINT)),
        Err(KeyMismatch::OtherAlgorithm)
    );
    assert_eq!(
        private_key_matches(
            &ec_pkcs8(P256, Some(POINT)),
            &rsa_spki(&[0xC3, 0x51], &[0x03])
        ),
        Err(KeyMismatch::OtherAlgorithm)
    );
}

#[test]
fn a_version_two_structure_is_proven_by_the_public_key_beside_the_private_one() {
    let algorithm = seq(&[&der(OID, ED25519)]);
    let public = [7u8; 32];
    let spki = seq(&[&algorithm, &bits(&public)]);
    let with = |carried: Option<&[u8]>| {
        let mut parts = vec![
            der(INTEGER, &[1]),
            algorithm.clone(),
            der(OCTET_STRING, &der(OCTET_STRING, &[9u8; 32])),
        ];
        if let Some(carried) = carried {
            parts.push(der(IMPLICIT_1, &[&[0u8][..], carried].concat()));
        }
        der(SEQUENCE, &parts.concat())
    };
    assert_eq!(
        private_key_matches(&with(Some(&public)), &spki),
        Ok(KeyMatch::Proven)
    );
    assert_eq!(
        private_key_matches(&with(Some(&[8u8; 32])), &spki),
        Err(KeyMismatch::OtherKey)
    );
    assert_eq!(
        private_key_matches(&with(None), &spki),
        Ok(KeyMatch::Undecided)
    );
}

#[test]
fn bytes_that_are_no_key_are_refused() {
    let spki = ec_spki(P256, POINT);
    let good = ec_pkcs8(P256, Some(POINT));
    for garbage in [
        &b""[..],
        b"not a key",
        &[0x30],
        &[0x30, 0x05, 0x02, 0x01],
        &[0x30, 0x80, 0x00, 0x00],
        &[0xFF; 64],
    ] {
        assert_eq!(
            private_key_matches(garbage, &spki),
            Err(KeyMismatch::NotPkcs8),
            "{garbage:?}"
        );
    }
    // A key cut short, and a key with bytes after it.
    assert_eq!(
        private_key_matches(&good[..good.len() - 1], &spki),
        Err(KeyMismatch::NotPkcs8)
    );
    assert_eq!(
        private_key_matches(&[good.as_slice(), b"x"].concat(), &spki),
        Err(KeyMismatch::NotPkcs8)
    );
    assert_eq!(
        private_key_matches(&good, b"not a public key"),
        Err(KeyMismatch::NotSpki)
    );
}

#[test]
fn the_reader_reads_long_lengths_and_refuses_what_der_has_not() {
    // A content of 200 bytes takes the long form of one length byte.
    let long = der(OCTET_STRING, &[7u8; 200]);
    assert_eq!(long[1], 0x81);
    assert_eq!(Der::new(&long).expect(OCTET_STRING), Some(&[7u8; 200][..]));
    // And one of 300 bytes two.
    let longer = der(OCTET_STRING, &[7u8; 300]);
    assert_eq!(longer[1], 0x82);
    assert_eq!(
        Der::new(&longer).expect(OCTET_STRING).map(<[u8]>::len),
        Some(300)
    );

    // The indefinite form, a tag number past 30, a length past the input,
    // and a length of five bytes.
    for refused in [
        &[0x30, 0x80, 0x00, 0x00][..],
        &[0x1F, 0x01, 0x00],
        &[0x04, 0x05, 0x00],
        &[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00],
        &[0x04],
        &[],
    ] {
        assert_eq!(Der::new(refused).next_element(), None, "{refused:?}");
    }
    // Another tag than the one expected.
    assert_eq!(Der::new(&long).expect(INTEGER), None);
    // `whole` refuses bytes after the element.
    assert!(Der::whole(&long, OCTET_STRING).is_some());
    assert!(Der::whole(&[long.as_slice(), &[0]].concat(), OCTET_STRING).is_none());
}

#[test]
fn an_integer_is_compared_without_its_leading_zeros() {
    assert_eq!(magnitude(&[0, 0, 5, 0]), &[5, 0]);
    assert_eq!(magnitude(&[5]), &[5]);
    assert_eq!(magnitude(&[0, 0]), &[] as &[u8]);
    assert_eq!(magnitude(&[]), &[] as &[u8]);
}

proptest! {
    /// No bytes make the check panic, whichever side they are on.
    #[test]
    fn the_check_ends_on_any_input(
        key in proptest::collection::vec(any::<u8>(), 0..256),
        spki in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let good_key = ec_pkcs8(P256, Some(POINT));
        let good_spki = ec_spki(P256, POINT);
        prop_assert!(private_key_matches(&key, &good_spki).is_err());
        prop_assert!(private_key_matches(&good_key, &spki) != Ok(KeyMatch::Proven) || spki == good_spki);
        // Two arbitrary inputs: nothing is proven from nothing.
        if private_key_matches(&key, &spki) == Ok(KeyMatch::Proven) {
            prop_assert!(!key.is_empty() && !spki.is_empty());
        }
    }

    /// A well-formed key with one byte changed is never proven against the
    /// certificate unless the change left what is compared alone.
    #[test]
    fn a_damaged_key_is_not_proven_by_accident(position in 0usize..200, value in any::<u8>()) {
        let spki = ec_spki(P256, POINT);
        let mut key = ec_pkcs8(P256, Some(POINT));
        let position = position % key.len();
        let unchanged = key[position] == value;
        key[position] = value;
        if private_key_matches(&key, &spki) == Ok(KeyMatch::Proven) && !unchanged {
            // Only the private scalar, or the version, may differ.
            let original = ec_pkcs8(P256, Some(POINT));
            let point_at = original.len() - POINT.len();
            prop_assert!(position < point_at, "byte {position} of the point changed");
        }
    }

    /// The reader hands out content from inside the input only, and ends.
    #[test]
    fn the_reader_ends_on_any_input(input in proptest::collection::vec(any::<u8>(), 0..128)) {
        let mut reader = Der::new(&input);
        let mut read = 0usize;
        while let Some((_, content)) = reader.next_element() {
            // Each element takes at least its tag and length bytes.
            read += content.len() + 2;
            prop_assert!(read <= input.len());
        }
    }

    /// An element written with any length reads back as it was written.
    #[test]
    fn an_element_round_trips(tag in 0u8..0x1F, content in proptest::collection::vec(any::<u8>(), 0..400)) {
        let encoded = der(tag, &content);
        let mut reader = Der::new(&encoded);
        prop_assert_eq!(reader.next_element(), Some((tag, content.as_slice())));
        prop_assert_eq!(reader.next_element(), None);
    }
}
