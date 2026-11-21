//! An HOTP code computed from RFC 4226 here, not by the library under test:
//! the value a test offers a verifier that must accept or refuse it.

/// The HOTP code for the given base32 secret at the given counter
/// (RFC 4226). Used to validate the counter-advance + replay-rejection paths.
pub fn generate_hotp_code(secret: &str, counter: u64) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;

    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let mut mac = Hmac::<Sha1>::new_from_slice(&decoded).unwrap();
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0f) as usize;
    let binary = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);
    format!("{:06}", binary % 1_000_000)
}
