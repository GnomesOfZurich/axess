//! A TOTP code for an instant the test names: the HOTP code of that
//! instant's 30-second step. A binary that declares this module declares
//! `hotp_code` beside it.

/// The TOTP code for the given base32 secret at the given time.
pub fn generate_totp_code(secret: &str, now: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    crate::hotp_code::generate_hotp_code(secret, secs / 30)
}
