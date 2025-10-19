// use lazy_regex::regex;
#[cfg(feature = "authn")]
use totp_rs::{Algorithm, TOTP};

// pub(crate) fn is_valid_email(email: &str) -> bool {
//     // let re = reg::new(r"^(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$").unwrap();
//     // re.is_match(email)
//     let re = regex!(r#"^(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"#);
//     re.is_match(email)
// }

#[cfg(feature = "authn")]
pub fn verify_totp(secret: &str, code: &str) -> bool {
    // Create TOTP safely and return false on any construction/check error
    match TOTP::new(Algorithm::SHA1, 6, 30, 1, secret.as_bytes().to_vec()) {
        Ok(totp) => totp.check_current(code).unwrap_or(false),
        Err(e) => {
            tracing::error!("TOTP creation failed: {:?}", e);
            false
        }
    }
}
