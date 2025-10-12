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
    let totp = TOTP::new(Algorithm::SHA1, 6, 30, 1, secret.as_bytes().to_vec());
    totp.expect("Failed to get TOTP")
        .check_current(code)
        .unwrap_or(false)

    // async fn verify_totp(&self, user: &User, totp_code: &str) -> Result<bool, Self::Error> {
    //     // TODO: Implement TOTP verification

    //     let totp = TOTP::new(
    //         Algorithm::SHA1,
    //         6,
    //         1,
    //         30,
    //         user.otp_secret.as_ref().unwrap().clone().into_bytes(),
    //     )?;

    //     Ok(totp.check_current(totp_code)?)
    // }
}
