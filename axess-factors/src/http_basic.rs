//! The form-urlencoded step of HTTP Basic client authentication
//! (`client_secret_basic`, RFC 6749 section 2.3.1), shared by the OAuth
//! ceremony (`oauth`) and the outbound client (`outbound-oauth`), which build
//! without each other.

/// Form-urlencode one half of a `client_secret_basic` credential. RFC 6749
/// section 2.3.1 has the client id and secret each encoded this way before
/// they are joined with `:`, so a secret carrying `:`, `+` or `%` reaches a
/// strict server intact. The one place the spelling is made.
pub(crate) fn form_urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::form_urlencode;

    #[test]
    fn the_characters_a_basic_credential_must_not_carry_raw_are_encoded() {
        assert_eq!(form_urlencode("axess-id"), "axess-id");
        assert_eq!(form_urlencode("Gnomes2+"), "Gnomes2%2B");
        assert_eq!(form_urlencode("a:b%c d"), "a%3Ab%25c+d");
    }
}
