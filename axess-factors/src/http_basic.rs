//! The form-urlencoded step of HTTP Basic client authentication
//! (`client_secret_basic`, RFC 6749 section 2.3.1), shared by the OAuth
//! ceremony (`oauth`) and the outbound client (`outbound-oauth`), which build
//! without each other, and the header built from it.

/// Form-urlencode one half of a `client_secret_basic` credential. RFC 6749
/// section 2.3.1 has the client id and secret each encoded this way before
/// they are joined with `:`, so a secret carrying `:`, `+` or `%` reaches a
/// strict server intact. The one place the spelling is made.
pub(crate) fn form_urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Base64 payload of a `client_secret_basic` credential: the client id and
/// secret each [`form_urlencode`]d, joined with `:`, base64-encoded. The
/// value is the secret in another spelling, so it is a
/// [`ZeroizedString`](crate::secret::ZeroizedString), as is every buffer on
/// the way to it.
pub(crate) fn credentials(client_id: &str, client_secret: &str) -> crate::secret::ZeroizedString {
    use crate::secret::ZeroizedString;
    use base64::Engine as _;
    let enc = |s: &str| ZeroizedString::new(form_urlencode(s));
    let id = enc(client_id);
    let secret = enc(client_secret);
    // Sized up front: a buffer that grows leaves its earlier allocations
    // behind unzeroed.
    let mut joined = String::with_capacity(id.len() + 1 + secret.len());
    joined.push_str(&id);
    joined.push(':');
    joined.push_str(&secret);
    let joined = ZeroizedString::new(joined);
    ZeroizedString::new(base64::engine::general_purpose::STANDARD.encode(&*joined))
}

/// The `Authorization` header for `client_secret_basic`: `Basic` and
/// [`credentials`], marked sensitive so the header is redacted wherever the
/// request's headers are printed.
pub(crate) fn authorization(
    client_id: &str,
    client_secret: &str,
) -> Result<reqwest::header::HeaderValue, reqwest::header::InvalidHeaderValue> {
    const SCHEME: &str = "Basic ";
    let credentials = credentials(client_id, client_secret);
    let mut value = String::with_capacity(SCHEME.len() + credentials.len());
    value.push_str(SCHEME);
    value.push_str(&credentials);
    let value = crate::secret::ZeroizedString::new(value);
    let mut header = reqwest::header::HeaderValue::from_str(&value)?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::form_urlencode;

    #[test]
    fn the_characters_a_basic_credential_must_not_carry_raw_are_encoded() {
        assert_eq!(form_urlencode("axess-id"), "axess-id");
        assert_eq!(form_urlencode("Sample2+"), "Sample2%2B");
        assert_eq!(form_urlencode("a:b%c d"), "a%3Ab%25c+d");
    }
}
