//! The wire format of the browser front-end, in one place.
//!
//! The W3C Device Bound Session Credentials draft is still moving. The
//! values below were compared with the editor's draft of 9 November 2026;
//! no browser has run against them. The names, the two response header
//! values, the reading of the two request header values, the proof's layout,
//! the status codes and the member names of the session description are
//! constants or functions here, each with a test that pins it, so a
//! correction of one of them when the draft moves is a change to this file
//! and to that test.
//!
//! Three things the draft also governs are not in this file. Which claims
//! the verifier compares follows [`PROOF_AUDIENCE_CLAIM`] and
//! [`PROOF_KEY_PLACE`], in `key_proof`. The identifier a session is named
//! by (`<tenant>.<device>`, the value of [`SESSION_ID_HEADER`] and of the
//! description's [`session::IDENTIFIER`]) and the composition of the
//! session description (its scope, `include_site` false, the one cookie
//! credential and its attributes) are written by the session layer of
//! axess-core, from the member names here.
//!
//! Header names are lower-case because that is the form an HTTP header name
//! is compared in.

/// Response header that offers a registration.
pub const REGISTRATION_HEADER: &str = "secure-session-registration";

/// Response header that carries a challenge.
pub const CHALLENGE_HEADER: &str = "secure-session-challenge";

/// Request header that carries a proof.
pub const RESPONSE_HEADER: &str = "secure-session-response";

/// Request header that names the registration a refresh is for.
pub const SESSION_ID_HEADER: &str = "sec-secure-session-id";

/// Parameter of [`REGISTRATION_HEADER`] that names the registration path.
pub const REGISTRATION_PATH_PARAM: &str = "path";

/// Parameter of [`REGISTRATION_HEADER`] that carries the challenge.
pub const REGISTRATION_CHALLENGE_PARAM: &str = "challenge";

/// Parameter of [`CHALLENGE_HEADER`] that names the registration.
pub const CHALLENGE_ID_PARAM: &str = "id";

/// Status of an answer that only hands out a challenge.
pub const CHALLENGE_STATUS: u16 = 403;

/// Status of the answer that ends a registration.
pub const ENDED_STATUS: u16 = 200;

/// Body of the answer that ends a registration.
pub const ENDED_BODY: &str = r#"{"continue":false}"#;

/// `typ` of a proof.
pub const PROOF_TYP: &str = "dbsc+jwt";

/// Claim of a proof that holds the challenge it answers.
pub const PROOF_CHALLENGE_CLAIM: &str = "jti";

/// Claim of a proof that names the URL it was made for, when the format has
/// one. `None`: the later revision carries none, and a
/// proof is then bound to its endpoint and its device by the challenge
/// alone, which is single-use and minted for exactly one of each.
pub const PROOF_AUDIENCE_CLAIM: Option<&str> = None;

/// Where a registration proof carries its public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPlace {
    /// In the JOSE header.
    Header,
    /// Among the claims.
    Claims,
}

/// Where a registration proof carries its public key.
pub const PROOF_KEY_PLACE: KeyPlace = KeyPlace::Header;

/// The member, in [`PROOF_KEY_PLACE`], that holds the public key as a JWK.
pub const PROOF_KEY_MEMBER: &str = "jwk";

/// Members of the JSON a registration is answered with.
pub mod session {
    /// The registration's identifier.
    pub const IDENTIFIER: &str = "session_identifier";
    /// The path a refresh is sent to.
    pub const REFRESH_URL: &str = "refresh_url";
    /// The object that says which requests the registration covers.
    pub const SCOPE: &str = "scope";
    /// Member of [`SCOPE`]: the origin covered.
    pub const SCOPE_ORIGIN: &str = "origin";
    /// Member of [`SCOPE`]: whether the whole site is covered.
    pub const SCOPE_INCLUDE_SITE: &str = "include_site";
    /// The list of credentials the registration keeps fresh.
    pub const CREDENTIALS: &str = "credentials";
    /// Member of a credential: its kind.
    pub const CREDENTIAL_TYPE: &str = "type";
    /// The one kind of credential: a cookie.
    pub const CREDENTIAL_TYPE_COOKIE: &str = "cookie";
    /// Member of a credential: the cookie's name.
    pub const CREDENTIAL_NAME: &str = "name";
    /// Member of a credential: the attributes the cookie is set with.
    pub const CREDENTIAL_ATTRIBUTES: &str = "attributes";
}

/// Status of a final refusal at the refresh path: a request that names no
/// session, a value that is no proof, a proof for another request, a
/// signature that is not the key's. It is not [`CHALLENGE_STATUS`], which a
/// browser answers by sending the same refresh again with the challenge it
/// holds, and not 407 or 429, which a browser passes over: the draft has a
/// browser end its session on any other status from 400 to 499.
pub const REFRESH_REFUSED_STATUS: u16 = 400;

/// The string a request header of the draft carries, from the header's
/// value.
///
/// The draft defines the values of [`RESPONSE_HEADER`] and
/// [`SESSION_ID_HEADER`] as structured-field strings, the text in double
/// quotes with any parameters to be ignored, and shows them so; its own
/// algorithm appends the bare value. Both forms are read: the content of a
/// quoted string, or the bare value up to a parameter. `None` for a quoted
/// string that is not closed or that holds a backslash escape: neither a
/// proof nor an identifier contains a character that needs one.
pub fn request_header_string(value: &str) -> Option<&str> {
    let value = value.trim_matches(' ');
    match value.strip_prefix('"') {
        Some(rest) => {
            let end = rest.find(['"', '\\'])?;
            rest[end..].starts_with('"').then_some(&rest[..end])
        }
        None => Some(
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim_end_matches(' '),
        ),
    }
}

/// The value of [`REGISTRATION_HEADER`]: a structured-field list of the
/// one algorithm offered, with the registration path and the challenge the
/// registration proof must answer as its parameters.
pub fn registration_header_value(algorithm: &str, path: &str, challenge: &str) -> String {
    format!(
        "({algorithm});{REGISTRATION_PATH_PARAM}=\"{path}\";\
         {REGISTRATION_CHALLENGE_PARAM}=\"{challenge}\""
    )
}

/// The value of [`CHALLENGE_HEADER`]: the challenge as a quoted string,
/// with the identifier of the session it is for as its parameter.
pub fn challenge_header_value(challenge: &str, identifier: &str) -> String {
    format!("\"{challenge}\";{CHALLENGE_ID_PARAM}=\"{identifier}\"")
}

#[cfg(test)]
mod tests {
    //! One test per constant. A test that fails here after an edit is the
    //! reminder to check the edit against the draft's text.
    use super::*;

    /// A final refusal must be a status the draft has a browser end its
    /// session on: from 400 to 499 and none of the three it treats apart.
    #[test]
    fn refresh_refused_status() {
        assert_eq!(REFRESH_REFUSED_STATUS, 400);
        assert!((400..500).contains(&REFRESH_REFUSED_STATUS));
        assert!(![CHALLENGE_STATUS, 407, 429].contains(&REFRESH_REFUSED_STATUS));
    }

    /// A request header's string is read quoted, as the draft defines it,
    /// and bare, as its algorithm appends it; parameters are ignored.
    #[test]
    fn a_request_header_string_is_read_quoted_and_bare() {
        for value in [
            "a.b.c",
            "\"a.b.c\"",
            "\"a.b.c\";x=1",
            "\"a.b.c\"; x=\"y\"",
            " \"a.b.c\" ",
            "a.b.c;x=1",
            " a.b.c ",
        ] {
            assert_eq!(request_header_string(value), Some("a.b.c"), "{value:?}");
        }
        assert_eq!(request_header_string("\"\""), Some(""));
        assert_eq!(request_header_string(""), Some(""));
        for value in ["\"a.b.c", "\"", "\"a\\\"b\"", "\"a\\\\b\""] {
            assert_eq!(request_header_string(value), None, "{value:?}");
        }
    }

    #[test]
    fn the_two_header_values() {
        assert_eq!(
            registration_header_value("ES256", "/axess/device-key", "v1.9.abc"),
            r#"(ES256);path="/axess/device-key";challenge="v1.9.abc""#
        );
        assert_eq!(
            challenge_header_value("c2lnbg", "tenant.device"),
            r#""c2lnbg";id="tenant.device""#
        );
    }

    #[test]
    fn registration_header() {
        assert_eq!(REGISTRATION_HEADER, "secure-session-registration");
    }

    #[test]
    fn challenge_header() {
        assert_eq!(CHALLENGE_HEADER, "secure-session-challenge");
    }

    #[test]
    fn response_header() {
        assert_eq!(RESPONSE_HEADER, "secure-session-response");
    }

    #[test]
    fn session_id_header() {
        assert_eq!(SESSION_ID_HEADER, "sec-secure-session-id");
    }

    /// A header name is compared in lower case, and an upper-case letter in
    /// one of these would make `HeaderName::from_static` panic.
    #[test]
    fn header_names_are_lower_case_tokens() {
        for name in [
            REGISTRATION_HEADER,
            CHALLENGE_HEADER,
            RESPONSE_HEADER,
            SESSION_ID_HEADER,
        ] {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{name}"
            );
        }
    }

    #[test]
    fn registration_path_param() {
        assert_eq!(REGISTRATION_PATH_PARAM, "path");
    }

    #[test]
    fn registration_challenge_param() {
        assert_eq!(REGISTRATION_CHALLENGE_PARAM, "challenge");
    }

    #[test]
    fn challenge_id_param() {
        assert_eq!(CHALLENGE_ID_PARAM, "id");
    }

    #[test]
    fn challenge_status() {
        assert_eq!(CHALLENGE_STATUS, 403);
    }

    #[test]
    fn ended_status() {
        assert_eq!(ENDED_STATUS, 200);
    }

    #[test]
    fn ended_body() {
        assert_eq!(ENDED_BODY, "{\"continue\":false}");
        let parsed: serde_json::Value = serde_json::from_str(ENDED_BODY).unwrap();
        assert_eq!(parsed["continue"], serde_json::Value::Bool(false));
    }

    #[test]
    fn proof_typ() {
        assert_eq!(PROOF_TYP, "dbsc+jwt");
    }

    #[test]
    fn proof_challenge_claim() {
        assert_eq!(PROOF_CHALLENGE_CLAIM, "jti");
    }

    #[test]
    fn proof_audience_claim() {
        assert_eq!(PROOF_AUDIENCE_CLAIM, None);
    }

    #[test]
    fn proof_key_place() {
        assert_eq!(PROOF_KEY_PLACE, KeyPlace::Header);
    }

    #[test]
    fn proof_key_member() {
        assert_eq!(PROOF_KEY_MEMBER, "jwk");
    }

    #[test]
    fn session_identifier_member() {
        assert_eq!(session::IDENTIFIER, "session_identifier");
    }

    #[test]
    fn session_refresh_url_member() {
        assert_eq!(session::REFRESH_URL, "refresh_url");
    }

    #[test]
    fn session_scope_members() {
        assert_eq!(session::SCOPE, "scope");
        assert_eq!(session::SCOPE_ORIGIN, "origin");
        assert_eq!(session::SCOPE_INCLUDE_SITE, "include_site");
    }

    #[test]
    fn session_credential_members() {
        assert_eq!(session::CREDENTIALS, "credentials");
        assert_eq!(session::CREDENTIAL_TYPE, "type");
        assert_eq!(session::CREDENTIAL_TYPE_COOKIE, "cookie");
        assert_eq!(session::CREDENTIAL_NAME, "name");
        assert_eq!(session::CREDENTIAL_ATTRIBUTES, "attributes");
    }
}
