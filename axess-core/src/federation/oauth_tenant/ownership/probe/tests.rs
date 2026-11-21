//! How a failed discovery reads in the probe's traced reason: each kind of
//! failure by its own sentence, and a transport failure without its URL.

use super::*;

#[test]
fn each_discovery_failure_reads_as_its_own_reason() {
    let cases = [
        (
            OidcError::EgressRefused {
                setting: "issuer URL".into(),
                range: "loopback".into(),
            },
            "discovery refused: issuer URL refused: loopback",
        ),
        (
            OidcError::NonHttpsIssuer("http://idp.example".into()),
            "discovery refused: HTTPS required",
        ),
        (
            OidcError::InvalidIssuer("https://idp.example".into()),
            "the discovery document names another issuer",
        ),
        (
            OidcError::MissingField("jwks_uri"),
            "the discovery document has no jwks_uri",
        ),
        (
            OidcError::DiscoveryParse("expected value".into()),
            "the discovery document does not parse",
        ),
        (
            OidcError::DiscoveryFetch(
                "error sending request for url (https://idp.example/)".into(),
            ),
            "the discovery document could not be fetched",
        ),
    ];
    for (error, reason) in cases {
        assert_eq!(discovery_failure(&error), reason, "{error:?}");
    }
}
