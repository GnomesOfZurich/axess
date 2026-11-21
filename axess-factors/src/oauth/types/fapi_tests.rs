//! What a verified JARM response shows when it is printed.

use super::fapi::JarmResponse;

/// The authorization code redeems for tokens and the `state` is the
/// ceremony's CSRF value: neither reaches a log through `{:?}`.
#[test]
fn the_debug_output_of_a_jarm_response_redacts_the_code_and_the_state() {
    let response = JarmResponse {
        iss: "https://idp.example".into(),
        code: Some("SplxlOBeZQQYbYS6WxSbIA".into()),
        state: Some("af0ifjsldkj".into()),
        error: None,
    };

    let printed = format!("{response:?}");

    assert!(!printed.contains("SplxlOBeZQQYbYS6WxSbIA"), "{printed}");
    assert!(!printed.contains("af0ifjsldkj"), "{printed}");
    assert!(printed.contains("https://idp.example"), "{printed}");
    assert!(printed.contains("[redacted]"), "{printed}");

    let refusal = JarmResponse {
        iss: "https://idp.example".into(),
        code: None,
        state: None,
        error: Some("access_denied".into()),
    };
    let printed = format!("{refusal:?}");
    assert!(
        printed.contains("access_denied") && printed.contains("None"),
        "{printed}"
    );
}
