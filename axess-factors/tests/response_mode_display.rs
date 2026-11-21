#![cfg(feature = "oauth")]
//! A response mode displays as the `response_mode` parameter value it puts
//! on the authorization request.

use axess_factors::oauth::ResponseMode;

#[test]
fn a_response_mode_displays_as_its_parameter_value() {
    for (mode, value) in [
        (ResponseMode::Query, "query"),
        (ResponseMode::Fragment, "fragment"),
        (ResponseMode::FormPost, "form_post"),
    ] {
        assert_eq!(mode.to_string(), value);
        assert_eq!(mode.to_string(), mode.as_str());
    }
}
