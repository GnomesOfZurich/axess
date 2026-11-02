//! The facade names both front-channel logout handlers, so an adopter can
//! hold the bound handler `with_session_match_required` returns (as router
//! state, in a struct field) without a direct axess-core dependency.

#![cfg(feature = "oauth")]

use axess::federation::oauth::{
    BoundFrontChannelLogoutHandler, FrontChannelLogoutHandler, FrontChannelLogoutParams,
};

#[test]
fn both_front_channel_handlers_are_reachable_from_the_facade() {
    let bind: fn(FrontChannelLogoutHandler) -> BoundFrontChannelLogoutHandler =
        FrontChannelLogoutHandler::with_session_match_required;
    let params = FrontChannelLogoutParams {
        sid: Some("sid-1".into()),
        iss: None,
    };
    assert_eq!(params.sid.as_deref(), Some("sid-1"));
    assert!(std::mem::size_of_val(&bind) > 0);
}
