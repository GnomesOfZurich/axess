//! The facade names both front-channel logout handlers, so an adopter can
//! hold the bound handler `FrontChannelLogoutHandler::new` returns (as router
//! state, in a struct field) without a direct axess-core dependency.

#![cfg(feature = "oauth")]

use axess::federation::oauth::{
    BoundFrontChannelLogoutHandler, FrontChannelLogoutHandler, FrontChannelLogoutParams,
};

#[test]
fn both_front_channel_handlers_are_reachable_from_the_facade() {
    // `new` builds the bound handler and `new_unbound` the plain one.
    fn bound<A, B, C>(_: fn(A, B, C) -> BoundFrontChannelLogoutHandler) {}
    fn unbound<A, B, C>(_: fn(A, B, C) -> FrontChannelLogoutHandler) {}
    bound(FrontChannelLogoutHandler::new);
    unbound(FrontChannelLogoutHandler::new_unbound);
    let params = FrontChannelLogoutParams {
        sid: Some("sid-1".into()),
        iss: None,
    };
    assert_eq!(params.sid.as_deref(), Some("sid-1"));
}
