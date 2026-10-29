//! The audit hook of the back-channel logout handler.
//!
//! An IdP-initiated logout ends sessions without any request of the user's
//! own, and nothing else would record it: the invalidation goes straight to
//! the session registry. The handler therefore tells an optional
//! [`LogoutAudit`] about every session it ends, once per session, after the
//! registry has ended it.

use crate::authn::ids::UserId;
use crate::session::id::SessionId;
use std::future::Future;
use std::pin::Pin;

/// One session ended by a back-channel logout token.
#[derive(Debug, Clone)]
pub struct IdpSessionEnded {
    /// The issuer that sent the logout token.
    pub iss: String,
    /// The local user the session belonged to.
    pub user_id: UserId,
    /// The session that was ended.
    pub session_id: SessionId,
}

/// Where the handler reports the sessions it ends.
///
/// [`AuthnService::backchannel_logout_audit`](crate::authn::service::AuthnService::backchannel_logout_audit)
/// is the implementation that writes a `SessionInvalidated` audit row per
/// session; an application with its own sink implements the trait instead.
///
/// The session is already ended when this is called, so a failure is logged
/// and does not undo or retry the logout: the IdP's retry would only find its
/// token replayed.
pub trait LogoutAudit: Send + Sync + 'static {
    /// Record that `ended` was ended by the identity provider.
    fn session_ended<'a>(
        &'a self,
        ended: &'a IdpSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
