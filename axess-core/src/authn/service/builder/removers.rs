//! The store operations the credential-change paths need, behind trait
//! objects so the service does not take the stores' types as parameters.

/// Deletes one stored session row, behind a trait object so the service does
/// not take the session store's type as a parameter.
pub(crate) trait SessionRowRemover: Send + Sync {
    /// Delete the row of `id`. The error is its text.
    fn delete_row<'a>(
        &'a self,
        id: &'a crate::session::id::SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;
}

pub(super) struct RowRemover<S>(pub(super) S);

impl<S: crate::session::store::SessionStore> SessionRowRemover for RowRemover<S> {
    fn delete_row<'a>(
        &'a self,
        id: &'a crate::session::id::SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.0.delete(id).await.map_err(|e| e.to_string()) })
    }
}

/// The one refresh-token operation the credential-change paths need, behind a
/// trait object so the service does not take the store's type as a parameter.
pub(crate) trait UserTokenRevoker: Send + Sync {
    /// Revoke every refresh token of `user_id`. The error is its text.
    fn revoke_user_tokens<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;
}

pub(super) struct RefreshStoreRevoker<R>(pub(super) R);

impl<R> UserTokenRevoker for RefreshStoreRevoker<R>
where
    R: crate::session::refresh::RefreshTokenStore + 'static,
{
    fn revoke_user_tokens<'a>(
        &'a self,
        user_id: &'a crate::authn::ids::UserId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .revoke_user_tokens(user_id)
                .await
                .map_err(|e| e.to_string())
        })
    }
}
