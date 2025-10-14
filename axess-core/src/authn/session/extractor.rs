use crate::{
    authn::{
        backend::AuthnBackend,
        session::{auth_session::AuthSession, registry::SessionRegistry},
    },
    axum::{
        extract::FromRequestParts,
        http::{StatusCode, request::Parts},
    },
};

impl<S, B, R> FromRequestParts<S> for AuthSession<B, R>
where
    S: Send + Sync,
    B: AuthnBackend + Send + Sync + 'static,
    R: SessionRegistry + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.remove::<AuthSession<B, R>>().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to extract authentication session from `AuthManagerLayer`, please ensure it is applied correctly.",
        ))
    }
}
