use crate::{
    authn::{
        backend::AuthnBackend,
        session::{auth_session::AuthSession, registry::SessionRegistry},
    },
    axum::{
        extract::FromRequestParts,
        http::{StatusCode, request::Parts},
    },
    utils::random::SecureRng,
};

impl<S, B, R, Rng> FromRequestParts<S> for AuthSession<B, R, Rng>
where
    S: Send + Sync,
    B: AuthnBackend + Send + Sync + 'static,
    R: SessionRegistry + Send + Sync + 'static,
    Rng: SecureRng,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.remove::<AuthSession<B, R, Rng>>().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to extract authentication session from `AuthManagerLayer`, please ensure it is applied correctly.",
        ))
    }
}
