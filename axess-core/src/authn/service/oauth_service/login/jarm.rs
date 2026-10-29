//! `finish_oauth_login_jarm`: the callback of a provider that returns the
//! authorization response as a signed JWT (JWT Secured Authorization Response
//! Mode, `response_mode=jwt`).

use super::finish::IssCheck;
use crate::authn::event::AuthFailureReason;
use crate::authn::service::RequestAuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::extractor::AuthSession;

/// Longest response JWT accepted, in bytes. A signed response carries a code,
/// a state and a few claims; anything near this size is not one.
const MAX_JARM_RESPONSE_BYTES: usize = 16 * 1024;

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Complete an OAuth/OIDC login whose authorization response is a JWT
    /// (the `response` query or form parameter of the callback).
    ///
    /// The JWT is verified against the provider's key set (its signature, an
    /// `iss` equal to the provider's issuer, an `aud` naming this client, an
    /// unexpired `exp`; never `none`, never a symmetric algorithm). A stale
    /// key set is refreshed once and the check repeated. The `code`, `state`
    /// and `iss` it carries then go through exactly the checks
    /// [`finish_oauth_login_with_iss`](Self::finish_oauth_login_with_iss)
    /// makes, with `iss` required, so a signed response cannot be replayed
    /// into another flow.
    ///
    /// A response that carries the IdP's `error` instead of a code ends the
    /// ceremony and is refused as
    /// [`OAuthError::TokenExchange`](axess_factors::oauth::OAuthError::TokenExchange).
    ///
    /// # Errors
    ///
    /// [`OAuthError::NoFlow`](axess_factors::oauth::OAuthError::NoFlow)
    /// without a ceremony in the session,
    /// [`OAuthError::InvalidParameter`](axess_factors::oauth::OAuthError::InvalidParameter)
    /// for an oversized or incomplete response, and
    /// [`OAuthError::IdTokenValidation`](axess_factors::oauth::OAuthError::IdTokenValidation)
    /// when the JWT does not verify. Everything
    /// [`finish_oauth_login_with_iss`](Self::finish_oauth_login_with_iss)
    /// reports follows.
    #[tracing::instrument(skip(self, response, session))]
    pub async fn finish_oauth_login_jarm(
        &self,
        response: &str,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        if response.len() > MAX_JARM_RESPONSE_BYTES {
            return Err(OAuthError::InvalidParameter);
        }
        let provider_name = session
            .get_custom(oauth_keys::PROVIDER)
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or(OAuthError::NoFlow)?;
        let provider = self
            .inner
            .oauth_providers
            .get(&provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.clone()))?
            .clone();

        let verified = match provider.verify_authorization_response_jwt(response) {
            Err(OAuthError::UnknownKid(_) | OAuthError::JwksExpired) => {
                if let Err(e) = provider.refresh_jwks().await {
                    tracing::warn!(error = %e, "JWKS refresh before JARM retry failed");
                }
                provider.verify_authorization_response_jwt(response)
            }
            other => other,
        };
        let verified = match verified {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    provider = %provider_name,
                    error = %e,
                    "authorization response JWT did not verify"
                );
                self.record_oauth_failure_and_clear(
                    AuthFailureReason::ProviderMismatch,
                    &provider_name,
                    session,
                )
                .await?;
                return Err(OAuthError::IdTokenValidation(
                    "authorization response did not verify".to_string(),
                ));
            }
        };

        if verified.error.is_some() {
            tracing::warn!(
                provider = %provider_name,
                "the identity provider refused the authorization request"
            );
            self.record_oauth_failure_and_clear(
                AuthFailureReason::Other("authorization_refused".to_string()),
                &provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::TokenExchange(
                "the identity provider refused the authorization request".to_string(),
            ));
        }
        let (Some(code), Some(state)) = (&verified.code, &verified.state) else {
            return Err(OAuthError::InvalidParameter);
        };
        self.finish_oauth_login_checked(
            code,
            state,
            IssCheck::Compared(Some(&verified.iss)),
            true,
            session,
        )
        .await
    }
}
