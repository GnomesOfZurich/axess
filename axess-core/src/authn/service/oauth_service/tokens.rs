//! Token-side OAuth operations: revocation (RFC 7009), RP-Initiated
//! Logout URL construction, and DPoP proof generation (RFC 9449).
//!
//! Each method is a thin pass-through to the configured provider; the
//! security-relevant logic (allowlist enforcement on logout redirects,
//! proof signing for DPoP) lives on the provider implementation itself. A
//! revocation made through a [`ScopedOAuth`](super::ScopedOAuth) is
//! recorded by a request row written before the provider is asked, and not
//! sent when that row cannot be written, and by an outcome row written after
//! the provider answers.

use super::scoped::Scope;
use crate::authn::event::{AuthEventBuilder, AuthEventType, AuthFailureReason};
use crate::authn::factor::FactorKind;
use crate::authn::service::{AuthnService, RequestAuthnService};
use crate::authn::store::{FactorStore, IdentityStore};

/// The reason on the `LogoutAttempt` row a scoped OAuth token revocation
/// writes before the identity provider is asked: the request, not its
/// outcome.
///
/// The row is a `Failure` until an outcome row with the same `request_id`
/// says otherwise, so a request whose outcome was never recorded (a crash
/// in between, or an outcome row the store refused) never reads as a
/// revoked token. The outcome row follows the provider's answer: a
/// `Success` when it revoked the token, a `Failure` whose reason starts
/// with `oauth token revocation refused` when it refused, and one that
/// starts with `oauth token revocation unconfirmed` when it did not answer
/// (a timeout, a connection lost after the request was sent, a server
/// error), since the provider may then have revoked the token or not.
pub const OAUTH_REVOCATION_REQUESTED_REASON: &str = "oauth_token_revocation_requested";

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// A fresh DPoP key for one session, drawn from the service's injected
    /// [`SecureRng`](axess_rng::SecureRng).
    ///
    /// RFC 9449 binds an access token to one key (`cnf.jkt`) and requires
    /// every proof presented with that token to be signed by it. Make one key
    /// when the session starts, keep it for the token's life (the key exports its
    /// scalar for that), and pass it to every
    /// [`generate_dpop_proof`](super::ScopedOAuth::generate_dpop_proof) call.
    pub fn new_dpop_key(&self) -> axess_factors::oauth::DpopKey {
        axess_factors::oauth::DpopKey::generate(&*self.inner.rng)
    }

    /// The DPoP proof of [`ScopedOAuth`](super::ScopedOAuth).
    pub(super) async fn dpop_proof_scoped(
        &self,
        scope: &Scope,
        provider_name: &str,
        key: &axess_factors::oauth::DpopKey,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> Result<axess_factors::oauth::DpopProof, axess_factors::oauth::OAuthError> {
        let provider = self.scoped_provider(scope, provider_name).await?;
        self.sign_dpop_proof(&provider, key, http_method, http_url, access_token)
    }

    fn sign_dpop_proof(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        key: &axess_factors::oauth::DpopKey,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> Result<axess_factors::oauth::DpopProof, axess_factors::oauth::OAuthError> {
        let mut jti_bytes = [0u8; 16];
        self.inner.rng.fill_bytes(&mut jti_bytes);
        let iat = self.inner.clock.now().unix_seconds();

        provider.generate_dpop_proof(key, http_method, http_url, access_token, iat, jti_bytes)
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The revocation [`ScopedOAuth`](super::ScopedOAuth) runs, recorded by
    /// two `LogoutAttempt` rows that name the provider, carry the scope's
    /// user and tenant when it has them, and share a `request_id` (the audit
    /// context's, or one drawn for this revocation when the context has
    /// none).
    ///
    /// The request row ([`OAUTH_REVOCATION_REQUESTED_REASON`], a `Failure`)
    /// is written first, and a store that refuses it fails the call before
    /// the provider is asked. The outcome row follows the provider's answer:
    /// `Success` for a revoked token, `Failure` with the refusal, or
    /// `Failure` marked unconfirmed when the provider did not answer. A
    /// store that refuses the outcome row fails the call with
    /// [`OAuthError::AuditStore`](axess_factors::oauth::OAuthError::AuditStore)
    /// whose message says what the provider answered: the token may then be
    /// revoked, and the trail shows the request with no outcome. A row the
    /// audit pipeline sheds
    /// ([`AuditOutcome::Shed`](crate::authn::store::AuditOutcome::Shed))
    /// counts as written, as it does for every audited flow: the sink chose
    /// to drop it, and the shed is counted in the audit metrics.
    pub(super) async fn revoke_scoped(
        &self,
        scope: &Scope,
        provider_name: &str,
        token: &str,
        token_type_hint: Option<&str>,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;
        let provider = self.scoped_provider(scope, provider_name).await?;
        let kind = self.scoped_provider_kind(scope, provider_name).await;
        let (user, tenant) = scope.attribution();
        let request_id = self.revocation_request_id();
        let row = |builder: AuthEventBuilder| {
            builder
                .maybe_attributed_to(user, tenant)
                .with_factor(FactorKind::Federated(kind.clone()))
                .with_request_id(request_id.clone())
        };
        self.emit_audit(row(AuthEventBuilder::failure(AuthEventType::LogoutAttempt)
            .with_error(AuthFailureReason::from(OAUTH_REVOCATION_REQUESTED_REASON))))
            .await
            .map_err(|e| OAuthError::AuditStore(e.to_string()))?;
        let signer = dpop_key.map(|key| axess_factors::oauth::DpopSigner {
            key,
            rng: &*self.inner.rng,
        });
        let revoked = provider.revoke_token(token, token_type_hint, signer).await;
        let (outcome, answered) = match &revoked {
            Ok(()) => (
                AuthEventBuilder::success(AuthEventType::LogoutAttempt),
                "the provider revoked the token".to_string(),
            ),
            Err(e) => {
                let verdict = if matches!(e, OAuthError::TokenEndpointTransient { .. }) {
                    "unconfirmed"
                } else {
                    "refused"
                };
                let text = format!("oauth token revocation {verdict}: {e}");
                (
                    AuthEventBuilder::failure(AuthEventType::LogoutAttempt)
                        .with_error(AuthFailureReason::Other(text.clone())),
                    text,
                )
            }
        };
        self.emit_audit(row(outcome)).await.map_err(|e| {
            OAuthError::AuditStore(format!(
                "the revocation's outcome row was not written ({answered}): {e}"
            ))
        })?;
        revoked
    }

    /// A `request_id` that pairs a revocation's request row with its outcome
    /// row when the audit context carries none.
    fn revocation_request_id(&self) -> String {
        let mut bytes = [0u8; 16];
        self.inner.rng.fill_bytes(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        format!("oauth-revocation-{hex}")
    }
}
