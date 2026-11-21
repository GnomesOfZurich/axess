//! OAuth refresh-token flow: exchanges a stored refresh token at the IdP
//! for fresh access/ID tokens and updated [`OAuthClaims`].
//!
//! Distinct from the session/HTTP refresh-token flow in
//! [`crate::session::refresh`]: that path issues axess's own refresh
//! tokens against axess sessions; this path delegates to the upstream
//! IdP's `/token` endpoint with the IdP's refresh token.

use super::scoped::Scope;
use crate::authn::service::RequestAuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorKind, FederatedProvider},
    store::{FactorStore, IdentityStore},
};

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The refresh of [`ScopedOAuth`](super::ScopedOAuth); `scope` says whose
    /// provider `provider_name` names.
    #[tracing::instrument(
        name = "refresh_oauth_token",
        skip(self, scope, provider_name, refresh_token, expected_subject, original_nonce, dpop_key),
        fields(provider_name = %super::logged_provider_name(provider_name))
    )]
    pub(super) async fn refresh_scoped(
        &self,
        scope: &Scope,
        provider_name: &str,
        refresh_token: &str,
        expected_subject: &str,
        original_nonce: Option<&str>,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::RefreshOutcome, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        // Every early-return below records a Failure event with a
        // distinguishing reason tag. The original implementation only
        // emitted on the happy path, so SOC dashboards saw no signal for
        // repeated refresh-token failures (a brute-force or
        // stolen-refresh-token signal). Reasons used:
        //   * `token_refresh_no_token`       ; empty refresh_token
        //   * `token_refresh_unknown_provider`; provider_name not registered
        //   * `token_refresh_provider_rejected`; IdP rejected the token
        //   * `token_refresh_dpop_key_missing`; a binding provider, no key
        // Success continues to record `token_refresh` so the two are
        // distinguishable in the audit stream.

        // Until the name resolves it is only the caller's text, and the
        // failure rows carry it as a span does: escaped and cut. A resolved
        // name is a registered one and is written as it is.
        let unresolved_name = super::logged_provider_name(provider_name);
        // A configured kind is the configuration's, not the caller's text,
        // and is recorded as it is; a name with none is recorded escaped.
        let unresolved_kind = match self.scoped_provider_kind(scope, provider_name).await {
            FederatedProvider::Custom(_) => FederatedProvider::Custom(unresolved_name),
            configured => configured,
        };
        if refresh_token.is_empty() {
            self.record_oauth_refresh_failure(
                AuthFailureReason::TokenRefreshNoToken,
                unresolved_kind,
                scope,
            )
            .await?;
            return Err(OAuthError::NoRefreshToken);
        }

        let provider = match self.scoped_provider(scope, provider_name).await {
            Ok(provider) => provider,
            Err(e) => {
                let reason = if matches!(e, OAuthError::UnknownProvider(_)) {
                    AuthFailureReason::TokenRefreshUnknownProvider
                } else {
                    AuthFailureReason::TokenRefreshProviderRejected
                };
                self.record_oauth_refresh_failure(reason, unresolved_kind, scope)
                    .await?;
                return Err(e);
            }
        };

        // The name resolved: the rows from here record its configured kind.
        let kind = self.scoped_provider_kind(scope, provider_name).await;

        let signer = dpop_key.map(|key| axess_factors::oauth::DpopSigner {
            key,
            rng: &*self.inner.rng,
        });
        let outcome = match provider
            .refresh_token(refresh_token, expected_subject, original_nonce, signer)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // A refusal before anything was sent is the caller's fault,
                // not the IdP's verdict on the token: a SOC reading
                // "provider rejected" would chase a stolen token.
                let reason = if matches!(e, OAuthError::DpopKeyRequired) {
                    AuthFailureReason::TokenRefreshDpopKeyMissing
                } else {
                    AuthFailureReason::TokenRefreshProviderRejected
                };
                self.record_oauth_refresh_failure(reason, kind, scope)
                    .await?;
                return Err(e);
            }
        };

        // The IdP subject is never a local user id; the row names the user
        // and tenant the scope was given (`attributed_to`, `oauth_in_tenant`, or
        // the authenticated session behind `oauth_for_session`).
        let (user, tenant) = scope.attribution();
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .maybe_attributed_to(user, tenant)
                .with_factor(FactorKind::Federated(kind))
                .with_error(AuthFailureReason::TokenRefresh),
        )
        .await
        .map_err(|e| OAuthError::AuditStore(e.to_string()))?;

        Ok(outcome)
    }

    /// Record an OAuth refresh-token failure audit event.
    ///
    /// Mirrors [`record_oauth_failure`](super::login::RequestAuthnService::record_oauth_failure)
    /// but session-free: the refresh path is called with a provider name and
    /// a token, and the user and tenant the scope was given. `provider` is the
    /// resolved provider's kind, or `Custom` of the caller's name, escaped,
    /// while the name has not resolved.
    async fn record_oauth_refresh_failure(
        &self,
        reason: AuthFailureReason,
        provider: FederatedProvider,
        scope: &Scope,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;
        let (user, tenant) = scope.attribution();
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::LoginAttempt)
                .maybe_attributed_to(user, tenant)
                .with_factor(FactorKind::Federated(provider))
                .with_error(reason),
        )
        .await
        .map_err(|e| OAuthError::AuditStore(e.to_string()))
    }
}
