//! Step 2 of the OAuth/OIDC login ceremony: `finish_oauth_login`.
//!
//! Handles the callback: validates state + PKCE + provider issuer,
//! exchanges the code for OIDC claims, and mints the claim-binding
//! lock that `complete_oauth_login` will verify.

use super::helpers::{compute_claim_lock, is_valid_pkce_verifier, normalize_issuer};
use crate::authn::service::RequestAuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::FactorKind,
    ids::UserId,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use subtle::ConstantTimeEq;

/// Whether the callback's `iss` parameter is compared.
#[derive(Clone, Copy)]
pub(super) enum IssCheck<'a> {
    /// The caller used the form that does not take it.
    Skipped,
    /// The caller passed what the callback carried, possibly nothing.
    Compared(Option<&'a str>),
}

/// RFC 9207 §2.4: a present `iss` equals the provider's issuer by simple
/// string comparison (constant time here, as it is compared with a value an
/// attacker influences); an absent one is acceptable only when the provider
/// does not advertise that it sends one.
fn iss_parameter_acceptable(
    response_iss: Option<&str>,
    provider_issuer: Option<&str>,
    required: bool,
) -> bool {
    match (response_iss, provider_issuer) {
        (Some(got), Some(want)) => bool::from(got.as_bytes().ct_eq(want.as_bytes())),
        // A provider without an issuer has nothing to compare with.
        (Some(_), None) => false,
        (None, _) => !required,
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Complete an OAuth/OIDC login flow.
    ///
    /// This form does not look at the `iss` parameter of the authorization
    /// response, so the mix-up defence of RFC 9207 rests on the session state
    /// alone. Prefer
    /// [`finish_oauth_login_with_iss`](Self::finish_oauth_login_with_iss),
    /// which compares it.
    #[tracing::instrument(skip(self, code, state, session))]
    pub async fn finish_oauth_login(
        &self,
        code: &str,
        state: &str,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        self.finish_oauth_login_checked(code, state, IssCheck::Skipped, false, session)
            .await
    }

    /// Complete an OAuth/OIDC login flow, comparing the `iss` parameter of
    /// the authorization response with the provider's issuer (RFC 9207).
    ///
    /// Pass the `iss` query (or form) parameter of the callback, or `None`
    /// when the response had none. A present `iss` must equal the issuer of
    /// the provider the flow began with, exactly; a different one is a mix-up
    /// attempt and is refused as a CSRF mismatch. A missing `iss` is refused
    /// when the provider's metadata advertises
    /// `authorization_response_iss_parameter_supported`, and accepted when it
    /// does not.
    ///
    /// Register one redirect URI per provider as well: the parameter is the
    /// defence for an authorization server that cannot be told from another by
    /// the redirect URI alone.
    #[tracing::instrument(skip(self, code, state, iss, session))]
    pub async fn finish_oauth_login_with_iss(
        &self,
        code: &str,
        state: &str,
        iss: Option<&str>,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        self.finish_oauth_login_checked(code, state, IssCheck::Compared(iss), false, session)
            .await
    }

    /// The shared body of the finish forms. `jarm` says the `code`, `state`
    /// and `iss` come out of a verified JWT Secured Authorization Response;
    /// a provider that requires that refuses them any other way.
    pub(super) async fn finish_oauth_login_checked(
        &self,
        code: &str,
        state: &str,
        iss: IssCheck<'_>,
        jarm: bool,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        use crate::validation::MAX_OAUTH_PARAM_BYTES;
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        // Reject oversized callback parameters before processing.
        let iss_len = match iss {
            IssCheck::Compared(Some(iss)) => iss.len(),
            _ => 0,
        };
        if code.len() > MAX_OAUTH_PARAM_BYTES
            || state.len() > MAX_OAUTH_PARAM_BYTES
            || iss_len > MAX_OAUTH_PARAM_BYTES
        {
            return Err(OAuthError::InvalidParameter);
        }

        let get_str = |v: serde_json::Value| v.as_str().map(|s| s.to_string());

        let stored_csrf = session
            .get_custom(oauth_keys::CSRF_STATE)
            .await
            .and_then(get_str)
            .ok_or(OAuthError::NoFlow)?;
        let stored_nonce = session
            .get_custom(oauth_keys::NONCE)
            .await
            .and_then(get_str)
            .ok_or(OAuthError::NoFlow)?;
        let stored_verifier = session
            .get_custom(oauth_keys::PKCE_VERIFIER)
            .await
            .and_then(get_str)
            .ok_or(OAuthError::NoFlow)?;
        // Extracted before the PKCE validation below so the warn!/record
        // failure paths can attribute the failure to a provider.
        let provider_name = session
            .get_custom(oauth_keys::PROVIDER)
            .await
            .and_then(get_str)
            .ok_or(OAuthError::NoFlow)?;
        // Validate the stashed PKCE code_verifier locally before
        // we waste the AS round-trip. RFC 7636 §4.1 fixes the alphabet
        // (`unreserved` = ALPHA / DIGIT / "-" / "." / "_" / "~") and
        // length (43..=128). A verifier outside the spec means session
        // tampering or a bug in `begin_oauth_login`; either way the AS
        // would reject the exchange anyway.
        if !is_valid_pkce_verifier(&stored_verifier) {
            tracing::warn!(
                provider = %provider_name,
                verifier_len = stored_verifier.len(),
                "stashed PKCE code_verifier failed RFC 7636 §4.1 validation"
            );
            self.record_oauth_failure_and_clear(
                AuthFailureReason::PkceVerifierInvalid,
                &provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::InvalidParameter);
        }

        if self.is_oauth_expired(session, &provider_name).await {
            self.record_oauth_failure_and_clear(
                AuthFailureReason::CeremonyExpired,
                &provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::Expired);
        }

        if !bool::from(state.as_bytes().ct_eq(stored_csrf.as_bytes())) {
            self.record_oauth_failure_and_clear(
                AuthFailureReason::CsrfMismatch,
                &provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::CsrfMismatch);
        }

        // Cycle session ID immediately after successful CSRF/nonce validation
        // to prevent session fixation during the OAuth callback window.
        session.regenerate().await;

        // Validate that the callback came from the same provider that initiated
        // the flow. Without this check an attacker who compromises Provider A
        // could replay a valid state from Provider A at Provider B's callback
        // (confused-deputy attack).
        let provider = self
            .inner
            .oauth_providers
            .get(&provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.clone()))?
            .clone();

        // Anti-confused-deputy rail: the issuer the begin-side stashed
        // must match the issuer of the provider whose callback we're
        // handling. See helper for the full argument.
        self.verify_provider_issuer_matches(&provider, &provider_name, session)
            .await?;

        if provider.authorization_response_jwt_required() && !jarm {
            tracing::warn!(
                provider = %provider_name,
                "plain authorization response for a provider that requires JARM; refusing"
            );
            self.record_oauth_failure_and_clear(
                AuthFailureReason::ProviderMismatch,
                &provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::InvalidParameter);
        }

        if let IssCheck::Compared(response_iss) = iss {
            self.verify_response_iss(&provider, &provider_name, response_iss, session)
                .await?;
        }

        let claims = self
            .exchange_code_for_login(
                &provider,
                &provider_name,
                code,
                stored_verifier,
                stored_nonce,
                session,
            )
            .await?;

        self.seal_finished_login(&provider_name, &claims, session)
            .await?;

        Ok(claims)
    }

    /// Exchange the code at the provider, recording and clearing the ceremony
    /// when the exchange fails.
    async fn exchange_code_for_login(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        provider_name: &str,
        code: &str,
        stored_verifier: String,
        stored_nonce: String,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        // A provider that binds tokens to a DPoP key gets a fresh one per
        // login, drawn from the service's rng; the claims carry it back.
        let dpop_key = provider
            .fapi_config()
            .filter(|f| {
                matches!(
                    f.sender_constraint,
                    axess_factors::oauth::SenderConstraint::DPoP
                )
            })
            .map(|_| axess_factors::oauth::DpopKey::generate(&*self.inner.rng));
        let signer = dpop_key
            .as_ref()
            .map(|key| axess_factors::oauth::DpopSigner {
                key,
                rng: &*self.inner.rng,
            });

        match provider
            .exchange_code_with(code, stored_verifier, stored_nonce, signer)
            .await
        {
            Ok(c) => Ok(c),
            Err(e) => {
                // Log the original error server-side but return a generic error
                // to prevent leaking provider-specific details to the caller.
                tracing::error!(
                    provider = %provider_name,
                    error = %e,
                    "OAuth token exchange failed"
                );
                self.record_oauth_failure_and_clear(
                    AuthFailureReason::TokenExchange,
                    provider_name,
                    session,
                )
                .await?;
                Err(OAuthError::TokenExchange(
                    "token exchange failed".to_string(),
                ))
            }
        }
    }

    /// After a successful exchange: clear the ceremony state, stash the
    /// claim-binding lock, and audit the login attempt.
    async fn seal_finished_login(
        &self,
        provider_name: &str,
        claims: &axess_factors::oauth::OAuthClaims,
        session: &AuthSession,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::keys as oauth_keys;
        // Keep the expected-tenant binding: `complete_oauth_login` checks
        // it against the resolved user and removes it afterwards.
        self.clear_oauth_state_except_tenant(session).await;

        // Stash a claim-binding lock in the session AFTER the
        // OAuth ceremony state is cleared so it survives into the
        // application's claims→user resolver call and the subsequent
        // `complete_oauth_login`. The lock is
        // SHA-256(provider || ":" || subject || ":" || session_id); a
        // value computed exclusively from data the IdP just attested to,
        // bound to this session. `complete_oauth_login` recomputes the
        // same hash from its argument claims and the current session id,
        // and refuses if the lock is missing or doesn't match. Defends
        // against a misbehaving handler that bypasses `finish_oauth_login`
        // and calls `complete_oauth_login` directly with attacker-supplied
        // `User`/`OAuthClaims`.
        let lock = compute_claim_lock(provider_name, &claims.subject, session).await;
        session
            .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
            .await;

        // Attribution: the OAuth subject may or may not be a valid UserId,
        // and the local tenant has not yet been resolved at this stage.
        // Record whatever attribution we have; `None` for anything that
        // cannot be turned into a typed id.
        let subject_user = UserId::try_new(claims.subject.as_str()).ok();
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .maybe_attributed_to(subject_user.as_ref(), None)
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.to_string()),
                )),
        )
        .await
        .map_err(|e| axess_factors::oauth::OAuthError::AuditStore(e.to_string()))?;

        Ok(())
    }

    /// RFC 9207: the `iss` parameter of the authorization response names the
    /// server that issued the code, which defeats a mix-up that the session
    /// state alone does not. A mismatch is recorded, the ceremony cleared, and
    /// the callback refused as a CSRF mismatch.
    async fn verify_response_iss(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        provider_name: &str,
        response_iss: Option<&str>,
        session: &AuthSession,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        if iss_parameter_acceptable(
            response_iss,
            provider.issuer(),
            provider.authorization_response_iss_required(),
        ) {
            return Ok(());
        }
        tracing::warn!(
            provider = %provider_name,
            "authorization response `iss` does not match the provider's issuer; refusing"
        );
        self.record_oauth_failure_and_clear(
            AuthFailureReason::ProviderMismatch,
            provider_name,
            session,
        )
        .await?;
        Err(axess_factors::oauth::OAuthError::CsrfMismatch)
    }

    /// Verify the callback's provider issuer matches what
    /// `begin_oauth_login` stashed (anti-confused-deputy rail).
    ///
    /// Without this check an attacker who compromises Provider A
    /// could replay a valid `state` value from a Provider A
    /// authorization request at Provider B's callback endpoint, since
    /// the begin-side stash of `(provider, csrf_state)` survives
    /// across providers because the session is the same. We pin the
    /// callback's provider to the begin-side issuer URL so a
    /// cross-provider `state` replay reaches a normalised-issuer
    /// inequality and is rejected as `CsrfMismatch`.
    ///
    /// **Fails closed** when the issuer is missing from the session
    /// (old session, mid-flow library upgrade that didn't stash the
    /// issuer, tampering): rejected as `NoFlow` rather than
    /// silently letting the callback through. Both branches go
    /// through `record_oauth_failure_and_clear` so the SOC sees the
    /// rejection and the session-side ceremony state is released
    /// for the next `begin_oauth_login`.
    async fn verify_provider_issuer_matches(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        provider_name: &str,
        session: &AuthSession,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        let stored_provider_issuer = session
            .get_custom(oauth_keys::PROVIDER_ISSUER)
            .await
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        match stored_provider_issuer {
            Some(stored_issuer) => {
                let current_issuer = provider.issuer().map(normalize_issuer).unwrap_or_default();
                if stored_issuer != current_issuer {
                    self.record_oauth_failure_and_clear(
                        AuthFailureReason::ProviderMismatch,
                        provider_name,
                        session,
                    )
                    .await?;
                    return Err(OAuthError::CsrfMismatch);
                }
                Ok(())
            }
            None => {
                self.record_oauth_failure_and_clear(
                    AuthFailureReason::MissingIssuer,
                    provider_name,
                    session,
                )
                .await?;
                Err(OAuthError::NoFlow)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::iss_parameter_acceptable;

    #[test]
    fn the_iss_parameter_rule() {
        let want = Some("https://idp.example");
        assert!(iss_parameter_acceptable(
            Some("https://idp.example"),
            want,
            true
        ));
        assert!(!iss_parameter_acceptable(
            Some("https://evil.example"),
            want,
            false
        ));
        assert!(!iss_parameter_acceptable(
            Some("https://idp.example/"),
            want,
            false
        ));
        assert!(!iss_parameter_acceptable(Some("x"), None, false));
        assert!(!iss_parameter_acceptable(None, want, true));
        assert!(iss_parameter_acceptable(None, want, false));
    }
}
