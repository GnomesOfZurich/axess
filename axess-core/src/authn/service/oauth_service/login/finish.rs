//! Step 2 of the OAuth/OIDC login ceremony: `finish_oauth_login`.
//!
//! Handles the callback: validates state + PKCE + provider issuer,
//! exchanges the code for OIDC claims, and mints the claim-binding
//! lock that `complete_oauth_login` will verify.

use super::helpers::{compute_claim_lock, is_valid_pkce_verifier, normalize_issuer};
use crate::authn::service::AuthnService;
use crate::authn::{
    event::{AuthEventBuilder, AuthEventType},
    factor::FactorKind,
    ids::UserId,
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;
use subtle::ConstantTimeEq;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Complete an OAuth/OIDC login flow.
    #[tracing::instrument(skip(self, code, state, session))]
    pub async fn finish_oauth_login(
        &self,
        code: &str,
        state: &str,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        use crate::validation::MAX_OAUTH_PARAM_BYTES;
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        // Reject oversized callback parameters before processing.
        if code.len() > MAX_OAUTH_PARAM_BYTES || state.len() > MAX_OAUTH_PARAM_BYTES {
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
            self.record_oauth_failure_and_clear("pkce_verifier_invalid", &provider_name, session)
                .await;
            return Err(OAuthError::InvalidParameter);
        }

        if self.is_oauth_expired(session, &provider_name).await {
            self.record_oauth_failure_and_clear("ceremony_expired", &provider_name, session)
                .await;
            return Err(OAuthError::Expired);
        }

        if !bool::from(state.as_bytes().ct_eq(stored_csrf.as_bytes())) {
            self.record_oauth_failure_and_clear("csrf_mismatch", &provider_name, session)
                .await;
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
            .oauth_providers
            .get(&provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.clone()))?
            .clone();

        // Anti-confused-deputy rail: the issuer the begin-side stashed
        // must match the issuer of the provider whose callback we're
        // handling. See helper for the full argument.
        self.verify_provider_issuer_matches(&provider, &provider_name, session)
            .await?;

        let claims = match provider
            .exchange_code(code, stored_verifier, stored_nonce)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // Log the original error server-side but return a generic error
                // to prevent leaking provider-specific details to the caller.
                tracing::error!(
                    provider = %provider_name,
                    error = %e,
                    "OAuth token exchange failed"
                );
                self.record_oauth_failure_and_clear("token_exchange", &provider_name, session)
                    .await;
                return Err(OAuthError::TokenExchange(
                    "token exchange failed".to_string(),
                ));
            }
        };

        self.clear_oauth_state(session).await;

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
        let lock = compute_claim_lock(&provider_name, &claims.subject, session).await;
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
                    crate::authn::factor::FederatedProvider::Custom(provider_name.clone()),
                )),
        )
        .await;

        Ok(claims)
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
                        "provider_mismatch",
                        provider_name,
                        session,
                    )
                    .await;
                    return Err(OAuthError::CsrfMismatch);
                }
                Ok(())
            }
            None => {
                self.record_oauth_failure_and_clear("missing_issuer", provider_name, session)
                    .await;
                Err(OAuthError::NoFlow)
            }
        }
    }
}
