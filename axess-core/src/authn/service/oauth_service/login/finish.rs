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

/// How the callback's `code`, `state` and `iss` arrived.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseForm {
    /// As query or form parameters of the callback.
    Plain,
    /// Out of a verified JWT Secured Authorization Response (JARM); a
    /// provider that requires JARM refuses them any other way.
    Jarm,
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

/// What `begin_oauth_login` stashed in the session and the code exchange
/// presents: the PKCE verifier, the nonce, and the DPoP key the pushed
/// authorization request named, when the ceremony stashed one.
struct StashedCeremony {
    verifier: String,
    nonce: String,
    dpop_key: Option<axess_factors::oauth::DpopKey>,
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
    /// which compares it. A provider that advertises
    /// `authorization_response_iss_parameter_supported` refuses this form
    /// with [`OAuthError::Config`](axess_factors::oauth::OAuthError::Config)
    /// before the code is exchanged, and the ceremony is cleared: its
    /// responses carry an `iss` this form cannot compare, so a callback that
    /// drops the parameter would give up the defence the provider offers.
    #[tracing::instrument(skip(self, code, state, session))]
    pub async fn finish_oauth_login(
        &self,
        code: &str,
        state: &str,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        self.finish_oauth_login_checked(
            code,
            state,
            IssCheck::Skipped,
            ResponseForm::Plain,
            None,
            session,
        )
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
        self.finish_oauth_login_checked(
            code,
            state,
            IssCheck::Compared(iss),
            ResponseForm::Plain,
            None,
            session,
        )
        .await
    }

    /// The shared body of the finish forms. `form` says how the `code`,
    /// `state` and `iss` arrived. `resolved` is the ceremony's provider when
    /// the caller already resolved it (the JARM form, to verify the response
    /// with it); otherwise it is resolved here, once.
    pub(super) async fn finish_oauth_login_checked(
        &self,
        code: &str,
        state: &str,
        iss: IssCheck<'_>,
        form: ResponseForm,
        resolved: Option<std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>>,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        use crate::validation::MAX_OAUTH_PARAM_BYTES;
        use axess_factors::oauth::OAuthError;

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

        let (stored_csrf, stored_nonce, stored_verifier, provider_name) =
            read_stashed_ceremony(session).await?;
        // The provider the ceremony began with, resolved once: the expiry
        // check reads its timeout, the exchange runs against it.
        let provider = match resolved {
            Some(provider) => provider,
            None => self.finish_provider(&provider_name, session).await?,
        };
        self.refuse_invalid_pkce_verifier(&stored_verifier, &provider_name, session)
            .await?;
        let stashed_dpop_key = self.stashed_dpop_key(&provider_name, session).await?;

        if self
            .is_oauth_expired(session, &provider_name, provider.ceremony_timeout())
            .await
        {
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

        // Anti-confused-deputy rail: the issuer the begin-side stashed
        // must match the issuer of the provider whose callback we're
        // handling. See helper for the full argument.
        self.verify_provider_issuer_matches(&provider, &provider_name, session)
            .await?;

        self.check_authorization_response_form(&provider, &provider_name, iss, form, session)
            .await?;

        let mut claims = self
            .exchange_code_for_login(
                &provider,
                &provider_name,
                code,
                StashedCeremony {
                    verifier: stored_verifier,
                    nonce: stored_nonce.clone(),
                    dpop_key: stashed_dpop_key,
                },
                session,
            )
            .await?;
        // The provider verified the ID token's nonce against this one, so
        // they are equal; a provider that does not fill the field still
        // returns the login's nonce for the caller to store.
        claims.nonce.get_or_insert(stored_nonce);

        self.seal_finished_login(&provider_name, &claims, session)
            .await?;

        Ok(claims)
    }

    /// The provider the ceremony named, resolved for its tenant binding when
    /// it has one. A provider that does not resolve (removed since the
    /// begin, its tenant's store unreachable, its discovery failed, an
    /// unreadable binding) is recorded and the ceremony cleared, like every
    /// other failure of the callback.
    pub(super) async fn finish_provider(
        &self,
        provider_name: &str,
        session: &AuthSession,
    ) -> Result<
        std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        axess_factors::oauth::OAuthError,
    > {
        match self.ceremony_provider(session, provider_name).await {
            Ok(provider) => Ok(provider),
            Err(e) => {
                tracing::warn!(
                    provider = %provider_name,
                    error = %e,
                    "the ceremony's provider does not resolve at the callback"
                );
                self.record_oauth_failure_and_clear(
                    AuthFailureReason::ProviderUnavailable,
                    provider_name,
                    session,
                )
                .await?;
                Err(e)
            }
        }
    }

    /// Refuse a stashed PKCE verifier outside RFC 7636, recording the
    /// failure and clearing the ceremony.
    async fn refuse_invalid_pkce_verifier(
        &self,
        stored_verifier: &str,
        provider_name: &str,
        session: &AuthSession,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        // Validate the stashed PKCE code_verifier locally before
        // we waste the AS round-trip. RFC 7636 §4.1 fixes the alphabet
        // (`unreserved` = ALPHA / DIGIT / "-" / "." / "_" / "~") and
        // length (43..=128). A verifier outside the spec means session
        // tampering or a bug in `begin_oauth_login`; either way the AS
        // would reject the exchange anyway.
        if !is_valid_pkce_verifier(stored_verifier) {
            tracing::warn!(
                provider = %provider_name,
                verifier_len = stored_verifier.len(),
                "stashed PKCE code_verifier failed RFC 7636 §4.1 validation"
            );
            self.record_oauth_failure_and_clear(
                AuthFailureReason::PkceVerifierInvalid,
                provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::InvalidParameter);
        }
        Ok(())
    }

    /// The DPoP key the ceremony stashed, if it stashed one.
    async fn stashed_dpop_key(
        &self,
        provider_name: &str,
        session: &AuthSession,
    ) -> Result<Option<axess_factors::oauth::DpopKey>, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        // The DPoP key the pushed authorization request named, when the
        // provider binds tokens; the token request must present the same
        // key. A stash that does not decode is tampering or a bug, like a
        // malformed verifier, and is refused the same way.
        match session.get_custom(oauth_keys::DPOP_KEY).await {
            None => Ok(None),
            Some(value) => match value.as_str().and_then(super::helpers::decode_dpop_key) {
                Some(key) => Ok(Some(key)),
                None => {
                    tracing::warn!(provider = %provider_name, "stashed DPoP key does not decode");
                    self.record_oauth_failure_and_clear(
                        AuthFailureReason::DpopKeyInvalid,
                        provider_name,
                        session,
                    )
                    .await?;
                    Err(OAuthError::InvalidParameter)
                }
            },
        }
    }

    /// Refuse an authorization response in a form the provider does not
    /// accept: a plain response where it requires JARM, an `iss` that does
    /// not match, or a form that skips the `iss` the provider sends.
    async fn check_authorization_response_form(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        provider_name: &str,
        iss: IssCheck<'_>,
        form: ResponseForm,
        session: &AuthSession,
    ) -> Result<(), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        if provider.authorization_response_jwt_required() && form != ResponseForm::Jarm {
            tracing::warn!(
                provider = %provider_name,
                "plain authorization response for a provider that requires JARM; refusing"
            );
            self.record_oauth_failure_and_clear(
                AuthFailureReason::ProviderMismatch,
                provider_name,
                session,
            )
            .await?;
            return Err(OAuthError::InvalidParameter);
        }

        match iss {
            IssCheck::Compared(response_iss) => {
                self.verify_response_iss(provider, provider_name, response_iss, session)
                    .await?;
            }
            IssCheck::Skipped if provider.authorization_response_iss_required() => {
                tracing::warn!(
                    provider = %provider_name,
                    "the provider sends the iss parameter (RFC 9207) and this callback did not \
                     pass it; use finish_oauth_login_with_iss"
                );
                self.record_oauth_failure_and_clear(
                    AuthFailureReason::MissingIssuer,
                    provider_name,
                    session,
                )
                .await?;
                return Err(OAuthError::Config(
                    "this provider sends the authorization response iss parameter; finish the \
                     callback with finish_oauth_login_with_iss so it is compared"
                        .to_string(),
                ));
            }
            IssCheck::Skipped => {}
        }
        Ok(())
    }

    /// Exchange the code at the provider, recording and clearing the ceremony
    /// when the exchange fails.
    async fn exchange_code_for_login(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        provider_name: &str,
        code: &str,
        stashed: StashedCeremony,
        session: &AuthSession,
    ) -> Result<axess_factors::oauth::OAuthClaims, axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::OAuthError;

        let StashedCeremony {
            verifier,
            nonce,
            dpop_key: stashed_dpop_key,
        } = stashed;
        // A provider that binds tokens to a DPoP key presents the key the
        // begin stashed (and a pushed request named); the claims carry it
        // back. A ceremony begun without one (the provider started binding
        // between begin and callback, after a rediscovery) is refused and
        // restarts: a key improvised here was never named to the server.
        let dpop_key = match (provider.binds_to_dpop(), stashed_dpop_key) {
            (true, Some(key)) => Some(key),
            (true, None) => {
                tracing::warn!(
                    provider = %provider_name,
                    "the provider binds tokens to a DPoP key and the ceremony has none; \
                     the login restarts"
                );
                self.record_oauth_failure_and_clear(
                    AuthFailureReason::DpopKeyInvalid,
                    provider_name,
                    session,
                )
                .await?;
                return Err(OAuthError::InvalidParameter);
            }
            (false, _) => None,
        };
        let signer = dpop_key
            .as_ref()
            .map(|key| axess_factors::oauth::DpopSigner {
                key,
                rng: &*self.inner.rng,
            });

        match provider.exchange_code(code, verifier, nonce, signer).await {
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

        // Attribution: the local user is not resolved until
        // `complete_oauth_login`, whose row names it; the IdP subject is the
        // IdP's identifier and never a local user id, even when it parses as
        // one (a row under a foreign subject would attribute the login to
        // whatever local user shares that id). The tenant is the one the
        // begin bound the ceremony to, when it did; a row with no tenant is
        // a platform row that every tenant's `include_unscoped` query sees.
        let tenant = super::state::ceremony_tenant(session)
            .await
            .ok()
            .flatten()
            .map(|binding| binding.tenant);
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::LoginAttempt)
                .maybe_attributed_to(None, tenant.as_ref())
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

/// The strings `begin_oauth_login` stashed in the session, in this order:
/// the CSRF state, the nonce, the PKCE verifier and the provider name. Any
/// one missing means there is no ceremony to finish.
async fn read_stashed_ceremony(
    session: &AuthSession,
) -> Result<(String, String, String, String), axess_factors::oauth::OAuthError> {
    use axess_factors::oauth::{OAuthError, keys as oauth_keys};

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
    // Read before the PKCE validation that follows, so the warn!/record
    // failure paths can attribute the failure to a provider.
    let provider_name = session
        .get_custom(oauth_keys::PROVIDER)
        .await
        .and_then(get_str)
        .ok_or(OAuthError::NoFlow)?;
    Ok((stored_csrf, stored_nonce, stored_verifier, provider_name))
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
