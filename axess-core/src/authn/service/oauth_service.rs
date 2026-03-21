//! OAuth/OIDC ceremony methods on [`AuthnService`].

use super::*;

impl<I, F, R, C> AuthnService<I, F, R, C>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
    R: SecureRng,
    C: Clock,
{
    /// Begin an OAuth/OIDC login flow.
    ///
    /// Generates an authorization URL with PKCE, state (CSRF), and nonce.
    /// Returns `(authorization_url, csrf_state_token)`.
    pub async fn begin_oauth_login(
        &self,
        provider_name: &str,
        options: &crate::authn::oauth::OAuthLoginOptions,
        session: &AuthSession,
    ) -> Result<(url::Url, String), crate::authn::oauth::OAuthError> {
        use crate::authn::oauth::{OAuthError, keys as oauth_keys};
        use openidconnect::{
            CsrfToken, Nonce, PkceCodeChallenge, Scope, core::CoreAuthenticationFlow,
        };

        let provider = self
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = provider.make_client();
        let mut auth_request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);

        for scope in &provider.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }
        for scope in &options.extra_scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        if let Some(prompt) = &options.prompt {
            auth_request = auth_request.add_extra_param("prompt", prompt);
        }
        if let Some(hint) = &options.login_hint {
            auth_request = auth_request.add_extra_param("login_hint", hint);
        }

        let (auth_url, csrf_state, nonce) = auth_request.url();

        let str_val = |s: String| serde_json::Value::String(s);
        session
            .set_custom(
                oauth_keys::PKCE_VERIFIER,
                str_val(pkce_verifier.secret().to_string()),
            )
            .await;
        session
            .set_custom(
                oauth_keys::CSRF_STATE,
                str_val(csrf_state.secret().to_string()),
            )
            .await;
        session
            .set_custom(oauth_keys::NONCE, str_val(nonce.secret().to_string()))
            .await;
        session
            .set_custom(oauth_keys::PROVIDER, str_val(provider_name.to_string()))
            .await;
        session
            .set_custom(oauth_keys::STARTED, str_val(self.clock.now().to_rfc3339()))
            .await;

        Ok((auth_url, csrf_state.secret().clone()))
    }

    /// Complete an OAuth/OIDC login flow.
    pub async fn finish_oauth_login(
        &self,
        code: &str,
        state: &str,
        session: &AuthSession,
    ) -> Result<crate::authn::oauth::OAuthClaims, crate::authn::oauth::OAuthError> {
        use crate::authn::oauth::{OAuthClaims, OAuthError, keys as oauth_keys};
        use openidconnect::{
            AuthorizationCode, Nonce, OAuth2TokenResponse, PkceCodeVerifier, TokenResponse,
        };

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
        let provider_name = session
            .get_custom(oauth_keys::PROVIDER)
            .await
            .and_then(get_str)
            .ok_or(OAuthError::NoFlow)?;

        if self.is_oauth_expired(session, &provider_name).await {
            self.record_oauth_failure("ceremony_expired", &provider_name, session)
                .await;
            self.clear_oauth_state(session).await;
            return Err(OAuthError::Expired);
        }

        if state != stored_csrf {
            self.record_oauth_failure("csrf_mismatch", &provider_name, session)
                .await;
            self.clear_oauth_state(session).await;
            return Err(OAuthError::CsrfMismatch);
        }

        let provider = self
            .oauth_providers
            .get(&provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.clone()))?;

        let client = provider.make_client();
        let token_request = match client.exchange_code(AuthorizationCode::new(code.to_string())) {
            Ok(r) => r.set_pkce_verifier(PkceCodeVerifier::new(stored_verifier)),
            Err(e) => {
                self.record_oauth_failure("token_exchange_config", &provider_name, session)
                    .await;
                self.clear_oauth_state(session).await;
                return Err(OAuthError::TokenExchange(format!("{e}")));
            }
        };

        let token_response = match token_request.request_async(&provider.http_client).await {
            Ok(r) => r,
            Err(e) => {
                self.record_oauth_failure("token_exchange", &provider_name, session)
                    .await;
                self.clear_oauth_state(session).await;
                return Err(OAuthError::TokenExchange(format!("{e}")));
            }
        };

        let id_token = match token_response.id_token() {
            Some(t) => t,
            None => {
                self.record_oauth_failure("no_id_token", &provider_name, session)
                    .await;
                self.clear_oauth_state(session).await;
                return Err(OAuthError::IdTokenValidation(
                    "no ID token in response".to_string(),
                ));
            }
        };

        let id_token_verifier = client.id_token_verifier();
        let claims = match id_token.claims(&id_token_verifier, &Nonce::new(stored_nonce)) {
            Ok(c) => c,
            Err(e) => {
                self.record_oauth_failure("id_token_validation", &provider_name, session)
                    .await;
                self.clear_oauth_state(session).await;
                return Err(OAuthError::IdTokenValidation(format!("{e}")));
            }
        };

        let subject = claims.subject().to_string();
        let email = claims.email().map(|e| e.as_str().to_string());
        let email_verified = claims.email_verified();
        let name = {
            let localized = claims.name();
            localized
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_string())
        };

        let additional_claims =
            serde_json::to_value(claims).unwrap_or(serde_json::Value::Object(Default::default()));

        let groups = additional_claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let roles = additional_claims
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let refresh_token =
            OAuth2TokenResponse::refresh_token(&token_response).map(|t| t.secret().to_string());

        self.clear_oauth_state(session).await;

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    subject.as_str().into(),
                    "".into(),
                    AuthEventType::LoginAttempt,
                    AuthEventStatus::Success,
                )
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.clone().into()),
                ))
                .build_at(self.clock.now()),
            )
            .await;

        Ok(OAuthClaims {
            provider: provider_name.into(),
            subject,
            email,
            email_verified,
            name,
            groups,
            roles,
            refresh_token,
            additional_claims,
        })
    }

    /// Check if the OAuth ceremony has exceeded the provider's timeout.
    async fn is_oauth_expired(&self, session: &AuthSession, provider_name: &str) -> bool {
        use crate::authn::oauth::keys as oauth_keys;
        let Some(started) = session.get_custom(oauth_keys::STARTED).await else {
            return false;
        };
        let Some(ts) = started.as_str() else {
            return false;
        };
        let Ok(started_at) = chrono::DateTime::parse_from_rfc3339(ts) else {
            return false;
        };
        let timeout = self
            .oauth_providers
            .get(provider_name)
            .map(|p| p.ceremony_timeout)
            .unwrap_or(std::time::Duration::from_secs(600));
        let elapsed = self.clock.now() - started_at.with_timezone(&chrono::Utc);
        elapsed.to_std().unwrap_or_default() > timeout
    }

    /// Complete an OAuth login by linking claims to a local user and
    /// establishing an authenticated session.
    ///
    /// OAuth uses a three-step flow (unlike the two-step core and FIDO2 flows):
    /// 1. `begin_oauth_login` — redirect the user to the IdP
    /// 2. `finish_oauth_login` — handle the callback, get `OAuthClaims`
    /// 3. `complete_oauth_login` — the application resolves the local `User`
    ///    from the claims (find or create), then calls this to establish the
    ///    session. This step is separate because user resolution is
    ///    application-specific logic that the library cannot perform.
    pub async fn complete_oauth_login(
        &self,
        user: &crate::authn::types::User,
        claims: &crate::authn::oauth::OAuthClaims,
        session: &AuthSession,
    ) -> Result<(), AuthnError<I::Error>> {
        let now = self.clock.now();
        session
            .set_authenticated(user.id.clone(), user.tenant_id.clone(), now)
            .await;

        self.identity
            .reset_failed_attempts(&user.id)
            .await
            .map_err(AuthnError::Store)?;

        let sid = session.session_id().await;
        if let Some(reg) = &self.registry {
            reg.register(&user.id, &sid).await;
        }

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user.id.clone(),
                    user.tenant_id.clone(),
                    AuthEventType::Authenticated,
                    AuthEventStatus::Success,
                )
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(claims.provider.clone()),
                ))
                .with_session(sid)
                .build_at(now),
            )
            .await;

        Ok(())
    }

    /// Record an OAuth failure audit event.
    async fn record_oauth_failure(&self, reason: &str, provider_name: &str, session: &AuthSession) {
        let user_id: Arc<str> = session.user_id().await.unwrap_or_else(|| "unknown".into());

        let _ = self
            .identity
            .record_event(
                AuthEventBuilder::new(
                    user_id,
                    "".into(),
                    AuthEventType::LoginAttempt,
                    AuthEventStatus::Failure,
                )
                .with_factor(FactorKind::Federated(
                    crate::authn::factor::FederatedProvider::Custom(provider_name.into()),
                ))
                .with_error(reason)
                .build_at(self.clock.now()),
            )
            .await;
    }

    /// Clear all OAuth ceremony state from the session.
    async fn clear_oauth_state(&self, session: &AuthSession) {
        use crate::authn::oauth::keys as oauth_keys;
        for key in [
            oauth_keys::PKCE_VERIFIER,
            oauth_keys::CSRF_STATE,
            oauth_keys::NONCE,
            oauth_keys::PROVIDER,
            oauth_keys::STARTED,
        ] {
            session.set_custom(key, serde_json::Value::Null).await;
        }
    }
}
