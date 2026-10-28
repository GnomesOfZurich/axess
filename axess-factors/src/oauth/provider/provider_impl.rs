//! `impl OAuthProvider for OAuthProviderConfig`: the trait surface
//! axess offers to the rest of the codebase.
//!
//! Each method is a thin adapter over either the openidconnect crate's
//! typed client (built on-the-fly via
//! [`OAuthProviderConfig::make_client`]) or a sibling submodule
//! ([`device_flow`](super::device_flow), [`fapi_flow`](super::fapi_flow)).
//! Heavier ID-token validation lives in
//! [`OAuthProviderConfig::extract_claims_from_response`].

use super::OAuthProviderConfig;
use crate::oauth::types::*;
use axess_rng::SecureRng;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

impl OAuthProvider for OAuthProviderConfig {
    fn name(&self) -> &Arc<str> {
        &self.name
    }

    fn issuer(&self) -> Option<&str> {
        Some(self.metadata.issuer().as_str())
    }

    fn client_id(&self) -> Option<&str> {
        Some(self.client_id.as_str())
    }

    fn scopes(&self) -> &[String] {
        &self.scopes
    }

    fn ceremony_timeout(&self) -> std::time::Duration {
        self.ceremony_timeout
    }

    fn refresh_jwks<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthError>> + Send + 'a>> {
        Box::pin(self.refresh_jwks())
    }

    fn verify_logout_jwt(&self, token: &str) -> Result<serde_json::Value, OAuthError> {
        // Delegate to the shared `authn::jwt::validation`
        // primitive. The reusable verifier already enforces:
        // - asymmetric-algorithm allowlist (no `none`, no HS*)
        // - JWT `kid` lookup against the JWKS
        // - JWK-declared algorithm match (defense against key
        //   confusion across rotating JWKS that mixes RSA and EC keys)
        // - audience binding when supplied
        // The back-channel logout handler's downstream `aud_contains`
        // check is now redundant defense rather than the only one.
        use crate::jwt::validation::{ALLOWED_ALGORITHMS, JwtError, ValidationConfig, verify_jwt};

        // Recover from a poisoned lock. The data may be stale, but
        // verification will simply fail with a "no matching kid"
        // error and trigger a refresh.
        let handle = self.jwks_cache.fresh_handle().map_err(|e| match e {
            crate::oidc::OidcError::JwksExpired { .. } => OAuthError::JwksExpired,
            other => OAuthError::Discovery(other.to_string()),
        })?;
        let jwks_guard = handle.read().unwrap_or_else(|poisoned| {
            tracing::warn!("JWKS RwLock was poisoned; recovering for read");
            poisoned.into_inner()
        });

        let mut config = ValidationConfig::new();
        config.audience = Some(self.client_id.as_str().to_string());
        verify_jwt(
            token,
            &jwks_guard,
            &config,
            ALLOWED_ALGORITHMS,
            &*self.clock,
        )
        .map_err(|e| match e {
            JwtError::UnknownKid(kid) => OAuthError::UnknownKid(kid),
            JwtError::InvalidHeader(msg) => {
                OAuthError::IdTokenValidation(format!("invalid JWT header: {msg}"))
            }
            JwtError::DisallowedAlgorithm(alg) => {
                OAuthError::IdTokenValidation(format!("disallowed JWT algorithm: {alg:?}"))
            }
            JwtError::MissingKid => {
                OAuthError::IdTokenValidation("logout JWT has no `kid` header".to_string())
            }
            JwtError::AlgorithmMismatch {
                header_alg,
                jwk_alg,
            } => OAuthError::IdTokenValidation(format!(
                "JWT header alg {header_alg:?} does not match JWK alg {jwk_alg}"
            )),
            JwtError::KeyConstruction(msg) => {
                OAuthError::IdTokenValidation(format!("failed to build key from JWK: {msg}"))
            }
            JwtError::VerificationFailed(msg) => {
                OAuthError::IdTokenValidation(format!("JWT signature verification failed: {msg}"))
            }
        })
    }

    fn fetch_userinfo<'a>(
        &'a self,
        access_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            let userinfo_url = self
                .metadata
                .userinfo_endpoint()
                .ok_or_else(|| {
                    OAuthError::UserInfo(
                        "provider metadata does not include a userinfo_endpoint".to_string(),
                    )
                })?
                .url()
                .clone();

            let mut response = self
                .http_client
                .get(userinfo_url)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| OAuthError::UserInfo(format!("HTTP request failed: {e}")))?;

            match response.status().as_u16() {
                200 => {}
                401 => return Err(OAuthError::AccessTokenExpired),
                403 => return Err(OAuthError::InsufficientScope),
                status => {
                    return Err(OAuthError::UserInfo(format!(
                        "userinfo endpoint returned HTTP {status}"
                    )));
                }
            }

            let body = crate::http_body::read_limited(
                &mut response,
                crate::http_body::MAX_USERINFO_BODY_BYTES,
            )
            .await
            .map_err(|e| OAuthError::UserInfo(format!("failed to read response body: {e}")))?;

            let claims: UserInfoClaims = serde_json::from_slice(&body)
                .map_err(|e| OAuthError::UserInfo(format!("failed to parse response: {e}")))?;

            Ok(claims)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            use openidconnect::RefreshToken;

            let client = self.make_client();
            let refresh = RefreshToken::new(refresh_token.to_string());
            let token_request = client
                .exchange_refresh_token(&refresh)
                .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?;

            let token_response = token_request
                .request_async(&self.http_client)
                .await
                .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?;

            self.with_fresh_keys(|client| {
                self.claims_from_refresh_response(client, &token_response, refresh_token)
            })
            .await
        })
    }

    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: String,
        nonce: String,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            use openidconnect::{AuthorizationCode, PkceCodeVerifier};

            let client = self.make_client();
            let token_request = client
                .exchange_code(AuthorizationCode::new(code.to_string()))
                .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?
                .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier));

            let token_response = token_request
                .request_async(&self.http_client)
                .await
                .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?;

            self.extract_claims_from_response(&token_response, &nonce)
                .await
        })
    }

    fn build_auth_url(
        &self,
        options: &OAuthLoginOptions,
        rng: &dyn SecureRng,
    ) -> Result<AuthUrlResult, OAuthError> {
        use openidconnect::{Scope, core::CoreAuthenticationFlow};

        let secrets = super::ceremony::mint(rng);
        let csrf_state = secrets.csrf_state;
        let nonce = secrets.nonce;

        let client = self.make_client();
        let mut auth_request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || csrf_state,
                move || nonce,
            )
            .set_pkce_challenge(secrets.pkce_challenge);

        for scope in &self.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }
        for scope in &options.extra_scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        if let Some(ref mode) = options.response_mode {
            auth_request = auth_request.add_extra_param("response_mode", mode.as_str());
        }
        if let Some(prompt) = &options.prompt {
            auth_request = auth_request.add_extra_param("prompt", prompt);
        }
        if let Some(hint) = &options.login_hint {
            auth_request = auth_request.add_extra_param("login_hint", hint);
        }

        let (auth_url, csrf_state, nonce) = auth_request.url();

        Ok((
            auth_url,
            csrf_state.secret().clone(),
            nonce.secret().clone(),
            secrets.pkce_verifier.secret().to_string(),
        ))
    }

    fn build_auth_url_par<'a>(
        &'a self,
        options: &'a OAuthLoginOptions,
        rng: &'a dyn SecureRng,
    ) -> Pin<Box<dyn Future<Output = Result<AuthUrlResult, OAuthError>> + Send + 'a>> {
        Box::pin(super::fapi_flow::build_auth_url_par(self, options, rng))
    }

    fn fapi_config(&self) -> Option<&FapiConfig> {
        self.fapi.as_ref()
    }

    fn push_authorization_request<'a>(
        &'a self,
        params: &'a [(&'a str, &'a str)],
    ) -> Pin<Box<dyn Future<Output = Result<ParResponse, OAuthError>> + Send + 'a>> {
        Box::pin(super::fapi_flow::push_authorization_request(self, params))
    }

    #[cfg(feature = "fapi")]
    fn generate_dpop_proof(
        &self,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
        key_seed: [u8; 32],
        iat: i64,
        jti_bytes: [u8; 16],
    ) -> Result<DpopProof, OAuthError> {
        super::fapi_flow::generate_dpop_proof(
            http_method,
            http_url,
            access_token,
            key_seed,
            iat,
            jti_bytes,
        )
    }

    fn build_end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Option<url::Url> {
        let endpoint = self.end_session_endpoint.as_deref()?;
        let mut url = url::Url::parse(endpoint).ok()?;
        if let Some(hint) = id_token_hint {
            url.query_pairs_mut().append_pair("id_token_hint", hint);
        }
        // Validate the redirect against the configured allowlist before
        // forwarding it to the IdP. When the allowlist is non-empty and the
        // redirect is not in it, the parameter is dropped; a defense
        // against open-redirect/phishing chains where the IdP's logout page
        // links the user onward to attacker-controlled origins.
        if let Some(redirect) = post_logout_redirect_uri {
            if self.allowed_post_logout_redirect_uris.is_empty()
                || self
                    .allowed_post_logout_redirect_uris
                    .iter()
                    .any(|allowed| allowed == redirect)
            {
                url.query_pairs_mut()
                    .append_pair("post_logout_redirect_uri", redirect);
            } else {
                tracing::warn!(
                    redirect = %redirect,
                    "build_end_session_url: post_logout_redirect_uri not in allowlist; dropped"
                );
            }
        }
        if let Some(st) = state {
            url.query_pairs_mut().append_pair("state", st);
        }
        Some(url)
    }

    fn revoke_token<'a>(
        &'a self,
        token: &'a str,
        token_type_hint: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            let revocation_url = self.revocation_endpoint.as_deref().ok_or_else(|| {
                OAuthError::Config(
                    "provider metadata does not include a revocation_endpoint".to_string(),
                )
            })?;

            let mut form: Vec<(&str, &str)> =
                vec![("token", token), ("client_id", self.client_id.as_str())];
            if let Some(ref secret) = self.client_secret {
                form.push(("client_secret", secret.secret()));
            }
            if let Some(hint) = token_type_hint {
                form.push(("token_type_hint", hint));
            }

            let mut response = self
                .http_client
                .post(revocation_url)
                .form(&form)
                .send()
                .await
                .map_err(|e| {
                    OAuthError::TokenExchange(format!("revocation request failed: {e}"))
                })?;

            let status = response.status();
            if status.is_success() {
                tracing::info!(provider = %self.name, "token revoked successfully");
                return Ok(());
            }

            let body = crate::http_body::read_error_snippet(&mut response).await;

            // Surface RFC 7009 / 6749 error semantics rather than
            // collapsing every non-2xx into a generic TokenExchange error.
            //
            // - 4xx with `error: "unsupported_token_type"` → the AS knows
            //   the request but cannot revoke this particular token kind.
            //   Distinct so callers can treat it as a no-op rather than
            //   propagating an alarming error to the user.
            // - 5xx → transient AS failure; callers may retry.
            // - other 4xx → keep the existing TokenExchange variant.
            let parsed_error = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));

            tracing::warn!(
                provider = %self.name,
                status = status.as_u16(),
                body = %body,
                error_code = parsed_error.as_deref().unwrap_or("<none>"),
                "token revocation failed"
            );

            if status.is_server_error() {
                Err(OAuthError::TokenEndpointTransient {
                    status: status.as_u16(),
                    body,
                })
            } else if parsed_error.as_deref() == Some("unsupported_token_type") {
                Err(OAuthError::UnsupportedTokenType)
            } else {
                Err(OAuthError::TokenExchange(format!(
                    "revocation endpoint returned HTTP {status}"
                )))
            }
        })
    }

    fn client_credentials<'a>(
        &'a self,
        scopes: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<ClientCredentialsToken, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            let token_url = self
                .metadata
                .token_endpoint()
                .ok_or_else(|| OAuthError::Config("no token endpoint in metadata".to_string()))?
                .url()
                .to_string();

            let mut form = vec![
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
            ];
            if let Some(ref secret) = self.client_secret {
                form.push(("client_secret", secret.secret()));
            }
            let scope_str = scopes.join(" ");
            if !scope_str.is_empty() {
                form.push(("scope", &scope_str));
            }

            let mut response = self
                .http_client
                .post(&token_url)
                .form(&form)
                .send()
                .await
                .map_err(|e| {
                    OAuthError::TokenExchange(format!("client_credentials request failed: {e}"))
                })?;

            let status = response.status();
            let body = crate::http_body::read_for_status(
                &mut response,
                crate::http_body::MAX_TOKEN_BODY_BYTES,
            )
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("response read failed: {e}")))?;

            if !status.is_success() {
                let error_body = String::from_utf8_lossy(&body);
                tracing::warn!(
                    status = status.as_u16(),
                    body = %error_body,
                    "client_credentials token endpoint error"
                );
                let error_code = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("error")?.as_str().map(String::from))
                    .unwrap_or_else(|| format!("HTTP {status}"));
                return Err(OAuthError::TokenExchange(error_code));
            }

            serde_json::from_slice(&body).map_err(|e| {
                OAuthError::TokenExchange(format!("failed to parse token response: {e}"))
            })
        })
    }

    fn request_device_code<'a>(
        &'a self,
        scopes: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<DeviceAuthResponse, OAuthError>> + Send + 'a>> {
        Box::pin(super::device_flow::request_device_code(self, scopes))
    }

    fn poll_device_token<'a>(
        &'a self,
        device_code: &'a str,
        current_interval: u64,
        nonce: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<DeviceTokenOutcome, OAuthError>> + Send + 'a>> {
        Box::pin(super::device_flow::poll_device_token(
            self,
            device_code,
            current_interval,
            nonce,
        ))
    }
}
