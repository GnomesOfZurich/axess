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

/// Whether a logout token's `typ` header is one a logout token may carry:
/// `logout+jwt` (the explicit type), plain `JWT`, or `Logout`, which IdPs in
/// the field send. Compared case-insensitively and without the optional
/// `application/` prefix (RFC 7515 §4.1.9).
fn logout_typ_acceptable(typ: &str) -> bool {
    let typ = typ.to_ascii_lowercase();
    let typ = typ.strip_prefix("application/").unwrap_or(&typ);
    matches!(typ, "logout+jwt" | "jwt" | "logout")
}

/// Whether a logout token's `typ` is the explicit `logout+jwt`, compared as
/// [`logout_typ_acceptable`] compares.
fn logout_typ_is_explicit(typ: &str) -> bool {
    let typ = typ.to_ascii_lowercase();
    typ.strip_prefix("application/").unwrap_or(&typ) == "logout+jwt"
}

/// The verdict on a logout token's `typ` header under the provider's
/// setting: `typ` is `None` when the token has none. `Err` carries the
/// reason.
fn check_logout_typ(typ: Option<&str>, required: bool) -> Result<(), String> {
    match (typ, required) {
        (Some(typ), true) if !logout_typ_is_explicit(typ) => Err(format!(
            "logout token `typ` `{typ}` is not `logout+jwt`, which this provider requires"
        )),
        (None, true) => Err(
            "logout token has no `typ` header, and this provider requires `logout+jwt`".to_string(),
        ),
        (Some(typ), false) if !logout_typ_acceptable(typ) => Err(format!(
            "logout token `typ` `{typ}` is not a logout token type"
        )),
        _ => Ok(()),
    }
}

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

    fn authorization_response_iss_required(&self) -> bool {
        self.iss_parameter_supported
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
        use crate::jwt::validation::{ALLOWED_ALGORITHMS, ValidationConfig, verify_jwt};

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

        // The token's `typ`, when it has one, must be a logout or generic JWT
        // type. A `dpop+jwt` or `at+jwt` signed by the same key is another
        // kind of token, and being valid as that kind is no reason to take
        // it for a logout.
        if let Ok(header) = jsonwebtoken::decode_header(token)
            && let Err(reason) = check_logout_typ(header.typ.as_deref(), self.require_logout_typ)
        {
            return Err(OAuthError::IdTokenValidation(reason));
        }

        let mut config = ValidationConfig::new();
        config.audience = Some(self.client_id.as_str().to_string());
        // Pin `iss` here as well as at the handler: the verifier then
        // refuses a token another issuer signed with a key this JWKS holds.
        config.issuer = Some(self.metadata.issuer().as_str().to_string());
        verify_jwt(
            token,
            &jwks_guard,
            &config,
            ALLOWED_ALGORITHMS,
            &*self.clock,
        )
        .map_err(super::fapi_profile::jwt_error)
    }

    fn fetch_userinfo<'a>(
        &'a self,
        access_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
        Box::pin(self.fetch_userinfo_constrained(access_token, None))
    }

    fn fetch_userinfo_for_subject_with<'a>(
        &'a self,
        access_token: &'a str,
        expected_subject: &'a str,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            let claims = self.fetch_userinfo_constrained(access_token, dpop).await?;
            if claims.sub != expected_subject {
                return Err(OAuthError::SubjectMismatch);
            }
            Ok(claims)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        refresh_token: &'a str,
        original_nonce: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<RefreshOutcome, OAuthError>> + Send + 'a>> {
        Box::pin(self.refresh_token_constrained(refresh_token, original_nonce, None))
    }

    fn refresh_token_with<'a>(
        &'a self,
        refresh_token: &'a str,
        original_nonce: Option<&'a str>,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<RefreshOutcome, OAuthError>> + Send + 'a>> {
        Box::pin(self.refresh_token_constrained(refresh_token, original_nonce, dpop))
    }

    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: String,
        nonce: String,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
        Box::pin(self.exchange_code_constrained(code, pkce_verifier, nonce, None))
    }

    fn exchange_code_with<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: String,
        nonce: String,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
        Box::pin(self.exchange_code_constrained(code, pkce_verifier, nonce, dpop))
    }

    fn authorization_response_jwt_required(&self) -> bool {
        self.fapi.as_ref().is_some_and(|f| f.require_jarm)
    }

    fn verify_authorization_response_jwt(
        &self,
        response: &str,
    ) -> Result<JarmResponse, OAuthError> {
        self.verify_authorization_response(response)
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

        if self.authorization_response_jwt_required() {
            auth_request = auth_request.add_extra_param("response_mode", "jwt");
        } else if let Some(ref mode) = options.response_mode {
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

    fn generate_dpop_proof(
        &self,
        key: &DpopKey,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
        iat: i64,
        jti_bytes: [u8; 16],
    ) -> Result<DpopProof, OAuthError> {
        super::fapi_flow::generate_dpop_proof(
            key,
            http_method,
            http_url,
            access_token,
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
        // The `id_token_hint` rides in this URL's query, so the endpoint has
        // to be one the browser reaches over HTTPS.
        super::endpoint::require_secure(Some(endpoint), "end_session_endpoint").ok()?;
        let mut url = url::Url::parse(endpoint).ok()?;
        if let Some(hint) = id_token_hint {
            url.query_pairs_mut().append_pair("id_token_hint", hint);
        }
        // Forward the redirect only when it matches an entry of the
        // configured allowlist exactly. Otherwise it is dropped: a defence
        // against open-redirect/phishing chains where the IdP's logout page
        // links the user onward to an attacker-chosen origin. An empty list
        // allows nothing, so a provider nobody configured does not forward
        // whatever the caller passed.
        if let Some(redirect) = post_logout_redirect_uri {
            if self.allowed_post_logout_redirect_uris.is_empty() {
                tracing::warn!(
                    "build_end_session_url: no post_logout_redirect_uri allowlist is \
                     configured; the redirect is dropped (see \
                     with_allowed_post_logout_redirect_uris)"
                );
            } else if self
                .allowed_post_logout_redirect_uris
                .iter()
                .any(|allowed| allowed == redirect)
            {
                url.query_pairs_mut()
                    .append_pair("post_logout_redirect_uri", redirect);
            } else {
                tracing::warn!(
                    "build_end_session_url: post_logout_redirect_uri not in the allowlist; dropped"
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

            super::endpoint::require_secure(Some(revocation_url), "revocation_endpoint")?;

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

            // The body is returned to the caller in the transient error but
            // not logged: an error page can carry the token or an echo of the
            // request.
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
                let error_code = serde_json::from_slice::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("error")?.as_str().map(String::from))
                    .unwrap_or_else(|| format!("HTTP {status}"));
                tracing::warn!(
                    status = status.as_u16(),
                    error_code = %error_code,
                    "client_credentials token endpoint error"
                );
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

#[cfg(test)]
mod tests {
    use super::{check_logout_typ, logout_typ_acceptable};

    #[test]
    fn only_logout_typ_values_are_acceptable() {
        for ok in [
            "logout+jwt",
            "Logout+JWT",
            "JWT",
            "jwt",
            "Logout",
            "application/logout+jwt",
        ] {
            assert!(logout_typ_acceptable(ok), "{ok} should be acceptable");
        }
        for bad in ["dpop+jwt", "at+jwt", "secevent+jwt", "id_token+jwt", ""] {
            assert!(!logout_typ_acceptable(bad), "{bad} should be refused");
        }
    }

    #[test]
    fn a_required_typ_must_be_the_explicit_logout_type() {
        for ok in ["logout+jwt", "Logout+JWT", "application/logout+jwt"] {
            assert!(check_logout_typ(Some(ok), true).is_ok(), "{ok}");
        }
        for bad in ["JWT", "Logout", "dpop+jwt", ""] {
            assert!(check_logout_typ(Some(bad), true).is_err(), "{bad}");
        }
        assert!(
            check_logout_typ(None, true).is_err(),
            "a token with no typ is refused when the type is required"
        );
    }

    #[test]
    fn without_the_switch_a_missing_or_generic_typ_is_taken() {
        assert!(check_logout_typ(None, false).is_ok());
        assert!(check_logout_typ(Some("JWT"), false).is_ok());
        assert!(check_logout_typ(Some("dpop+jwt"), false).is_err());
    }
}
