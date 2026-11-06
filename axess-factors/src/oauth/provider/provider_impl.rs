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

/// A `typ` header as it is compared: lower case, without the optional
/// `application/` prefix (RFC 7515 §4.1.9).
fn normalised_typ(typ: &str) -> String {
    let typ = typ.to_ascii_lowercase();
    match typ.strip_prefix("application/") {
        Some(bare) => bare.to_string(),
        None => typ,
    }
}

/// Whether a logout token's `typ` header is one a logout token may carry:
/// `logout+jwt` (the explicit type), plain `JWT`, or `Logout`, which IdPs in
/// the field send.
fn logout_typ_acceptable(typ: &str) -> bool {
    matches!(
        normalised_typ(typ).as_str(),
        "logout+jwt" | "jwt" | "logout"
    )
}

/// Whether a logout token's `typ` is the explicit `logout+jwt`.
fn logout_typ_is_explicit(typ: &str) -> bool {
    normalised_typ(typ) == "logout+jwt"
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
        // The token's `typ`, when it has one, must be a logout or generic JWT
        // type. A `dpop+jwt` or `at+jwt` signed by the same key is another
        // kind of token, and being valid as that kind is no reason to take
        // it for a logout.
        if let Ok(header) = jsonwebtoken::decode_header(token)
            && let Err(reason) = check_logout_typ(header.typ.as_deref(), self.require_logout_typ)
        {
            return Err(OAuthError::IdTokenValidation(reason));
        }
        // The shared verifier enforces the asymmetric algorithm allow-list
        // (no `none`, no HS*), the `kid` lookup, the JWK-declared algorithm
        // (defence against key confusion across a set that mixes RSA and EC
        // keys), the audience and the issuer.
        self.verify_issuer_jwt(token)
    }

    fn fetch_userinfo_unchecked<'a>(
        &'a self,
        access_token: &'a str,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
        Box::pin(self.fetch_userinfo_constrained(access_token, dpop))
    }

    fn refresh_token_unchecked<'a>(
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

        Ok(AuthUrlResult {
            url: auth_url,
            csrf_state: csrf_state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: secrets.pkce_verifier.secret().to_string(),
        })
    }

    fn build_auth_url_par<'a>(
        &'a self,
        options: &'a OAuthLoginOptions,
        rng: &'a dyn SecureRng,
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<AuthUrlResult, OAuthError>> + Send + 'a>> {
        Box::pin(super::fapi_flow::build_auth_url_par(
            self, options, rng, dpop,
        ))
    }

    fn fapi_config(&self) -> Option<&FapiConfig> {
        self.fapi.as_ref()
    }

    fn binds_to_dpop(&self) -> bool {
        self.dpop
    }

    fn push_authorization_request<'a>(
        &'a self,
        params: &'a [(&'a str, &'a str)],
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<ParResponse, OAuthError>> + Send + 'a>> {
        Box::pin(super::fapi_flow::push_authorization_request(
            self, params, dpop,
        ))
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
        super::dpop::generate_dpop_proof(key, http_method, http_url, access_token, iat, jti_bytes)
    }

    fn build_end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Option<url::Url> {
        // The `id_token_hint` rides in this URL's query; discovery and the
        // builder took the endpoint only over HTTPS.
        let endpoint = self.end_session_endpoint.as_deref()?;
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
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthError>> + Send + 'a>> {
        Box::pin(self.revoke_token_constrained(token, token_type_hint, dpop))
    }

    fn client_credentials<'a>(
        &'a self,
        scopes: &'a [&'a str],
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<ClientCredentialsToken, OAuthError>> + Send + 'a>> {
        Box::pin(self.client_credentials_constrained(scopes, dpop))
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
        dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<DeviceTokenOutcome, OAuthError>> + Send + 'a>> {
        Box::pin(super::device_flow::poll_device_token(
            self,
            device_code,
            current_interval,
            nonce,
            dpop,
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
