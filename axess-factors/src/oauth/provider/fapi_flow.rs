//! Pushed Authorization Requests (RFC 9126), which the FAPI 2.0 profile
//! requires, with the DPoP binding of the pushed request (RFC 9449 section
//! 10) when the provider binds tokens to a DPoP key.
//!
//! These free functions carry the protocol logic. The corresponding
//! [`OAuthProvider`](super::super::OAuthProvider) trait methods on
//! [`OAuthProviderConfig`](super::OAuthProviderConfig) are thin wrappers that
//! delegate here.

use super::super::types::DpopSigner;
use super::super::types::{AuthUrlResult, OAuthError, OAuthLoginOptions, ParResponse};
use super::OAuthProviderConfig;
use axess_rng::SecureRng;

/// Build an authorization URL using the Pushed Authorization Request (PAR)
/// endpoint (RFC 9126). Unlike the standard flow, the request parameters
/// are first POSTed to the PAR endpoint; the returned `request_uri` is then
/// used as the sole parameter on the browser redirect.
///
/// With `dpop`, the pushed request carries `dpop_jkt` (RFC 9449 section
/// 10) and the POST carries a proof signed by the same key (section 10.1),
/// so the authorization server binds the code it issues to that key before
/// the token request presents it.
pub(super) async fn build_auth_url_par(
    cfg: &OAuthProviderConfig,
    options: &OAuthLoginOptions,
    rng: &dyn SecureRng,
    dpop: Option<DpopSigner<'_>>,
) -> Result<AuthUrlResult, OAuthError> {
    let super::ceremony::CeremonySecrets {
        pkce_challenge,
        pkce_verifier,
        csrf_state,
        nonce,
    } = super::ceremony::mint(rng);

    // Collect all scopes.
    let mut all_scopes: Vec<String> = cfg.scopes.clone();
    all_scopes.extend(options.extra_scopes.iter().cloned());
    let scope_str = all_scopes.join(" ");

    // Build PAR form parameters.
    let nonce_str = nonce.secret().clone();
    let state_str = csrf_state.secret().clone();
    let redirect_str = cfg.redirect_url.to_string();
    let challenge_str = pkce_challenge.as_str().to_string();
    let mut params: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("redirect_uri", &redirect_str),
        ("scope", &scope_str),
        ("state", &state_str),
        ("nonce", &nonce_str),
        ("code_challenge", &challenge_str),
        ("code_challenge_method", "S256"),
    ];

    let response_mode_str;
    if cfg.fapi.as_ref().is_some_and(|f| f.require_jarm) {
        // JARM (FAPI 2.0 / JWT Secured Authorization Response Mode): the
        // response is a signed JWT, whatever mode the caller asked for.
        params.push(("response_mode", "jwt"));
    } else if let Some(ref mode) = options.response_mode {
        response_mode_str = mode.as_str().to_string();
        params.push(("response_mode", &response_mode_str));
    }
    let prompt_str;
    if let Some(ref prompt) = options.prompt {
        prompt_str = prompt.clone();
        params.push(("prompt", &prompt_str));
    }
    let hint_str;
    if let Some(ref hint) = options.login_hint {
        hint_str = hint.clone();
        params.push(("login_hint", &hint_str));
    }
    let jkt;
    if let Some(signer) = dpop {
        jkt = signer.key.thumbprint()?;
        params.push(("dpop_jkt", &jkt));
    }

    // Push to PAR endpoint.
    let par_response = push_authorization_request(cfg, &params, dpop).await?;

    // Build minimal authorization URL with request_uri.
    let auth_endpoint = cfg.metadata.authorization_endpoint().url().clone();

    let mut auth_url = auth_endpoint;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", cfg.client_id.as_str())
        .append_pair("request_uri", &par_response.request_uri);

    Ok(AuthUrlResult {
        url: auth_url,
        csrf_state: state_str,
        nonce: nonce_str,
        pkce_verifier: pkce_verifier.secret().to_string(),
    })
}

/// POST the authorization request parameters to the IdP's PAR endpoint.
/// Called by [`build_auth_url_par`] as part of the FAPI flow, and behind
/// the trait's
/// [`push_authorization_request`](crate::oauth::OAuthProvider::push_authorization_request),
/// which downstream code calls to push requests of its own.
///
/// With `dpop` the POST carries a DPoP proof (RFC 9449 section 10.1), and
/// a `use_dpop_nonce` refusal is answered once with a proof that echoes the
/// server's nonce, as the token request does. The `dpop_jkt` parameter is
/// the caller's to put in `params`; [`build_auth_url_par`] does.
pub(super) async fn push_authorization_request(
    cfg: &OAuthProviderConfig,
    params: &[(&str, &str)],
    dpop: Option<DpopSigner<'_>>,
) -> Result<ParResponse, OAuthError> {
    let par_url = cfg.par_endpoint.as_deref().ok_or_else(|| {
        OAuthError::Config(
            "provider metadata does not include pushed_authorization_request_endpoint".to_string(),
        )
    })?;

    let mut form: Vec<(String, String)> = Vec::with_capacity(params.len() + 3);
    let basic = cfg.token_grant_auth(&mut form, par_url)?;
    form.extend(
        params
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );

    let (status, body) = cfg
        .post_form_constrained(par_url, &form, basic, dpop, "PAR request")
        .await?;

    if !status.is_success() {
        let error_body = String::from_utf8_lossy(&body);
        return Err(OAuthError::TokenExchange(format!(
            "PAR endpoint returned HTTP {status}: {error_body}"
        )));
    }

    serde_json::from_slice(&body)
        .map_err(|e| OAuthError::TokenExchange(format!("PAR response parse failed: {e}")))
}
