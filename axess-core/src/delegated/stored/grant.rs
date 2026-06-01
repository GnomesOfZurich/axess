//! Grant-flow primitives: `begin_grant` (mint the authorization
//! URL) and `complete_grant` (validate state, exchange code for
//! tokens).
//!
//! State handling is the adopter's job: `begin_grant` returns a
//! [`GrantContext`] containing the `state` + PKCE `code_verifier`;
//! the adopter persists this somewhere (signed cookie, short-lived
//! server-side store, encrypted session bag) and replays it into
//! `complete_grant` once the IdP redirects back. axess does not
//! impose a state-storage policy; different adopters have different
//! constraints (cookie size limits, SameSite policy, stateless
//! workers, …).

use chrono::Utc;
use openidconnect::PkceCodeChallenge;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use url::Url;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;

use crate::delegated::error::DelegatedError;
use axess_factors::ZeroizedString;

use super::credential::StoredDelegation;
use super::provider::DelegatedProvider;

/// Per-grant-attempt state that the adopter persists between
/// `begin_grant` and the IdP-side redirect back to `complete_grant`.
///
/// Carries:
/// - `state`: the OAuth `state` value (CSRF token). `complete_grant`
///   verifies the state echoed by the IdP matches this value.
/// - `code_verifier`: the PKCE verifier whose SHA-256 hash was sent
///   to the IdP in `begin_grant`. `complete_grant` POSTs this to the
///   token endpoint as `code_verifier`.
/// - `requested_scopes`: recorded for adopter audit / debugging;
///   the IdP's granted scopes are what land on the resulting
///   `StoredDelegation`.
#[derive(Debug, Clone)]
pub struct GrantContext {
    /// OAuth2 `state` value. Random, single-use.
    pub state: String,
    /// PKCE `code_verifier` (RFC 7636). 43-128 chars from the
    /// unreserved alphabet; never log or persist longer than the
    /// callback flow requires.
    pub code_verifier: ZeroizedString,
    /// Scopes the caller requested at `begin_grant` time. Adopter
    /// can compare against the granted scopes on the returned
    /// `StoredDelegation` to detect partial consent.
    pub requested_scopes: Vec<String>,
}

/// Begin an authorization-code grant against `provider`. Returns
/// `(authorization_url, GrantContext)`; the adopter redirects the
/// user's browser to `authorization_url` and persists the
/// `GrantContext` somewhere it can be retrieved when the IdP
/// redirects back to the adopter's callback handler.
///
/// `scopes_override`: pass an empty slice to use the provider's
/// `default_scopes`; pass a non-empty slice to override.
pub fn begin_grant(
    provider: &DelegatedProvider,
    scopes_override: &[String],
) -> Result<(Url, GrantContext), DelegatedError> {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = openidconnect::CsrfToken::new_random();

    let scopes: Vec<String> = if scopes_override.is_empty() {
        provider.default_scopes.clone()
    } else {
        scopes_override.to_vec()
    };
    let scope_str = scopes.join(" ");

    let mut auth_url = provider.authorization_endpoint.clone();
    {
        let mut q = auth_url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &provider.client_id);
        q.append_pair("redirect_uri", provider.redirect_uri.as_str());
        q.append_pair("state", state.secret());
        q.append_pair("code_challenge", challenge.as_str());
        q.append_pair("code_challenge_method", "S256");
        if !scope_str.is_empty() {
            q.append_pair("scope", &scope_str);
        }
    }

    let context = GrantContext {
        state: state.secret().clone(),
        code_verifier: ZeroizedString::from(verifier.secret().clone()),
        requested_scopes: scopes,
    };

    Ok((auth_url, context))
}

/// Complete an authorization-code grant: verify the returned `state`
/// matches the context, then POST to the IdP's token endpoint with
/// the code + PKCE verifier + client credentials. Returns the
/// `StoredDelegation` ready to hand to a
/// [`DelegatedCredentialStore`](super::credential::DelegatedCredentialStore).
pub async fn complete_grant(
    provider: &DelegatedProvider,
    context: &GrantContext,
    code: &str,
    state_from_callback: &str,
    http: &reqwest::Client,
) -> Result<StoredDelegation, DelegatedError> {
    // CSRF check; constant-time comparison would be ideal but the
    // state values are random per request and not under attacker
    // influence in a way that timing can leak. Plain `==` is fine
    // here, mirroring openidconnect's own callback-side handling.
    if context.state != state_from_callback {
        return Err(DelegatedError::StateMismatch);
    }

    if !axess_factors::pkce::is_valid_verifier(&context.code_verifier) {
        return Err(DelegatedError::PkceVerifier);
    }

    let form: Vec<(&str, String)> = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", provider.redirect_uri.to_string()),
        ("code_verifier", (*context.code_verifier).to_string()),
        // RFC 6749 §2.3.1 allows client_id in form body alongside
        // Basic auth; some IdPs require it.
        ("client_id", provider.client_id.clone()),
    ];

    let response = post_token_endpoint(http, provider, &form).await?;
    parse_token_response(provider, response).await
}

/// Refresh-token grant: RFC 6749 §6. Internal helper shared with
/// `StoredDelegationSession::get_access_token` on the refresh path.
pub(super) async fn refresh_token_grant(
    provider: &DelegatedProvider,
    refresh_token: &str,
    http: &reqwest::Client,
) -> Result<StoredDelegation, DelegatedError> {
    let form: Vec<(&str, String)> = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", provider.client_id.clone()),
    ];
    let response = post_token_endpoint(http, provider, &form).await?;
    parse_token_response(provider, response).await
}

/// POST to the IdP's token endpoint with HTTP Basic auth carrying the
/// provider's `(client_id, client_secret)`. Form body is shared
/// across `authorization_code` and `refresh_token` grants.
async fn post_token_endpoint(
    http: &reqwest::Client,
    provider: &DelegatedProvider,
    form: &[(&str, String)],
) -> Result<reqwest::Response, DelegatedError> {
    let creds = format!("{}:{}", provider.client_id, &*provider.client_secret);
    let encoded = B64_STANDARD.encode(creds);

    http.post(provider.token_endpoint.clone())
        .header(AUTHORIZATION, format!("Basic {encoded}"))
        .form(form)
        .send()
        .await
        .map_err(|e| DelegatedError::Transport(e.to_string()))
}

/// RFC 6749 §5.1 token response body. Only the fields the credential
/// actually consumes are deserialised; serde tolerates unknown fields
/// so vendor-extension claims (e.g. `id_token`, `refresh_token_expires_in`)
/// don't trip parsing.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn parse_token_response(
    provider: &DelegatedProvider,
    response: reqwest::Response,
) -> Result<StoredDelegation, DelegatedError> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        // 400 + `invalid_grant` body specifically signals refresh-token
        // rejection; RFC 6749 §5.2. Surface the dedicated variant so
        // adopter UX can route to "please reconnect".
        if status.as_u16() == 400 && body.contains("invalid_grant") {
            return Err(DelegatedError::RefreshRejected);
        }
        return Err(DelegatedError::TokenEndpoint {
            status: status.as_u16(),
            body,
        });
    }

    let parsed: TokenResponse = response
        .json()
        .await
        .map_err(|e| DelegatedError::MalformedResponse(e.to_string()))?;

    if parsed.access_token.is_empty() {
        return Err(DelegatedError::MalformedResponse(
            "access_token field is empty".into(),
        ));
    }

    let expires_at = parsed
        .expires_in
        .filter(|s| *s > 0)
        .map(|s| Utc::now() + chrono::Duration::seconds(s as i64));

    let scopes: Vec<String> = parsed
        .scope
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    Ok(StoredDelegation {
        provider: provider.name.clone(),
        access_token: ZeroizedString::from(parsed.access_token),
        refresh_token: parsed.refresh_token.map(ZeroizedString::from),
        expires_at,
        scopes,
        token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
    })
}
