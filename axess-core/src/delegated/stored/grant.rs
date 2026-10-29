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

use axess_clock::Clock;
use axess_rng::SecureRng;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

use crate::delegated::error::DelegatedError;
use axess_factors::ZeroizedString;

use crate::delegated::body::{read_error_body, read_success_body};

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
///
/// `rng` supplies the PKCE verifier and the `state`: two separate
/// 32-byte draws, each base64url-encoded without padding (43
/// characters). The raw bytes are zeroed once encoded. The challenge
/// is `BASE64URL(SHA-256(verifier))`.
pub fn begin_grant(
    provider: &DelegatedProvider,
    scopes_override: &[String],
    rng: &dyn SecureRng,
) -> Result<(Url, GrantContext), DelegatedError> {
    let verifier = random_token(rng);
    let state = random_token(rng);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

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
        q.append_pair("state", &state);
        q.append_pair("code_challenge", &challenge);
        q.append_pair("code_challenge_method", "S256");
        if !scope_str.is_empty() {
            q.append_pair("scope", &scope_str);
        }
    }

    let context = GrantContext {
        state: (*state).clone(),
        code_verifier: ZeroizedString::from((*verifier).clone()),
        requested_scopes: scopes,
    };

    Ok((auth_url, context))
}

/// 32 random bytes from `rng`, base64url-encoded without padding. The
/// raw buffer is zeroed on drop and so is the returned string.
fn random_token(rng: &dyn SecureRng) -> Zeroizing<String> {
    let mut raw = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *raw);
    // Borrowed, so the secret is not copied to an unwiped temporary.
    Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice()))
}

/// Complete an authorization-code grant: verify the returned `state`
/// matches the context, then POST to the IdP's token endpoint with
/// the code + PKCE verifier + client credentials. Returns the
/// `StoredDelegation` ready to hand to a
/// [`DelegatedCredentialStore`](super::credential::DelegatedCredentialStore).
///
/// Token expiry is measured from `clock`, so a simulated clock gives a
/// deterministic `expires_at`; use [`complete_grant_at`] to supply the
/// instant itself.
pub async fn complete_grant(
    provider: &DelegatedProvider,
    context: &GrantContext,
    code: &str,
    state_from_callback: &str,
    http: &reqwest::Client,
    clock: &dyn Clock,
) -> Result<StoredDelegation, DelegatedError> {
    complete_grant_at(
        provider,
        context,
        code,
        state_from_callback,
        http,
        clock.now(),
    )
    .await
}

/// [`complete_grant`] with the instant the resulting credential's
/// `expires_at` is measured from supplied by the caller.
pub async fn complete_grant_at(
    provider: &DelegatedProvider,
    context: &GrantContext,
    code: &str,
    state_from_callback: &str,
    http: &reqwest::Client,
    now: DateTime<Utc>,
) -> Result<StoredDelegation, DelegatedError> {
    // The state is compared in constant time: it is the secret that
    // binds the callback to the browser that started the flow.
    let state_matches: bool = context
        .state
        .as_bytes()
        .ct_eq(state_from_callback.as_bytes())
        .into();
    // An empty state on both sides compares equal and checks nothing: a
    // context without a state is refused, not matched.
    if context.state.is_empty() || !state_matches {
        return Err(DelegatedError::StateMismatch);
    }

    if !axess_factors::pkce::is_valid_verifier(&context.code_verifier) {
        return Err(DelegatedError::PkceVerifier);
    }

    // Borrowed throughout: the verifier and code are never copied into
    // buffers of this function's own.
    let redirect_uri = provider.redirect_uri.as_str();
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", &context.code_verifier),
        // RFC 6749 §2.3.1 allows client_id in form body alongside
        // Basic auth; some IdPs require it.
        ("client_id", &provider.client_id),
    ];

    let response = post_token_endpoint(http, provider, &form).await?;
    let grant = parse_token_response(provider, response, now, TokenRequest::CodeExchange).await?;
    // RFC 6749 §5.1: an omitted `scope` means the granted scope is the one
    // requested.
    let scopes = grant
        .scope
        .unwrap_or_else(|| context.requested_scopes.clone());
    Ok(StoredDelegation {
        scopes,
        ..grant.credential
    })
}

/// Refresh-token grant: RFC 6749 §6. Internal helper shared with
/// `StoredDelegationSession::get_access_token` on the refresh path.
///
/// The expiry is measured from `clock.now()` read after the token
/// endpoint has answered, so a slow exchange does not shorten the
/// lifetime recorded for the new access token.
pub(super) async fn refresh_token_grant(
    provider: &DelegatedProvider,
    refresh_token: &str,
    http: &reqwest::Client,
    clock: &dyn Clock,
) -> Result<TokenGrant, DelegatedError> {
    let form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &provider.client_id),
    ];
    let response = post_token_endpoint(http, provider, &form).await?;
    parse_token_response(provider, response, clock.now(), TokenRequest::Refresh).await
}

/// Which grant a token response answers. Only a refresh can be "rejected" in
/// the sense of [`DelegatedError::RefreshRejected`]: on an authorization-code
/// exchange `invalid_grant` means the code was bad, used or expired, and
/// sending the user to "reconnect" is the wrong message.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenRequest {
    CodeExchange,
    Refresh,
}

/// The RFC 6749 §5.2 `error` member of an error body, when the body is the
/// JSON object the RFC specifies. Exact: `error_description` text that
/// mentions `invalid_grant` is not the error.
fn oauth_error_code(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("error")?
        .as_str()
        .map(str::to_string)
}

/// A parsed token response: the credential it describes, and the scope the
/// endpoint stated. `scope` is `None` when the response omitted the field,
/// which RFC 6749 §5.1 and §6 define as "unchanged", so each caller falls
/// back to the scopes it already knows; `credential.scopes` is empty then.
pub(super) struct TokenGrant {
    pub(super) credential: StoredDelegation,
    pub(super) scope: Option<Vec<String>>,
}

/// POST to the IdP's token endpoint with HTTP Basic auth carrying the
/// provider's `(client_id, client_secret)`. Form body is shared
/// across `authorization_code` and `refresh_token` grants.
async fn post_token_endpoint(
    http: &reqwest::Client,
    provider: &DelegatedProvider,
    form: &[(&str, &str)],
) -> Result<reqwest::Response, DelegatedError> {
    let encoded = axess_factors::basic_credentials(&provider.client_id, &provider.client_secret);

    // Before any request: the client credentials go in this POST.
    crate::outbound_http::require_https_or_loopback(&provider.token_endpoint)
        .map_err(|reason| DelegatedError::Transport(reason.to_string()))?;

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
    /// Wire field. Typed [`ZeroizedString`] so the plaintext the
    /// provider sent is redacted in `Debug` and zeroed on drop: this
    /// struct is where the token first lands, and zeroing only the
    /// copy would leave the original in the heap for the process's
    /// lifetime.
    access_token: ZeroizedString,
    #[serde(default)]
    refresh_token: Option<ZeroizedString>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn parse_token_response(
    provider: &DelegatedProvider,
    mut response: reqwest::Response,
    now: DateTime<Utc>,
    request: TokenRequest,
) -> Result<TokenGrant, DelegatedError> {
    let status = response.status();
    if !status.is_success() {
        let body = read_error_body(&mut response).await;
        // 400 + `error: "invalid_grant"` on a REFRESH specifically signals
        // refresh-token rejection (RFC 6749 §5.2). Surface the dedicated
        // variant so adopter UX can route to "please reconnect". The member is
        // compared exactly, and only on the refresh grant.
        if request == TokenRequest::Refresh
            && status.as_u16() == 400
            && oauth_error_code(&body).as_deref() == Some("invalid_grant")
        {
            return Err(DelegatedError::RefreshRejected);
        }
        return Err(DelegatedError::TokenEndpoint {
            status: status.as_u16(),
            body,
        });
    }

    let body = read_success_body(&mut response).await?;
    let parsed: TokenResponse = serde_json::from_slice(&body)
        .map_err(|e| DelegatedError::MalformedResponse(e.to_string()))?;

    if parsed.access_token.is_empty() {
        return Err(DelegatedError::MalformedResponse(
            "access_token field is empty".into(),
        ));
    }

    // `expires_in: 0` is a token that is already expired, not one that never
    // expires: it gets `expires_at = now` and is refreshed on next use.
    let expires_at = match parsed.expires_in {
        None => None,
        Some(s) => Some(axess_factors::expiry_after(now, s).ok_or_else(|| {
            DelegatedError::MalformedResponse(format!("expires_in {s} is out of range"))
        })?),
    };

    let scope: Option<Vec<String>> = parsed
        .scope
        .map(|s| s.split_whitespace().map(str::to_string).collect());

    Ok(TokenGrant {
        credential: StoredDelegation {
            provider: provider.name.clone(),
            access_token: parsed.access_token,
            refresh_token: parsed.refresh_token,
            expires_at,
            scopes: Vec::new(),
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
        },
        scope,
    })
}
