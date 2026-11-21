//! Grant-flow primitives: `begin_grant` (mint the authorization
//! URL) and `complete_grant` (validate state, exchange code for
//! tokens).
//!
//! State handling is the adopter's job: `begin_grant` returns a
//! [`GrantContext`] containing the `state`, the PKCE `code_verifier` and
//! the registration the grant began with;
//! the adopter persists this somewhere (signed cookie, short-lived
//! server-side store, encrypted session bag) and replays it into
//! `complete_grant` once the IdP redirects back. axess does not
//! impose a state-storage policy; different adopters have different
//! constraints (cookie size limits, SameSite policy, stateless
//! workers, …).

use axess_clock::Clock;
use axess_clock::Timestamp;
use axess_rng::SecureRng;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

use crate::delegated::error::DelegatedError;
use axess_factors::ZeroizedString;
use axess_factors::egress::{ClientSettings, ScreenedClient};

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
/// - `registration`: which registration the grant began with.
///   `complete_grant` refuses any other, so a code is never sent to a
///   provider that shares only the name.
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
    /// The registration `begin_grant` was called with. Persist it with the
    /// rest: [`complete_grant`] compares it with the provider it is handed.
    pub registration: GrantRegistration,
}

/// The registration a grant began with: what [`complete_grant`] compares
/// with the provider it is handed.
///
/// A provider's `name` is the application's label, and two registrations
/// may share it (one for each tenant, or a tenant's own beside a shared
/// one), so the name does not say which client the IdP issued the code to.
/// The `fingerprint` covers what makes a registration: the name, the client
/// id, the authorization endpoint, the token endpoint and the
/// `redirect_uri`. It holds no secret and is persisted with the rest of the
/// [`GrantContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRegistration {
    /// The provider's `name`.
    pub provider: String,
    /// `BASE64URL(SHA-256(..))` over the five values, each preceded by its
    /// length, so no two lists of values share a digest by their joining.
    pub fingerprint: String,
}

impl GrantRegistration {
    /// The registration `provider` is.
    #[must_use]
    pub fn of(provider: &DelegatedProvider) -> Self {
        let mut hasher = Sha256::new();
        for part in [
            provider.name.as_str(),
            provider.client_id.as_str(),
            provider.authorization_endpoint.as_str(),
            provider.token_endpoint.as_str(),
            provider.redirect_uri.as_str(),
        ] {
            hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        Self {
            provider: provider.name.clone(),
            fingerprint: URL_SAFE_NO_PAD.encode(hasher.finalize()),
        }
    }
}

/// The HTTP client [`complete_grant`] sends the code exchange with.
///
/// The library builds it, so it follows no redirect: the exchange carries
/// the code, the PKCE verifier and the client credentials, and a client
/// that followed a 307 or 308 would repeat them to wherever the answer
/// points. A 10-second connect timeout and a 30-second request timeout are
/// set first and `configure`'s settings after them (a `User-Agent`, a
/// trusted root certificate, a client certificate, other timeouts); a
/// [`ClientSettings`] offers nothing that restores redirects. Build one at
/// startup and share it: it holds a connection pool.
///
/// # Errors
///
/// [`DelegatedError::ClientBuild`] when the client cannot be built with the
/// settings.
pub fn grant_client(
    configure: impl FnOnce(ClientSettings) -> ClientSettings,
) -> Result<ScreenedClient, DelegatedError> {
    Ok(crate::outbound_http::hardened_screened_client(configure)?)
}

/// Begin an authorization-code grant against `provider`. Returns
/// `(authorization_url, GrantContext)`; the adopter redirects the
/// user's browser to `authorization_url` and persists the
/// `GrantContext` somewhere it can be retrieved when the IdP
/// redirects back to the adopter's callback handler.
///
/// The authorization endpoint and the `redirect_uri` must be HTTPS (or
/// HTTP to a loopback host, for local development): any other is refused
/// with [`DelegatedError::Transport`], naming the setting, before the URL
/// is built. The IdP sends the browser back to `redirect_uri` with the
/// code and the `state`, so it is as much a secret-bearing endpoint as
/// the other two.
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
    // The browser is sent here with the client id, the PKCE challenge and the
    // state in the URL: refused before any of them is drawn.
    crate::outbound_http::require_https_or_loopback(&provider.authorization_endpoint)
        .map_err(|reason| DelegatedError::Transport(reason.to_string()))?;
    require_secure_redirect_uri(provider)?;
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
        registration: GrantRegistration::of(provider),
    };

    Ok((auth_url, context))
}

/// The `redirect_uri` the IdP sends the browser back to, with the code and
/// the `state`: HTTPS, or HTTP to a loopback host, and nothing else. The
/// refusal names the setting and not the URL.
fn require_secure_redirect_uri(provider: &DelegatedProvider) -> Result<(), DelegatedError> {
    crate::outbound_http::require_https_or_loopback(&provider.redirect_uri)
        .map_err(|reason| DelegatedError::Transport(format!("redirect_uri: {reason}")))
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
/// `provider` must be the registration the grant began with
/// ([`GrantContext::registration`]): any other, one of the same name
/// included, is refused with [`DelegatedError::RegistrationMismatch`]
/// before anything is sent. `http` is a client the library built
/// ([`grant_client`], or any [`ScreenedClient`]), never one of the caller's
/// own, so no redirect carries the code and the client credentials on.
///
/// Token expiry is measured from `clock`, so a simulated clock gives a
/// deterministic `expires_at`; use [`complete_grant_at`] to supply the
/// instant itself.
pub async fn complete_grant(
    provider: &DelegatedProvider,
    context: &GrantContext,
    code: &str,
    state_from_callback: &str,
    http: &ScreenedClient,
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
    http: &ScreenedClient,
    now: Timestamp,
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
    // The IdP issued the code to the registration the grant began with. Any
    // other would be sent the code and the verifier with its own client
    // credentials: refused before any request, whatever its name.
    if GrantRegistration::of(provider) != context.registration {
        return Err(DelegatedError::RegistrationMismatch {
            provider: provider.name.clone(),
        });
    }
    // The grant could not have begun with this provider; refused before any
    // request, as `begin_grant` refuses it before any redirect.
    require_secure_redirect_uri(provider)?;

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

    let response = post_token_endpoint(http.inner(), provider, &form).await?;
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
    let header = axess_factors::basic_authorization(&provider.client_id, &provider.client_secret)
        .map_err(DelegatedError::ClientCredentials)?;

    // Before any request: the client credentials go in this POST.
    crate::outbound_http::require_https_or_loopback(&provider.token_endpoint)
        .map_err(|reason| DelegatedError::Transport(reason.to_string()))?;

    // `without_url`: reqwest's message names the URL it was sent to.
    http.post(provider.token_endpoint.clone())
        .header(AUTHORIZATION, header)
        .form(form)
        .send()
        .await
        .map_err(|e| DelegatedError::Transport(e.without_url().to_string()))
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
    now: Timestamp,
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
            && body.string_member("error").as_deref() == Some("invalid_grant")
        {
            return Err(DelegatedError::RefreshRejected);
        }
        return Err(DelegatedError::TokenEndpoint {
            status: status.as_u16(),
            body: crate::delegated::body::log_safe(&body),
        });
    }

    let body = read_success_body(&mut response).await?;
    let parsed: TokenResponse = serde_json::from_slice(&body).map_err(|e| {
        DelegatedError::MalformedResponse(axess_factors::http_body::log_safe_parse_error(&e))
    })?;

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
            registration: Some(GrantRegistration::of(provider)),
            access_token: parsed.access_token,
            refresh_token: parsed.refresh_token,
            expires_at,
            scopes: Vec::new(),
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
        },
        scope,
    })
}
