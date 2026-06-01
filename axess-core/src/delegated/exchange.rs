//! RFC 8693 OAuth 2.0 Token Exchange. On-demand on-behalf-of: take a
//! subject token proving the user's identity (typically the user's
//! current axess session JWT or an inbound JWT-SVID) and exchange it at
//! a configured token endpoint for a fresh token scoped to a downstream
//! service. No persistent storage; the input is the user's
//! authorization. See [`docs/identity/delegated-obo.md`](../../../../docs/identity/delegated-obo.md)
//! for the use-case taxonomy and the comparison with [`super::stored`](crate::delegated::stored).

use std::sync::Arc;

use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use url::Url;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;

use crate::delegated::error::DelegatedError;
use axess_factors::ZeroizedString;

/// Standard RFC 8693 `token_type` URIs. Use as
/// [`TokenExchangeRequest::subject_token_type`] /
/// [`TokenExchangeRequest::actor_token_type`].
pub mod token_types {
    /// Generic access token: `urn:ietf:params:oauth:token-type:access_token`.
    pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    /// JWT: `urn:ietf:params:oauth:token-type:jwt`. Use when the
    /// subject token is a JWT (axess session, JWT-SVID, OIDC ID
    /// token).
    pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
    /// SAML 2.0 assertion: `urn:ietf:params:oauth:token-type:saml2`.
    pub const SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
    /// Refresh token: `urn:ietf:params:oauth:token-type:refresh_token`.
    pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
    /// ID token: `urn:ietf:params:oauth:token-type:id_token`.
    pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
}

/// The `grant_type` value RFC 8693 §2.1 mandates.
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Inputs to a single token exchange. Builder-style usage:
///
/// ```ignore
/// let req = TokenExchangeRequest::new(user_session_jwt, token_types::JWT)
///     .with_audience("https://compute-worker.gnomes")
///     .with_scopes(["compute.read", "compute.write"])
///     .with_actor_token(axess_workload_jwt, token_types::JWT);
/// let resp = exchanger.exchange(&req).await?;
/// ```
#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    /// The user's current token; proves who the exchange is "on
    /// behalf of". Required.
    pub subject_token: String,
    /// `urn:ietf:params:oauth:token-type:*` describing
    /// `subject_token`. See [`token_types`] for the standard values.
    pub subject_token_type: String,
    /// Optional `actor_token`; proves who is *acting on the user's
    /// behalf*. Used by Azure AD's OBO flow and by RFC 8693 to
    /// preserve the actor chain across hops. Typically axess's own
    /// workload-identity JWT.
    pub actor_token: Option<String>,
    /// Token-type URI for `actor_token`.
    pub actor_token_type: Option<String>,
    /// `audience`: the downstream service's logical identifier.
    /// The AS encodes this into the issued token's `aud` claim so
    /// downstream verifiers can pin it.
    pub audience: Option<String>,
    /// `resource`: alternative to `audience` per RFC 8707; a URI
    /// identifying the target resource. Some AS implementations
    /// require this instead of `audience`.
    pub resource: Option<Url>,
    /// OAuth scopes requested for the exchanged token.
    pub scopes: Vec<String>,
    /// `requested_token_type`: what the AS should return. Defaults
    /// to access_token; some AS use this to issue ID tokens or
    /// refresh tokens via exchange.
    pub requested_token_type: Option<String>,
}

impl TokenExchangeRequest {
    /// Build a request with the subject token + type. All other
    /// fields default to `None` / empty.
    pub fn new(subject_token: impl Into<String>, subject_token_type: impl Into<String>) -> Self {
        Self {
            subject_token: subject_token.into(),
            subject_token_type: subject_token_type.into(),
            actor_token: None,
            actor_token_type: None,
            audience: None,
            resource: None,
            scopes: Vec::new(),
            requested_token_type: None,
        }
    }

    /// Attach an actor token + type; used for RFC 8693 actor-chain
    /// preservation and Azure AD's OBO grant.
    pub fn with_actor_token(
        mut self,
        actor_token: impl Into<String>,
        actor_token_type: impl Into<String>,
    ) -> Self {
        self.actor_token = Some(actor_token.into());
        self.actor_token_type = Some(actor_token_type.into());
        self
    }

    /// Set the downstream audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the downstream resource (RFC 8707 alternative to audience).
    pub fn with_resource(mut self, resource: Url) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Set the requested scopes.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Set `requested_token_type`. Defaults to `None` (= access_token).
    pub fn with_requested_token_type(mut self, t: impl Into<String>) -> Self {
        self.requested_token_type = Some(t.into());
        self
    }
}

/// The exchanged-token result, per RFC 8693 §2.2.
#[derive(Debug)]
pub struct TokenExchangeResponse {
    /// The issued token. Plaintext is held in a [`ZeroizedString`]
    /// so the in-memory copy zeroes on drop.
    pub access_token: ZeroizedString,
    /// `issued_token_type` per RFC 8693 §2.2.1. AS implementations
    /// must echo this; carries the same URN shape as
    /// `requested_token_type`.
    pub issued_token_type: String,
    /// `token_type` per RFC 6749 §5.1; almost always `Bearer`.
    pub token_type: String,
    /// Seconds until the issued token expires. `None` if the AS
    /// omitted `expires_in`.
    pub expires_in: Option<u64>,
    /// Granted scopes (may be a subset of requested).
    pub scopes: Vec<String>,
    /// `refresh_token`: RFC 8693 explicitly *recommends against*
    /// returning a refresh token from a token-exchange call, but some
    /// AS do anyway (Azure AD's OBO flow). Captured if present so
    /// adopter code can route into the `stored` module if persistence
    /// is wanted.
    pub refresh_token: Option<ZeroizedString>,
}

/// Token-exchange client: one per (AS, axess-client-credentials)
/// tuple. Holds the AS's token endpoint URL + the client credentials
/// axess presents to authenticate itself to the AS.
#[derive(Debug, Clone)]
pub struct TokenExchangeClient {
    token_endpoint: Url,
    client_id: String,
    client_secret: Option<Arc<ZeroizedString>>,
    http: reqwest::Client,
}

impl TokenExchangeClient {
    /// Build a client. The `client_secret` is optional; some AS
    /// flows authenticate axess via mTLS at the transport layer
    /// instead of a shared secret, in which case pass `None` and
    /// configure the [`reqwest::Client`] via
    /// [`with_http_client`](Self::with_http_client) to present the
    /// client cert.
    pub fn new(
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: Option<ZeroizedString>,
    ) -> Self {
        Self {
            token_endpoint,
            client_id: client_id.into(),
            client_secret: client_secret.map(Arc::new),
            http: reqwest::Client::new(),
        }
    }

    /// Override the HTTP client; used for outbound mTLS / proxy /
    /// timeout config.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Perform one token exchange. The returned `access_token` is
    /// the downstream-scoped token the caller passes to the target
    /// service.
    pub async fn exchange(
        &self,
        request: &TokenExchangeRequest,
    ) -> Result<TokenExchangeResponse, DelegatedError> {
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE.to_string()),
            ("subject_token", request.subject_token.clone()),
            ("subject_token_type", request.subject_token_type.clone()),
            ("client_id", self.client_id.clone()),
        ];
        if let Some(actor_token) = &request.actor_token {
            form.push(("actor_token", actor_token.clone()));
        }
        if let Some(actor_token_type) = &request.actor_token_type {
            form.push(("actor_token_type", actor_token_type.clone()));
        }
        if let Some(audience) = &request.audience {
            form.push(("audience", audience.clone()));
        }
        if let Some(resource) = &request.resource {
            form.push(("resource", resource.to_string()));
        }
        if !request.scopes.is_empty() {
            form.push(("scope", request.scopes.join(" ")));
        }
        if let Some(t) = &request.requested_token_type {
            form.push(("requested_token_type", t.clone()));
        }

        let mut req = self.http.post(self.token_endpoint.clone());
        if let Some(secret) = &self.client_secret {
            let creds = format!("{}:{}", self.client_id, &***secret);
            let encoded = B64_STANDARD.encode(creds);
            req = req.header(AUTHORIZATION, format!("Basic {encoded}"));
        }

        let response = req
            .form(&form)
            .send()
            .await
            .map_err(|e| DelegatedError::Transport(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(DelegatedError::TokenEndpoint {
                status: status.as_u16(),
                body,
            });
        }

        let parsed: TokenExchangeResponseBody = response
            .json()
            .await
            .map_err(|e| DelegatedError::MalformedResponse(e.to_string()))?;
        if parsed.access_token.is_empty() {
            return Err(DelegatedError::MalformedResponse(
                "access_token field is empty".into(),
            ));
        }

        let scopes: Vec<String> = parsed
            .scope
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();

        Ok(TokenExchangeResponse {
            access_token: ZeroizedString::from(parsed.access_token),
            issued_token_type: parsed
                .issued_token_type
                .unwrap_or_else(|| token_types::ACCESS_TOKEN.to_string()),
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_in: parsed.expires_in,
            scopes,
            refresh_token: parsed.refresh_token.map(ZeroizedString::from),
        })
    }
}

/// RFC 8693 §2.2.1 token-exchange response body.
#[derive(Debug, Deserialize)]
struct TokenExchangeResponseBody {
    access_token: String,
    #[serde(default)]
    issued_token_type: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[cfg(test)]
mod tests;
