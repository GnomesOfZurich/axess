//! Requests that carry a sender constraint: a DPoP proof (RFC 9449) on the
//! token request and on the userinfo call, and the error handling around the
//! server-supplied nonce.
//!
//! The mTLS half needs no code on the request path: `with_fapi` puts the
//! client certificate into the HTTP client every request goes through (see
//! [`fapi_profile`](super::fapi_profile)), so a request to a TLS server that
//! asks for one presents it.

use super::{OAuthProviderConfig, fapi_flow};
use crate::oauth::types::*;
use openidconnect::reqwest;
use openidconnect::{AsyncHttpClient, HttpClientError, HttpRequest, HttpResponse};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

type TransportFuture<'a> = Pin<
    Box<dyn Future<Output = Result<HttpResponse, HttpClientError<reqwest::Error>>> + Send + 'a>,
>;

/// The `htu` of a proof: the request URL without its query and fragment
/// (RFC 9449 §4.2).
fn htu(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// An HTTP transport for the token request that adds `proof` as the `DPoP`
/// header and records the `DPoP-Nonce` header of whatever comes back, so a
/// `use_dpop_nonce` refusal can be answered with a proof that echoes it.
///
/// A named type with no lifetime of its own, like `reqwest::Client`: a closure
/// returning a boxed future, or a type borrowing the client, leaves the
/// compiler unable to prove the caller's future is `Send` for every `'c`.
struct DpopTransport {
    client: reqwest::Client,
    proof: String,
    nonce_slot: Arc<Mutex<Option<String>>>,
}

impl<'c> AsyncHttpClient<'c> for DpopTransport {
    type Error = HttpClientError<reqwest::Error>;
    type Future = TransportFuture<'c>;

    fn call(&'c self, mut request: HttpRequest) -> Self::Future {
        match openidconnect::http::HeaderValue::from_str(&self.proof) {
            Ok(value) => {
                request.headers_mut().insert("dpop", value);
            }
            Err(_) => {
                return Box::pin(async {
                    Err(HttpClientError::Other(
                        "DPoP proof is not a valid header value".to_string(),
                    ))
                });
            }
        }
        Box::pin(async move {
            let response = AsyncHttpClient::call(&self.client, request).await?;
            if let Some(nonce) = response
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
            {
                *self.nonce_slot.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(nonce.to_string());
            }
            Ok(response)
        })
    }
}

/// Whether a token-endpoint refusal is `use_dpop_nonce` (RFC 9449 §8).
fn is_use_dpop_nonce<RE>(
    error: &openidconnect::RequestTokenError<
        RE,
        openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    >,
) -> bool
where
    RE: std::error::Error + 'static,
{
    use openidconnect::RequestTokenError::ServerResponse;
    use openidconnect::core::CoreErrorResponseType::Extension;
    matches!(error, ServerResponse(e) if matches!(e.error(), Extension(s) if s == "use_dpop_nonce"))
}

/// Send a token request with a DPoP proof, once more with the server's nonce
/// when the first attempt is refused with `use_dpop_nonce`.
///
/// `$build` makes the request, since sending one consumes it and the second
/// attempt needs a fresh one. A macro, not a function: the request types of
/// `exchange_code` and `exchange_refresh_token` differ, and a generic over
/// "something with `request_async`" would have to name openidconnect's whole
/// typestate.
macro_rules! send_with_dpop {
    ($cfg:expr, $signer:expr, $url:expr, $build:expr) => {{
        let slot = Arc::new(Mutex::new(None::<String>));
        let proof = $cfg.dpop_proof($signer, "POST", $url, None, None)?;
        let first = {
            let transport = DpopTransport {
                client: $cfg.http_client.clone(),
                proof: proof.clone(),
                nonce_slot: slot.clone(),
            };
            $build()?.request_async(&transport).await
        };
        let retry_nonce = match &first {
            Err(e) if is_use_dpop_nonce(e) => slot.lock().unwrap_or_else(|p| p.into_inner()).take(),
            _ => None,
        };
        match retry_nonce {
            Some(nonce) => {
                let proof = $cfg.dpop_proof($signer, "POST", $url, None, Some(&nonce))?;
                let transport = DpopTransport {
                    client: $cfg.http_client.clone(),
                    proof: proof.clone(),
                    nonce_slot: slot.clone(),
                };
                $build()?.request_async(&transport).await
            }
            None => first,
        }
    }};
}

impl OAuthProviderConfig {
    /// One DPoP proof for a request to `url`, with a `jti` from the signer's
    /// rng and `iat` from the provider's clock.
    fn dpop_proof(
        &self,
        signer: DpopSigner<'_>,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        server_nonce: Option<&str>,
    ) -> Result<String, OAuthError> {
        let mut jti = [0u8; 16];
        signer.rng.fill_bytes(&mut jti);
        let proof = fapi_flow::generate_dpop_proof_with_nonce(
            signer.key,
            method,
            htu(url),
            access_token,
            server_nonce,
            self.clock.now().timestamp(),
            jti,
        )?;
        Ok(proof.proof_jwt)
    }

    /// The signer a token request must use: the caller's when it passed one,
    /// and a refusal when the provider is configured for DPoP and the caller
    /// passed none. Sending that request bare would hand a bearer token to a
    /// deployment that asked for a bound one.
    fn require_signer<'s>(
        &self,
        dpop: Option<DpopSigner<'s>>,
    ) -> Result<Option<DpopSigner<'s>>, OAuthError> {
        let wants_dpop = matches!(
            self.fapi.as_ref().map(|f| &f.sender_constraint),
            Some(SenderConstraint::DPoP)
        );
        if dpop.is_none() && wants_dpop {
            return Err(OAuthError::Config(
                "this provider binds tokens to a DPoP key: use the exchange_code_with and \
                 refresh_token_with forms, which take the key"
                    .to_string(),
            ));
        }
        Ok(dpop)
    }

    fn token_endpoint_url(&self) -> Result<String, OAuthError> {
        self.metadata
            .token_endpoint()
            .map(|e| e.url().to_string())
            .ok_or_else(|| OAuthError::Config("no token endpoint in metadata".to_string()))
    }

    /// A DPoP-bound response says so, and an access token that is a JWT with
    /// a `cnf.jkt` carries the thumbprint of the key that signed the proof.
    fn check_bound_response(
        response: &openidconnect::core::CoreTokenResponse,
        key: &DpopKey,
    ) -> Result<(), OAuthError> {
        use openidconnect::OAuth2TokenResponse;
        let token_type = OAuth2TokenResponse::token_type(response);
        if !AsRef::<str>::as_ref(token_type).eq_ignore_ascii_case("dpop") {
            return Err(OAuthError::TokenExchange(
                "the token response is not DPoP-bound (token_type is not DPoP)".to_string(),
            ));
        }
        let access = OAuth2TokenResponse::access_token(response).secret();
        if access.matches('.').count() == 2
            && let Ok(payload) = crate::oidc::logout_token::decode_jwt_payload(access)
            && let Some(jkt) = payload
                .get("cnf")
                .and_then(|c| c.get("jkt"))
                .and_then(|j| j.as_str())
            && jkt != key.thumbprint()?
        {
            return Err(OAuthError::TokenExchange(
                "the access token is bound to a different DPoP key (cnf.jkt)".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) async fn exchange_code_constrained(
        &self,
        code: &str,
        pkce_verifier: String,
        nonce: String,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<OAuthClaims, OAuthError> {
        use openidconnect::{AuthorizationCode, PkceCodeVerifier};

        let dpop = self.require_signer(dpop)?;
        let client = self.make_client();
        let build = || -> Result<_, OAuthError> {
            Ok(client
                .exchange_code(AuthorizationCode::new(code.to_string()))
                .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?
                .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.clone())))
        };

        let response = match dpop {
            None => build()?.request_async(&self.http_client).await,
            Some(signer) => {
                let url = self.token_endpoint_url()?;
                send_with_dpop!(self, signer, &url, build)
            }
        }
        .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?;

        if let Some(signer) = dpop {
            Self::check_bound_response(&response, signer.key)?;
        }
        let mut claims = self.extract_claims_from_response(&response, &nonce).await?;
        claims.dpop_key = dpop.map(|s| Arc::new(DpopKey::from_seed(*s.key.to_seed_bytes())));
        Ok(claims)
    }

    pub(super) async fn refresh_token_constrained(
        &self,
        refresh_token: &str,
        original_nonce: Option<&str>,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<RefreshOutcome, OAuthError> {
        use openidconnect::RefreshToken;

        let dpop = self.require_signer(dpop)?;
        let client = self.make_client();
        let refresh = RefreshToken::new(refresh_token.to_string());
        let build = || -> Result<_, OAuthError> {
            client
                .exchange_refresh_token(&refresh)
                .map_err(|e| OAuthError::TokenExchange(format!("{e}")))
        };

        let response = match dpop {
            None => build()?.request_async(&self.http_client).await,
            Some(signer) => {
                let url = self.token_endpoint_url()?;
                send_with_dpop!(self, signer, &url, build)
            }
        }
        .map_err(|e| OAuthError::TokenExchange(format!("{e}")))?;

        if let Some(signer) = dpop {
            Self::check_bound_response(&response, signer.key)?;
        }
        self.refresh_outcome(&response, refresh_token, original_nonce)
            .await
    }

    pub(super) async fn fetch_userinfo_constrained(
        &self,
        access_token: &str,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<UserInfoClaims, OAuthError> {
        let url = self
            .metadata
            .userinfo_endpoint()
            .ok_or_else(|| {
                OAuthError::UserInfo(
                    "provider metadata does not include a userinfo_endpoint".to_string(),
                )
            })?
            .url()
            .clone();

        let build = |nonce: Option<&str>| -> Result<reqwest::RequestBuilder, OAuthError> {
            let request = self.http_client.get(url.clone());
            match dpop {
                None => Ok(request.bearer_auth(access_token)),
                Some(signer) => {
                    let proof =
                        self.dpop_proof(signer, "GET", url.as_str(), Some(access_token), nonce)?;
                    Ok(request
                        .header("authorization", format!("DPoP {access_token}"))
                        .header("dpop", proof))
                }
            }
        };
        let send = |request: reqwest::RequestBuilder| async move {
            request
                .send()
                .await
                .map_err(|e| OAuthError::UserInfo(format!("HTTP request failed: {e}")))
        };

        let mut response = send(build(None)?).await?;
        // RFC 9449 §9: a resource server that wants a nonce answers 401 with
        // the value in `DPoP-Nonce`; the request is sent once more with it.
        if dpop.is_some()
            && response.status().as_u16() == 401
            && let Some(nonce) = response
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        {
            response = send(build(Some(&nonce))?).await?;
        }

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

        serde_json::from_slice(&body)
            .map_err(|e| OAuthError::UserInfo(format!("failed to parse response: {e}")))
    }
}
