//! Requests that carry a sender constraint: a DPoP proof (RFC 9449) on the
//! token request and on the userinfo call, and the error handling around the
//! server-supplied nonce.
//!
//! One switch decides whether a provider binds its tokens to a DPoP key:
//! its `dpop` field, resolved by the builder (see [`dpop`](super::dpop)).
//! Every request here reads it through
//! [`require_signer`](OAuthProviderConfig::require_signer).
//!
//! The mTLS half needs no code on the request path: the builder puts the
//! client certificate into the HTTP client every request goes through (see
//! [`fapi_profile`](super::fapi_profile)), so a request to a TLS server that
//! asks for one presents it.

use super::{OAuthProviderConfig, dpop};
use crate::oauth::types::*;
use openidconnect::reqwest;
use std::future::Future;
use std::sync::Arc;

/// Send a request, and send it once more with the server's nonce when the
/// answer asks for one (RFC 9449 sections 8 and 9). `send` makes and sends
/// the request with the nonce it is given; `nonce_asked` reads the nonce out
/// of an answer that asks for one, and `None` out of any other. The one rule
/// both kinds of endpoint follow: one retry, only on the server's request.
async fn retry_on_nonce<R, S, F>(
    send: S,
    nonce_asked: impl Fn(&R) -> Option<String>,
) -> Result<R, OAuthError>
where
    S: Fn(Option<String>) -> F,
    F: Future<Output = Result<R, OAuthError>>,
{
    let first = send(None).await?;
    match nonce_asked(&first) {
        Some(nonce) => send(Some(nonce)).await,
        None => Ok(first),
    }
}

/// The `DPoP-Nonce` header of an answer, when it has one.
fn dpop_nonce_header(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// An authorization server's answer to a form POST: the status, the
/// `DPoP-Nonce` header, and the body.
struct FormAnswer {
    status: reqwest::StatusCode,
    nonce: Option<String>,
    body: Vec<u8>,
}

impl FormAnswer {
    /// The nonce a token-endpoint refusal asks for: a `400` whose body says
    /// `use_dpop_nonce` and that carries a `DPoP-Nonce` (RFC 9449 section 8).
    fn nonce_asked(&self) -> Option<String> {
        if self.status != reqwest::StatusCode::BAD_REQUEST {
            return None;
        }
        let wants = serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(|e| e == "use_dpop_nonce"))
            .unwrap_or(false);
        wants.then(|| self.nonce.clone()).flatten()
    }
}

/// Whether one `WWW-Authenticate` value holds a `DPoP` challenge with
/// `error="use_dpop_nonce"`. The value may carry several challenges
/// (RFC 9110 section 11.6.1), each a scheme followed by comma-separated
/// parameters, so it is read element by element, with quoted strings kept
/// whole: a comma inside one does not end an element.
fn challenges_ask_for_a_nonce(value: &str) -> bool {
    let mut elements = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                elements.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    elements.push(&value[start..]);

    let mut in_dpop = false;
    for element in elements {
        let element = element.trim();
        let (head, rest) = match element.split_once(char::is_whitespace) {
            Some((h, r)) => (h, r.trim()),
            None => (element, ""),
        };
        // `name=value` is a parameter of the current challenge; anything
        // else starts a new one, whose first parameter may follow its name.
        let param = if head.contains('=') {
            element
        } else {
            in_dpop = head.eq_ignore_ascii_case("dpop");
            rest
        };
        if in_dpop
            && let Some((k, v)) = param.split_once('=')
            && k.trim().eq_ignore_ascii_case("error")
            && v.trim().trim_matches('"') == "use_dpop_nonce"
        {
            return true;
        }
    }
    false
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
        let proof = dpop::generate_dpop_proof_with_nonce(
            signer.key,
            method,
            url,
            access_token,
            server_nonce,
            self.clock.now().timestamp(),
            jti,
        )?;
        Ok(proof.proof_jwt)
    }

    /// The signer a token request must use: the caller's when it passed one,
    /// and a refusal when the provider binds tokens to a DPoP key and the
    /// caller passed none. Sending that request bare would hand a bearer
    /// token to a deployment that asked for a bound one.
    pub(super) fn require_signer<'s>(
        &self,
        dpop: Option<DpopSigner<'s>>,
    ) -> Result<Option<DpopSigner<'s>>, OAuthError> {
        if dpop.is_none() && self.dpop {
            return Err(OAuthError::DpopKeyRequired);
        }
        Ok(dpop)
    }

    /// Whether a resource server's `401` asks for a nonce: RFC 9449 section
    /// 9 has it answer `WWW-Authenticate: DPoP error="use_dpop_nonce"` with
    /// the nonce in `DPoP-Nonce`. Any other `401` that happens to carry a
    /// `DPoP-Nonce` header (a server that sends one on every answer) is the
    /// refusal it says it is, and is not retried.
    fn is_use_dpop_nonce_challenge(response: &reqwest::Response) -> bool {
        response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(challenges_ask_for_a_nonce)
    }

    /// POST `form` to `url` and read the answer: the body in full on
    /// success (up to [`MAX_TOKEN_BODY_BYTES`](crate::http_body::MAX_TOKEN_BODY_BYTES)),
    /// a short snippet otherwise. `basic` is the client id and secret for a
    /// `client_secret_basic` header (see
    /// [`token_grant_auth`](Self::token_grant_auth)). With a signer the
    /// request carries a DPoP proof, and a `use_dpop_nonce` refusal (RFC 9449
    /// section 8) is answered once with a proof that echoes the server's
    /// `DPoP-Nonce`. `what` names the request in errors.
    pub(super) async fn post_form_constrained(
        &self,
        url: &str,
        form: &[(String, String)],
        basic: Option<(&str, &str)>,
        dpop: Option<DpopSigner<'_>>,
        what: &str,
    ) -> Result<(reqwest::StatusCode, Vec<u8>), OAuthError> {
        let send = |nonce: Option<String>| async move {
            // A client assertion is single-use (FAPI 2.0 has the server
            // refuse a repeated `jti`), so a retry signs its own.
            let mut attempt = form.to_vec();
            if nonce.is_some()
                && let Some(slot) = attempt.iter_mut().find(|(k, _)| k == "client_assertion")
                && let Some(fresh) = self.client_assertion_for(url)?
            {
                slot.1 = fresh;
            }
            let mut request = self.http_client.post(url).form(&attempt);
            if let Some((id, secret)) = basic {
                let (id, secret) = super::client_auth::basic_credentials(id, secret);
                request = request.basic_auth(id, Some(secret));
            }
            if let Some(signer) = dpop {
                request = request.header(
                    "dpop",
                    self.dpop_proof(signer, "POST", url, None, nonce.as_deref())?,
                );
            }
            let mut response = request.send().await.map_err(|e| {
                tracing::warn!(error = %e, "{what} got no answer");
                OAuthError::transient(None)
            })?;
            let status = response.status();
            let nonce = dpop_nonce_header(response.headers());
            let body = crate::http_body::read_for_status(
                &mut response,
                crate::http_body::MAX_TOKEN_BODY_BYTES,
            )
            .await
            .map_err(|e| OAuthError::TokenExchange(format!("response read failed: {e}")))?;
            Ok(FormAnswer {
                status,
                nonce,
                body,
            })
        };
        let answer = retry_on_nonce(send, |answer: &FormAnswer| {
            dpop.and_then(|_| answer.nonce_asked())
        })
        .await?;
        Ok((answer.status, answer.body))
    }

    /// A token response of the authorization code or refresh grant, parsed
    /// as the ID-token verification reads it. A refusal carries the server's
    /// `error` (and description) in the message.
    fn token_response(
        status: reqwest::StatusCode,
        body: &[u8],
    ) -> Result<openidconnect::core::CoreTokenResponse, OAuthError> {
        if status.is_server_error() {
            return Err(OAuthError::transient(Some(status.as_u16())));
        }
        if !status.is_success() {
            let refusal = serde_json::from_slice::<
                openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
            >(body)
            .map(|e| format!("server returned error response: {e}"))
            .unwrap_or_else(|_| format!("token endpoint returned HTTP {status}"));
            return Err(OAuthError::TokenExchange(refusal));
        }
        serde_json::from_slice(body)
            .map_err(|e| OAuthError::TokenExchange(format!("failed to parse token response: {e}")))
    }

    /// The client credentials grant (RFC 6749 section 4.4), with the token
    /// request bound to `dpop` when the provider binds tokens.
    pub(super) async fn client_credentials_constrained(
        &self,
        scopes: &[&str],
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<ClientCredentialsToken, OAuthError> {
        let dpop = self.require_signer(dpop)?;
        let token_url = self.token_endpoint_url()?;

        let mut form: Vec<(String, String)> =
            vec![("grant_type".to_string(), "client_credentials".to_string())];
        let basic = self.token_grant_auth(&mut form, &token_url)?;
        let scope_str = scopes.join(" ");
        if !scope_str.is_empty() {
            form.push(("scope".to_string(), scope_str));
        }

        let (status, body) = self
            .post_form_constrained(&token_url, &form, basic, dpop, "client_credentials request")
            .await?;

        if status.is_server_error() {
            return Err(OAuthError::transient(Some(status.as_u16())));
        }
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

        let token: ClientCredentialsToken = serde_json::from_slice(&body).map_err(|e| {
            OAuthError::TokenExchange(format!("failed to parse token response: {e}"))
        })?;
        if let Some(signer) = dpop {
            Self::check_bound_token(&token.token_type, &token.access_token, signer.key)?;
        }
        Ok(token)
    }

    /// Token revocation (RFC 7009), with a DPoP proof on the request when
    /// `dpop` is given. A revocation issues no token, so there is no bearer
    /// token a request without a proof could be handed; it is therefore sent
    /// without one, not refused, and a signer is attached when the caller
    /// holds the key the token is bound to.
    pub(super) async fn revoke_token_constrained(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<(), OAuthError> {
        let revocation_url = self.revocation_endpoint.as_deref().ok_or_else(|| {
            OAuthError::Config(
                "provider metadata does not include a revocation_endpoint".to_string(),
            )
        })?;

        let mut form: Vec<(String, String)> = vec![("token".to_string(), token.to_string())];
        let basic = self.token_grant_auth(&mut form, revocation_url)?;
        if let Some(hint) = token_type_hint {
            form.push(("token_type_hint".to_string(), hint.to_string()));
        }

        let (status, body) = self
            .post_form_constrained(revocation_url, &form, basic, dpop, "revocation request")
            .await?;

        if status.is_success() {
            tracing::info!(provider = %self.name, "token revoked successfully");
            return Ok(());
        }

        // The body is neither logged nor kept in the transient error: an
        // error page can carry the token or an echo of the request. RFC 7009 / 6749 error semantics are kept apart: a 4xx with
        // `error: "unsupported_token_type"` means the AS cannot revoke this
        // token kind (callers treat it as a no-op); a 5xx is transient and
        // may be retried; any other 4xx is a TokenExchange error.
        let body = String::from_utf8_lossy(&body).into_owned();
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
            Err(OAuthError::transient(Some(status.as_u16())))
        } else if parsed_error.as_deref() == Some("unsupported_token_type") {
            Err(OAuthError::UnsupportedTokenType)
        } else {
            Err(OAuthError::TokenExchange(format!(
                "revocation endpoint returned HTTP {status}"
            )))
        }
    }

    pub(super) fn token_endpoint_url(&self) -> Result<String, OAuthError> {
        self.metadata
            .token_endpoint()
            .map(|e| e.url().to_string())
            .ok_or_else(|| OAuthError::Config("no token endpoint in metadata".to_string()))
    }

    /// A DPoP-bound response says so, and an access token that is a JWT with
    /// a `cnf.jkt` carries the thumbprint of the key that signed the proof.
    pub(super) fn check_bound_response(
        response: &openidconnect::core::CoreTokenResponse,
        key: &DpopKey,
    ) -> Result<(), OAuthError> {
        use openidconnect::OAuth2TokenResponse;
        let token_type = OAuth2TokenResponse::token_type(response);
        Self::check_bound_token(
            AsRef::<str>::as_ref(token_type),
            OAuth2TokenResponse::access_token(response).secret(),
            key,
        )
    }

    /// [`check_bound_response`](Self::check_bound_response) on the two
    /// members it reads, for a response parsed outside openidconnect.
    pub(super) fn check_bound_token(
        token_type: &str,
        access: &str,
        key: &DpopKey,
    ) -> Result<(), OAuthError> {
        if !token_type.eq_ignore_ascii_case("dpop") {
            return Err(OAuthError::TokenExchange(
                "the token response is not DPoP-bound (token_type is not DPoP)".to_string(),
            ));
        }
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

    /// The token request of the authorization code grant, with a DPoP proof
    /// when `dpop` is given.
    pub(super) async fn exchange_code_constrained(
        &self,
        code: &str,
        pkce_verifier: String,
        nonce: String,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<OAuthClaims, OAuthError> {
        let dpop = self.require_signer(dpop)?;
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("code_verifier".to_string(), pkce_verifier),
            ("redirect_uri".to_string(), self.redirect_url.to_string()),
        ];
        let response = self.token_grant(&mut form, dpop, "token request").await?;
        let mut claims = self.extract_claims_from_response(&response, &nonce).await?;
        claims.dpop_key = dpop.map(|s| Arc::new(DpopKey::from_seed(*s.key.to_seed_bytes())));
        Ok(claims)
    }

    /// The token request of the refresh grant, with a DPoP proof when `dpop`
    /// is given.
    pub(super) async fn refresh_token_constrained(
        &self,
        refresh_token: &str,
        original_nonce: Option<&str>,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<RefreshOutcome, OAuthError> {
        let dpop = self.require_signer(dpop)?;
        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
        ];
        let response = self.token_grant(&mut form, dpop, "refresh request").await?;
        self.refresh_outcome(&response, refresh_token, original_nonce)
            .await
    }

    /// POST a grant to the token endpoint with the client's authentication,
    /// and parse the answer; with `dpop`, check that it is DPoP-bound.
    async fn token_grant(
        &self,
        form: &mut Vec<(String, String)>,
        dpop: Option<DpopSigner<'_>>,
        what: &str,
    ) -> Result<openidconnect::core::CoreTokenResponse, OAuthError> {
        let token_url = self.token_endpoint_url()?;
        let basic = self.token_grant_auth(form, &token_url)?;
        let (status, body) = self
            .post_form_constrained(&token_url, form, basic, dpop, what)
            .await?;
        let response = Self::token_response(status, &body)?;
        if let Some(signer) = dpop {
            Self::check_bound_response(&response, signer.key)?;
        }
        Ok(response)
    }

    /// The userinfo call, with the token presented under the `DPoP` scheme
    /// and a proof naming its hash when `dpop` is given. A provider that
    /// binds tokens to a DPoP key refuses a call without a key before
    /// anything is sent: its access tokens are bound, and one sent as `Bearer` is
    /// refused by the resource server, or, worse, accepted by one that does
    /// not check the binding.
    pub(super) async fn fetch_userinfo_constrained(
        &self,
        access_token: &str,
        dpop: Option<DpopSigner<'_>>,
    ) -> Result<UserInfoClaims, OAuthError> {
        let dpop = self.require_signer(dpop)?;
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

        let send = |nonce: Option<String>| {
            let url = url.clone();
            async move {
                let request = self.http_client.get(url.clone());
                let request = match dpop {
                    None => request.bearer_auth(access_token),
                    Some(signer) => {
                        let proof = self.dpop_proof(
                            signer,
                            "GET",
                            url.as_str(),
                            Some(access_token),
                            nonce.as_deref(),
                        )?;
                        request
                            .header("authorization", format!("DPoP {access_token}"))
                            .header("dpop", proof)
                    }
                };
                request
                    .send()
                    .await
                    .map_err(|e| OAuthError::UserInfo(format!("HTTP request failed: {e}")))
            }
        };
        // RFC 9449 §9: a resource server that wants a nonce answers 401 with
        // `WWW-Authenticate: DPoP error="use_dpop_nonce"` and the value in
        // `DPoP-Nonce`; the request is sent once more with it. A 401 that
        // says anything else is the refusal it says it is.
        let mut response = retry_on_nonce(send, |response: &reqwest::Response| {
            (dpop.is_some()
                && response.status().as_u16() == 401
                && Self::is_use_dpop_nonce_challenge(response))
            .then(|| dpop_nonce_header(response.headers()))
            .flatten()
        })
        .await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, nonce: Option<&str>, body: serde_json::Value) -> FormAnswer {
        FormAnswer {
            status: reqwest::StatusCode::from_u16(status).unwrap(),
            nonce: nonce.map(str::to_string),
            body: body.to_string().into_bytes(),
        }
    }

    /// The token endpoint asks for a nonce only with a `400` whose body says
    /// `use_dpop_nonce` and a `DPoP-Nonce` header; anything less is the
    /// answer it is.
    #[test]
    fn a_token_endpoint_asks_for_a_nonce_only_the_rfc_way() {
        let asks = serde_json::json!({ "error": "use_dpop_nonce" });
        assert_eq!(
            answer(400, Some("n1"), asks.clone())
                .nonce_asked()
                .as_deref(),
            Some("n1")
        );
        assert_eq!(answer(400, None, asks.clone()).nonce_asked(), None);
        assert_eq!(answer(401, Some("n1"), asks).nonce_asked(), None);
        let other = serde_json::json!({ "error": "invalid_grant" });
        assert_eq!(answer(400, Some("n1"), other).nonce_asked(), None);
        assert_eq!(
            answer(200, Some("n1"), serde_json::json!({})).nonce_asked(),
            None
        );
    }

    /// One retry, with the nonce, and only when the answer asks for one.
    #[tokio::test]
    async fn the_retry_is_sent_once_with_the_nonce() {
        let sent = std::sync::Mutex::new(Vec::new());
        let send = |nonce: Option<String>| {
            sent.lock().unwrap().push(nonce.clone());
            async move { Ok::<_, OAuthError>(nonce.is_none()) }
        };
        // The first answer asks (true); the retry answers false.
        let last = retry_on_nonce(send, |asks: &bool| asks.then(|| "n1".to_string()))
            .await
            .unwrap();
        assert!(!last);
        assert_eq!(*sent.lock().unwrap(), [None, Some("n1".to_string())]);

        let sent = std::sync::Mutex::new(0);
        let send = |_nonce: Option<String>| {
            *sent.lock().unwrap() += 1;
            async { Ok::<_, OAuthError>(()) }
        };
        retry_on_nonce(send, |_: &()| None).await.unwrap();
        assert_eq!(*sent.lock().unwrap(), 1, "no retry unless asked");
    }
}
