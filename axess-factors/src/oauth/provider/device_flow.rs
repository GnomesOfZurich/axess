//! OAuth 2.0 Device Authorization Grant (RFC 8628) helpers.
//!
//! These free functions carry the actual protocol logic for the device
//! code flow. The corresponding [`OAuthProvider`](super::super::OAuthProvider)
//! trait methods on [`OAuthProviderConfig`](super::OAuthProviderConfig)
//! are thin wrappers that delegate here.

/// Longest refusal text kept from the token endpoint's `error_description`.
const MAX_DENIAL_BYTES: usize = 512;

use super::super::types::{
    DeviceAuthResponse, DeviceTokenOutcome, DpopKey, DpopSigner, OAuthError,
};
use super::OAuthProviderConfig;
use std::sync::Arc;

/// Request a device + user code pair from the IdP's device authorization
/// endpoint. Requires the endpoint to have been configured via
/// [`OAuthProviderBuilder::with_device_authorization_endpoint`](super::OAuthProviderBuilder::with_device_authorization_endpoint); it is not
/// part of standard OIDC discovery.
pub(super) async fn request_device_code(
    cfg: &OAuthProviderConfig,
    scopes: &[&str],
) -> Result<DeviceAuthResponse, OAuthError> {
    let device_url = cfg
        .device_authorization_endpoint
        .as_deref()
        .ok_or_else(|| {
            OAuthError::DeviceAuthorization(
                "no device_authorization_endpoint configured; call with_device_authorization_endpoint()".to_string(),
            )
        })?;

    // The client proves who it is here as at every other endpoint
    // (RFC 8628 section 3.1 defers to RFC 6749 section 3.2.1).
    let mut form: Vec<(String, String)> = Vec::new();
    let basic = cfg.token_grant_auth(&mut form, device_url)?;
    let scope_str = scopes.join(" ");
    if !scope_str.is_empty() {
        form.push(("scope".to_string(), scope_str));
    }

    let (status, body) = cfg
        .post_form_constrained(
            device_url,
            &form,
            basic,
            None,
            "device authorization request",
        )
        .await
        .map_err(|e| {
            OAuthError::DeviceAuthorization(format!("device authorization request failed: {e}"))
        })?;

    if !status.is_success() {
        // The code is the IdP's text and is logged: escaped and cut, as
        // every other upstream error text.
        let error_code = crate::http_body::log_safe_error_code(&body, status);
        tracing::warn!(
            status = status.as_u16(),
            error_code = %error_code,
            "device authorization endpoint error"
        );
        return Err(OAuthError::DeviceAuthorization(error_code));
    }

    serde_json::from_slice(&body).map_err(|e| {
        OAuthError::DeviceAuthorization(format!(
            "failed to parse device response: {}",
            crate::remote_text::parse_error(&e)
        ))
    })
}

/// Poll the IdP's token endpoint with a previously-issued `device_code`.
/// Returns:
/// - [`DeviceTokenOutcome::Pending`] while the user has not yet approved
///   (`authorization_pending`)
/// - [`DeviceTokenOutcome::SlowDown`] when the IdP signals the polling
///   interval should be increased by 5s (RFC 8628 §3.5)
/// - [`DeviceTokenOutcome::Authorized`] once the user has approved
/// - [`DeviceTokenOutcome::Denied`] on any other error
///
/// The `current_interval` lets the helper compute the new back-off
/// interval to return on `slow_down` without the caller tracking it.
pub(super) async fn poll_device_token(
    cfg: &OAuthProviderConfig,
    device_code: &str,
    current_interval: u64,
    nonce: Option<&str>,
    dpop: Option<DpopSigner<'_>>,
) -> Result<DeviceTokenOutcome, OAuthError> {
    let dpop = cfg.require_signer(dpop)?;
    let token_url = cfg.token_endpoint_url()?;

    let mut form: Vec<(String, String)> = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        ("device_code".to_string(), device_code.to_string()),
    ];
    let basic = cfg.token_grant_auth(&mut form, &token_url)?;

    let (status, body) = cfg
        .post_form_constrained(&token_url, &form, basic, dpop, "device token poll")
        .await?;

    if status.is_success() {
        // Token granted; extract claims from the ID token.
        let token_response: openidconnect::core::CoreTokenResponse = serde_json::from_slice(&body)
            .map_err(|e| {
                OAuthError::TokenExchange(format!(
                    "failed to parse token response: {}",
                    crate::remote_text::parse_error(&e)
                ))
            })?;
        if let Some(signer) = dpop {
            OAuthProviderConfig::check_bound_response(&token_response, signer.key)?;
        }

        // Nonce IS allowed in device flows. When the caller
        // generated one in `request_device_authorization` and stashed it,
        // pass it here so the verifier enforces the binding. When no
        // nonce was generated (`None`), preserve the previous behavior
        // of empty-string-skips-validation. The empty-string sentinel is
        // a quirk of openidconnect 4.x; passing `""` is interpreted as
        // "no nonce expected"; any non-empty string activates the check.
        let nonce_for_verify = nonce.unwrap_or("");
        let mut claims = cfg
            .extract_claims_from_response(&token_response, nonce_for_verify)
            .await
            .map_err(|e| {
                OAuthError::IdTokenValidation(format!(
                    "device code flow: ID token extraction failed: {e}"
                ))
            })?;
        claims.dpop_key = dpop.map(|s| Arc::new(DpopKey::from_seed(*s.key.to_seed_bytes())));

        return Ok(DeviceTokenOutcome::Authorized(Box::new(claims)));
    }

    // A server error is the IdP failing, not the user refusing.
    if status.is_server_error() {
        return Err(OAuthError::transient(Some(status.as_u16())));
    }

    // Check for standard OAuth error codes, read member by member so a long
    // description, before the code or after it, does not cost the code.
    let error_code = crate::http_body::string_member(&body, "error");
    if error_code.is_none() {
        tracing::warn!("device token poll: the error response carries no `error` code");
    }
    let error_code = error_code.unwrap_or_default();

    match error_code.as_str() {
        "authorization_pending" => Ok(DeviceTokenOutcome::Pending),
        // RFC 8628 §3.5: distinct outcome so the caller can
        // increase its polling interval. The new interval is the prior
        // one plus 5 seconds per the spec.
        "slow_down" => Ok(DeviceTokenOutcome::SlowDown {
            new_interval: current_interval.saturating_add(5),
        }),
        // The text is the IdP's and is usually logged or shown: control
        // characters and the Unicode line separators are escaped and the
        // text is cut, as every other upstream error text.
        _ => Ok(DeviceTokenOutcome::Denied(crate::http_body::log_safe(
            &crate::http_body::string_member(&body, "error_description")
                .unwrap_or_else(|| error_code.clone()),
            MAX_DENIAL_BYTES,
        ))),
    }
}
