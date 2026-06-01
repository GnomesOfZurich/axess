//! OAuth 2.0 Device Authorization Grant (RFC 8628) helpers.
//!
//! These free functions carry the actual protocol logic for the device
//! code flow. The corresponding [`OAuthProvider`](super::super::OAuthProvider)
//! trait methods on [`OAuthProviderConfig`](super::OAuthProviderConfig)
//! are thin wrappers that delegate here.

use super::super::types::{DeviceAuthResponse, DeviceTokenOutcome, OAuthError};
use super::OAuthProviderConfig;

/// Request a device + user code pair from the IdP's device authorization
/// endpoint. Requires the endpoint to have been configured via
/// [`OAuthProviderConfig::with_device_authorization_endpoint`]; it is not
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

    let mut form = vec![("client_id", cfg.client_id.as_str())];
    let scope_str = scopes.join(" ");
    if !scope_str.is_empty() {
        form.push(("scope", &scope_str));
    }

    let response = cfg
        .http_client
        .post(device_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            OAuthError::DeviceAuthorization(format!("device authorization request failed: {e}"))
        })?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| OAuthError::DeviceAuthorization(format!("response read failed: {e}")))?;

    if !status.is_success() {
        let error_body = String::from_utf8_lossy(&body);
        tracing::warn!(
            status = status.as_u16(),
            body = %error_body,
            "device authorization endpoint error"
        );
        let error_code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(String::from))
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(OAuthError::DeviceAuthorization(error_code));
    }

    serde_json::from_slice(&body).map_err(|e| {
        OAuthError::DeviceAuthorization(format!("failed to parse device response: {e}"))
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
) -> Result<DeviceTokenOutcome, OAuthError> {
    let token_url = cfg
        .metadata
        .token_endpoint()
        .ok_or_else(|| OAuthError::Config("no token endpoint in metadata".to_string()))?
        .url()
        .to_string();

    let mut form = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", cfg.client_id.as_str()),
    ];
    if let Some(ref secret) = cfg.client_secret {
        form.push(("client_secret", secret.secret()));
    }

    let response = cfg
        .http_client
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| OAuthError::TokenExchange(format!("device token poll failed: {e}")))?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| OAuthError::TokenExchange(format!("response read failed: {e}")))?;

    if status.is_success() {
        // Token granted; extract claims from the ID token.
        let token_response: openidconnect::core::CoreTokenResponse = serde_json::from_slice(&body)
            .map_err(|e| {
                OAuthError::TokenExchange(format!("failed to parse token response: {e}"))
            })?;

        // Nonce IS allowed in device flows. When the caller
        // generated one in `request_device_authorization` and stashed it,
        // pass it here so the verifier enforces the binding. When no
        // nonce was generated (`None`), preserve the previous behavior
        // of empty-string-skips-validation. The empty-string sentinel is
        // a quirk of openidconnect 4.x; passing `""` is interpreted as
        // "no nonce expected"; any non-empty string activates the check.
        let nonce_for_verify = nonce.unwrap_or("");
        let claims = cfg
            .extract_claims_from_response(&token_response, nonce_for_verify)
            .map_err(|e| {
                OAuthError::IdTokenValidation(format!(
                    "device code flow: ID token extraction failed: {e}"
                ))
            })?;

        return Ok(DeviceTokenOutcome::Authorized(Box::new(claims)));
    }

    // Check for standard OAuth error codes.
    let error: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("device token poll: invalid JSON in error response: {e}");
            serde_json::Value::Null
        }
    };
    let error_code = error.get("error").and_then(|v| v.as_str()).unwrap_or("");

    match error_code {
        "authorization_pending" => Ok(DeviceTokenOutcome::Pending),
        // RFC 8628 §3.5: distinct outcome so the caller can
        // increase its polling interval. The new interval is the prior
        // one plus 5 seconds per the spec.
        "slow_down" => Ok(DeviceTokenOutcome::SlowDown {
            new_interval: current_interval.saturating_add(5),
        }),
        _ => Ok(DeviceTokenOutcome::Denied(
            error
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or(error_code)
                .to_string(),
        )),
    }
}
