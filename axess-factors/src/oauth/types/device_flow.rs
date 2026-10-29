//! OAuth 2.0 Device Authorization Grant (RFC 8628).

use serde::{Deserialize, Serialize};

use super::claims::OAuthClaims;

/// Response from the device authorization endpoint (RFC 8628 Section 3.2).
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    /// The device verification code (opaque to the client).
    pub device_code: String,
    /// The short user code to display (e.g. `"WDJB-MJHT"`).
    pub user_code: String,
    /// The URI the user visits to enter the code.
    pub verification_uri: String,
    /// Optional URI with the user code embedded (one-click auth).
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the device code in seconds.
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    pub interval: u64,
}

/// Prints everything but the device code, which is the credential the client
/// polls the token endpoint with. The user code is meant to be shown.
impl std::fmt::Debug for DeviceAuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthResponse")
            .field("device_code", &"[redacted]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Result of polling the token endpoint during a device code flow.
#[derive(Debug)]
pub enum DeviceTokenOutcome {
    /// User has authorized; here are the claims.
    Authorized(Box<OAuthClaims>),
    /// Authorization is still pending; poll again after `interval` seconds.
    Pending,
    /// Authorization is still pending AND the IdP asked us to back off:
    /// per RFC 8628 §3.5, the polling interval MUST be increased by
    /// 5 seconds. The new interval (in seconds) is included so the
    /// caller can update its polling cadence without remembering the
    /// previous value.
    SlowDown {
        /// Updated polling interval in seconds, already increased by 5s per RFC 8628 §3.5.
        new_interval: u64,
    },
    /// Authorization was denied or the device code expired.
    Denied(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_the_device_code_and_keeps_the_user_code() {
        let response = DeviceAuthResponse {
            device_code: "device-secret-777".to_owned(),
            user_code: "WDJB-MJHT".to_owned(),
            verification_uri: "https://idp.example/device".to_owned(),
            verification_uri_complete: None,
            expires_in: 600,
            interval: 5,
        };
        let shown = format!("{response:?}");
        assert!(!shown.contains("device-secret-777"), "{shown}");
        assert!(shown.contains("WDJB-MJHT"));
    }
}
