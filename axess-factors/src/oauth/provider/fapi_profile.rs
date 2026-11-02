//! Switching the FAPI 2.0 profile on: the sender constraint, the ID-token
//! algorithm allow-list, and the JARM response check.
//!
//! DPoP under the profile is the provider's one DPoP switch (see
//! [`dpop`](super::dpop)) turned on; the profile adds its own rules on top:
//! no client secret, PAR, the ID-token limits, JARM.
//!
//! [`OAuthProviderBuilder::with_fapi`](super::OAuthProviderBuilder::with_fapi)
//! records the profile and
//! [`OAuthProviderBuilder::build`](super::OAuthProviderBuilder::build) applies
//! it through the checks here. It either returns a provider whose token
//! requests are sender-constrained, whose client authenticates without a
//! secret and whose ID tokens are checked against the profile, or an error
//! naming what is missing; there is no half-enabled state.

use super::OAuthProviderConfig;
use crate::oauth::types::*;
use openidconnect::core::CoreJwsSigningAlgorithm;

/// The `mtls_endpoint_aliases` of the discovery document (RFC 8705 §5): the
/// endpoints a client that authenticates with a certificate must use, since
/// the ordinary ones may not ask for it.
#[derive(Debug, Clone, Default)]
pub(crate) struct MtlsAliases {
    pub(super) token_endpoint: Option<String>,
    pub(super) userinfo_endpoint: Option<String>,
    pub(super) revocation_endpoint: Option<String>,
    pub(super) pushed_authorization_request_endpoint: Option<String>,
}

impl MtlsAliases {
    /// Read the aliases out of the raw discovery document.
    pub(super) fn from_document(raw: &serde_json::Value) -> Self {
        let get = |name: &str| {
            raw.get("mtls_endpoint_aliases")
                .and_then(|a| a.get(name))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        Self {
            token_endpoint: get("token_endpoint"),
            userinfo_endpoint: get("userinfo_endpoint"),
            revocation_endpoint: get("revocation_endpoint"),
            pushed_authorization_request_endpoint: get("pushed_authorization_request_endpoint"),
        }
    }
}

/// The ID-token signature algorithms a provider accepts when it is pinned to
/// a list (by the FAPI profile, by
/// [`with_id_token_signing_algs`](super::OAuthProviderBuilder::with_id_token_signing_algs),
/// or by both), in the two
/// vocabularies the verifiers speak.
#[derive(Debug, Clone)]
pub(crate) struct IdTokenAlgs {
    pub(super) openid: Vec<CoreJwsSigningAlgorithm>,
    pub(super) jwt: Vec<jsonwebtoken::Algorithm>,
}

impl IdTokenAlgs {
    /// Parse JOSE algorithm names. Symmetric algorithms and `none` are never
    /// acceptable for an ID token verified against a public key set, and an
    /// empty list would accept nothing, so both are refused here rather than
    /// at the first login.
    pub(super) fn parse(names: &[String], what: &str) -> Result<Self, OAuthError> {
        use jsonwebtoken::Algorithm as J;
        if names.is_empty() {
            return Err(OAuthError::Config(format!(
                "{what} is empty: no ID token could verify"
            )));
        }
        let mut openid = Vec::with_capacity(names.len());
        let mut jwt = Vec::with_capacity(names.len());
        for name in names {
            let (o, j) = match name.as_str() {
                "RS256" => (CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, J::RS256),
                "RS384" => (CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384, J::RS384),
                "RS512" => (CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512, J::RS512),
                "PS256" => (CoreJwsSigningAlgorithm::RsaSsaPssSha256, J::PS256),
                "PS384" => (CoreJwsSigningAlgorithm::RsaSsaPssSha384, J::PS384),
                "PS512" => (CoreJwsSigningAlgorithm::RsaSsaPssSha512, J::PS512),
                "ES256" => (CoreJwsSigningAlgorithm::EcdsaP256Sha256, J::ES256),
                "ES384" => (CoreJwsSigningAlgorithm::EcdsaP384Sha384, J::ES384),
                "EdDSA" => (CoreJwsSigningAlgorithm::EdDsa, J::EdDSA),
                other => {
                    return Err(OAuthError::Config(format!(
                        "{what}: `{other}` is not an asymmetric \
                         signature algorithm this provider verifies"
                    )));
                }
            };
            openid.push(o);
            jwt.push(j);
        }
        Ok(Self { openid, jwt })
    }

    /// The algorithms both lists name, in this list's order.
    pub(super) fn intersect(&self, other: &Self) -> Self {
        let (openid, jwt) = self
            .openid
            .iter()
            .zip(&self.jwt)
            .filter(|(_, j)| other.jwt.contains(j))
            .map(|(o, j)| (o.clone(), *j))
            .unzip();
        Self { openid, jwt }
    }
}

/// An HTTP client that presents the client certificate on every TLS
/// handshake: no redirects, a 30 second timeout, like the one discovery built.
pub(super) fn mtls_client(
    cert_path: &str,
    key_path: &str,
) -> Result<openidconnect::reqwest::Client, OAuthError> {
    let mut pem = std::fs::read(cert_path)
        .map_err(|e| OAuthError::Config(format!("mTLS client certificate unreadable: {e}")))?;
    pem.push(b'\n');
    pem.extend_from_slice(
        &std::fs::read(key_path)
            .map_err(|e| OAuthError::Config(format!("mTLS client key unreadable: {e}")))?,
    );
    let identity = openidconnect::reqwest::Identity::from_pem(&pem)
        .map_err(|e| OAuthError::Config(format!("mTLS client certificate or key invalid: {e}")))?;
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .use_rustls_tls()
        .identity(identity)
        .build()
        .map_err(|e| OAuthError::Config(format!("mTLS HTTP client build failed: {e}")))
}

/// The FAPI profile's demands on the client (FAPI 2.0 section 5.3.1.1): it
/// authenticates by an assertion or by its certificate (RFC 8705 section
/// 2.1), never by a shared secret, and its authorization requests are pushed.
pub(super) fn check_client_and_par(
    config: &FapiConfig,
    has_signer: bool,
    has_par_endpoint: bool,
) -> Result<(), OAuthError> {
    if !has_par_endpoint {
        return Err(OAuthError::Config(
            "FAPI 2.0 requires pushed_authorization_request_endpoint in provider metadata \
             or with_par_endpoint"
                .to_string(),
        ));
    }
    let mtls = matches!(config.sender_constraint, SenderConstraint::Mtls { .. });
    if !has_signer && !mtls {
        return Err(OAuthError::Config(
            "FAPI 2.0 does not allow a client secret: authenticate the client by \
             private_key_jwt (with_private_key_jwt or discover_with_private_key_jwt) \
             or by mTLS (SenderConstraint::Mtls)"
                .to_string(),
        ));
    }
    Ok(())
}

impl OAuthProviderConfig {
    /// Point the token, userinfo, revocation and PAR requests at the
    /// `mtls_endpoint_aliases` the server advertised, for the ones it did.
    pub(super) fn use_mtls_aliases(&mut self) -> Result<(), OAuthError> {
        use openidconnect::{TokenUrl, UserInfoUrl};
        let aliases = self.mtls_aliases.clone();
        let invalid =
            |what: &str| OAuthError::Config(format!("mtls_endpoint_aliases {what} is not a URL"));
        if let Some(url) = &aliases.token_endpoint {
            super::endpoint::require_secure(Some(url), "mtls token_endpoint")?;
            let url = TokenUrl::new(url.clone()).map_err(|_| invalid("token_endpoint"))?;
            self.metadata = self.metadata.clone().set_token_endpoint(Some(url));
        }
        if let Some(url) = &aliases.userinfo_endpoint {
            super::endpoint::require_secure(Some(url), "mtls userinfo_endpoint")?;
            let url = UserInfoUrl::new(url.clone()).map_err(|_| invalid("userinfo_endpoint"))?;
            self.metadata = self.metadata.clone().set_userinfo_endpoint(Some(url));
        }
        if let Some(url) = aliases.revocation_endpoint {
            super::endpoint::require_secure(Some(&url), "mtls revocation_endpoint")?;
            self.revocation_endpoint = Some(url);
        }
        if let Some(url) = aliases.pushed_authorization_request_endpoint {
            super::endpoint::require_secure(
                Some(&url),
                "mtls pushed_authorization_request_endpoint",
            )?;
            self.par_endpoint = Some(url);
        }
        Ok(())
    }

    /// The verifier for an ID token: the client's, with the clock and, under
    /// FAPI, the profile's algorithm allow-list in place of whatever the IdP
    /// advertised.
    pub(super) fn id_token_verifier<'a>(
        &self,
        client: &'a super::OidcClient,
    ) -> openidconnect::core::CoreIdTokenVerifier<'a> {
        let verifier = client.id_token_verifier().set_time_fn(self.time_fn());
        match &self.id_token_algs {
            Some(algs) => verifier.set_allowed_algs(algs.openid.iter().cloned()),
            None => verifier,
        }
    }

    /// Verify a JARM authorization response (see
    /// [`OAuthProvider::verify_authorization_response_jwt`]).
    pub(super) fn verify_authorization_response(
        &self,
        response: &str,
    ) -> Result<JarmResponse, OAuthError> {
        let payload = self.verify_issuer_jwt(response)?;

        let text = |name: &str| {
            payload
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let iss = text("iss").ok_or_else(|| {
            OAuthError::IdTokenValidation("authorization response has no `iss`".to_string())
        })?;
        Ok(JarmResponse {
            iss,
            code: text("code"),
            state: text("state"),
            error: text("error"),
        })
    }
}
