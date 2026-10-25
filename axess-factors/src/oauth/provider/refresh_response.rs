//! The claims of a refresh-token response: its ID token verified against a
//! client whose verifier holds the provider's current key set.

use super::OAuthProviderConfig;
use super::OidcClient;
use crate::oauth::extract_string_array;
use crate::oauth::types::*;

impl OAuthProviderConfig {
    /// Verify the ID token of a refresh response against `client`'s verifier
    /// and return the claims, with the rotated tokens.
    pub(super) fn claims_from_refresh_response(
        &self,
        client: &OidcClient,
        token_response: &openidconnect::core::CoreTokenResponse,
        refresh_token: &str,
    ) -> Result<OAuthClaims, OAuthError> {
        // Refresh token responses may include a new ID token. If they do,
        // we validate it (but without nonce verification since the refresh
        // flow has no nonce). If no ID token is returned, the refresh only
        // renewed the access token; we cannot extract OIDC claims.
        use openidconnect::{OAuth2TokenResponse, TokenResponse};

        let id_token = token_response.id_token().ok_or_else(|| {
            OAuthError::IdTokenValidation(
                "no ID token in refresh response; IdP may not return ID tokens on refresh"
                    .to_string(),
            )
        })?;

        let verifier = client.id_token_verifier().set_time_fn(self.time_fn());

        // Preserve raw JWT for RP-Initiated Logout.
        // See `extract_claims_from_response`; call IdToken's
        // `ToString` impl directly rather than the fragile
        // serde_json round-trip.
        let raw_id_token: Option<String> = Some(id_token.to_string());

        // Skip nonce verification for refresh: the nonce was validated
        // during the original login. Refresh responses typically don't
        // include a nonce, or include the same one from the original flow.
        // Passing a closure that accepts any nonce (or none) satisfies the
        // NonceVerifier trait.
        let claims = id_token
            .claims(&verifier, |_: Option<&openidconnect::Nonce>| Ok(()))
            .map_err(super::fresh_keys::claims_error)?;

        // Re-bind `iss` to the originally-configured issuer.
        // openidconnect's verifier validates `iss` against the metadata
        // it was constructed with, but in a MITM scenario where the
        // attacker can sit between us and the token endpoint AND can
        // also offer a JWKS-trusted key signing a different `iss`, the
        // refresh response could quietly switch issuers. Compare the
        // claim against the metadata-resolved issuer we cached at
        // discovery time.
        let configured_iss = self.metadata.issuer().as_str();
        let claim_iss = claims.issuer().as_str();
        if claim_iss != configured_iss {
            return Err(OAuthError::IdTokenValidation(format!(
                "refresh-response iss `{claim_iss}` does not match \
                 configured provider issuer `{configured_iss}`"
            )));
        }

        let subject = claims.subject().to_string();
        let email = claims.email().map(|e| e.as_str().to_string());
        let email_verified = claims.email_verified();
        let name = {
            let localized = claims.name();
            localized
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_string())
        };

        let additional_claims =
            serde_json::to_value(claims).unwrap_or(serde_json::Value::Object(Default::default()));

        let groups = extract_string_array(&additional_claims, "groups");
        let roles = extract_string_array(&additional_claims, "roles");
        let oidc_sid = additional_claims
            .get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Zeroize bearer-class tokens.
        use crate::secret::ZeroizedString;
        let new_access_token = Some(ZeroizedString::new(
            OAuth2TokenResponse::access_token(token_response)
                .secret()
                .to_string(),
        ));
        let new_refresh_token = OAuth2TokenResponse::refresh_token(token_response)
            .map(|t| ZeroizedString::new(t.secret().to_string()));

        Ok(OAuthClaims {
            provider: self.name.clone(),
            subject,
            email,
            email_verified,
            name,
            groups,
            roles,
            access_token: new_access_token,
            refresh_token: new_refresh_token
                .or_else(|| Some(ZeroizedString::new(refresh_token.to_string()))),
            oidc_sid,
            id_token_hint: raw_id_token.map(ZeroizedString::new),
            additional_claims,
        })
    }
}
