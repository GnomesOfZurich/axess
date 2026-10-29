//! The result of a refresh-token response: the rotated tokens, and the claims
//! of its ID token (verified against a client whose verifier holds the
//! provider's current key set) when it carries one.

use super::OAuthProviderConfig;
use super::OidcClient;
use crate::oauth::extract_string_array;
use crate::oauth::types::*;
use crate::secret::ZeroizedString;

/// The check an ID token's `nonce` must pass on a refresh (OIDC Core 12.2):
/// absent is fine, present must equal the nonce of the original login. A
/// nonce with no original to compare it with is refused, since accepting it
/// would let any value through.
pub(super) fn refresh_nonce_check(
    token_nonce: Option<&openidconnect::Nonce>,
    original: Option<&str>,
) -> Result<(), String> {
    use subtle::ConstantTimeEq;
    match (token_nonce, original) {
        (None, _) => Ok(()),
        (Some(got), Some(want)) if bool::from(got.secret().as_bytes().ct_eq(want.as_bytes())) => {
            Ok(())
        }
        (Some(_), Some(_)) => Err("refresh ID token nonce does not match the original".to_string()),
        (Some(_), None) => Err(
            "refresh ID token carries a nonce and no original nonce was supplied to compare"
                .to_string(),
        ),
    }
}

impl OAuthProviderConfig {
    /// Turn a refresh response into a [`RefreshOutcome`]: verify the ID token
    /// when there is one, and take the rotated tokens either way.
    pub(super) async fn refresh_outcome(
        &self,
        token_response: &openidconnect::core::CoreTokenResponse,
        refresh_token: &str,
        original_nonce: Option<&str>,
    ) -> Result<RefreshOutcome, OAuthError> {
        use openidconnect::{OAuth2TokenResponse, TokenResponse};

        let id_token_claims = if token_response.id_token().is_some() {
            Some(
                self.with_fresh_keys(|client| {
                    self.claims_from_refresh_response(
                        client,
                        token_response,
                        refresh_token,
                        original_nonce,
                    )
                })
                .await?,
            )
        } else {
            // OIDC Core 12.2: the ID token of a refresh response is optional.
            // The exchange succeeded and the IdP may have rotated the token,
            // so the tokens are returned and nothing is claimed about the
            // subject.
            None
        };

        let access_token = ZeroizedString::new(
            OAuth2TokenResponse::access_token(token_response)
                .secret()
                .to_string(),
        );
        // A response without a refresh token leaves the one that was sent
        // valid (RFC 6749 §6).
        let new_refresh = ZeroizedString::new(
            OAuth2TokenResponse::refresh_token(token_response)
                .map(|t| t.secret().to_string())
                .unwrap_or_else(|| refresh_token.to_string()),
        );
        Ok(RefreshOutcome {
            id_token_claims,
            access_token,
            refresh_token: new_refresh,
            expires_in: OAuth2TokenResponse::expires_in(token_response).map(|d| d.as_secs()),
        })
    }

    /// Verify the ID token of a refresh response against `client`'s verifier
    /// and return the claims, with the rotated tokens.
    pub(super) fn claims_from_refresh_response(
        &self,
        client: &OidcClient,
        token_response: &openidconnect::core::CoreTokenResponse,
        refresh_token: &str,
        original_nonce: Option<&str>,
    ) -> Result<OAuthClaims, OAuthError> {
        use openidconnect::{OAuth2TokenResponse, TokenResponse};

        let id_token = token_response.id_token().ok_or_else(|| {
            OAuthError::IdTokenValidation("no ID token in refresh response".to_string())
        })?;

        let verifier = self.id_token_verifier(client);

        // Preserve raw JWT for RP-Initiated Logout.
        // See `extract_claims_from_response`; call IdToken's
        // `ToString` impl directly rather than the fragile
        // serde_json round-trip.
        let raw_id_token: Option<String> = Some(id_token.to_string());

        // OIDC Core 12.2: a nonce in a refresh ID token, if present, must
        // equal the original one. A missing nonce is accepted.
        let claims = id_token
            .claims(&verifier, |nonce: Option<&openidconnect::Nonce>| {
                refresh_nonce_check(nonce, original_nonce)
            })
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
            dpop_key: None,
        })
    }
}
