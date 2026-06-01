//! OAuthProviderConfig: production OIDC provider implementation.
//!
//! Split from the previous monolithic `provider/mod.rs` (1114 lines)
//! into orthogonal sub-files:
//!
//! - `discover`: async OIDC discovery constructor.
//! - `builder`: chainable `with_*` configuration setters.
//! - `jwks`: JWKS refresh with single-flight + min-interval coalescing.
//! - `provider_impl`: `impl OAuthProvider for OAuthProviderConfig`.
//!
//! Plus the existing siblings:
//!
//! - `device_flow`: RFC 8628 Device Authorization Grant.
//! - `fapi_flow`: FAPI 2.0 Baseline Profile (PAR + DPoP).
//! - `dpop_verify`: DPoP proof validation (`fapi` feature).
//!
//! `mod.rs` itself only carries the struct definition + the two
//! cross-cutting helpers (`make_client`, `extract_claims_from_response`)
//! that the trait impl and sibling submodules share.

mod builder;
mod device_flow;
mod discover;
#[cfg(feature = "fapi")]
pub mod dpop_verify;
mod fapi_flow;
mod jwks;
mod provider_impl;

use super::{extract_string_array, types::*};
use crate::oidc::JwksCache;
use openidconnect::{ClientId, ClientSecret, RedirectUrl, core::CoreProviderMetadata};
use std::sync::Arc;

/// Fully-configured OIDC client type returned by [`OAuthProviderConfig::make_client`].
///
/// The openidconnect 4.0 typestate system produces this unwieldy type.
/// Aliased here so it doesn't leak into method signatures across the codebase.
type OidcClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::core::CoreTokenResponse,
    openidconnect::core::CoreTokenIntrospectionResponse,
    openidconnect::core::CoreRevocableToken,
    openidconnect::core::CoreRevocationErrorResponse,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

// ── OAuthProviderConfig ──────────────────────────────────────────────────────

/// Configuration for an OAuth 2.0 / OIDC identity provider.
pub struct OAuthProviderConfig {
    /// Short identifier for this provider (e.g. `"google"`, `"github"`).
    pub name: Arc<str>,
    /// OIDC provider metadata (endpoints, keys).
    pub(crate) metadata: CoreProviderMetadata,
    /// OAuth client ID.
    pub(crate) client_id: ClientId,
    /// OAuth client secret.
    pub(crate) client_secret: Option<ClientSecret>,
    /// Redirect URL for the callback.
    pub(crate) redirect_url: RedirectUrl,
    /// HTTP client for token exchange (configured not to follow redirects).
    pub(crate) http_client: openidconnect::reqwest::Client,
    /// JWKS cache for back-channel logout signature verification.
    /// Refresh is single-flight + min-interval debounced (see
    /// [`crate::oidc::jwks_cache`]) so concurrent unknown-`kid` tokens
    /// collapse into one outbound HTTPS GET per provider on rotation.
    pub(crate) jwks_cache: JwksCache,
    /// Device authorization endpoint URL (RFC 8628), if configured.
    ///
    /// Not part of standard OIDC discovery; must be set via
    /// [`with_device_authorization_endpoint`](Self::with_device_authorization_endpoint).
    pub(crate) device_authorization_endpoint: Option<String>,
    /// OIDC RP-Initiated Logout endpoint, from discovery metadata.
    pub(crate) end_session_endpoint: Option<String>,
    /// OAuth 2.0 Token Revocation endpoint (RFC 7009), from discovery metadata.
    pub(crate) revocation_endpoint: Option<String>,
    /// Pushed Authorization Request endpoint (RFC 9126), from discovery metadata.
    pub(crate) par_endpoint: Option<String>,
    /// FAPI configuration: when set, enforces FAPI 2.0 Baseline Profile.
    pub(crate) fapi: Option<FapiConfig>,
    /// Source of wall-clock time for `exp`/`iat`/`nbf` checks. Defaults
    /// to [`SystemClock`](axess_clock::SystemClock); swap in a
    /// [`MockClock`](axess_clock::testing::MockClock) for DST.
    pub(crate) clock: Arc<dyn axess_clock::Clock>,
    /// Allowlist of `post_logout_redirect_uri` values accepted by
    /// [`build_end_session_url`](OAuthProvider::build_end_session_url). When non-empty, any redirect not in the
    /// list is dropped before being forwarded to the IdP, preventing
    /// open-redirect-style phishing via the logout flow. Empty by default
    /// (back-compat); operators should populate it for any production
    /// deployment that exposes a logout link with a `return_to` parameter.
    pub(crate) allowed_post_logout_redirect_uris: Vec<String>,
    /// Scopes to request. Default: `["openid", "email", "profile"]`.
    pub scopes: Vec<String>,
    /// How long the OAuth ceremony (redirect → callback) is valid.
    /// Default: 10 minutes. Set higher for IdPs with slow MFA prompts.
    pub ceremony_timeout: std::time::Duration,
}

impl OAuthProviderConfig {
    /// Construct a fully-configured OIDC client for a single operation.
    ///
    /// openidconnect 4.0 uses typestates that make the fully-configured client
    /// type unwieldy to store as a struct field. We construct it on-the-fly
    /// instead; this is cheap (no network calls, just copying Arc'd data).
    pub(crate) fn make_client(&self) -> OidcClient {
        openidconnect::core::CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_url.clone())
    }

    /// Extract [`OAuthClaims`] from an openidconnect token response.
    ///
    /// Visible to sibling `provider::` submodules (device_flow, fapi_flow) so
    /// they can reuse the ID-token validation logic without duplicating it.
    pub(super) fn extract_claims_from_response(
        &self,
        token_response: &openidconnect::core::CoreTokenResponse,
        nonce: &str,
    ) -> Result<OAuthClaims, OAuthError> {
        use openidconnect::{Nonce, OAuth2TokenResponse, TokenResponse};

        let id_token = token_response
            .id_token()
            .ok_or_else(|| OAuthError::IdTokenValidation("no ID token in response".to_string()))?;

        // Preserve the raw JWT for RP-Initiated Logout (id_token_hint).
        // openidconnect's `IdToken` implements `ToString`
        // explicitly to return the wire-form JWT; call it directly
        // instead of round-tripping through `serde_json::to_value`, which
        // only produces a string by accident of the serialize impl and
        // would silently break if the impl ever switches to a structured
        // representation. `ToString::to_string` is infallible.
        let raw_id_token: Option<String> = Some(id_token.to_string());

        let client = self.make_client();
        let id_token_verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&id_token_verifier, &Nonce::new(nonce.to_string()))
            .map_err(|e| OAuthError::IdTokenValidation(format!("{e}")))?;

        // at_hash / c_hash enforcement.
        //
        // OIDC Core §3.1.3.6 / §3.2.2.10 specifies `at_hash` (= leftmost
        // half of the hash of `access_token` under the ID-token signing
        // alg) when the IdP returns an access token alongside the ID
        // token. openidconnect 4.x does not enforce this by default;
        // the verifier short-circuits when no `access_token_hash` is set
        // on the verifier instance. Enforce it manually here when both
        // claims and the access token are present, so a tampered
        // access-token swap is detected even on IdPs that emit the hash.
        if let Some(claim_hash) = claims.access_token_hash() {
            use openidconnect::OAuth2TokenResponse;
            let access_token = OAuth2TokenResponse::access_token(token_response).secret();
            let alg = id_token
                .signing_alg()
                .map_err(|e| OAuthError::IdTokenValidation(format!("{e}")))?;
            let signing_key = id_token
                .signing_key(&id_token_verifier)
                .map_err(|e| OAuthError::IdTokenValidation(format!("signing key: {e}")))?;
            let expected = openidconnect::AccessTokenHash::from_token(
                &openidconnect::AccessToken::new(access_token.to_string()),
                alg,
                signing_key,
            )
            .map_err(|e| OAuthError::IdTokenValidation(format!("at_hash compute: {e}")))?;
            if expected.as_str() != claim_hash.as_str() {
                return Err(OAuthError::IdTokenValidation(
                    "at_hash claim does not match access_token; IdP-side tampering or \
                     wrong access token routed"
                        .to_string(),
                ));
            }
        }
        // c_hash is computed from the authorization code; we don't have
        // the original code at this point in the flow (it was consumed
        // by the token exchange), so c_hash enforcement would need to
        // happen earlier. Document the gap and leave c_hash for the
        // FAPI-mode verifier to be added once the upstream openidconnect
        // crate exposes it.

        // FAPI 2.0 §5.2.2; when FAPI is configured, enforce
        // strict ID-token lifetime AND require `nbf`. openidconnect's
        // default verifier honours `exp` (rejects expired tokens) but
        // does NOT cap `exp - iat` nor require `nbf`. The doc on
        // FapiConfig advertises both; the enforcement was missing.
        if let Some(fapi) = &self.fapi {
            let exp = claims.expiration();
            let iat = claims.issue_time();
            let lifetime = (exp - iat).num_seconds();
            if lifetime <= 0 || lifetime > fapi.max_id_token_lifetime_secs as i64 {
                return Err(OAuthError::IdTokenValidation(format!(
                    "ID token lifetime {lifetime}s exceeds FAPI cap of {}s (exp - iat)",
                    fapi.max_id_token_lifetime_secs
                )));
            }

            // Read nbf from the structural claims object; openidconnect
            // does not expose `nbf` on `IdTokenClaims` directly, so go
            // through the to_value round-trip.
            let claims_json = serde_json::to_value(claims)
                .map_err(|e| OAuthError::IdTokenValidation(format!("claims serialise: {e}")))?;
            let nbf = claims_json.get("nbf").and_then(|v| v.as_i64());
            match nbf {
                None => {
                    return Err(OAuthError::IdTokenValidation(
                        "FAPI requires `nbf` claim on ID token; missing".to_string(),
                    ));
                }
                Some(nbf_secs) => {
                    let now = self.clock.now();
                    let nbf_time =
                        chrono::DateTime::from_timestamp(nbf_secs, 0).ok_or_else(|| {
                            OAuthError::IdTokenValidation(
                                "FAPI `nbf` claim is not a valid Unix timestamp".to_string(),
                            )
                        })?;
                    // Allow up to 60s of clock skew on the not-before check.
                    if nbf_time > now + chrono::Duration::seconds(60) {
                        return Err(OAuthError::IdTokenValidation(format!(
                            "FAPI `nbf` claim is in the future ({nbf_time}); rejecting",
                        )));
                    }
                }
            }
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

        // Wrap bearer-class tokens in ZeroizedString so the
        // plaintext is wiped from heap on drop.
        use crate::secret::ZeroizedString;
        let access_token = Some(ZeroizedString::new(
            OAuth2TokenResponse::access_token(token_response)
                .secret()
                .to_string(),
        ));
        let refresh_token = OAuth2TokenResponse::refresh_token(token_response)
            .map(|t| ZeroizedString::new(t.secret().to_string()));

        Ok(OAuthClaims {
            provider: self.name.clone(),
            subject,
            email,
            email_verified,
            name,
            groups,
            roles,
            access_token,
            refresh_token,
            oidc_sid,
            id_token_hint: raw_id_token.map(ZeroizedString::new),
            additional_claims,
        })
    }
}
