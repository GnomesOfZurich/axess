//! OAuthProviderConfig: production OIDC provider implementation.
//!
//! This file carries the struct, the openidconnect client it builds per
//! operation (`make_client`) and the ID-token claim extraction the trait
//! impl and the grant submodules share. The rest is split by concern:
//!
//! - `discover`: async OIDC discovery, which returns the builder.
//! - `builder`: [`OAuthProviderBuilder`], its `with_*` settings and the
//!   one `build` that checks them together.
//! - `fapi_profile`: the FAPI 2.0 profile's checks, the mTLS client and
//!   aliases, the ID-token verifier and the JARM response.
//! - `provider_impl`: `impl OAuthProvider for OAuthProviderConfig`.
//! - `sender_constrained`: the token requests and the userinfo call, with a
//!   DPoP proof and the one nonce retry.
//! - `client_auth`: the client secret or `private_key_jwt` assertion on a
//!   request.
//! - `issuer_jwt`: the logout and JARM tokens the issuer signs.
//! - `jwks`, `fresh_keys`: the refreshable key set.
//! - `device_flow`: RFC 8628 Device Authorization Grant.
//! - `dpop`: DPoP proofs (RFC 9449) and the discovery advertisement.
//! - `fapi_flow`: Pushed Authorization Requests (RFC 9126).
//! - `dpop_verify`: DPoP proof validation for a resource server.

mod builder;
pub use builder::OAuthProviderBuilder;
mod ceremony;
mod client_auth;
mod device_flow;
mod discover;
mod dpop;
pub mod dpop_verify;
mod endpoint;
mod fapi_flow;
mod fapi_profile;
mod fresh_keys;
mod issuer_jwt;
mod jwks;
mod provider_impl;
mod refresh_response;
mod sender_constrained;

use super::{extract_string_array, types::*};
use crate::oidc::JwksCache;
use axess_clock::{SignedDuration, Timestamp};
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
    /// OAuth client secret. `None` when the client authenticates by
    /// [`client_assertion`](Self::client_assertion) or by certificate, and
    /// always under the FAPI profile.
    pub(crate) client_secret: Option<ClientSecret>,
    /// `private_key_jwt` signer, set by
    /// [`with_private_key_jwt`](OAuthProviderBuilder::with_private_key_jwt).
    /// While it is set no request carries a client secret.
    pub(crate) client_assertion: Option<crate::client_assertion::ClientAssertionSigner>,
    /// Entropy for the `jti` of client assertions. Defaults to
    /// [`SystemRng`](axess_rng::SystemRng); see
    /// [`with_rng`](OAuthProviderBuilder::with_rng).
    pub(crate) rng: Arc<dyn axess_rng::SecureRng>,
    /// Redirect URL for the callback.
    pub(crate) redirect_url: RedirectUrl,
    /// HTTP client for token exchange, built by [`egress`](Self::egress):
    /// it follows no redirect and, under a screened policy, connects to no
    /// reserved address and follows no proxy from the environment.
    pub(crate) http_client: openidconnect::reqwest::Client,
    /// The egress policy discovery ran under. Every client the provider
    /// builds later (the mTLS client of the FAPI profile) is built by it,
    /// and every URL that reaches the provider after discovery (the
    /// `mtls_endpoint_aliases`) is checked against it.
    pub(crate) egress: crate::egress::EgressPolicy,
    /// JWKS cache for back-channel logout signature verification.
    /// Refresh is single-flight + min-interval debounced (see
    /// [`crate::oidc::jwks_cache`]) so concurrent unknown-`kid` tokens
    /// collapse into one outbound HTTPS GET per provider on rotation.
    pub(crate) jwks_cache: JwksCache,
    /// Device authorization endpoint URL (RFC 8628), if configured.
    ///
    /// Not part of standard OIDC discovery; must be set via
    /// [`with_device_authorization_endpoint`](OAuthProviderBuilder::with_device_authorization_endpoint).
    pub(crate) device_authorization_endpoint: Option<String>,
    /// OIDC RP-Initiated Logout endpoint, from discovery metadata.
    pub(crate) end_session_endpoint: Option<String>,
    /// OAuth 2.0 Token Revocation endpoint (RFC 7009), from discovery metadata.
    pub(crate) revocation_endpoint: Option<String>,
    /// Pushed Authorization Request endpoint (RFC 9126), from discovery metadata.
    pub(crate) par_endpoint: Option<String>,
    /// Whether the IdP advertises `authorization_response_iss_parameter_supported`
    /// (RFC 9207): its authorization responses carry an `iss` parameter that
    /// the callback must compare with the issuer.
    pub(crate) iss_parameter_supported: bool,
    /// The `mtls_endpoint_aliases` of the discovery document, used when
    /// the FAPI profile selects mTLS.
    pub(crate) mtls_aliases: fapi_profile::MtlsAliases,
    /// FAPI configuration, set by
    /// [`OAuthProviderBuilder::with_fapi`]: the sender constraint on the
    /// token requests and the ID-token limits.
    pub(crate) fapi: Option<FapiConfig>,
    /// Whether tokens are bound to a DPoP key (RFC 9449): every token
    /// request and userinfo call carries a proof, and a call without the key
    /// is refused. Resolved by [`OAuthProviderBuilder::build`] from
    /// [`dpop_advertised`](Self::dpop_advertised),
    /// [`with_dpop`](OAuthProviderBuilder::with_dpop),
    /// [`without_dpop`](OAuthProviderBuilder::without_dpop) and the FAPI
    /// profile.
    pub(crate) dpop: bool,
    /// Whether the discovery document advertises DPoP with the algorithm
    /// the proofs are signed with (`ES256` in
    /// `dpop_signing_alg_values_supported`).
    pub(crate) dpop_advertised: bool,
    /// The ID-token signature algorithms the provider accepts: the pin of
    /// [`with_id_token_signing_algs`](OAuthProviderBuilder::with_id_token_signing_algs),
    /// the FAPI profile's list, or the algorithms both name. `None` leaves
    /// the IdP's advertised list in force.
    pub(crate) id_token_algs: Option<fapi_profile::IdTokenAlgs>,
    /// Source of wall-clock time for `exp`/`iat`/`nbf` checks. Defaults
    /// to [`SystemClock`](axess_clock::SystemClock); swap in a
    /// `MockClock` for DST.
    pub(crate) clock: Arc<dyn axess_clock::Clock>,
    /// Allowlist of `post_logout_redirect_uri` values accepted by
    /// [`build_end_session_url`](OAuthProvider::build_end_session_url). When non-empty, any redirect not in the
    /// list is dropped before being forwarded to the IdP, preventing
    /// open-redirect-style phishing via the logout flow. Empty by default
    /// (back-compat); operators should populate it for any production
    /// deployment that exposes a logout link with a `return_to` parameter.
    pub(crate) allowed_post_logout_redirect_uris: Vec<String>,
    /// Whether a back-channel logout token must carry the `typ` header
    /// `logout+jwt`. Off by default, where a token with no `typ` and the
    /// plain `JWT` and `Logout` spellings IdPs send are taken too; see
    /// [`with_required_logout_typ`](OAuthProviderBuilder::with_required_logout_typ).
    pub(crate) require_logout_typ: bool,
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

    /// The provider's clock as the closure openidconnect's ID-token
    /// verifier reads, so `exp` and `iat` checks follow the injected
    /// clock instead of the wall clock. The verifier takes the time as a
    /// chrono value, so the reading is converted here.
    pub(crate) fn time_fn(
        &self,
    ) -> impl Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync + 'static {
        let clock = self.clock.clone();
        move || chrono_time(clock.now())
    }

    /// Extract [`OAuthClaims`] from an openidconnect token response.
    ///
    /// Visible to sibling `provider::` submodules (device_flow, fapi_flow) so
    /// they can reuse the ID-token validation logic without duplicating it.
    pub(super) async fn extract_claims_from_response(
        &self,
        token_response: &openidconnect::core::CoreTokenResponse,
        nonce: &str,
    ) -> Result<OAuthClaims, OAuthError> {
        self.with_fresh_keys(|client| self.claims_from_response_with(client, token_response, nonce))
            .await
    }

    /// FAPI 2.0 §5.2.2 limits on a verified ID token; see
    /// [`fapi_id_token_violation`]. Does nothing when FAPI is not configured.
    fn enforce_fapi_id_token(
        &self,
        lifetime: i64,
        verified_payload: &serde_json::Value,
    ) -> Result<(), OAuthError> {
        match &self.fapi {
            Some(fapi) => {
                fapi_id_token_violation(fapi, self.clock.now(), lifetime, verified_payload)
            }
            None => Ok(()),
        }
    }

    /// [`extract_claims_from_response`](Self::extract_claims_from_response)
    /// against the verifier of `client`.
    fn claims_from_response_with(
        &self,
        client: &OidcClient,
        token_response: &openidconnect::core::CoreTokenResponse,
        nonce: &str,
    ) -> Result<OAuthClaims, OAuthError> {
        use openidconnect::{Nonce, TokenResponse};

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

        let id_token_verifier = self.id_token_verifier(client);
        let claims = id_token
            .claims(&id_token_verifier, &Nonce::new(nonce.to_string()))
            .map_err(fresh_keys::claims_error)?;

        // The signature, `iss`, `aud`, `exp` and nonce checks above have run
        // over exactly these bytes. `IdTokenClaims<EmptyAdditionalClaims>`
        // discards every claim outside the standard set (`nbf`, `groups`,
        // `roles`, `sid`, ...), so read those from the verified payload.
        let verified_payload = raw_id_token
            .as_deref()
            .and_then(|jwt| crate::oidc::logout_token::decode_id_token_payload(jwt).ok())
            .ok_or_else(|| {
                OAuthError::IdTokenValidation("ID token payload is not readable".to_string())
            })?;

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
            enforce_at_hash(id_token, &id_token_verifier, claim_hash, token_response)?;
        }
        // `c_hash` is not checked here. It binds an ID token that arrives
        // beside an authorization code (the hybrid flow, OIDC Core
        // §3.3.2.11) to that code. Every login here asks for
        // `response_type=code`, so the ID token comes only from the token
        // endpoint, in the answer to the request that spent the code.

        // When FAPI is configured, cap the ID-token lifetime and refuse an
        // `nbf` in the future. openidconnect's default verifier honours
        // `exp` (rejects expired tokens) but neither caps `exp - iat` nor
        // reads `nbf`.
        self.enforce_fapi_id_token(
            (claims.expiration() - claims.issue_time()).num_seconds(),
            &verified_payload,
        )?;

        Ok(self.oauth_claims(claims, verified_payload, token_response, raw_id_token))
    }

    /// The [`OAuthClaims`] of a verified ID token: the standard claims, the
    /// claims the typed view drops (read from the verified payload) and the
    /// tokens of the response.
    fn oauth_claims(
        &self,
        claims: &openidconnect::core::CoreIdTokenClaims,
        verified_payload: serde_json::Value,
        token_response: &openidconnect::core::CoreTokenResponse,
        raw_id_token: Option<String>,
    ) -> OAuthClaims {
        use openidconnect::OAuth2TokenResponse;

        let subject = claims.subject().to_string();
        let email = claims.email().map(|e| e.as_str().to_string());
        let email_verified = claims.email_verified();
        let name = {
            let localized = claims.name();
            localized
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_string())
        };

        let mut additional_claims =
            serde_json::to_value(claims).unwrap_or(serde_json::Value::Object(Default::default()));
        // Overlay the claims the typed view drops, keeping the typed
        // values wherever both carry a key.
        if let (Some(target), Some(extra)) = (
            additional_claims.as_object_mut(),
            verified_payload.as_object(),
        ) {
            for (k, v) in extra {
                target.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }

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
        let nonce = additional_claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        OAuthClaims {
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
            nonce,
            id_token_hint: raw_id_token.map(ZeroizedString::new),
            additional_claims,
            dpop_key: None,
        }
    }
}

/// OIDC Core `at_hash`: `claim_hash` must be the hash of the response's
/// access token under the ID token's signing algorithm.
fn enforce_at_hash(
    id_token: &openidconnect::core::CoreIdToken,
    id_token_verifier: &openidconnect::core::CoreIdTokenVerifier<'_>,
    claim_hash: &openidconnect::AccessTokenHash,
    token_response: &openidconnect::core::CoreTokenResponse,
) -> Result<(), OAuthError> {
    use openidconnect::OAuth2TokenResponse;
    let access_token = OAuth2TokenResponse::access_token(token_response).secret();
    let alg = id_token
        .signing_alg()
        .map_err(|e| OAuthError::IdTokenValidation(crate::remote_text::error_text(&e)))?;
    let signing_key = id_token
        .signing_key(id_token_verifier)
        .map_err(|e| OAuthError::IdTokenValidation(format!("signing key: {e}")))?;
    let expected = openidconnect::AccessTokenHash::from_token(
        &openidconnect::AccessToken::new(access_token.to_string()),
        alg,
        signing_key,
    )
    .map_err(|e| OAuthError::IdTokenValidation(format!("at_hash compute: {e}")))?;
    use subtle::ConstantTimeEq as _;
    if !bool::from(
        expected
            .as_str()
            .as_bytes()
            .ct_eq(claim_hash.as_str().as_bytes()),
    ) {
        return Err(OAuthError::IdTokenValidation(
            "at_hash claim does not match access_token; IdP-side tampering or \
             wrong access token routed"
                .to_string(),
        ));
    }
    Ok(())
}

/// A reading as the chrono value openidconnect takes. A `Timestamp` and a
/// chrono `DateTime<Utc>` have the same range, so every reading converts.
/// Were one not to, chrono's latest value stands in, at which every token
/// has expired.
fn chrono_time(at: Timestamp) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(at.unix_seconds(), at.subsec_nanos())
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC)
}

/// The FAPI limits on a verified ID token: its lifetime (`exp - iat`, in
/// seconds) is within `fapi`'s cap, and its `nbf`, read from the verified
/// payload, is not more than 60 seconds in the future (FAPI 2.0 section
/// 5.3.2.1, the rule for any JWT). `nbf` is optional: neither OpenID Connect
/// nor FAPI 2.0 requires it in an ID token, and Keycloak issues none.
pub(crate) fn fapi_id_token_violation(
    fapi: &FapiConfig,
    now: Timestamp,
    lifetime: i64,
    verified_payload: &serde_json::Value,
) -> Result<(), OAuthError> {
    let cap = i64::try_from(fapi.max_id_token_lifetime.as_secs()).unwrap_or(i64::MAX);
    if lifetime <= 0 || lifetime > cap {
        return Err(OAuthError::IdTokenValidation(format!(
            "ID token lifetime {lifetime}s exceeds FAPI cap of {cap}s (exp - iat)"
        )));
    }

    // `IdTokenClaims` is built with `EmptyAdditionalClaims`, which drops
    // `nbf`; read it from the verified payload instead.
    let Some(nbf) = verified_payload.get("nbf") else {
        return Ok(());
    };
    let nbf_secs = nbf.as_i64().ok_or_else(|| {
        OAuthError::IdTokenValidation("ID token `nbf` claim is not an integer".to_string())
    })?;
    let nbf_time = Timestamp::from_unix_seconds(nbf_secs).ok_or_else(|| {
        OAuthError::IdTokenValidation("FAPI `nbf` claim is not a valid Unix timestamp".to_string())
    })?;
    // `nbf > now + 60 s`, as the span between the two readings, which is
    // defined for every pair of them.
    if nbf_time.since(now) > SignedDuration::seconds(60) {
        return Err(OAuthError::IdTokenValidation(format!(
            "FAPI `nbf` claim is in the future ({nbf_time}); rejecting",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod fapi_id_token_tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_unix_seconds(1_700_000_000).unwrap()
    }

    #[test]
    fn nbf_is_optional_and_must_not_be_in_the_future() {
        let fapi = FapiConfig::default();
        let t = now().unix_seconds();
        let check = |payload| fapi_id_token_violation(&fapi, now(), 120, &payload);
        assert!(check(serde_json::json!({ "nbf": t - 5 })).is_ok());
        assert!(check(serde_json::json!({})).is_ok());
        assert!(check(serde_json::json!({ "nbf": t + 60 })).is_ok());
        assert!(check(serde_json::json!({ "nbf": t + 61 })).is_err());
        assert!(check(serde_json::json!({ "nbf": t + 600 })).is_err());
        assert!(check(serde_json::json!({ "nbf": "soon" })).is_err());
    }

    #[test]
    fn nbf_is_judged_at_either_end_of_the_range_without_an_overflow() {
        let fapi = FapiConfig::default();
        let nbf = serde_json::json!({ "nbf": now().unix_seconds() });
        // At the last reading no `nbf` is in the future, and at the first
        // every one is.
        assert!(fapi_id_token_violation(&fapi, Timestamp::MAX, 120, &nbf).is_ok());
        assert!(fapi_id_token_violation(&fapi, Timestamp::MIN, 120, &nbf).is_err());
        // A second count no reading holds is refused, not clamped.
        let beyond = serde_json::json!({ "nbf": i64::MAX });
        assert!(fapi_id_token_violation(&fapi, now(), 120, &beyond).is_err());
    }

    #[test]
    fn a_reading_is_the_same_instant_as_the_chrono_value_the_verifier_takes() {
        let at = Timestamp::new(1_700_000_000, 250_000_000).unwrap();
        let converted = chrono_time(at);
        assert_eq!(converted.timestamp(), 1_700_000_000);
        assert_eq!(converted.timestamp_subsec_nanos(), 250_000_000);
        // The two ranges have the same ends, so the fallback is never taken.
        assert_eq!(
            chrono_time(Timestamp::MAX),
            chrono::DateTime::<chrono::Utc>::MAX_UTC
        );
        assert_eq!(
            chrono_time(Timestamp::MIN),
            chrono::DateTime::<chrono::Utc>::MIN_UTC
        );
        assert_eq!(
            chrono_time(Timestamp::UNIX_EPOCH),
            chrono::DateTime::<chrono::Utc>::UNIX_EPOCH
        );
    }

    #[test]
    fn lifetime_is_capped() {
        let fapi = FapiConfig::default();
        let payload = serde_json::json!({ "nbf": now().unix_seconds() });
        assert!(fapi_id_token_violation(&fapi, now(), 300, &payload).is_ok());
        assert!(fapi_id_token_violation(&fapi, now(), 301, &payload).is_err());
        assert!(fapi_id_token_violation(&fapi, now(), 0, &payload).is_err());
    }

    /// The lifetime is whole seconds, so a cap with a fraction admits the
    /// whole seconds it holds and no more.
    #[test]
    fn a_cap_with_a_fraction_counts_its_whole_seconds() {
        let fapi = FapiConfig {
            max_id_token_lifetime: std::time::Duration::from_millis(300_999),
            ..FapiConfig::default()
        };
        let payload = serde_json::json!({});
        assert!(fapi_id_token_violation(&fapi, now(), 300, &payload).is_ok());
        let refused = fapi_id_token_violation(&fapi, now(), 301, &payload).unwrap_err();
        assert!(
            refused.to_string().contains("FAPI cap of 300s"),
            "{refused}"
        );
    }
}
