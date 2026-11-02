//! [`OAuthProviderBuilder`]: the settings of a discovered provider, checked
//! together by [`build`](OAuthProviderBuilder::build).
//!
//! Every `with_*` method records what was asked for and returns the builder;
//! none of them looks at another. [`build`](OAuthProviderBuilder::build) is
//! the one place the settings meet: it checks the FAPI profile's demands,
//! resolves DPoP, narrows the ID-token algorithm list, checks the transport
//! of every endpoint a setter named, and puts the mTLS endpoint aliases in
//! place last. The same calls in any order therefore give the same provider,
//! or the same refusal, and nothing reaches a request before the check:
//!
//! ```text
//! let provider = OAuthProviderConfig::discover(...).await?
//!     .with_scopes(vec!["openid".into(), "email".into()])
//!     .with_ceremony_timeout(Duration::from_secs(900))
//!     .with_par_endpoint("https://idp.example/par")
//!     .with_allowed_post_logout_redirect_uris(["https://app.example/logout"])
//!     .build()?;
//! ```

use super::OAuthProviderConfig;
use super::fapi_profile::{self, IdTokenAlgs};
use crate::client_assertion::ClientAssertionSigner;
use crate::oauth::types::{FapiConfig, OAuthError, SenderConstraint};

/// What the caller asked for about DPoP. Resolved against the IdP's
/// advertisement and the FAPI profile by [`resolve_dpop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DpopPolicy {
    /// On when the IdP advertises DPoP, off when it does not.
    Advertised,
    /// Off: [`OAuthProviderBuilder::without_dpop`].
    Off,
    /// On, and refused when nothing provides it:
    /// [`OAuthProviderBuilder::with_dpop`].
    Required,
}

/// A discovered provider and the settings asked of it, not yet checked
/// against each other.
///
/// Returned by [`OAuthProviderConfig::discover`] and
/// [`OAuthProviderConfig::discover_with_private_key_jwt`]. Every `with_*`
/// method returns the builder, whatever it sets; [`build`](Self::build)
/// checks the settings together and returns the provider. The order of the
/// calls never matters.
pub struct OAuthProviderBuilder {
    /// The provider as discovery found it, carrying the settings no rule
    /// constrains (scopes, timeouts, the clock, the RNG, the logout
    /// settings). The fields the rules below decide are written by
    /// [`build`](Self::build) only.
    base: OAuthProviderConfig,
    signer: Option<ClientAssertionSigner>,
    dpop: DpopPolicy,
    id_token_algs: Option<Vec<String>>,
    fapi: Option<FapiConfig>,
    par_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
}

impl std::fmt::Debug for OAuthProviderBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderBuilder")
            .field("name", &self.base.name)
            .field("dpop", &self.dpop)
            .field("fapi", &self.fapi)
            .field("id_token_algs", &self.id_token_algs)
            .field("private_key_jwt", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

impl OAuthProviderBuilder {
    /// The builder over what discovery found.
    pub(super) fn discovered(base: OAuthProviderConfig) -> Self {
        Self {
            base,
            signer: None,
            dpop: DpopPolicy::Advertised,
            id_token_algs: None,
            fapi: None,
            par_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            device_authorization_endpoint: None,
        }
    }

    /// Override the default scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.base.scopes = scopes;
        self
    }

    /// Require every back-channel logout token to carry the `typ` header
    /// `logout+jwt` (OpenID Connect Back-Channel Logout 1.0, section 2.4).
    ///
    /// By default a token is taken when its `typ` is `logout+jwt`, `JWT` or
    /// `Logout` (any case, with or without `application/`), or when it has
    /// none, because IdPs in the field send all of those. Only the types of
    /// other tokens signed by the same key (`dpop+jwt`, `at+jwt`) are
    /// refused. Turn this on for an IdP known to send the explicit type, and
    /// a token with another `typ` or none is refused too.
    #[must_use]
    pub fn with_required_logout_typ(mut self) -> Self {
        self.base.require_logout_typ = true;
        self
    }

    /// Accept ID tokens and logout tokens signed with these algorithms only,
    /// whatever the IdP advertises: the `id_token_signed_response_alg` of the
    /// client registration (OIDC Core 3.1.3.7 step 7 asks for the default,
    /// `RS256`, or the algorithm the client registered). Without it a token
    /// is accepted when it verifies under a key the IdP published and its
    /// algorithm is one of the asymmetric defaults (`RS256`, `RS384`,
    /// `RS512`, `ES256`, `ES384`) for a logout token, or one the IdP
    /// advertised for an ID token.
    ///
    /// Names are JOSE names: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`,
    /// `PS512`, `ES256`, `ES384`, `EdDSA`. Under the FAPI profile
    /// ([`with_fapi`](Self::with_fapi)) the provider accepts the algorithms
    /// both lists name: a pin narrows the profile and never widens it, and
    /// [`build`](Self::build) refuses a pin the profile shares nothing with.
    /// A second call replaces the first.
    ///
    /// [`build`](Self::build) refuses an empty list and a name that is
    /// symmetric, `none` or unknown.
    #[must_use]
    pub fn with_id_token_signing_algs<I, S>(mut self, algs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.id_token_algs = Some(algs.into_iter().map(|a| a.as_ref().to_owned()).collect());
        self
    }

    /// Override the ceremony timeout (default: 10 minutes).
    #[must_use]
    pub fn with_ceremony_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.base.ceremony_timeout = timeout;
        self
    }

    /// Bind this provider's tokens to a DPoP key (RFC 9449), and refuse to
    /// build a provider that would not.
    ///
    /// [`discover`](OAuthProviderConfig::discover) already turns DPoP on
    /// when the discovery document lists `ES256` (the algorithm axess signs
    /// proofs with) in `dpop_signing_alg_values_supported`, and leaves it off
    /// otherwise. This method makes it a requirement: [`build`](Self::build)
    /// refuses an IdP that does not advertise DPoP, at startup, instead of
    /// issuing Bearer tokens, unless the FAPI profile with
    /// [`SenderConstraint::DPoP`] binds the tokens anyway. It replaces an
    /// earlier [`without_dpop`](Self::without_dpop). Any client
    /// authentication works with it, a client secret included; the FAPI
    /// profile is not needed.
    ///
    /// What a bound provider does:
    ///
    /// * **Login.** `begin_oauth_login` makes a key for the login and keeps
    ///   it with the ceremony; the code exchange carries a proof signed by
    ///   it, the response must say `token_type` `DPoP`, and an access token
    ///   that is a JWT must name the key in `cnf.jkt`. The key comes back in
    ///   `OAuthClaims::dpop_key`.
    /// * **Every later call** with the tokens (refresh, userinfo, the
    ///   client credentials and device grants) takes the key in its `dpop`
    ///   argument (`dpop_key` on the service: `refresh_oauth_token`,
    ///   `fetch_userinfo`). A call given `None` is refused with
    ///   [`OAuthError::DpopKeyRequired`] before anything is sent, since a
    ///   bound token sent as Bearer is refused by a resource server that
    ///   checks the binding and taken by one that does not. Revocation is
    ///   sent either way, with a proof when given the key.
    /// * **Nonces.** A `use_dpop_nonce` refusal (RFC 9449 sections 8 and 9)
    ///   is answered once with a proof that echoes the server's nonce; no
    ///   other refusal is retried.
    ///
    /// **Keep the key for the tokens' life.** axess does not store it. Save
    /// `DpopKey::to_seed_bytes` beside the refresh token, as secret as the
    /// token itself, and restore it with `DpopKey::from_seed` in whichever
    /// process refreshes: a key made afresh does not match the access tokens
    /// already issued.
    #[must_use]
    pub fn with_dpop(mut self) -> Self {
        self.dpop = DpopPolicy::Required;
        self
    }

    /// Send Bearer requests to an IdP that advertises DPoP: no request
    /// carries a proof and the tokens come back unbound.
    ///
    /// The setting for deployments whose resource servers accept only
    /// Bearer tokens. A DPoP-bound access token travels with the `DPoP`
    /// authorization scheme and a proof, which such a server refuses. It
    /// gives up what DPoP buys: a bearer token that leaks is usable by
    /// whoever holds it, where a bound one is useless without the key.
    /// Leave DPoP on wherever the resource servers take it.
    ///
    /// An IdP that does not advertise DPoP needs nothing: the provider is
    /// already unbound. [`build`](Self::build) refuses it under the FAPI
    /// profile with [`SenderConstraint::DPoP`], which requires DPoP. It
    /// replaces an earlier [`with_dpop`](Self::with_dpop).
    #[must_use]
    pub fn without_dpop(mut self) -> Self {
        self.dpop = DpopPolicy::Off;
        self
    }

    /// Enable the FAPI 2.0 profile for this provider. A second call
    /// replaces the first.
    ///
    /// What [`build`](Self::build) then demands and does:
    ///
    /// * **No client secret.** FAPI 2.0 (Security Profile section 5.3.1.1)
    ///   lets the client authenticate by `private_key_jwt` or mTLS only. The
    ///   provider must hold a `private_key_jwt` signer
    ///   ([`with_private_key_jwt`](Self::with_private_key_jwt) or
    ///   [`discover_with_private_key_jwt`](OAuthProviderConfig::discover_with_private_key_jwt)),
    ///   or `sender_constraint` must be [`SenderConstraint::Mtls`], whose
    ///   certificate authenticates the client (`tls_client_auth`). Any secret
    ///   the provider was discovered with is dropped, so no request it makes
    ///   (PAR, the code exchange, the refresh, revocation,
    ///   `client_credentials`, the device grant) carries one, in the form or
    ///   in a Basic header.
    /// * **Sender-constrained tokens.** With [`SenderConstraint::DPoP`]
    ///   the provider binds its tokens to a DPoP key exactly as
    ///   [`with_dpop`](Self::with_dpop) describes, whether or not the IdP
    ///   advertises DPoP, and [`without_dpop`](Self::without_dpop) is
    ///   refused; the pushed authorization request names the key too
    ///   (`dpop_jkt`). With [`SenderConstraint::Mtls`] DPoP is off and
    ///   [`with_dpop`](Self::with_dpop) is refused; the certificate and key
    ///   are loaded into the HTTP client, and the server's
    ///   `mtls_endpoint_aliases` replace the token, userinfo, revocation and
    ///   PAR endpoints it lists, including one a setter named.
    /// * **PAR** is required: the provider must have a PAR endpoint, from
    ///   discovery or [`with_par_endpoint`](Self::with_par_endpoint).
    /// * **ID tokens** must live no longer than
    ///   `max_id_token_lifetime_secs`, carry no `nbf` more than 60 seconds
    ///   in the future, and be signed with one of
    ///   `allowed_id_token_algs` (`PS256`, `ES256`, `EdDSA` by default),
    ///   whatever the IdP advertises, narrowed by
    ///   [`with_id_token_signing_algs`](Self::with_id_token_signing_algs).
    /// * **JARM** when `require_jarm` is set: authorization requests ask for
    ///   `response_mode=jwt` and the callback is finished with the response
    ///   JWT; a plain callback is refused.
    #[must_use]
    pub fn with_fapi(mut self, config: FapiConfig) -> Self {
        self.fapi = Some(config);
        self
    }

    /// Set the PAR endpoint (RFC 9126), in place of the one discovery found.
    ///
    /// Only needed if the IdP doesn't advertise it in OIDC discovery metadata.
    /// [`build`](Self::build) refuses a URL that is not HTTPS (plain HTTP to
    /// a loopback host aside).
    #[must_use]
    pub fn with_par_endpoint(mut self, url: impl Into<String>) -> Self {
        self.par_endpoint = Some(url.into());
        self
    }

    /// Set the OAuth 2.0 token revocation endpoint (RFC 7009), in place of
    /// the one discovery found.
    ///
    /// Only needed when the IdP exposes a revocation endpoint but does
    /// not advertise it in the standard OIDC discovery metadata under
    /// the `revocation_endpoint` field; `revoke_token` otherwise answers
    /// `Config("...does not include a revocation_endpoint")`.
    /// [`build`](Self::build) refuses a URL that is not HTTPS.
    #[must_use]
    pub fn with_revocation_endpoint(mut self, url: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(url.into());
        self
    }

    /// Set the OIDC RP-Initiated Logout endpoint (`end_session_endpoint`),
    /// in place of the one discovery found.
    ///
    /// Same rationale as [`with_revocation_endpoint`](Self::with_revocation_endpoint):
    /// many IdPs expose the endpoint without advertising it in
    /// discovery, so [`build_end_session_url`](crate::oauth::OAuthProvider::build_end_session_url)
    /// returns `None` until the URL is supplied. [`build`](Self::build)
    /// refuses a URL that is not HTTPS.
    #[must_use]
    pub fn with_end_session_endpoint(mut self, url: impl Into<String>) -> Self {
        self.end_session_endpoint = Some(url.into());
        self
    }

    /// Configure the set of `post_logout_redirect_uri` values accepted by
    /// [`build_end_session_url`](crate::oauth::OAuthProvider::build_end_session_url). Each entry must match exactly (no glob /
    /// substring matching); values not in the list are dropped (with a
    /// warning) before being passed to the IdP, defeating phishing chains
    /// where an attacker tricks a user-controlled redirect parameter through
    /// the logout flow.
    ///
    /// The list is empty by default and an empty list forwards nothing: a
    /// provider that exposes a logout link with a redirect parameter must
    /// list the destinations it accepts here, and each must also be
    /// registered at the IdP.
    #[must_use]
    pub fn with_allowed_post_logout_redirect_uris(
        mut self,
        uris: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.base.allowed_post_logout_redirect_uris = uris.into_iter().map(Into::into).collect();
        self
    }

    /// Set the device authorization endpoint URL (RFC 8628).
    ///
    /// Required for the device code flow. Not part of standard OIDC discovery;
    /// check your IdP's documentation for the URL. [`build`](Self::build)
    /// refuses a URL that is not HTTPS.
    #[must_use]
    pub fn with_device_authorization_endpoint(mut self, url: impl Into<String>) -> Self {
        self.device_authorization_endpoint = Some(url.into());
        self
    }

    /// Authenticate to the IdP by `private_key_jwt` (RFC 7523) instead of a
    /// client secret. A second call replaces the first.
    ///
    /// Every request that proves the client's identity (the code exchange,
    /// the refresh, the pushed authorization request, revocation and
    /// `client_credentials`) then carries a fresh signed `client_assertion`
    /// and no `client_secret`; any secret the provider was discovered with
    /// is dropped. The assertion's `jti` comes from the provider's RNG
    /// ([`with_rng`](Self::with_rng)) and its `iat`/`exp` from its clock
    /// ([`with_clock`](Self::with_clock)). It is what the FAPI profile asks
    /// of a client that does not authenticate by mTLS: DPoP and mTLS
    /// constrain the tokens, the assertion authenticates the client, and
    /// under the profile the assertion names the issuer as its audience
    /// unless the signer fixed one.
    #[must_use]
    pub fn with_private_key_jwt(mut self, signer: ClientAssertionSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Swap the random source behind the `jti` of client assertions.
    /// Defaults to [`SystemRng`](axess_rng::SystemRng); pass a seeded
    /// `MockRng` under DST.
    #[must_use]
    pub fn with_rng(mut self, rng: std::sync::Arc<dyn axess_rng::SecureRng>) -> Self {
        self.base.rng = rng;
        self
    }

    /// Swap the clock behind every time-bound decision the provider makes:
    /// ID-token `exp` and `iat` (inside `openidconnect`), the FAPI `nbf`
    /// check, back-channel logout token lifetimes, and the JWKS refresh
    /// debounce. Defaults to [`SystemClock`](axess_clock::SystemClock).
    /// Pass a `MockClock` under DST so all of them are deterministic.
    #[must_use]
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn axess_clock::Clock>) -> Self {
        self.base.jwks_cache = self.base.jwks_cache.with_clock(clock.clone());
        self.base.clock = clock;
        self
    }

    /// Check the settings together and return the provider.
    ///
    /// The one place the settings meet, so the order of the `with_*` calls
    /// never matters:
    ///
    /// 1. Each endpoint a setter named must be HTTPS (plain HTTP to a
    ///    loopback host aside) and replaces the discovered one.
    /// 2. Under the FAPI profile, the provider must have a PAR endpoint and
    ///    authenticate by `private_key_jwt` or mTLS; any client secret is
    ///    dropped, as it is whenever a `private_key_jwt` signer is set.
    /// 3. DPoP is resolved: the profile's sender constraint, then
    ///    [`with_dpop`](Self::with_dpop) or
    ///    [`without_dpop`](Self::without_dpop), then the IdP's
    ///    advertisement. A setting the profile contradicts is refused.
    /// 4. The ID-token algorithms are the pin, the profile's list, or the
    ///    algorithms both name.
    /// 5. Under mTLS the certificate is loaded and the advertised
    ///    `mtls_endpoint_aliases` replace the endpoints they name, last, so
    ///    no endpoint setting moves a request off the certificate-bound
    ///    endpoint.
    ///
    /// Reads the mTLS certificate and key files synchronously; call it at
    /// startup, not on a request path.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] naming the first rule that fails: an endpoint
    /// that is not secure; under FAPI no PAR endpoint, or a client that
    /// would authenticate by a secret; a DPoP setting the profile
    /// contradicts, or [`with_dpop`](Self::with_dpop) for an IdP that does
    /// not advertise DPoP; an algorithm list that is empty or names an
    /// algorithm that is not an asymmetric one this provider verifies, or a
    /// pin the profile shares nothing with; mTLS files that cannot be read
    /// or parsed, or an advertised mTLS alias that is not a secure URL.
    pub fn build(self) -> Result<OAuthProviderConfig, OAuthError> {
        let Self {
            mut base,
            signer,
            dpop,
            id_token_algs,
            fapi,
            par_endpoint,
            revocation_endpoint,
            end_session_endpoint,
            device_authorization_endpoint,
        } = self;

        for (url, slot, what) in [
            (
                par_endpoint,
                &mut base.par_endpoint,
                "pushed_authorization_request_endpoint",
            ),
            (
                revocation_endpoint,
                &mut base.revocation_endpoint,
                "revocation_endpoint",
            ),
            (
                end_session_endpoint,
                &mut base.end_session_endpoint,
                "end_session_endpoint",
            ),
            (
                device_authorization_endpoint,
                &mut base.device_authorization_endpoint,
                "device_authorization_endpoint",
            ),
        ] {
            if let Some(url) = url {
                super::endpoint::require_secure(Some(&url), what)?;
                *slot = Some(url);
            }
        }

        if let Some(fapi) = &fapi {
            fapi_profile::check_client_and_par(
                fapi,
                signer.is_some(),
                base.par_endpoint.is_some(),
            )?;
        }
        if signer.is_some() || fapi.is_some() {
            base.client_secret = None;
        }
        base.client_assertion = signer;

        let constraint = fapi.as_ref().map(|f| &f.sender_constraint);
        base.dpop = resolve_dpop(dpop, base.dpop_advertised, constraint)?;
        base.id_token_algs = resolve_id_token_algs(id_token_algs.as_deref(), fapi.as_ref())?;

        if let Some(SenderConstraint::Mtls {
            client_cert_path,
            client_key_path,
        }) = constraint
        {
            base.http_client = fapi_profile::mtls_client(client_cert_path, client_key_path)?;
            base.use_mtls_aliases()?;
        }
        base.fapi = fapi;
        Ok(base)
    }
}

/// Whether the provider binds its tokens to a DPoP key, from what the caller
/// asked for, whether the IdP advertises DPoP, and the FAPI profile's sender
/// constraint. The profile's constraint decides when there is one; a policy
/// it contradicts is refused rather than overridden.
pub(super) fn resolve_dpop(
    policy: DpopPolicy,
    advertised: bool,
    constraint: Option<&SenderConstraint>,
) -> Result<bool, OAuthError> {
    match (constraint, policy) {
        (Some(c), DpopPolicy::Off) if c.binds_dpop() => Err(OAuthError::Config(
            "the FAPI profile with SenderConstraint::DPoP requires DPoP; without_dpop would \
             send its tokens unbound"
                .to_string(),
        )),
        (Some(c), _) if c.binds_dpop() => Ok(true),
        (Some(_), DpopPolicy::Required) => Err(OAuthError::Config(
            "the FAPI profile binds this provider's tokens by mTLS; with_dpop would add a \
             second binding the profile did not ask for"
                .to_string(),
        )),
        (Some(_), _) => Ok(false),
        (None, DpopPolicy::Advertised) => Ok(advertised),
        (None, DpopPolicy::Off) => Ok(false),
        (None, DpopPolicy::Required) if advertised => Ok(true),
        (None, DpopPolicy::Required) => Err(OAuthError::Config(format!(
            "with_dpop: the IdP does not advertise DPoP with {}: its discovery document has no \
             dpop_signing_alg_values_supported listing it",
            super::dpop::DPOP_SIGNING_ALG
        ))),
    }
}

/// The ID-token algorithm list: the pin, the profile's list, or, with both,
/// the algorithms both name in the pin's order. A pin narrows the profile
/// and never widens it; one the profile shares nothing with is refused.
pub(super) fn resolve_id_token_algs(
    pin: Option<&[String]>,
    fapi: Option<&FapiConfig>,
) -> Result<Option<IdTokenAlgs>, OAuthError> {
    let pin = pin
        .map(|names| IdTokenAlgs::parse(names, "the ID token algorithm list"))
        .transpose()?;
    let profile = fapi
        .map(|f| {
            IdTokenAlgs::parse(
                &f.allowed_id_token_algs,
                "FapiConfig::allowed_id_token_algs",
            )
        })
        .transpose()?;
    match (pin, profile) {
        (Some(pin), Some(profile)) => {
            let both = pin.intersect(&profile);
            if both.jwt.is_empty() {
                return Err(OAuthError::Config(format!(
                    "the ID token algorithm list shares no algorithm with the FAPI profile's \
                     allowed_id_token_algs {:?}",
                    fapi.map(|f| &f.allowed_id_token_algs)
                )));
            }
            Ok(Some(both))
        }
        (pin, profile) => Ok(pin.or(profile)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    fn mtls() -> SenderConstraint {
        SenderConstraint::Mtls {
            client_cert_path: "c".into(),
            client_key_path: "k".into(),
        }
    }

    /// The resolution table: the profile's constraint decides, a policy it
    /// contradicts is refused, and without a profile the policy and the
    /// advertisement decide.
    #[test]
    fn dpop_resolves_from_the_profile_then_the_policy_then_the_advertisement() {
        use DpopPolicy::*;
        let dpop = SenderConstraint::DPoP;
        let mtls = mtls();
        for advertised in [true, false] {
            assert!(resolve_dpop(Advertised, advertised, Some(&dpop)).unwrap());
            assert!(resolve_dpop(Required, advertised, Some(&dpop)).unwrap());
            assert!(resolve_dpop(Off, advertised, Some(&dpop)).is_err());
            assert!(!resolve_dpop(Advertised, advertised, Some(&mtls)).unwrap());
            assert!(!resolve_dpop(Off, advertised, Some(&mtls)).unwrap());
            assert!(resolve_dpop(Required, advertised, Some(&mtls)).is_err());
            assert_eq!(
                resolve_dpop(Advertised, advertised, None).unwrap(),
                advertised
            );
            assert!(!resolve_dpop(Off, advertised, None).unwrap());
        }
        assert!(resolve_dpop(Required, true, None).unwrap());
        assert!(resolve_dpop(Required, false, None).is_err());
    }

    fn jwt_names(algs: &IdTokenAlgs) -> Vec<jsonwebtoken::Algorithm> {
        algs.jwt.clone()
    }

    /// A pin narrows the profile and never widens it; a pin the profile
    /// shares nothing with is refused; each list alone is taken as it is.
    #[test]
    fn a_pin_narrows_the_profile_and_one_outside_it_is_refused() {
        use jsonwebtoken::Algorithm as J;
        let fapi = FapiConfig::default();
        let narrowed = resolve_id_token_algs(Some(&names(&["PS256"])), Some(&fapi))
            .unwrap()
            .unwrap();
        assert_eq!(jwt_names(&narrowed), [J::PS256]);

        let partly = resolve_id_token_algs(Some(&names(&["RS256", "ES256"])), Some(&fapi))
            .unwrap()
            .unwrap();
        assert_eq!(jwt_names(&partly), [J::ES256]);

        let outside = resolve_id_token_algs(Some(&names(&["RS256"])), Some(&fapi));
        assert!(matches!(outside, Err(OAuthError::Config(m)) if m.contains("shares no")));

        let profile = resolve_id_token_algs(None, Some(&fapi)).unwrap().unwrap();
        assert_eq!(jwt_names(&profile), [J::PS256, J::ES256, J::EdDSA]);
        let pin = resolve_id_token_algs(Some(&names(&["RS256"])), None)
            .unwrap()
            .unwrap();
        assert_eq!(jwt_names(&pin), [J::RS256]);
        assert!(resolve_id_token_algs(None, None).unwrap().is_none());
    }

    /// The parse rules still apply to the pin and to the profile.
    #[test]
    fn an_empty_or_symmetric_list_is_refused() {
        assert!(resolve_id_token_algs(Some(&[]), None).is_err());
        assert!(resolve_id_token_algs(Some(&names(&["HS256"])), None).is_err());
        let fapi = FapiConfig {
            allowed_id_token_algs: names(&["none"]),
            ..FapiConfig::default()
        };
        assert!(resolve_id_token_algs(None, Some(&fapi)).is_err());
    }
}
