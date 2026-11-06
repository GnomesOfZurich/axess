//! Step 1 of the OAuth/OIDC login ceremony: `begin_oauth_login`.
//!
//! Generates PKCE / state / nonce, stashes them in the session, and
//! returns the IdP authorization URL. Also exposes the tenant-bound
//! variant that pins the ceremony to a specific tenant for the
//! `complete_oauth_login` cross-tenant rail.

use super::helpers::normalize_issuer;
use super::state::CeremonyTenant;
use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::extractor::AuthSession;

/// What a begin stashes in the session; see
/// [`AuthnService::stash_oauth_ceremony`].
struct StashedBegin<'a> {
    pkce_verifier: String,
    csrf_state: &'a str,
    nonce: String,
    provider_name: &'a str,
    provider_issuer: Option<&'a str>,
    dpop_key: Option<&'a axess_factors::oauth::DpopKey>,
    tenant: Option<CeremonyTenant>,
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Begin an OAuth/OIDC login flow.
    ///
    /// Generates an authorization URL with PKCE, state (CSRF), and nonce.
    /// Returns `(authorization_url, csrf_state_token)`.
    ///
    /// The ceremony's secrets (the PKCE verifier and, for a provider that
    /// binds tokens, the DPoP key's seed) are kept in the session's custom
    /// data, not sealed field by field: they are as private as the session
    /// store, which seals the whole row only when it was built with a
    /// `SessionCrypto` key. Use an encrypted store.
    #[tracing::instrument(skip(self, options, session))]
    pub async fn begin_oauth_login(
        &self,
        provider_name: &str,
        options: &axess_factors::oauth::OAuthLoginOptions,
        session: &AuthSession,
    ) -> Result<(url::Url, String), axess_factors::oauth::OAuthError> {
        let provider = self.global_provider(provider_name)?;
        self.begin_with_provider(&provider, provider_name, options, None, session)
            .await
    }

    /// The globally registered provider `provider_name`.
    fn global_provider(
        &self,
        provider_name: &str,
    ) -> Result<
        std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        axess_factors::oauth::OAuthError,
    > {
        self.inner
            .oauth_providers
            .load()
            .get(provider_name)
            .cloned()
            .ok_or_else(|| {
                axess_factors::oauth::OAuthError::UnknownProvider(provider_name.to_string())
            })
    }

    /// The ceremony start shared by every begin: everything after the
    /// provider is known. `tenant` is the binding the ceremony carries, if
    /// any.
    pub(super) async fn begin_with_provider(
        &self,
        provider: &std::sync::Arc<dyn axess_factors::oauth::OAuthProvider>,
        provider_name: &str,
        options: &axess_factors::oauth::OAuthLoginOptions,
        tenant: Option<CeremonyTenant>,
        session: &AuthSession,
    ) -> Result<(url::Url, String), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        // Refuse to mint a fresh PAR `request_uri` while the
        // previous one is still inside its single-use window. Without
        // this, a buggy front-end that fires two parallel begin calls
        // could push two PAR requests; the second authorization URL
        // would override the first and the abandoned `request_uri`
        // becomes dead client state. The IdP is the *authoritative*
        // single-use enforcer; this is defense-in-depth on our side.
        if provider.fapi_config().is_some()
            && let Some(serde_json::Value::Object(map)) =
                session.get_custom(oauth_keys::PAR_INFLIGHT).await
            && let Some(expires_at_str) = map.get("expires_at").and_then(|v| v.as_str())
            && let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str)
            && self.inner.clock.now() < expires_at.with_timezone(&chrono::Utc)
        {
            tracing::warn!(
                provider = %provider_name,
                "refusing PAR begin while a previous request_uri is still in its \
                 single-use window; clear the session ceremony state and retry"
            );
            return Err(OAuthError::CsrfMismatch);
        }

        // Clear any stale OAuth state from a previous abandoned flow before
        // storing new values, so orphaned CSRF/PKCE/nonce values don't
        // accumulate in the session.
        self.clear_oauth_state(session).await;

        // The authorization request is pushed (PAR) exactly when the FAPI
        // profile is on; a provider's PAR endpoint is not used outside it.
        let used_par = provider.fapi_config().is_some();
        // A provider that binds tokens to a DPoP key (by default one whose
        // IdP advertises DPoP, and FAPI with DPoP) gets the login's key
        // here. Under PAR the pushed request names it (`dpop_jkt`) and the
        // code comes back bound to it; either way the key is stashed with
        // the ceremony for the token request to present.
        let dpop_key = provider
            .binds_to_dpop()
            .then(|| axess_factors::oauth::DpopKey::generate(&*self.inner.rng));
        let axess_factors::oauth::AuthUrlResult {
            url: auth_url,
            csrf_state,
            nonce,
            pkce_verifier,
        } = if used_par {
            let signer = dpop_key
                .as_ref()
                .map(|key| axess_factors::oauth::DpopSigner {
                    key,
                    rng: &*self.inner.rng,
                });
            provider
                .build_auth_url_par(options, &*self.inner.rng, signer)
                .await?
        } else {
            provider.build_auth_url(options, &*self.inner.rng)?
        };

        if used_par {
            self.stash_par_inflight_marker(session, provider.ceremony_timeout())
                .await;
        }

        self.stash_oauth_ceremony(
            session,
            StashedBegin {
                pkce_verifier,
                csrf_state: &csrf_state,
                nonce,
                provider_name,
                provider_issuer: provider.issuer(),
                dpop_key: dpop_key.as_ref(),
                tenant,
            },
        )
        .await;

        Ok((auth_url, csrf_state))
    }

    /// Begin an OAuth/OIDC login flow bound to a specific tenant.
    ///
    /// Same as [`begin_oauth_login`](Self::begin_oauth_login), against the
    /// global registration, but the ceremony is bound to `expected_tenant`:
    /// on callback,
    /// [`complete_oauth_login`](crate::authn::service::RequestAuthnService::complete_oauth_login)
    /// refuses to authenticate the session if the resolved
    /// `User.tenant_id` does not match. To use the tenant's own provider as
    /// well, see
    /// [`begin_oauth_login_with_tenant_provider`](Self::begin_oauth_login_with_tenant_provider),
    /// which takes the same arguments in the same order.
    ///
    /// Use this whenever the OAuth login URL is reached via a tenant-scoped
    /// route (subdomain, path-prefix, or query param); the application
    /// already knows which tenant the user is logging into, and the rail
    /// prevents a buggy claims→user resolver from silently authenticating
    /// the session into the wrong tenant when the same external email
    /// exists in two tenants.
    pub async fn begin_oauth_login_in_tenant(
        &self,
        provider_name: &str,
        options: &axess_factors::oauth::OAuthLoginOptions,
        expected_tenant: &crate::authn::ids::TenantId,
        session: &AuthSession,
    ) -> Result<(url::Url, String), axess_factors::oauth::OAuthError> {
        let provider = self.global_provider(provider_name)?;
        let tenant = CeremonyTenant {
            tenant: *expected_tenant,
            provider_from_tenant: false,
        };
        self.begin_with_provider(&provider, provider_name, options, Some(tenant), session)
            .await
    }

    /// Stash the in-flight OAuth ceremony on the session, in one write.
    ///
    /// Writes every key of an in-flight ceremony (`PKCE_VERIFIER`,
    /// `CSRF_STATE`, `NONCE`, `PROVIDER`, `STARTED`, and, when there is
    /// one, `PROVIDER_ISSUER`, `DPOP_KEY` and `CEREMONY_TENANT`) inside one
    /// [`AuthSession::mutate_custom`], so a ceremony is in the session
    /// whole or not at all and "exactly these keys constitute an in-flight
    /// OAuth ceremony" is a property of this helper. The set must stay in
    /// lockstep with the key list `clear_oauth_state` removes. The
    /// PAR-inflight marker is stashed separately by
    /// [`stash_par_inflight_marker`](Self::stash_par_inflight_marker)
    /// because its lifetime semantics differ.
    ///
    /// `provider_issuer` is `None` for non-OIDC OAuth flows that
    /// don't advertise an issuer URL; in that case
    /// `finish_oauth_login`'s anti-confused-deputy check
    /// (`verify_provider_issuer_matches`) will fail closed
    /// with `MissingIssuer` if the provider DID advertise one at
    /// finish-time but didn't at begin-time (a consistency
    /// requirement, not a bug).
    async fn stash_oauth_ceremony(&self, session: &AuthSession, begun: StashedBegin<'_>) {
        use axess_factors::oauth::types::keys as oauth_keys;
        use serde_json::Value;
        let started = self.inner.clock.now().to_rfc3339();
        session
            .mutate_custom(move |obj| {
                obj.insert(
                    oauth_keys::PKCE_VERIFIER.into(),
                    Value::String(begun.pkce_verifier),
                );
                obj.insert(
                    oauth_keys::CSRF_STATE.into(),
                    Value::String(begun.csrf_state.to_string()),
                );
                obj.insert(oauth_keys::NONCE.into(), Value::String(begun.nonce));
                obj.insert(
                    oauth_keys::PROVIDER.into(),
                    Value::String(begun.provider_name.to_string()),
                );
                obj.insert(oauth_keys::STARTED.into(), Value::String(started));
                if let Some(issuer) = begun.provider_issuer {
                    obj.insert(
                        oauth_keys::PROVIDER_ISSUER.into(),
                        Value::String(normalize_issuer(issuer)),
                    );
                }
                if let Some(key) = begun.dpop_key {
                    obj.insert(
                        oauth_keys::DPOP_KEY.into(),
                        Value::String(super::helpers::encode_dpop_key(key)),
                    );
                }
                if let Some(tenant) = begun.tenant {
                    obj.insert(oauth_keys::CEREMONY_TENANT.into(), tenant.to_value());
                }
            })
            .await;
    }

    /// Stash the single-use PAR marker on the session.
    ///
    /// Upper-bounds the marker lifetime by the shorter of
    /// `ceremony_timeout` and 600s. RFC 9126 typical PAR expiry is
    /// ~90s but the AS is authoritative; the cap exists so a
    /// configuration mistake (e.g. `ceremony_timeout = 6h`) doesn't
    /// pin the session into a single-use blocker for hours after a
    /// stale flow. The fallback to 90s on `Duration::from_std`
    /// failure is paranoia: `chrono::Duration::from_std` only
    /// fails for nanoseconds-out-of-i64 inputs that
    /// `std::time::Duration` would never produce in this branch.
    async fn stash_par_inflight_marker(
        &self,
        session: &AuthSession,
        ceremony_timeout: std::time::Duration,
    ) {
        use axess_factors::oauth::types::keys as oauth_keys;
        let lifetime = ceremony_timeout.min(std::time::Duration::from_secs(600));
        let expires_at = self.inner.clock.now()
            + chrono::Duration::from_std(lifetime).unwrap_or(chrono::Duration::seconds(90));
        let mut entry = serde_json::Map::new();
        entry.insert(
            "expires_at".to_string(),
            serde_json::Value::String(expires_at.to_rfc3339()),
        );
        session
            .set_custom(oauth_keys::PAR_INFLIGHT, serde_json::Value::Object(entry))
            .await;
    }
}
