//! Step 1 of the OAuth/OIDC login ceremony: `begin_oauth_login`.
//!
//! Generates PKCE / state / nonce, stashes them in the session, and
//! returns the IdP authorization URL. Also exposes the tenant-bound
//! variant that pins the ceremony to a specific tenant for the
//! `complete_oauth_login` cross-tenant rail.

use super::helpers::normalize_issuer;
use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::extractor::AuthSession;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Begin an OAuth/OIDC login flow.
    ///
    /// Generates an authorization URL with PKCE, state (CSRF), and nonce.
    /// Returns `(authorization_url, csrf_state_token)`.
    #[tracing::instrument(skip(self, options, session))]
    pub async fn begin_oauth_login(
        &self,
        provider_name: &str,
        options: &axess_factors::oauth::OAuthLoginOptions,
        session: &AuthSession,
    ) -> Result<(url::Url, String), axess_factors::oauth::OAuthError> {
        use axess_factors::oauth::{OAuthError, keys as oauth_keys};

        let provider = self
            .oauth_providers
            .get(provider_name)
            .ok_or_else(|| OAuthError::UnknownProvider(provider_name.to_string()))?;

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
            && self.clock.now() < expires_at.with_timezone(&chrono::Utc)
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

        // Use PAR (Pushed Authorization Requests) when FAPI is enabled or
        // the provider has a PAR endpoint and the caller hasn't opted out.
        let used_par = provider.fapi_config().is_some();
        let (auth_url, csrf_state, nonce, pkce_verifier) = if used_par {
            provider.build_auth_url_par(options).await?
        } else {
            provider.build_auth_url(options)?
        };

        if used_par {
            self.stash_par_inflight_marker(session, provider.ceremony_timeout())
                .await;
        }

        self.stash_oauth_ceremony_state(
            session,
            pkce_verifier,
            &csrf_state,
            nonce,
            provider_name,
            provider.issuer(),
        )
        .await;

        Ok((auth_url, csrf_state))
    }

    /// Begin an OAuth/OIDC login flow bound to a specific tenant.
    ///
    /// Same as [`begin_oauth_login`](Self::begin_oauth_login) but stashes
    /// `expected_tenant` in the session under the internal
    /// `oauth_keys::EXPECTED_TENANT` slot.
    /// On callback, [`complete_oauth_login`](Self::complete_oauth_login)
    /// reads it and refuses to authenticate the session if the resolved
    /// `User.tenant_id` does not match.
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
        use axess_factors::oauth::types::keys as oauth_keys;
        let result = self
            .begin_oauth_login(provider_name, options, session)
            .await?;
        session
            .set_custom(
                oauth_keys::EXPECTED_TENANT,
                serde_json::Value::String(expected_tenant.to_string().to_string()),
            )
            .await;
        Ok(result)
    }

    /// Stash the in-flight OAuth ceremony state on the session.
    ///
    /// Writes the six standard ceremony keys (`PKCE_VERIFIER`,
    /// `CSRF_STATE`, `NONCE`, `PROVIDER`, `STARTED`, and the
    /// conditional `PROVIDER_ISSUER`) so a subsequent
    /// `finish_oauth_login` can replay every check the begin-side
    /// established. The set must stay in lockstep with the key list
    /// in [`clear_oauth_state`](Self::clear_oauth_state); adding a
    /// new ceremony key requires editing both. Centralising the
    /// stash here makes the "exactly these keys constitute an
    /// in-flight OAuth ceremony" invariant a property of the helper
    /// rather than per-call discipline. The PAR-inflight marker is
    /// stashed separately by [`stash_par_inflight_marker`](Self::stash_par_inflight_marker)
    /// because its lifetime semantics differ.
    ///
    /// `provider_issuer` is `None` for non-OIDC OAuth flows that
    /// don't advertise an issuer URL; in that case
    /// `finish_oauth_login`'s anti-confused-deputy check
    /// (`verify_provider_issuer_matches`) will fail closed
    /// with `MissingIssuer` if the provider DID advertise one at
    /// finish-time but didn't at begin-time (a consistency
    /// requirement, not a bug).
    async fn stash_oauth_ceremony_state(
        &self,
        session: &AuthSession,
        pkce_verifier: String,
        csrf_state: &str,
        nonce: String,
        provider_name: &str,
        provider_issuer: Option<&str>,
    ) {
        use axess_factors::oauth::types::keys as oauth_keys;
        let str_val = |s: String| serde_json::Value::String(s);
        session
            .set_custom(oauth_keys::PKCE_VERIFIER, str_val(pkce_verifier))
            .await;
        session
            .set_custom(oauth_keys::CSRF_STATE, str_val(csrf_state.to_string()))
            .await;
        session.set_custom(oauth_keys::NONCE, str_val(nonce)).await;
        session
            .set_custom(oauth_keys::PROVIDER, str_val(provider_name.to_string()))
            .await;
        session
            .set_custom(oauth_keys::STARTED, str_val(self.clock.now().to_rfc3339()))
            .await;
        if let Some(issuer) = provider_issuer {
            session
                .set_custom(
                    oauth_keys::PROVIDER_ISSUER,
                    str_val(normalize_issuer(issuer)),
                )
                .await;
        }
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
        let expires_at = self.clock.now()
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
