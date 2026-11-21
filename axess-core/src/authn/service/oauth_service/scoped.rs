//! The by-name OAuth helpers, resolved the way the login resolves.
//!
//! A login begun with `begin_oauth_login` runs against the global
//! registration; one begun with `begin_oauth_login_with_tenant_provider` runs against the
//! tenant's provider, and its callback finds that provider from the tenant the
//! server stored in the session. The helpers that follow the login (refresh,
//! userinfo, revocation, the RP-Initiated Logout URL, DPoP proofs) take the
//! same choice here. None of them has a form on the service that takes a
//! provider by its name alone: a name is unique only inside one tenant's
//! providers or the global registration, and a token sent to the wrong one
//! of two providers of a name is disclosed to it. Every helper is called on
//! a [`ScopedOAuth`], which reads the tenant's provider when it has a
//! tenant, and the global registration otherwise.

use crate::authn::factor::FederatedProvider;
use crate::authn::ids::{TenantId, UserId};
use crate::authn::service::{AuthnService, RequestAuthnService};
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::extractor::AuthSession;
use axess_factors::oauth::{OAuthError, OAuthProvider, keys as oauth_keys};
use std::sync::Arc;

/// Where a by-name helper looks for its provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum Source {
    /// The global registration.
    #[default]
    Global,
    /// The tenant's provider.
    Tenant {
        tenant: TenantId,
        /// When set, the tenant applies only to the provider of this name (a
        /// session logged in through one provider says nothing about
        /// another).
        only: Option<String>,
    },
    /// No provider: the session's login-tenant record is present but does
    /// not read, so neither the tenant's provider nor the global registration
    /// may stand in for it.
    Refused,
}

/// Where a by-name helper looks for its provider, and whom its audit rows
/// are attributed to.
#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    source: Source,
    /// The local user the helpers act for, named on their audit rows.
    user: Option<UserId>,
    /// The tenant the audit rows belong to. Set with `tenant` by
    /// `oauth_in_tenant`, and from the session by `oauth_for_session`; a
    /// row with neither is a platform row that every tenant's
    /// `include_unscoped` query sees.
    audit_tenant: Option<TenantId>,
}

impl Scope {
    pub(crate) fn global() -> Self {
        Self::default()
    }

    /// The scope of a ceremony bound to a tenant: that tenant's provider of
    /// `name` when the binding says the provider comes from the tenant, the
    /// global registration otherwise. Its audit rows belong to the tenant.
    pub(super) fn ceremony(binding: super::login::CeremonyTenant, name: &str) -> Self {
        Self {
            source: if binding.provider_from_tenant {
                Source::Tenant {
                    tenant: binding.tenant,
                    only: Some(name.to_string()),
                }
            } else {
                Source::Global
            },
            user: None,
            audit_tenant: Some(binding.tenant),
        }
    }

    /// The scope a session's login-tenant record names. Absent, the global
    /// registration; present and well-formed, that tenant's provider of that
    /// name; present but malformed, a refusing scope, never a quiet fallback
    /// to the global provider.
    pub(crate) fn from_login_tenant(value: Option<&serde_json::Value>) -> Self {
        let Some(value) = value else {
            return Self::global();
        };
        let tenant = value
            .get("tenant")
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse::<TenantId>().ok());
        let provider = value
            .get("provider")
            .and_then(|p| p.as_str())
            .map(str::to_string);
        match (tenant, provider) {
            (Some(tenant), Some(provider)) => Self {
                source: Source::Tenant {
                    tenant,
                    only: Some(provider),
                },
                ..Self::global()
            },
            _ => Self {
                source: Source::Refused,
                ..Self::global()
            },
        }
    }

    fn tenant(&self) -> Option<&TenantId> {
        match &self.source {
            Source::Tenant { tenant, .. } => Some(tenant),
            Source::Global | Source::Refused => None,
        }
    }

    fn tenant_for(&self, name: &str) -> Option<&TenantId> {
        match &self.source {
            Source::Tenant { tenant, only } if only.as_deref().is_none_or(|o| o == name) => {
                Some(tenant)
            }
            _ => None,
        }
    }

    /// `(user, tenant)` for the audit rows of a helper under this scope.
    pub(crate) fn attribution(&self) -> (Option<&UserId>, Option<&TenantId>) {
        (self.user.as_ref(), self.audit_tenant.as_ref())
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The provider `name` under `scope`: the tenant's when the scope has a
    /// tenant for that name, the global registration otherwise.
    pub(crate) async fn scoped_provider(
        &self,
        scope: &Scope,
        name: &str,
    ) -> Result<Arc<dyn OAuthProvider>, OAuthError> {
        let unknown = || super::unknown_provider(name);
        if scope.source == Source::Refused {
            return Err(unknown());
        }
        match scope.tenant_for(name) {
            Some(tenant) => self
                .tenant_oauth_provider(tenant, name)
                .await?
                .ok_or_else(unknown),
            None => self
                .inner
                .oauth_providers
                .load()
                .get(name)
                .cloned()
                .ok_or_else(unknown),
        }
    }
}

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The kind the rows and the session record for the provider `name`
    /// under `scope`: the tenant's provider's when the scope has a tenant for
    /// that name, the global registration's otherwise, and `Custom(name)`
    /// under a refusing scope.
    pub(crate) async fn scoped_provider_kind(
        &self,
        scope: &Scope,
        name: &str,
    ) -> FederatedProvider {
        if scope.source == Source::Refused {
            return FederatedProvider::Custom(name.to_string());
        }
        match scope.tenant_for(name) {
            Some(tenant) => match &self.inner.tenant_oauth_providers {
                Some(source) => source.provider_kind(tenant, name).await,
                None => FederatedProvider::Custom(name.to_string()),
            },
            None => self.inner.oauth_providers.load().provider_kind(name),
        }
    }
}

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The OAuth helpers for `tenant`'s providers.
    ///
    /// Use it where the tenant is known without a session: a background
    /// refresh keyed by a stored tenant id. The tenant must come from
    /// something the server established, never from a request body.
    pub fn oauth_in_tenant(&self, tenant: &TenantId) -> ScopedOAuth<'_, I, F> {
        ScopedOAuth {
            authn: self,
            scope: Scope {
                source: Source::Tenant {
                    tenant: *tenant,
                    only: None,
                },
                user: None,
                audit_tenant: Some(*tenant),
            },
        }
    }

    /// The OAuth helpers for the global registration, whatever a session
    /// logged in through.
    ///
    /// Use it where there is neither a session nor a tenant: a job that
    /// revokes a stored token of a provider every tenant shares. A request
    /// that holds a session uses
    /// [`oauth_for_session`](Self::oauth_for_session), which reads the
    /// tenant's provider when the login used one; the global registration
    /// read for such a session would send its token to another provider of
    /// the same name. The audit rows of the helpers carry no user and no
    /// tenant unless [`ScopedOAuth::attributed_to`] names one.
    pub fn oauth_global(&self) -> ScopedOAuth<'_, I, F> {
        ScopedOAuth {
            authn: self,
            scope: Scope::global(),
        }
    }

    /// The OAuth helpers for the provider `session` logged in through.
    ///
    /// When the session's login was begun with
    /// [`begin_oauth_login_with_tenant_provider`](crate::authn::service::AuthnService::begin_oauth_login_with_tenant_provider),
    /// the helpers resolve that provider from the tenant the server recorded
    /// at login; for a login begun with `begin_oauth_login`, or a session
    /// that has no OAuth login, they read the global registration.
    ///
    /// The audit rows of the helpers name the session's user and tenant when
    /// it is authenticated.
    pub async fn oauth_for_session(&self, session: &AuthSession) -> ScopedOAuth<'_, I, F> {
        let mut scope =
            Scope::from_login_tenant(session.get_custom(oauth_keys::LOGIN_TENANT).await.as_ref());
        scope.user = session.user_id().await;
        scope.audit_tenant = session.tenant_id().await;
        ScopedOAuth { authn: self, scope }
    }
}

/// The by-name OAuth helpers under a scope: a tenant's providers or the
/// global registration.
///
/// Obtained from
/// [`RequestAuthnService::oauth_for_session`],
/// [`RequestAuthnService::oauth_in_tenant`] or
/// [`RequestAuthnService::oauth_global`]. The helpers exist only here: each
/// resolves the provider it is given by name under the scope, as described
/// on those three methods, and a name the scope cannot resolve is
/// [`OAuthError::UnknownProvider`].
pub struct ScopedOAuth<'a, I, F>
where
    I: IdentityStore,
    F: FactorStore,
{
    authn: &'a RequestAuthnService<I, F>,
    scope: Scope,
}

impl<I, F> ScopedOAuth<'_, I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The tenant whose providers these helpers use, `None` for the global
    /// registration.
    ///
    /// `None` is also what a refused scope reads: the session's login-tenant
    /// record is present but does not read, so neither a tenant's provider
    /// nor the global registration is used and every by-name helper answers
    /// [`OAuthError::UnknownProvider`]. Check [`is_refused`](Self::is_refused)
    /// to tell the two apart.
    pub fn tenant(&self) -> Option<&TenantId> {
        self.scope.tenant()
    }

    /// Whether the scope is refused: the session's login-tenant record is
    /// present but does not read, so no provider resolves under it.
    pub fn is_refused(&self) -> bool {
        matches!(self.scope.source, Source::Refused)
    }

    /// Name `user` on the audit rows these helpers write: a background
    /// refresh runs for a stored user with no session to read one from. The
    /// id must come from the server's own record of whose token this is,
    /// never from the IdP subject or a request body.
    ///
    /// It changes the audit rows and nothing else: the provider the helpers
    /// reach is the scope's, whoever the rows name.
    #[must_use]
    pub fn attributed_to(mut self, user: UserId) -> Self {
        self.scope.user = Some(user);
        self
    }

    /// Refresh an OAuth token using a stored refresh token.
    ///
    /// Exchanges the refresh token at the IdP's token endpoint for new
    /// access/ID tokens. Validates the new ID token, when the IdP sent one,
    /// and returns it with the rotated tokens.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: The provider, resolved under this scope.
    /// * `refresh_token`: The refresh token obtained from a previous login
    ///   (stored in [`OAuthClaims::refresh_token`](axess_factors::oauth::OAuthClaims::refresh_token)).
    /// * `expected_subject`: The IdP subject the login recorded
    ///   ([`OAuthClaims::subject`](axess_factors::oauth::OAuthClaims::subject)).
    ///   A response for any other subject is refused (OIDC Core 12.2) and
    ///   audited as a provider rejection.
    /// * `original_nonce`: The `nonce` of the login that produced the refresh
    ///   token ([`OAuthClaims::nonce`](axess_factors::oauth::OAuthClaims::nonce),
    ///   stored beside the refresh token).
    ///   A refresh ID token that carries a nonce must equal it (OIDC Core
    ///   12.2); one without a nonce is accepted, and one with a nonce when
    ///   this is `None` is refused.
    /// * `dpop_key`: The key the login's tokens are bound to, for a provider
    ///   that binds them to a DPoP key: the one the login returned in
    ///   [`OAuthClaims::dpop_key`](axess_factors::oauth::OAuthClaims::dpop_key),
    ///   or restored with `DpopKey::from_seed`. The refresh request carries a
    ///   proof signed by it, and the rotated access token is bound to the
    ///   same key. `None` for a provider that does not bind.
    ///
    /// # Returns
    ///
    /// A [`RefreshOutcome`](axess_factors::oauth::RefreshOutcome). Store its
    /// `refresh_token` in place of the one you sent: a rotating IdP has spent
    /// the old one even when the response carries no ID token, in which case
    /// `id_token_claims` is `None` and the claims you already hold stand.
    ///
    /// # Errors
    ///
    /// [`OAuthError::DpopKeyRequired`]
    /// when the provider binds tokens and `dpop_key` is `None`, refused
    /// before anything is sent and audited as `token_refresh_dpop_key_missing`;
    /// the provider's own errors otherwise.
    pub async fn refresh_oauth_token(
        &self,
        provider_name: &str,
        refresh_token: &str,
        expected_subject: &str,
        original_nonce: Option<&str>,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::RefreshOutcome, OAuthError> {
        self.authn
            .refresh_scoped(
                &self.scope,
                provider_name,
                refresh_token,
                expected_subject,
                original_nonce,
                dpop_key,
            )
            .await
    }

    /// Fetch additional user claims from the OIDC UserInfo endpoint.
    ///
    /// Calls the provider's UserInfo endpoint using the access token obtained
    /// during login. Returns [`UserInfoClaims`](axess_factors::oauth::UserInfoClaims) with standard OIDC profile
    /// claims plus any provider-specific claims.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: The provider, resolved under this scope.
    /// * `access_token`: The access token from [`OAuthClaims::access_token`](axess_factors::oauth::OAuthClaims::access_token).
    /// * `expected_subject`: The `sub` of the ID token the login verified
    ///   ([`OAuthClaims::subject`](axess_factors::oauth::OAuthClaims::subject)).
    ///   A response for any other subject is refused (OIDC Core 5.3.2): a
    ///   substituted token or a mis-routed proxy would otherwise hand back
    ///   another user's profile for the caller to merge or link on.
    /// * `dpop_key`: The key the access token is bound to, for a provider
    ///   that binds tokens to a DPoP key: the one the login returned in
    ///   [`OAuthClaims::dpop_key`](axess_factors::oauth::OAuthClaims::dpop_key).
    ///   The request then uses the `DPoP` authorization scheme and carries a
    ///   proof signed by it that names the token's hash. `None` for a
    ///   provider that does not bind.
    ///
    /// # Errors
    ///
    /// * [`OAuthError::DpopKeyRequired`]: the provider binds tokens to a DPoP key
    ///   and `dpop_key` is `None`; nothing is sent.
    /// * [`OAuthError::SubjectMismatch`]: the response is about another subject.
    /// * [`OAuthError::NoAccessToken`]: empty access token.
    /// * [`OAuthError::UnknownProvider`]: provider not registered.
    /// * [`OAuthError::AccessTokenExpired`]: token expired or invalid (HTTP 401).
    /// * [`OAuthError::InsufficientScope`]: missing required scope (HTTP 403).
    /// * [`OAuthError::UserInfo`]: other HTTP or parse errors.
    pub async fn fetch_userinfo(
        &self,
        provider_name: &str,
        access_token: &str,
        expected_subject: &str,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<axess_factors::oauth::UserInfoClaims, OAuthError> {
        self.authn
            .userinfo_scoped(
                &self.scope,
                provider_name,
                access_token,
                expected_subject,
                dpop_key,
            )
            .await
    }

    /// Revoke an access or refresh token at the identity provider
    /// (RFC 7009), as part of a logout or when a token must not be used
    /// again.
    ///
    /// * `provider_name`: the provider, resolved under this scope.
    /// * `token`: the access or refresh token to revoke.
    /// * `token_type_hint`: `"access_token"` or `"refresh_token"`; optional,
    ///   and it helps the provider find the token.
    /// * `dpop_key`: the key the token is bound to, when the caller still
    ///   holds it: the request then carries a proof signed by it, for an
    ///   authorization server that wants one. A revocation issues no token,
    ///   so it is sent with `None` too, even to a provider that binds.
    ///
    /// The revocation writes two `LogoutAttempt` rows naming the provider
    /// and sharing a `request_id`: the request, a `Failure` with the reason
    /// [`OAUTH_REVOCATION_REQUESTED_REASON`](crate::authn::service::OAUTH_REVOCATION_REQUESTED_REASON),
    /// before the provider is asked; then the outcome, a `Success` when the
    /// provider revoked the token, or a `Failure` with its refusal or marked
    /// unconfirmed when it did not answer. A row the audit pipeline sheds
    /// ([`AuditOutcome::Shed`](crate::authn::store::AuditOutcome::Shed))
    /// counts as written, as it does in every audited flow.
    ///
    /// # Errors
    ///
    /// [`OAuthError::UnknownProvider`] for a name the scope cannot resolve
    /// and the source's own error when it fails, both before any row is
    /// written; [`OAuthError::AuditStore`] when the request row cannot be
    /// written, and nothing is sent; the provider's error when it refused
    /// or did not answer. [`OAuthError::AuditStore`] after the provider was
    /// asked means the outcome row could not be written, and its message
    /// says what the provider answered: the token may be revoked. RFC 7009
    /// answers a token already revoked as it answers a live one, so sending
    /// the revocation again records its outcome. A provider that did not
    /// answer ([`OAuthError::TokenEndpointTransient`]) may have revoked the
    /// token or not; send it again.
    pub async fn revoke_oauth_token(
        &self,
        provider_name: &str,
        token: &str,
        token_type_hint: Option<&str>,
        dpop_key: Option<&axess_factors::oauth::DpopKey>,
    ) -> Result<(), OAuthError> {
        self.authn
            .revoke_scoped(&self.scope, provider_name, token, token_type_hint, dpop_key)
            .await
    }

    /// Build an RP-Initiated Logout URL for the given provider.
    ///
    /// Returns a URL that the application should redirect the user's browser to
    /// after invalidating the local session. The IdP will terminate its session
    /// and redirect the user back to `post_logout_redirect_uri`.
    ///
    /// Returns `None` if the provider doesn't advertise an `end_session_endpoint`
    /// in its OIDC discovery metadata. A `post_logout_redirect_uri` is
    /// forwarded only when it matches an entry of the provider's configured
    /// allowlist exactly; with no allowlist configured it is dropped.
    ///
    /// # Arguments
    ///
    /// * `provider_name`: The provider, resolved under this scope.
    /// * `id_token_hint`: The raw ID token JWT from [`OAuthClaims::id_token_hint`](axess_factors::oauth::OAuthClaims::id_token_hint).
    ///   Allows the IdP to identify the session without re-authentication.
    /// * `post_logout_redirect_uri`: Where the IdP redirects after logout.
    /// * `state`: Optional CSRF protection for the post-logout redirect.
    ///
    /// Async, because resolving a tenant's provider reads its store;
    /// `Ok(None)` is a provider with no end-session endpoint.
    ///
    /// # Errors
    ///
    /// [`OAuthError::UnknownProvider`] for a name the scope cannot resolve;
    /// the source's own error when it fails.
    pub async fn build_end_session_url(
        &self,
        provider_name: &str,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Result<Option<url::Url>, OAuthError> {
        let provider = self
            .authn
            .scoped_provider(&self.scope, provider_name)
            .await?;
        Ok(provider.build_end_session_url(id_token_hint, post_logout_redirect_uri, state))
    }

    /// Generate a DPoP proof JWT for an API call to a resource server.
    ///
    /// The proof is signed with `key`, the one key the token is bound to, so
    /// two proofs for different URLs report the same `thumbprint`, which is
    /// the `jkt` of the sender-constrained access token. Include the returned
    /// JWT in the `DPoP` header. Pass `access_token` to add the `ath` claim
    /// that ties the proof to that token.
    ///
    /// The 16 bytes behind the `jti` are drawn from the service's injected
    /// [`SecureRng`](axess_rng::SecureRng), and `iat` is read from its
    /// injected clock, so DST tests get reproducible proofs.
    ///
    /// # Errors
    ///
    /// [`OAuthError::UnknownProvider`] for a name the scope cannot resolve;
    /// the source's own error when it fails; the provider's error when the
    /// proof cannot be signed.
    pub async fn generate_dpop_proof(
        &self,
        provider_name: &str,
        key: &axess_factors::oauth::DpopKey,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> Result<axess_factors::oauth::DpopProof, OAuthError> {
        self.authn
            .dpop_proof_scoped(
                &self.scope,
                provider_name,
                key,
                http_method,
                http_url,
                access_token,
            )
            .await
    }
}

#[cfg(test)]
mod login_tenant_scope_tests {
    use super::{Scope, Source};
    use serde_json::json;

    #[test]
    fn an_absent_login_tenant_is_the_global_scope() {
        let scope = Scope::from_login_tenant(None);
        assert_eq!(scope.source, Source::Global);
    }

    #[test]
    fn a_malformed_login_tenant_refuses_instead_of_falling_back_to_global() {
        for value in [
            json!({ "tenant": "not-a-tenant-id", "provider": "google" }),
            json!({ "provider": "google" }),
            json!({ "tenant": "not-a-tenant-id" }),
            json!("garbage"),
        ] {
            let scope = Scope::from_login_tenant(Some(&value));
            assert_eq!(scope.source, Source::Refused, "{value} must refuse");
        }
    }

    #[test]
    fn only_a_refused_scope_reads_as_refused() {
        let tenant = crate::authn::ids::testing::tenant("t1");
        let well_formed = json!({ "tenant": tenant.to_string(), "provider": "google" });
        for (value, refused) in [
            (None, false),
            (Some(&well_formed), false),
            (Some(&json!("garbage")), true),
        ] {
            let scope = Scope::from_login_tenant(value);
            assert_eq!(matches!(scope.source, Source::Refused), refused);
        }
    }

    #[test]
    fn a_well_formed_login_tenant_names_the_tenant_and_provider() {
        let tenant = crate::authn::ids::testing::tenant("t1");
        let value = json!({ "tenant": tenant.to_string(), "provider": "google" });
        let scope = Scope::from_login_tenant(Some(&value));
        assert_eq!(
            scope.source,
            Source::Tenant {
                tenant,
                only: Some("google".to_string())
            }
        );
    }
}
