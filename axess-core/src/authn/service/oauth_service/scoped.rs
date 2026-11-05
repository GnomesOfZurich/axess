//! The by-name OAuth helpers, resolved the way the login resolves.
//!
//! A login begun with `begin_oauth_login` runs against the global
//! registration; one begun with `begin_oauth_login_with_tenant_provider` runs against the
//! tenant's provider, and its callback finds that provider from the tenant the
//! server stored in the session. The helpers that follow the login (refresh,
//! userinfo, revocation, the RP-Initiated Logout URL, DPoP proofs) take the
//! same choice here. The by-name methods on the service stay the
//! single-tenant form and read the global registration only; a
//! [`ScopedOAuth`] reads the tenant's provider when it has a tenant, and the
//! global registration otherwise.

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
        let unknown = || OAuthError::UnknownProvider(name.to_string());
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
                .get(name)
                .cloned()
                .ok_or_else(unknown),
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

    /// The OAuth helpers for the provider `session` logged in through.
    ///
    /// When the session's login was begun with
    /// [`begin_oauth_login_with_tenant_provider`](crate::authn::service::AuthnService::begin_oauth_login_with_tenant_provider),
    /// the helpers resolve that provider from the tenant the server recorded
    /// at login; for a login begun with `begin_oauth_login`, or a session
    /// that has no OAuth login, they read the global registration, as the
    /// by-name methods on the service do.
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

/// The by-name OAuth helpers under a tenant scope.
///
/// Obtained from
/// [`RequestAuthnService::oauth_for_session`] or
/// [`RequestAuthnService::oauth_in_tenant`]. Each method does what the
/// method of the same name on the service does, with the provider resolved
/// as described there; a name the scope cannot resolve is
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
    #[must_use]
    pub fn as_user(mut self, user: UserId) -> Self {
        self.scope.user = Some(user);
        self
    }

    /// See [`RequestAuthnService::refresh_oauth_token`].
    ///
    /// # Errors
    ///
    /// As the by-name method.
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

    /// See [`AuthnService::fetch_userinfo`].
    ///
    /// # Errors
    ///
    /// As the by-name method.
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

    /// See [`AuthnService::revoke_oauth_token`].
    ///
    /// # Errors
    ///
    /// As the by-name method.
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

    /// See [`AuthnService::build_end_session_url`]. Async, because resolving
    /// a tenant's provider reads its store; `Ok(None)` is a provider with no
    /// end-session endpoint.
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

    /// See [`AuthnService::generate_dpop_proof`].
    ///
    /// # Errors
    ///
    /// As the by-name method.
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
