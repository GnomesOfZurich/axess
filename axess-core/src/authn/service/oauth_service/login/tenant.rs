//! Per-tenant providers (bring your own IdP): the begin that resolves a
//! provider by `(tenant, name)` and the lookup the callback repeats, both
//! through the one scoped resolution the by-name helpers use.

use super::super::scoped::Scope;
use super::state::CeremonyTenant;
use crate::authn::ids::TenantId;
use crate::authn::service::AuthnService;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::extractor::AuthSession;
use axess_factors::oauth::{OAuthError, OAuthProvider};
use std::sync::Arc;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The provider named `name` that `tenant` has configured, or `None`
    /// when the tenant has none by that name (or no per-tenant source is
    /// configured, see
    /// [`with_tenant_oauth_providers`](crate::authn::service::AuthnServiceBuilder::with_tenant_oauth_providers)).
    ///
    /// For the helpers that follow a login (refresh, userinfo, revocation,
    /// the end-session URL) use
    /// [`oauth_for_session`](crate::authn::service::RequestAuthnService::oauth_for_session)
    /// or
    /// [`oauth_in_tenant`](crate::authn::service::RequestAuthnService::oauth_in_tenant),
    /// which resolve through this method; the by-name methods on the service
    /// read the global registrations only.
    ///
    /// # Errors
    ///
    /// Whatever the source reports: an unreachable store, a failed
    /// discovery.
    pub async fn tenant_oauth_provider(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<Arc<dyn OAuthProvider>>, OAuthError> {
        match &self.inner.tenant_oauth_providers {
            Some(source) => source.provider(tenant, name).await,
            None => Ok(None),
        }
    }

    /// Begin an OAuth/OIDC login against the provider `tenant` has under
    /// `provider_name`.
    ///
    /// Takes the arguments of
    /// [`begin_oauth_login_in_tenant`](Self::begin_oauth_login_in_tenant), in
    /// the same order, and binds the ceremony to `tenant` the same way:
    /// `complete_oauth_login` refuses a resolved user of another tenant.
    /// Beyond that, the provider itself comes from the tenant's
    /// configuration, so two tenants can each have a provider called
    /// `"sso"` against different issuers in one process, and a tenant's
    /// update is used by the next login.
    ///
    /// `tenant` must come from something the server established (the route,
    /// the host, the signed-in session), never from a request body. It is
    /// stored in the server-side session, and the callback
    /// ([`finish_oauth_login`](crate::authn::service::RequestAuthnService::finish_oauth_login)
    /// and the JARM form) resolves the provider for that stored tenant, so
    /// the callback request chooses neither the tenant nor the provider.
    ///
    /// # Errors
    ///
    /// [`OAuthError::UnknownProvider`] when no per-tenant source is
    /// configured or the tenant has no provider by that name; the source's
    /// own error when it fails; everything
    /// [`begin_oauth_login`](Self::begin_oauth_login) reports.
    #[tracing::instrument(skip(self, options, session))]
    pub async fn begin_oauth_login_with_tenant_provider(
        &self,
        provider_name: &str,
        options: &axess_factors::oauth::OAuthLoginOptions,
        tenant: &TenantId,
        session: &AuthSession,
    ) -> Result<(url::Url, String), OAuthError> {
        let binding = CeremonyTenant {
            tenant: *tenant,
            provider_from_tenant: true,
        };
        let provider = self
            .scoped_provider(&Scope::ceremony(binding, provider_name), provider_name)
            .await?;
        self.begin_with_provider(&provider, provider_name, options, Some(binding), session)
            .await
    }

    /// The provider an in-flight ceremony runs against, resolved the way
    /// [`scoped_provider`](Self::scoped_provider) resolves every by-name
    /// helper: the tenant's when the ceremony was begun with
    /// [`begin_oauth_login_with_tenant_provider`](Self::begin_oauth_login_with_tenant_provider),
    /// the global registration otherwise. A tenant binding that does not
    /// read is [`OAuthError::NoFlow`].
    pub(super) async fn ceremony_provider(
        &self,
        session: &AuthSession,
        provider_name: &str,
    ) -> Result<Arc<dyn OAuthProvider>, OAuthError> {
        let binding = super::state::ceremony_tenant(session)
            .await
            .map_err(|super::state::UnreadableBinding| OAuthError::NoFlow)?;
        let scope = match binding {
            Some(binding) => Scope::ceremony(binding, provider_name),
            None => Scope::global(),
        };
        self.scoped_provider(&scope, provider_name).await
    }
}
