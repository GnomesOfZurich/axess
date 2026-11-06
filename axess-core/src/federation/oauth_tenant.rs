//! Bring-your-own identity provider, per tenant.
//!
//! The global registration ([`AuthnServiceBuilder::with_oauth_provider`])
//! names one provider for the whole process. A product where each customer
//! signs in with its own IdP (this tenant's Entra, that tenant's Keycloak,
//! both called `"sso"` in the UI) needs the provider chosen by
//! `(tenant, name)` at request time, from configuration an operator edits
//! while the service runs. This module is that:
//!
//! - [`TenantOAuthProviders`] is the seam the service asks:
//!   "the provider named `name` for `tenant`". Implement it to resolve from
//!   anywhere.
//! - [`TenantOAuthProviderRecord`] is the configuration of one such provider:
//!   issuer, client id, redirect URL, scopes, the client credential
//!   (a secret, or a `private_key_jwt` key) and the DPoP choice
//!   ([`TenantDpop`]), the credential sealed at rest when a
//!   [`FactorSecretCipher`] is configured.
//! - [`TenantOAuthProviderStore`] keeps records ([`MemoryTenantOAuthProviderStore`]
//!   here, `SqliteTenantOAuthProviderStore` under the `sqlite` feature).
//! - [`StoredTenantOAuthProviders`] is the [`TenantOAuthProviders`] over a
//!   store: it discovers and builds the provider on first use, keeps it, and
//!   rebuilds it the moment the record's revision moves, so an update is
//!   used by the next login with no restart and no call to make.
//!
//! The service side is
//! [`AuthnServiceBuilder::with_tenant_oauth_providers`](crate::authn::service::AuthnServiceBuilder::with_tenant_oauth_providers)
//! and [`AuthnService::begin_oauth_login_with_tenant_provider`](crate::authn::service::AuthnService::begin_oauth_login_with_tenant_provider).
//!
//! [`AuthnServiceBuilder::with_oauth_provider`]: crate::authn::service::AuthnServiceBuilder::with_oauth_provider
//! [`FactorSecretCipher`]: crate::authn::factor_secret::FactorSecretCipher

mod directory;
#[cfg(all(test, feature = "testing-oauth"))]
mod directory_tests;
mod live;
mod memory;
mod record;
#[cfg(test)]
mod record_tests;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use directory::StoredTenantOAuthProviders;
pub use live::LiveTenantOAuthProviders;
pub use memory::MemoryTenantOAuthProviderStore;
pub use record::{TenantClientCredential, TenantDpop, TenantOAuthProviderRecord};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteTenantOAuthProviderStore;

use crate::authn::ids::TenantId;
use axess_factors::oauth::{OAuthError, OAuthProvider};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What [`TenantOAuthProviders::provider`] returns: the provider, `None` for
/// an unknown name, or why it could not be built.
pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Arc<dyn OAuthProvider>>, OAuthError>> + Send + 'a>>;

/// A provider a tenant has configured, with the tenant that owns it.
#[derive(Clone)]
pub struct TenantProvider {
    /// The tenant the provider belongs to.
    pub tenant: TenantId,
    /// The provider's name within the tenant.
    pub name: Arc<str>,
    /// The provider, built from the tenant's configuration.
    pub provider: Arc<dyn OAuthProvider>,
}

/// A provider a tenant has configured that could not be built: its
/// credential does not open, its discovery failed, it requires DPoP of an IdP
/// that does not advertise it.
#[derive(Debug)]
pub struct BrokenTenantProvider {
    /// The tenant the provider belongs to.
    pub tenant: TenantId,
    /// The provider's name within the tenant.
    pub name: Arc<str>,
    /// The client id the tenant registered, from its configuration, so a
    /// caller can tell whether a request was addressed to this provider.
    pub client_id: String,
    /// Why it was not built.
    pub error: OAuthError,
}

/// What [`TenantOAuthProviders::providers_for_issuer`] finds: the providers
/// of the issuer that were built, and those that could not be.
#[derive(Default)]
pub struct IssuerProviders {
    /// The providers built from their tenants' configuration.
    pub providers: Vec<TenantProvider>,
    /// The providers of the issuer that could not be built.
    pub broken: Vec<BrokenTenantProvider>,
}

/// What [`TenantOAuthProviders::providers_for_issuer`] returns.
pub type IssuerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<IssuerProviders, OAuthError>> + Send + 'a>>;

/// Resolves the OAuth provider a tenant has under a name, at request time.
///
/// Its methods return boxed futures ([`ProviderFuture`], [`IssuerFuture`])
/// because the service holds it as `Arc<dyn TenantOAuthProviders>`, and a
/// trait with `impl Future` returns is not object safe;
/// [`TenantOAuthProviderStore`], used only as a generic parameter, keeps
/// `impl Future`.
///
/// The tenant is the caller's to establish from something it trusts (the
/// route, the host, the signed-in session) and never from a request body;
/// `begin_oauth_login_with_tenant_provider` records it in the server-side session so the
/// callback resolves against the same tenant.
pub trait TenantOAuthProviders: Send + Sync + 'static {
    /// The provider named `name` for `tenant`, or `None` when the tenant has
    /// none by that name.
    ///
    /// # Errors
    ///
    /// Whatever stops the provider from being built: an unreachable store, a
    /// record that does not open, a discovery that fails, a record that
    /// requires DPoP ([`TenantDpop::Required`]) of an IdP that does not
    /// advertise it.
    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a>;

    /// Every provider of every tenant whose issuer is exactly `issuer`.
    ///
    /// For a request that arrives from the IdP with no session and no
    /// tenant, only the issuer it names: the back-channel logout token.
    /// The caller decides what several matches mean; this reports them all.
    /// A provider that cannot be built is reported in
    /// [`IssuerProviders::broken`] and does not fail the call, so one
    /// tenant's broken configuration does not hide the other tenants of a
    /// shared issuer.
    ///
    /// # Errors
    ///
    /// Whatever stops the issuer's providers from being listed at all: an
    /// unreachable store.
    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a>;
}

/// A [`TenantOAuthProviderStore`] failed. The backend's error is kept as the
/// [`source`](std::error::Error::source).
#[derive(Debug, thiserror::Error)]
#[error("tenant OAuth provider store: {0}")]
pub struct TenantOAuthProviderStoreError(#[source] Box<dyn std::error::Error + Send + Sync>);

impl TenantOAuthProviderStoreError {
    /// The error of a store backend.
    pub fn new(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(cause.into())
    }
}

/// Persistence for [`TenantOAuthProviderRecord`]s, keyed by
/// `(tenant_id, name)`.
///
/// The store owns the record's `revision`: [`put`](Self::put) stores the
/// record with the revision after the one it replaces (1 for a new record)
/// and returns what it stored, so a reader holding an older revision can
/// tell its provider is stale.
pub trait TenantOAuthProviderStore: Send + Sync + 'static {
    /// The record for `(tenant, name)`, if any.
    fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> impl Future<
        Output = Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>,
    > + Send;

    /// Insert or replace a record; returns it with its new revision.
    fn put(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> impl Future<Output = Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError>> + Send;

    /// Store `record` only if the stored record still has revision `expected`,
    /// returning what it stored (with the next revision), or `None` when the
    /// revision had moved or the record was gone. The compare and the write
    /// are one step.
    ///
    /// [`StoredTenantOAuthProviders`] uses it to move a credential sealed
    /// under a previous key or binding to the current one the first time the
    /// record is used. The default writes nothing and returns `None`, so a
    /// store that does not override it keeps the record as it is; override it
    /// where the store can make the compare and the write atomic.
    fn put_if_revision(
        &self,
        record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> impl Future<
        Output = Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>,
    > + Send {
        let _ = (record, expected);
        async { Ok(None) }
    }

    /// Remove a record; `true` when there was one.
    fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> impl Future<Output = Result<bool, TenantOAuthProviderStoreError>> + Send;

    /// Every record, of any tenant, whose issuer is exactly `issuer`.
    fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> impl Future<Output = Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>> + Send;

    /// Every record of `tenant`, by name.
    fn list(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>> + Send;
}

/// A shared source: keep an `Arc` to the directory for `upsert` and hand a
/// clone to the builder.
impl<T: TenantOAuthProviders> TenantOAuthProviders for Arc<T> {
    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        (**self).provider(tenant, name)
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        (**self).providers_for_issuer(issuer)
    }
}
