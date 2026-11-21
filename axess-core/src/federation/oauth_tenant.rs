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
//! - [`ClientOwnershipProof`] is what the directory asks before it stores a
//!   record: that the tenant owns the `(issuer, client_id)` pair it
//!   registers. [`TokenEndpointProbe`] and [`OperatorAttestation`] ship, and
//!   [`OwnershipProofs`] names which a deployment accepts.
//!
//! The service side is
//! [`AuthnServiceBuilder::with_tenant_oauth_providers`](crate::authn::service::AuthnServiceBuilder::with_tenant_oauth_providers)
//! and [`AuthnService::begin_oauth_login_with_tenant_provider`](crate::authn::service::AuthnService::begin_oauth_login_with_tenant_provider).
//!
//! [`AuthnServiceBuilder::with_oauth_provider`]: crate::authn::service::AuthnServiceBuilder::with_oauth_provider
//! [`FactorSecretCipher`]: crate::authn::factor_secret::FactorSecretCipher

mod directory;
#[cfg(all(test, feature = "oauth"))]
mod directory_fault_tests;
#[cfg(all(test, feature = "oauth"))]
mod directory_held_tests;
#[cfg(all(test, feature = "oauth"))]
mod directory_pair_tests;
#[cfg(all(test, feature = "oauth"))]
mod directory_register_tests;
#[cfg(all(test, feature = "oauth"))]
mod directory_tests;
mod live;
#[cfg(all(test, feature = "oauth"))]
mod live_tests;
mod memory;
mod ownership;
#[cfg(all(test, feature = "oauth"))]
mod ownership_tests;
mod record;
#[cfg(test)]
mod record_tests;
#[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
mod sqlite;
#[cfg(all(test, any(feature = "sqlite", feature = "sqlite-unbundled")))]
mod sqlite_tests;

/// Doctests: a `TenantOAuthProviderStore` that leaves out the conditional
/// write or the full listing does not compile.
#[cfg(doctest)]
#[doc = include_str!("oauth_tenant/required_methods.md")]
struct RequiredMethods;

pub use directory::{Reproved, ResealReport, StoredTenantOAuthProviders, TenantOAuthRecords};
pub use live::LiveTenantOAuthProviders;
pub(crate) use live::pair_of;
pub use memory::MemoryTenantOAuthProviderStore;
pub use ownership::{
    ClientOwnershipProof, DEFAULT_OWNERSHIP_PROBE_TIMEOUT, OperatorAttestation,
    OwnershipAttestation, OwnershipClaim, OwnershipFuture, OwnershipProofs, OwnershipProven,
    OwnershipPurpose, OwnershipRefused, TokenEndpointProbe,
};
pub use record::{TenantClientCredential, TenantDpop, TenantOAuthProviderRecord};
#[cfg(any(feature = "sqlite", feature = "sqlite-unbundled"))]
pub use sqlite::SqliteTenantOAuthProviderStore;

use crate::authn::factor::FederatedProvider;
use crate::authn::ids::TenantId;
use axess_factors::oauth::{OAuthError, OAuthProvider};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What [`TenantOAuthProviders::provider`] returns: the provider, `None` for
/// an unknown name, or why it could not be built.
pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Arc<dyn OAuthProvider>>, OAuthError>> + Send + 'a>>;

/// What [`TenantOAuthProviders::provider_kind`] returns.
pub type KindFuture<'a> = Pin<Box<dyn Future<Output = FederatedProvider> + Send + 'a>>;

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

    /// The kind every login through the provider named `name` for `tenant`
    /// records: the [`FederatedProvider`] its configuration names, never one
    /// read from its issuer URL.
    ///
    /// The default is `FederatedProvider::Custom(name)`, the kind of a
    /// provider whose configuration names none.
    /// [`StoredTenantOAuthProviders`] answers the record's
    /// [`kind`](TenantOAuthProviderRecord::kind); a record it cannot read
    /// answers the default, with a warning. [`LiveTenantOAuthProviders`]
    /// answers the kind the reload that installed the entry named.
    fn provider_kind<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> KindFuture<'a> {
        let _ = tenant;
        Box::pin(std::future::ready(FederatedProvider::Custom(
            name.to_string(),
        )))
    }

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

    /// A number that changes whenever this source's answers can have changed:
    /// a provider added, replaced or removed through it. The back-channel
    /// logout route remembers, for a short time, that an issuer had no
    /// provider; it trusts a remembered miss only while this number is the
    /// one it saw when it asked, so a provider added through a live reload is
    /// found at once.
    ///
    /// The default is a constant, which leaves the remembered miss bounded by
    /// its time alone: a source that changes underneath the process (a store
    /// another process writes) or that does not implement this keeps that
    /// bound.
    fn generation(&self) -> u64 {
        0
    }

    /// The providers this registry holds built right now, over all tenants,
    /// without building any: what the JWKS refresh loop and
    /// [`AuthnService::refresh_all_jwks`](crate::authn::service::AuthnService::refresh_all_jwks)
    /// refresh beside the service's own providers, so a signing key a
    /// tenant's IdP withdrew does not stay trusted until the cache ages out.
    ///
    /// There is no default: a registry that refreshes nothing would keep a
    /// withdrawn key trusted without saying so. A registry that builds its
    /// providers on demand returns the ones it holds; one that holds none
    /// returns `Vec::new()` and means it.
    fn built_providers(&self) -> Vec<Arc<dyn OAuthProvider>>;
}

/// A [`TenantOAuthProviderStore`] failed. The backend's error is kept as the
/// [`source`](std::error::Error::source).
#[derive(Debug, thiserror::Error)]
#[error("tenant OAuth provider store: {cause}")]
pub struct TenantOAuthProviderStoreError {
    #[source]
    cause: Box<dyn std::error::Error + Send + Sync>,
    kind: StoreRefusal,
}

/// Which of the named refusals a [`TenantOAuthProviderStoreError`] is, if
/// any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreRefusal {
    /// A backend failure.
    Backend,
    /// The pair is held by another record.
    PairHeld,
    /// The store cannot compare and write in one step.
    PutIfRevisionUnsupported,
}

impl TenantOAuthProviderStoreError {
    /// The error of a store backend.
    pub fn new(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            cause: cause.into(),
            kind: StoreRefusal::Backend,
        }
    }

    /// The refusal of a write whose issuer and client id another record
    /// already holds: what a store's unique constraint over the pair reports.
    /// [`StoredTenantOAuthProviders::upsert`] turns it into the same
    /// [`OAuthError::Config`] as its
    /// own check.
    pub fn pair_held() -> Self {
        Self {
            cause: "the record's issuer and client id are already registered by another record"
                .into(),
            kind: StoreRefusal::PairHeld,
        }
    }

    /// Whether this is the refusal [`pair_held`](Self::pair_held) builds.
    pub fn is_pair_held(&self) -> bool {
        self.kind == StoreRefusal::PairHeld
    }

    /// The refusal of a [`TenantOAuthProviderStore::put_if_revision`] that
    /// cannot compare and write in one step: nothing was written.
    pub fn put_if_revision_unsupported() -> Self {
        Self {
            cause: "this store does not implement put_if_revision, so a credential under a \
                    previous key or binding is not moved to the current one"
                .into(),
            kind: StoreRefusal::PutIfRevisionUnsupported,
        }
    }

    /// Whether this is the refusal
    /// [`put_if_revision_unsupported`](Self::put_if_revision_unsupported)
    /// builds: the store wrote nothing, and never will for this method.
    pub fn is_put_if_revision_unsupported(&self) -> bool {
        self.kind == StoreRefusal::PutIfRevisionUnsupported
    }

    /// The refusal of a [`TenantOAuthProviderStore::reassign_pair`] that
    /// cannot remove the holders and write the record in one step: nothing
    /// was removed or written.
    pub fn reassign_pair_unsupported() -> Self {
        Self::new(
            "this store cannot reassign_pair: a pair cannot be handed from the record \
             that holds it to another in one step",
        )
    }
}

/// What [`TenantOAuthProviderStore::reassign_pair`] did: the record it stored
/// and the records it removed to free that record's issuer and client id.
#[derive(Debug, Clone)]
pub struct ReassignedPair {
    /// The record as stored, with its new revision.
    pub stored: TenantOAuthProviderRecord,
    /// Each record that held the pair and was removed, as it was stored;
    /// empty when the pair was free or already the record's own.
    pub removed: Vec<TenantOAuthProviderRecord>,
}

/// Persistence for [`TenantOAuthProviderRecord`]s, keyed by
/// `(tenant_id, name)`.
///
/// The store owns the record's `revision`: [`put`](Self::put) stores the
/// record with the revision after the one it replaces (1 for a new record)
/// and returns what it stored, so a reader holding an older revision can
/// tell its provider is stale.
///
/// The store also owns the uniqueness of `(issuer, client_id)` across every
/// tenant: [`put`](Self::put) and [`put_if_revision`](Self::put_if_revision)
/// refuse a record whose pair another record holds, with
/// [`TenantOAuthProviderStoreError::pair_held`], atomically against writers
/// in other processes (a unique index, not a read followed by a write). Two
/// records of one pair make every back-channel logout token for that client
/// ambiguous and refused. The shipped stores enforce it; a store of your own
/// must too, since the directory's own check holds only within one process.
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
    /// under a previous key or binding to the current one: in the start-up
    /// pass over every record
    /// ([`reseal_earlier_bindings`](StoredTenantOAuthProviders::reseal_earlier_bindings)),
    /// and the first time a record is used. Required: there is no default,
    /// since one that wrote nothing would leave every such credential where
    /// it is, and one that read and then wrote would overwrite an update
    /// another writer made in between, a rotated credential included.
    ///
    /// A store that cannot make the compare and the write one step returns
    /// [`TenantOAuthProviderStoreError::put_if_revision_unsupported`] and
    /// writes nothing. No credential is dropped for it: the start-up pass
    /// counts the record in [`ResealReport::not_moved`] and logs a warning
    /// naming it, and at use the cipher's
    /// [`with_earlier_tenant_binding`](crate::authn::factor_secret::FactorSecretCipher::with_earlier_tenant_binding)
    /// policy decides. Under the default,
    /// [`LegacyBlobs::Reject`](crate::session::legacy_blobs::LegacyBlobs::Reject),
    /// a credential still under the earlier binding is refused, and the
    /// refusal is logged naming the record and the reason; under the opt-out
    /// it serves as it is, as a credential under a previous key does, with a
    /// warning on each such use that says why it was not moved.
    fn put_if_revision(
        &self,
        record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> impl Future<
        Output = Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>,
    > + Send;

    /// Give `record`'s issuer and client id to `record` in one step: remove
    /// every other record that holds that pair, of any tenant, and store
    /// `record` as [`put`](Self::put) does, so no writer, in this process or
    /// another, can take the pair between the removal and the write.
    ///
    /// [`RequestAuthnService::reassign_tenant_oauth_pair_as`](crate::authn::service::RequestAuthnService::reassign_tenant_oauth_pair_as)
    /// calls it through the directory, for an operator handing a squatted
    /// pair to the tenant that owns the client.
    /// A delete followed by a put would leave the pair free in between, and
    /// the tenant that took it could take it again. The shipped stores make
    /// both one transaction.
    ///
    /// Every store implements it: there is no default, so a store that has
    /// not decided how it hands a pair over does not compile, rather than
    /// refusing the operator at the moment a squatted pair has to move.
    /// A store that cannot make the removal and the write one step returns
    /// [`TenantOAuthProviderStoreError::reassign_pair_unsupported`] and
    /// changes nothing.
    ///
    /// ```compile_fail,E0046
    /// use axess_core::authn::ids::TenantId;
    /// use axess_core::federation::oauth_tenant::{
    ///     TenantOAuthProviderRecord, TenantOAuthProviderStore, TenantOAuthProviderStoreError,
    /// };
    ///
    /// struct NoHandover;
    ///
    /// impl TenantOAuthProviderStore for NoHandover {
    ///     async fn get(
    ///         &self,
    ///         _: &TenantId,
    ///         _: &str,
    ///     ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
    ///         Ok(None)
    ///     }
    ///     async fn put(
    ///         &self,
    ///         record: TenantOAuthProviderRecord,
    ///     ) -> Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError> {
    ///         Ok(record)
    ///     }
    ///     async fn put_if_revision(
    ///         &self,
    ///         _: TenantOAuthProviderRecord,
    ///         _: u64,
    ///     ) -> Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
    ///         Ok(None)
    ///     }
    ///     async fn delete(&self, _: &TenantId, _: &str) -> Result<bool, TenantOAuthProviderStoreError> {
    ///         Ok(false)
    ///     }
    ///     async fn list_by_issuer(
    ///         &self,
    ///         _: &str,
    ///     ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
    ///         Ok(Vec::new())
    ///     }
    ///     async fn list(
    ///         &self,
    ///         _: &TenantId,
    ///     ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
    ///         Ok(Vec::new())
    ///     }
    ///     async fn list_all(
    ///         &self,
    ///     ) -> Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError> {
    ///         Ok(Vec::new())
    ///     }
    /// }
    /// ```
    fn reassign_pair(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> impl Future<Output = Result<ReassignedPair, TenantOAuthProviderStoreError>> + Send;

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

    /// Every record of every tenant, ordered by tenant and name.
    ///
    /// The directory's start-up pass reads it to re-seal every credential
    /// still sealed under an earlier binding
    /// ([`reseal_earlier_bindings`](StoredTenantOAuthProviders::reseal_earlier_bindings)),
    /// so no record is left that only an older policy opens. Required: the
    /// pass must reach every record, and only the store knows them all.
    fn list_all(
        &self,
    ) -> impl Future<Output = Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>> + Send;
}

/// A shared store: build the directory over one `Arc` and keep a clone for
/// the writes an operator makes past it (a migration, a repair), which
/// [`StoredTenantOAuthProviders::store`] does not offer.
impl<T: TenantOAuthProviderStore> TenantOAuthProviderStore for Arc<T> {
    fn get(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> impl Future<
        Output = Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>,
    > + Send {
        (**self).get(tenant, name)
    }

    fn put(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> impl Future<Output = Result<TenantOAuthProviderRecord, TenantOAuthProviderStoreError>> + Send
    {
        (**self).put(record)
    }

    fn put_if_revision(
        &self,
        record: TenantOAuthProviderRecord,
        expected: u64,
    ) -> impl Future<
        Output = Result<Option<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>,
    > + Send {
        (**self).put_if_revision(record, expected)
    }

    fn reassign_pair(
        &self,
        record: TenantOAuthProviderRecord,
    ) -> impl Future<Output = Result<ReassignedPair, TenantOAuthProviderStoreError>> + Send {
        (**self).reassign_pair(record)
    }

    fn delete(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> impl Future<Output = Result<bool, TenantOAuthProviderStoreError>> + Send {
        (**self).delete(tenant, name)
    }

    fn list_by_issuer(
        &self,
        issuer: &str,
    ) -> impl Future<Output = Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>> + Send
    {
        (**self).list_by_issuer(issuer)
    }

    fn list(
        &self,
        tenant: &TenantId,
    ) -> impl Future<Output = Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>> + Send
    {
        (**self).list(tenant)
    }

    fn list_all(
        &self,
    ) -> impl Future<Output = Result<Vec<TenantOAuthProviderRecord>, TenantOAuthProviderStoreError>> + Send
    {
        (**self).list_all()
    }
}

/// A shared source: keep an `Arc` to the directory for `upsert` and hand a
/// clone to the builder.
impl<T: TenantOAuthProviders> TenantOAuthProviders for Arc<T> {
    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        (**self).provider(tenant, name)
    }

    fn provider_kind<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> KindFuture<'a> {
        (**self).provider_kind(tenant, name)
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        (**self).providers_for_issuer(issuer)
    }

    fn generation(&self) -> u64 {
        (**self).generation()
    }

    fn built_providers(&self) -> Vec<Arc<dyn OAuthProvider>> {
        (**self).built_providers()
    }
}
