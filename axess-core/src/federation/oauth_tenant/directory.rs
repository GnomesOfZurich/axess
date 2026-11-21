//! [`StoredTenantOAuthProviders`]: providers built from a store's records.

mod records;
mod register;

pub use records::TenantOAuthRecords;
pub use register::Reproved;

use super::ownership::OwnershipProofs;
use super::{
    BrokenTenantProvider, IssuerFuture, IssuerProviders, KindFuture, ProviderFuture, TenantProvider,
};
use super::{
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TenantOAuthProviderStore,
    TenantOAuthProviderStoreError, TenantOAuthProviders,
};
use crate::authn::factor::FederatedProvider;
use crate::authn::factor_secret::{FactorSecretCipher, FactorSecretError};
use crate::authn::ids::TenantId;
use axess_clock::Clock;
use axess_factors::client_assertion::ClientAssertionSigner;
use axess_factors::egress::EgressPolicy;
use axess_factors::oauth::{OAuthError, OAuthProvider, OAuthProviderConfig};
use axess_rng::SecureRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

mod reseal;
use reseal::RecordCredentialError;
pub use reseal::ResealReport;

/// The provider of one record revision: built once, by the first resolution
/// that needs it, while the others that arrive meanwhile wait for that build.
///
/// It is held for the record's revision and its content together: a store
/// that numbers revisions per row starts again at 1 when a row is deleted and
/// written anew, so a revision alone can name two different records.
struct Built {
    revision: u64,
    fingerprint: Option<[u8; 32]>,
    provider: Arc<OnceCell<Arc<dyn OAuthProvider>>>,
}

/// The [`TenantOAuthProviders`] over a [`TenantOAuthProviderStore`].
///
/// Each resolution reads the record (one indexed row) and compares its
/// revision with the provider it holds; a match returns the held provider,
/// anything else discovers and builds a new one from the record. So an update
/// written through [`upsert`](Self::upsert), or by any other process into the
/// same store, is used by the next login with no restart and no explicit
/// invalidation, and a deleted record stops resolving at once.
///
/// A revision is built once: the logins that arrive while it is being built
/// wait for that build instead of each running discovery. A build that fails
/// is not kept, so the next resolution tries again. A resolution that read an
/// older revision than the one held reads the record again: when the store
/// still says the same, its revisions have started over (the record was
/// deleted and written anew) and the record is built and held; otherwise the
/// reader had lost a race with an update and takes the newer record.
///
/// The issuer URL of a record is the tenant's to write, so every request the
/// directory's providers make is screened by an [`EgressPolicy`]: HTTPS only,
/// no connection to a loopback, private, link-local, unique-local or
/// metadata address, at discovery and at every endpoint the discovery
/// document names. [`upsert`](Self::upsert) refuses a record whose issuer URL
/// the policy refuses. A deployment that federates with an identity provider
/// on its own network names the opt-out with
/// [`with_egress_policy`](Self::with_egress_policy), and tests against a mock
/// on the loopback interface use
/// [`EgressPolicy::screened_allowing_loopback_http`].
///
/// Whoever registers an issuer and client id first holds them, so a record
/// is stored only once the tenant's ownership of the client is proven: the
/// constructor takes the [`OwnershipProofs`] the deployment accepts, with no
/// default and no proof that accepts everything, and every write
/// ([`upsert`](Self::upsert), [`upsert_attested`](Self::upsert_attested)
/// and an operator's hand-over through
/// [`RequestAuthnService::reassign_tenant_oauth_pair_as`](crate::authn::service::RequestAuthnService::reassign_tenant_oauth_pair_as))
/// asks them first and refuses the record by name when none holds.
/// [`reprove`](Self::reprove) asks them of a stored record without writing
/// it, for records stored before the directory asked.
///
/// [`invalidate`](Self::invalidate) drops a held provider early, for a
/// reason the record does not show (the IdP rotated its keys and you want
/// discovery redone).
///
/// Nothing resolves before the start-up pass
/// ([`reseal_earlier_bindings`](Self::reseal_earlier_bindings)) has run to
/// the end once: [`started`](Self::started) runs it when the service
/// starts, and a directory that was not started runs it before its first
/// resolution. Until a pass succeeds every resolution is refused with the
/// pass's error, which names the record it could not move.
pub struct StoredTenantOAuthProviders<S> {
    store: S,
    cipher: Option<Arc<FactorSecretCipher>>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn SecureRng>,
    egress: EgressPolicy,
    /// The proofs of ownership a write needs.
    ownership: OwnershipProofs,
    /// The `(issuer, client id)` pairs the global registration holds, which
    /// no tenant may register.
    global: Vec<(String, String)>,
    /// Held across the check that a pair is free and the write that takes it,
    /// so two registrations in this process cannot both pass.
    registering: tokio::sync::Mutex<()>,
    built: Mutex<HashMap<(TenantId, String), Built>>,
    /// Bumped by every write the store accepts and by the invalidations;
    /// see
    /// [`TenantOAuthProviders::generation`].
    generation: std::sync::atomic::AtomicU64,
    /// Set once the start-up pass has run to the end: by
    /// [`started`](Self::started), or before the first resolution of a
    /// directory that was not started. A pass that fails sets nothing, so
    /// the next resolution runs it again.
    passed: OnceCell<()>,
}

impl<S: TenantOAuthProviderStore> StoredTenantOAuthProviders<S> {
    /// Providers over `store`, with the system clock and RNG. `upsert` seals
    /// each credential with `cipher` and a provider is built by opening it,
    /// so a client secret or private key is never in the table in clear
    /// text, and a sealed credential cannot be read without the cipher.
    ///
    /// `ownership` names the proofs that a tenant owns the client it
    /// registers which the deployment accepts: every write of a record asks
    /// them first, and a record none of them proves is not stored. There is
    /// no constructor without it:
    ///
    /// ```compile_fail,E0061
    /// use axess_core::federation::oauth_tenant::{
    ///     MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders,
    /// };
    /// let _ = StoredTenantOAuthProviders::new_unencrypted(MemoryTenantOAuthProviderStore::new());
    /// ```
    pub fn new(store: S, cipher: Arc<FactorSecretCipher>, ownership: OwnershipProofs) -> Self {
        Self::with_optional_cipher(store, Some(cipher), ownership)
    }

    /// Providers over `store` with no cipher: credentials are read and
    /// written as plain text.
    ///
    /// For tests and development only, like the `plaintext` constructors of
    /// the session and device stores. A production directory keeps client
    /// secrets and private keys in a table, which is where a backup, a
    /// replica or a SQL injection reads them; use [`new`](Self::new).
    /// `ownership` is as for `new`.
    pub fn new_unencrypted(store: S, ownership: OwnershipProofs) -> Self {
        Self::with_optional_cipher(store, None, ownership)
    }

    fn with_optional_cipher(
        store: S,
        cipher: Option<Arc<FactorSecretCipher>>,
        ownership: OwnershipProofs,
    ) -> Self {
        Self {
            store,
            cipher,
            clock: Arc::new(axess_clock::SystemClock),
            rng: Arc::new(axess_rng::SystemRng),
            egress: EgressPolicy::screened(),
            ownership,
            global: Vec::new(),
            registering: tokio::sync::Mutex::new(()),
            built: Mutex::new(HashMap::new()),
            generation: std::sync::atomic::AtomicU64::new(0),
            passed: OnceCell::new(),
        }
    }

    /// The clock the built providers use for ID-token checks and for the
    /// `iat` and `exp` of `private_key_jwt` assertions.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The RNG the built providers draw assertion `jti` values from.
    pub fn with_rng(mut self, rng: Arc<dyn SecureRng>) -> Self {
        self.rng = rng;
        self
    }

    /// The screen applied to the issuer URL and every URL its discovery
    /// document names. The default is [`EgressPolicy::screened`]; pass
    /// [`EgressPolicy::unscreened`] to federate with an identity provider on
    /// the deployment's own network, or
    /// [`EgressPolicy::screened_allowing_loopback_http`] in tests against a
    /// mock on the loopback interface.
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress = policy;
        self
    }

    /// Name an `(issuer, client id)` pair the global registration holds, so
    /// [`upsert`](Self::upsert) refuses a tenant record that takes it. Call it
    /// once per global provider: a tenant that registered the same pair would
    /// make every back-channel logout token addressed to that client
    /// ambiguous. (The logout route decides for the global registration
    /// whatever a record says; this refuses the record at the door.)
    #[must_use]
    pub fn with_global_registration(
        mut self,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        self.global.push((issuer.into(), client_id.into()));
        self
    }

    /// The records, read-only: [`get`](TenantOAuthRecords::get),
    /// [`list`](TenantOAuthRecords::list),
    /// [`list_by_issuer`](TenantOAuthRecords::list_by_issuer) and
    /// [`list_all`](TenantOAuthRecords::list_all).
    ///
    /// Every write goes through the directory
    /// ([`upsert`](Self::upsert), [`remove`](Self::remove), and an
    /// operator's hand-over), which proves ownership, checks the issuer
    /// against the egress policy, refuses a held or global pair, seals the
    /// credential and drops held providers. A raw write past all of that
    /// stays on the store handle you built the directory from (keep an
    /// `Arc` of it, which is a store too); never pass that handle to a path
    /// a tenant reaches.
    ///
    /// ```compile_fail,E0599
    /// use axess_core::federation::oauth_tenant::{
    ///     MemoryTenantOAuthProviderStore, StoredTenantOAuthProviders,
    ///     TenantOAuthProviderRecord, TenantOAuthProviderStore,
    /// };
    /// async fn write_past(
    ///     directory: &StoredTenantOAuthProviders<MemoryTenantOAuthProviderStore>,
    ///     record: TenantOAuthProviderRecord,
    /// ) {
    ///     let _ = directory.store().put(record).await;
    /// }
    /// ```
    pub fn store(&self) -> TenantOAuthRecords<'_, S> {
        TenantOAuthRecords::new(&self.store)
    }

    /// The store itself, for a test that writes past the directory or reads
    /// a test store's own counters.
    #[cfg(test)]
    pub(crate) fn raw_store(&self) -> &S {
        &self.store
    }

    /// Drop the provider held for `(tenant, name)`; the next resolution
    /// builds it afresh.
    pub fn invalidate(&self, tenant: &TenantId, name: &str) {
        self.lock().remove(&(*tenant, name.to_string()));
        self.bump();
    }

    /// Drop every provider held for `tenant`.
    pub fn invalidate_tenant(&self, tenant: &TenantId) {
        self.lock().retain(|(t, _), _| t != tenant);
        self.bump();
    }

    fn bump(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(TenantId, String), Built>> {
        self.built.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn resolve(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<Arc<dyn OAuthProvider>>, OAuthError> {
        self.pass_once().await?;
        let Some(record) = self.store.get(tenant, name).await.map_err(store_error)? else {
            self.invalidate(tenant, name);
            return Ok(None);
        };
        self.provider_of(&record).await
    }

    /// The provider held for `record`'s revision, built when none is. When
    /// the directory holds a later revision than `record`, the record is read
    /// again and the answer follows the store: a store error is the error,
    /// and a record that is gone is `None`, never the older record served
    /// once more.
    async fn provider_of(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<Option<Arc<dyn OAuthProvider>>, OAuthError> {
        let reread;
        let record = if self.holds_newer_than(record) {
            match self
                .store
                .get(&record.tenant_id, &record.name)
                .await
                .map_err(store_error)?
            {
                Some(current) => {
                    reread = current;
                    &reread
                }
                None => {
                    self.invalidate(&record.tenant_id, &record.name);
                    return Ok(None);
                }
            }
        } else {
            record
        };
        let cell = self.cell_for(record);
        let provider = cell
            .get_or_try_init(|| async {
                let built: Arc<dyn OAuthProvider> = Arc::new(self.build(record).await?);
                Ok::<_, OAuthError>(built)
            })
            .await?;
        Ok(Some(provider.clone()))
    }

    /// Whether the held provider of `record`'s name is for a later revision
    /// than `record` is.
    fn holds_newer_than(&self, record: &TenantOAuthProviderRecord) -> bool {
        self.lock()
            .get(&(record.tenant_id, record.name.clone()))
            .is_some_and(|built| built.revision > record.revision)
    }

    /// The build slot for `record`: the held one when it is for this
    /// revision and this content; a new one, held from now on, otherwise.
    fn cell_for(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Arc<OnceCell<Arc<dyn OAuthProvider>>> {
        let mut held = self.lock();
        let key = (record.tenant_id, record.name.clone());
        let fingerprint = fingerprint(record);
        match held.get(&key) {
            Some(built)
                if built.revision == record.revision
                    && fingerprint.is_some()
                    && built.fingerprint == fingerprint =>
            {
                built.provider.clone()
            }
            _ => {
                let cell = Arc::new(OnceCell::new());
                held.insert(
                    key,
                    Built {
                        revision: record.revision,
                        fingerprint,
                        provider: cell.clone(),
                    },
                );
                cell
            }
        }
    }

    /// Store `record` with its credential sealed under the cipher's current
    /// key and binding, if the stored record still says what `record` says
    /// at the revision it was read at. A failure or a lost race leaves the
    /// record as it is: it opens again, and moves on a later use.
    ///
    /// The revision alone does not show the record is unchanged: one removed
    /// and registered again (by an operator's hand-over, then its old
    /// tenant) starts at revision 1 again, and a write matched on the
    /// revision only would put the removed record, its pair included, back.
    /// So the stored record is read and its content compared, as
    /// [`cell_for`](Self::cell_for) does for a build, before the write that
    /// is still matched on the revision.
    pub(super) async fn move_to_current_binding(
        &self,
        record: &TenantOAuthProviderRecord,
        plain: &str,
    ) {
        let Some(cipher) = &self.cipher else { return };
        let unchanged = match self.store.get(&record.tenant_id, &record.name).await {
            Ok(Some(stored)) => {
                let read = fingerprint(record);
                stored.revision == record.revision && read.is_some() && fingerprint(&stored) == read
            }
            Ok(None) | Err(_) => false,
        };
        if !unchanged {
            return;
        }
        let mut resealed = record.clone();
        if resealed.reseal(cipher, plain).is_err() {
            return;
        }
        if let Err(error) = self.store.put_if_revision(resealed, record.revision).await {
            tracing::warn!(
                target: "axess::federation::oauth_tenant",
                tenant = %record.tenant_id,
                name = %crate::authn::service::log_text::logged_request_text(&record.name),
                %error,
                "could not move a tenant provider credential to the current binding"
            );
        }
    }

    /// Why `record`'s credential did not open, for the log line that names
    /// it: the cipher's error, or, for a credential still under the earlier
    /// binding that the cipher's policy refuses, that binding and the policy.
    fn refusal_reason(
        &self,
        record: &TenantOAuthProviderRecord,
        error: &FactorSecretError,
    ) -> String {
        let earlier = matches!(error, FactorSecretError::Open)
            && self.cipher.as_deref().is_some_and(|cipher| {
                !cipher.earlier_tenant_binding_readable()
                    && matches!(record.credential_due_a_reseal(cipher), Ok(Some(_)))
            });
        if earlier {
            "the credential is still sealed under the earlier binding, which the cipher's \
             with_earlier_tenant_binding policy refuses, and the start-up pass did not move it"
                .to_string()
        } else {
            error.to_string()
        }
    }

    async fn build(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<OAuthProviderConfig, OAuthError> {
        // A credential that does not open is refused, and the refusal is
        // logged naming its record and why, so an operator can find a row the
        // start-up pass could not reach or could not move. The error stays
        // the cipher's own.
        let (opened, rotated) = record
            .open_credential(self.cipher.as_deref())
            .map_err(|e| {
                tracing::warn!(
                    target: "axess::federation::oauth_tenant",
                    refused = %RecordCredentialError::new(record, self.refusal_reason(record, &e)),
                    "a tenant provider credential does not open"
                );
                OAuthError::Store(Box::new(e))
            })?;
        if rotated {
            self.move_to_current_binding(record, &opened).await;
        }
        let config = match &record.credential {
            TenantClientCredential::Secret(_) => {
                OAuthProviderConfig::discover_screened(
                    &record.name,
                    &record.issuer,
                    &record.client_id,
                    &opened,
                    &record.redirect_url,
                    self.egress,
                )
                .await?
            }
            TenantClientCredential::PrivateKeyJwt { signer, .. } => {
                let signer =
                    ClientAssertionSigner::from_spec(record.client_id.clone(), &opened, signer)?;
                OAuthProviderConfig::discover_screened_with_private_key_jwt(
                    &record.name,
                    &record.issuer,
                    signer,
                    &record.redirect_url,
                    self.egress,
                )
                .await?
            }
        };
        let config = if record.scopes.is_empty() {
            config
        } else {
            config.with_scopes(record.scopes.clone())
        };
        let config = match record.dpop {
            TenantDpop::Advertised => config,
            TenantDpop::Off => config.without_dpop(),
            TenantDpop::Required => config.with_dpop(),
        };
        config
            .with_clock(self.clock.clone())
            .with_rng(self.rng.clone())
            .build()
    }
}

/// A digest of what the record says, apart from its revision. `None` when
/// the record does not serialise: no digest is then equal to another, so the
/// provider is rebuilt rather than reused.
///
/// The serialised bytes hold the credential's text, so they are wiped when
/// the digest is taken.
fn fingerprint(record: &TenantOAuthProviderRecord) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;
    let mut content = record.clone();
    content.revision = 0;
    let bytes = Zeroizing::new(serde_json::to_vec(&content).ok()?);
    Some(Sha256::digest(&*bytes).into())
}

fn store_error(e: TenantOAuthProviderStoreError) -> OAuthError {
    if e.is_pair_held() {
        return OAuthError::Config(
            "tenant provider refused: its issuer and client id are already registered by \
             another record"
                .to_string(),
        );
    }
    OAuthError::Store(Box::new(e))
}

impl<S: TenantOAuthProviderStore> TenantOAuthProviders for StoredTenantOAuthProviders<S> {
    fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        Box::pin(self.resolve(tenant, name))
    }

    fn provider_kind<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> KindFuture<'a> {
        Box::pin(async move {
            match self.store.get(tenant, name).await {
                Ok(Some(record)) => record.federated_kind(),
                Ok(None) => FederatedProvider::Custom(name.to_string()),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "tenant OAuth provider record not read for its kind; the login records \
                         Custom(name)"
                    );
                    FederatedProvider::Custom(name.to_string())
                }
            }
        })
    }

    fn built_providers(&self) -> Vec<Arc<dyn OAuthProvider>> {
        self.lock()
            .values()
            .filter_map(|built| built.provider.get().cloned())
            .collect()
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        Box::pin(async move {
            self.pass_once().await?;
            let records = self
                .store
                .list_by_issuer(issuer)
                .await
                .map_err(store_error)?;
            // One record that does not build is reported beside the others
            // and does not fail the call: a logout token from an IdP many
            // tenants share must still reach the tenants that work.
            let mut found = IssuerProviders::default();
            for record in &records {
                match self.provider_of(record).await {
                    Ok(Some(provider)) => found.providers.push(TenantProvider {
                        tenant: record.tenant_id,
                        name: record.name.as_str().into(),
                        provider,
                    }),
                    // Deleted since the listing.
                    Ok(None) => {}
                    Err(error) => found.broken.push(BrokenTenantProvider {
                        tenant: record.tenant_id,
                        name: record.name.as_str().into(),
                        client_id: record.client_id.clone(),
                        error,
                    }),
                }
            }
            Ok(found)
        })
    }
}
