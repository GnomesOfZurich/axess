//! [`StoredTenantOAuthProviders`]: providers built from a store's records.

use super::{BrokenTenantProvider, IssuerFuture, IssuerProviders, ProviderFuture, TenantProvider};
use super::{
    TenantClientCredential, TenantDpop, TenantOAuthProviderRecord, TenantOAuthProviderStore,
    TenantOAuthProviderStoreError, TenantOAuthProviders,
};
use crate::authn::factor_secret::FactorSecretCipher;
use crate::authn::ids::TenantId;
use axess_clock::Clock;
use axess_factors::client_assertion::ClientAssertionSigner;
use axess_factors::oauth::{OAuthError, OAuthProvider, OAuthProviderConfig};
use axess_rng::SecureRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

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
/// [`invalidate`](Self::invalidate) drops a held provider early, for a
/// reason the record does not show (the IdP rotated its keys and you want
/// discovery redone).
pub struct StoredTenantOAuthProviders<S> {
    store: S,
    cipher: Option<Arc<FactorSecretCipher>>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn SecureRng>,
    built: Mutex<HashMap<(TenantId, String), Built>>,
}

impl<S: TenantOAuthProviderStore> StoredTenantOAuthProviders<S> {
    /// Providers over `store`, with the system clock and RNG. `upsert` seals
    /// each credential with `cipher` and a provider is built by opening it,
    /// so a client secret or private key is never in the table in clear
    /// text, and a sealed credential cannot be read without the cipher.
    pub fn new(store: S, cipher: Arc<FactorSecretCipher>) -> Self {
        Self::with_optional_cipher(store, Some(cipher))
    }

    /// Providers over `store` with no cipher: credentials are read and
    /// written as plain text.
    ///
    /// For tests and development only, like the `plaintext` constructors of
    /// the session and device stores. A production directory keeps client
    /// secrets and private keys in a table, which is where a backup, a
    /// replica or a SQL injection reads them; use [`new`](Self::new).
    pub fn new_unencrypted(store: S) -> Self {
        Self::with_optional_cipher(store, None)
    }

    fn with_optional_cipher(store: S, cipher: Option<Arc<FactorSecretCipher>>) -> Self {
        Self {
            store,
            cipher,
            clock: Arc::new(axess_clock::SystemClock),
            rng: Arc::new(axess_rng::SystemRng),
            built: Mutex::new(HashMap::new()),
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

    /// The underlying store, for listing and reading records.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Write a record (sealing its credential when a cipher is set). Returns
    /// the stored record with its new revision, which the next resolution
    /// builds.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the record is incomplete,
    /// [`OAuthError::Store`] when the credential cannot be sealed or the
    /// store fails.
    pub async fn upsert(
        &self,
        mut record: TenantOAuthProviderRecord,
    ) -> Result<TenantOAuthProviderRecord, OAuthError> {
        if record.name.is_empty() || record.issuer.is_empty() || record.client_id.is_empty() {
            return Err(OAuthError::Config(
                "a tenant provider needs a name, an issuer and a client id".to_string(),
            ));
        }
        if let Some(cipher) = &self.cipher {
            record
                .seal(cipher)
                .map_err(|e| OAuthError::Store(Box::new(e)))?;
        }
        self.store.put(record).await.map_err(store_error)
    }

    /// Remove a record and the provider held for it; `true` when there was a
    /// record.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Store`] when the store fails.
    pub async fn remove(&self, tenant: &TenantId, name: &str) -> Result<bool, OAuthError> {
        let removed = self.store.delete(tenant, name).await.map_err(store_error)?;
        self.invalidate(tenant, name);
        Ok(removed)
    }

    /// Drop the provider held for `(tenant, name)`; the next resolution
    /// builds it afresh.
    pub fn invalidate(&self, tenant: &TenantId, name: &str) {
        self.lock().remove(&(*tenant, name.to_string()));
    }

    /// Drop every provider held for `tenant`.
    pub fn invalidate_tenant(&self, tenant: &TenantId) {
        self.lock().retain(|(t, _), _| t != tenant);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(TenantId, String), Built>> {
        self.built.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn resolve(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Result<Option<Arc<dyn OAuthProvider>>, OAuthError> {
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
    /// key and binding, if the record is still at the revision it was read
    /// at. A failure or a lost race leaves the record as it is: it opens
    /// again, and moves on a later use.
    async fn move_to_current_binding(&self, record: &TenantOAuthProviderRecord, plain: &str) {
        let Some(cipher) = &self.cipher else { return };
        let mut resealed = record.clone();
        if resealed.reseal(cipher, plain).is_err() {
            return;
        }
        if let Err(error) = self.store.put_if_revision(resealed, record.revision).await {
            tracing::warn!(
                target: "axess::federation::oauth_tenant",
                tenant = %record.tenant_id,
                name = %record.name,
                %error,
                "could not move a tenant provider credential to the current binding"
            );
        }
    }

    async fn build(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<OAuthProviderConfig, OAuthError> {
        let (opened, rotated) = record
            .open_credential(self.cipher.as_deref())
            .map_err(|e| OAuthError::Store(Box::new(e)))?;
        if rotated {
            self.move_to_current_binding(record, &opened).await;
        }
        let config = match &record.credential {
            TenantClientCredential::Secret(_) => {
                OAuthProviderConfig::discover(
                    &record.name,
                    &record.issuer,
                    &record.client_id,
                    &opened,
                    &record.redirect_url,
                )
                .await?
            }
            TenantClientCredential::PrivateKeyJwt { signer, .. } => {
                let signer =
                    ClientAssertionSigner::from_spec(record.client_id.clone(), &opened, signer)?;
                OAuthProviderConfig::discover_with_private_key_jwt(
                    &record.name,
                    &record.issuer,
                    signer,
                    &record.redirect_url,
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
    OAuthError::Store(Box::new(e))
}

impl<S: TenantOAuthProviderStore> TenantOAuthProviders for StoredTenantOAuthProviders<S> {
    fn provider<'a>(&'a self, tenant: &'a TenantId, name: &'a str) -> ProviderFuture<'a> {
        Box::pin(self.resolve(tenant, name))
    }

    fn providers_for_issuer<'a>(&'a self, issuer: &'a str) -> IssuerFuture<'a> {
        Box::pin(async move {
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
