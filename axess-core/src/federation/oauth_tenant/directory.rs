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
struct Built {
    revision: u64,
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
/// older revision than the one held (a reader that lost a race with an
/// update) builds for itself and does not replace the newer provider.
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
    /// Providers over `store`, with the system clock and RNG and no cipher
    /// (credentials are read and written as plain text).
    pub fn new(store: S) -> Self {
        Self {
            store,
            cipher: None,
            clock: Arc::new(axess_clock::SystemClock),
            rng: Arc::new(axess_rng::SystemRng),
            built: Mutex::new(HashMap::new()),
        }
    }

    /// Seal credentials with `cipher` on [`upsert`](Self::upsert) and open
    /// them when a provider is built. A sealed credential cannot be read
    /// without it.
    pub fn with_cipher(mut self, cipher: Arc<FactorSecretCipher>) -> Self {
        self.cipher = Some(cipher);
        self
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
        self.provider_of(&record).await.map(Some)
    }

    /// The provider held for `record`'s revision, built when none is.
    async fn provider_of(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<Arc<dyn OAuthProvider>, OAuthError> {
        let cell = self.cell_for(record);
        let provider = cell
            .get_or_try_init(|| async {
                let built: Arc<dyn OAuthProvider> = Arc::new(self.build(record).await?);
                Ok::<_, OAuthError>(built)
            })
            .await?;
        Ok(provider.clone())
    }

    /// The build slot for `record`'s revision: the held one when it is for
    /// this revision; a new one, held from now on, when the held one is
    /// older or there is none; a new one that is not held when the held one
    /// is newer, since this record was read before an update.
    fn cell_for(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Arc<OnceCell<Arc<dyn OAuthProvider>>> {
        let mut held = self.lock();
        let key = (record.tenant_id, record.name.clone());
        match held.get(&key) {
            Some(built) if built.revision == record.revision => built.provider.clone(),
            Some(built) if built.revision > record.revision => Arc::new(OnceCell::new()),
            _ => {
                let cell = Arc::new(OnceCell::new());
                held.insert(
                    key,
                    Built {
                        revision: record.revision,
                        provider: cell.clone(),
                    },
                );
                cell
            }
        }
    }

    async fn build(
        &self,
        record: &TenantOAuthProviderRecord,
    ) -> Result<OAuthProviderConfig, OAuthError> {
        let opened = record
            .open_secret(self.cipher.as_deref())
            .map_err(|e| OAuthError::Store(Box::new(e)))?;
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
                    Ok(provider) => found.providers.push(TenantProvider {
                        tenant: record.tenant_id,
                        name: record.name.as_str().into(),
                        provider,
                    }),
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
