//! The start-up pass that moves every tenant OAuth credential to the current
//! key and binding, so the earlier binding can be refused at use.

use super::{StoredTenantOAuthProviders, store_error};
use crate::authn::factor_secret::{FactorSecretCipher, FactorSecretError};
use crate::authn::ids::TenantId;
use crate::federation::oauth_tenant::{TenantOAuthProviderRecord, TenantOAuthProviderStore};
use axess_factors::oauth::OAuthError;

/// How many times the pass re-reads a record whose revision moved under its
/// write before it gives up on it.
const RESEAL_ATTEMPTS: usize = 4;

/// A tenant provider record whose credential could not be opened or moved,
/// named by its tenant and provider name.
#[derive(Debug, thiserror::Error)]
#[error("tenant {tenant} provider {name:?}: {reason}")]
pub(crate) struct RecordCredentialError {
    tenant: TenantId,
    name: String,
    reason: String,
}

impl RecordCredentialError {
    /// The error for `record`, with `reason` as its text.
    pub(crate) fn new(record: &TenantOAuthProviderRecord, reason: impl ToString) -> Self {
        Self {
            tenant: record.tenant_id,
            name: record.name.clone(),
            reason: reason.to_string(),
        }
    }
}

fn refused(record: &TenantOAuthProviderRecord, reason: impl ToString) -> OAuthError {
    OAuthError::Store(Box::new(RecordCredentialError::new(record, reason)))
}

/// What one run of the start-up pass did: how many credentials it moved to
/// the current key and binding, and how many it could not move because the
/// store does not implement
/// [`put_if_revision`](TenantOAuthProviderStore::put_if_revision).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResealReport {
    /// Credentials moved to the current key and binding.
    pub moved: usize,
    /// Credentials due a move that the store could not write, each named in
    /// a warning. Under the cipher's default
    /// [`with_earlier_tenant_binding`](FactorSecretCipher::with_earlier_tenant_binding)
    /// policy one still under the earlier binding is refused at use; under
    /// the opt-out it serves, with a warning on each use.
    pub not_moved: usize,
}

/// What one record's turn in the pass came to.
enum Resealed {
    /// The credential was moved.
    Moved,
    /// The credential was current, or the record is gone.
    Left,
    /// The store cannot write the move.
    NotMoved,
}

impl<S: TenantOAuthProviderStore> StoredTenantOAuthProviders<S> {
    /// Run [`reseal_earlier_bindings`](Self::reseal_earlier_bindings) and
    /// hand the directory back: the way to start one, so a record the pass
    /// cannot move stops the service at start rather than its first login.
    ///
    /// A directory that is not started runs the same pass before its first
    /// resolution, and resolves nothing until the pass succeeds, so it is
    /// never served with a credential only an earlier policy opens either
    /// way; the pass runs once whichever comes first.
    ///
    /// # Errors
    ///
    /// As [`reseal_earlier_bindings`](Self::reseal_earlier_bindings): the
    /// directory does not start, and the error names the record.
    pub async fn started(self) -> Result<Self, OAuthError> {
        self.pass_once().await?;
        Ok(self)
    }

    /// The start-up pass, run to the end once per directory: the first call
    /// runs it (concurrent callers wait for that run), a call after a pass
    /// that succeeded returns at once, and a call after one that failed
    /// runs it again.
    pub(super) async fn pass_once(&self) -> Result<(), OAuthError> {
        self.passed
            .get_or_try_init(|| async { self.reseal_earlier_bindings().await.map(drop) })
            .await
            .map(|_| ())
    }

    /// Move every stored credential that is sealed under an earlier binding
    /// (the issuer and client id only, as 0.15 to 0.19 sealed it), the first
    /// release's binding or the previous key to the current key and binding,
    /// and return how many were moved. The pass reads the earlier binding
    /// whatever the cipher's
    /// [`with_earlier_tenant_binding`](FactorSecretCipher::with_earlier_tenant_binding)
    /// policy says, since retiring it is its purpose, and logs its counts.
    ///
    /// It is idempotent: a credential already current is left alone, so a
    /// second pass moves none. Each move is a
    /// [`put_if_revision`](TenantOAuthProviderStore::put_if_revision) at the
    /// revision read, and a record written meanwhile is read again and tried
    /// again. Without a cipher there is nothing sealed and it moves none.
    ///
    /// A store whose `put_if_revision` answers
    /// [`put_if_revision_unsupported`](crate::federation::oauth_tenant::TenantOAuthProviderStoreError::put_if_revision_unsupported)
    /// writes nothing and drops nothing: the record is counted in
    /// [`ResealReport::not_moved`], a warning names it and says what that
    /// means under the cipher's policy, and the pass goes on.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Store`] when the store cannot list, read or write, and
    /// when a sealed credential opens under no binding the cipher knows or
    /// keeps changing under the pass: that error names the tenant and the
    /// provider, and [`started`](Self::started) refuses to start.
    pub async fn reseal_earlier_bindings(&self) -> Result<ResealReport, OAuthError> {
        let Some(cipher) = self.cipher.clone() else {
            return Ok(ResealReport::default());
        };
        let records = self.store.list_all().await.map_err(store_error)?;
        let mut report = ResealReport::default();
        for record in records {
            match self.reseal_one(&cipher, record).await? {
                Resealed::Moved => report.moved += 1,
                Resealed::NotMoved => report.not_moved += 1,
                Resealed::Left => {}
            }
        }
        tracing::info!(
            target: "axess::federation::oauth_tenant",
            moved = report.moved,
            not_moved = report.not_moved,
            "tenant provider credentials moved to the current binding at start"
        );
        Ok(report)
    }

    /// Move one record's credential, re-reading it when its revision moved.
    async fn reseal_one(
        &self,
        cipher: &FactorSecretCipher,
        mut record: TenantOAuthProviderRecord,
    ) -> Result<Resealed, OAuthError> {
        for _ in 0..RESEAL_ATTEMPTS {
            let due = record
                .credential_due_a_reseal(cipher)
                .map_err(|e| refused(&record, opened_by_nothing(&e)))?;
            let Some(plain) = due else {
                return Ok(Resealed::Left);
            };
            let mut resealed = record.clone();
            resealed
                .reseal(cipher, &plain)
                .map_err(|e| refused(&record, e))?;
            match self.store.put_if_revision(resealed, record.revision).await {
                Ok(Some(_)) => {
                    self.invalidate(&record.tenant_id, &record.name);
                    return Ok(Resealed::Moved);
                }
                Ok(None) => {}
                Err(error) if error.is_put_if_revision_unsupported() => {
                    not_moved_warning(cipher, &record, &error);
                    return Ok(Resealed::NotMoved);
                }
                Err(error) => return Err(store_error(error)),
            }
            match self
                .store
                .get(&record.tenant_id, &record.name)
                .await
                .map_err(store_error)?
            {
                Some(current) => record = current,
                None => return Ok(Resealed::Left),
            }
        }
        Err(refused(
            &record,
            "the record kept changing while its credential was moved to the current binding",
        ))
    }
}

/// The warning for a record whose credential the store could not move,
/// naming it and saying what the cipher's policy makes of it at use.
fn not_moved_warning(
    cipher: &FactorSecretCipher,
    record: &TenantOAuthProviderRecord,
    error: &crate::federation::oauth_tenant::TenantOAuthProviderStoreError,
) {
    let at_use = if cipher.earlier_tenant_binding_readable() {
        "it serves as it is, under the cipher's opt-out for the earlier binding"
    } else {
        "a credential under the earlier binding is refused at use until it is moved"
    };
    tracing::warn!(
        target: "axess::federation::oauth_tenant",
        record = %RecordCredentialError::new(record, error),
        at_use,
        "a tenant provider credential was not moved to the current binding at start"
    );
}

/// Why a sealed credential that opens under no binding is refused.
fn opened_by_nothing(error: &FactorSecretError) -> String {
    format!("the credential opens under no binding the cipher knows ({error})")
}
