//! The service's session check and the identifier lookup that costs the
//! same whether or not the identifier exists.

use crate::authn::error::AuthnError;
use crate::authn::store::{FactorStore, IdentityStore};
use crate::session::extractor::AuthSession;

impl<I, F> crate::authn::service::AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Check whether the current session is valid (consults the registry if installed).
    #[tracing::instrument(skip(self, session))]
    pub async fn check_session(&self, session: &AuthSession) -> bool {
        if !session.is_authenticated().await {
            return false;
        }
        let user_id = match session.user_id().await {
            Some(id) => id,
            None => return false,
        };
        let sid = session.session_id().await;
        if let Some(reg) = &self.inner.registry {
            reg.is_valid(&user_id, &sid).await
        } else {
            true
        }
    }

    /// A random v4 UUID drawn from the service's RNG, so a deterministic
    /// RNG pins the throwaway ids the equalization lookups run against.
    pub(super) fn dummy_uuid(&self) -> uuid::Uuid {
        let mut bytes = [0u8; 16];
        self.inner.rng.fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes).into_uuid()
    }

    pub(super) fn dummy_tenant_id(&self) -> crate::authn::ids::TenantId {
        crate::authn::ids::TenantId::try_new(self.dummy_uuid().to_string())
            .expect("a UUID is a valid TenantId")
    }

    /// Look up a user by identifier with timing-equalization on miss.
    ///
    /// Returns `Ok(Some(user))` on a clean find + `validate()`,
    /// `Ok(None)` when the identifier is unknown OR the returned
    /// `User` failed validation. The caller maps `None` to
    /// `LoginOutcome::InvalidCredentials`.
    ///
    /// **Security invariant, do not change this without thinking
    /// carefully:** the `None` paths MUST run the same store queries
    /// the found-user path would (against a fresh-UUID dummy id) so
    /// the response time does not leak whether the identifier
    /// exists. Two-step MFA flows (identify → verify) inherently
    /// reveal whether an identifier maps to a valid account through
    /// the response *shape*, but timing must not be a second
    /// side-channel on top of that. This is the same trade-off
    /// Gmail, Microsoft, and most banks accept.
    ///
    /// The dummy UUID is drawn from the service's RNG per request so it cannot collide
    /// with any real user (including the reserved
    /// [`UserId::system()`](crate::authn::ids::UserId::system)),
    /// preserving timing-equalization semantics regardless of which
    /// principals the application has installed.
    ///
    /// **Scope of equalisation:** DB queries only. LDAP network
    /// latency is NOT equalised because LDAP bind only happens in
    /// `verify_factor` (after the user is already known to exist);
    /// user enumeration via LDAP timing is not reachable from
    /// `begin_login`. Re-evaluate this comment if any LDAP call
    /// migrates earlier in the flow.
    pub(super) async fn find_user_with_timing_equalization(
        &self,
        identifier: &str,
        tenant_id: &crate::authn::ids::TenantId,
    ) -> Result<Option<crate::authn::types::User>, AuthnError<I::Error>> {
        let user_opt = self
            .inner
            .identity
            .find_user(identifier, tenant_id)
            .await
            .map_err(AuthnError::Store)?;

        if let Some(u) = user_opt {
            match u.validate() {
                Ok(()) => return Ok(Some(u)),
                // A stored row that fails validation is answered like an
                // unknown identifier, including the dummy queries below, so
                // it costs the same store calls as one.
                Err(e) => tracing::error!(error = %e, "IdentityStore returned invalid User"),
            }
        }

        // Unknown identifier, or a row that failed validation; run the same
        // store queries the happy path would, against a fresh-UUID dummy, to
        // keep response time independent of identifier existence.
        let dummy_id = crate::authn::ids::UserId::try_new(self.dummy_uuid().to_string())
            .expect("a UUID is a valid UserId");
        let _ = self.inner.identity.account_status(&dummy_id).await;
        let _ = self.inner.identity.failed_attempts(&dummy_id).await;
        let _ = self
            .inner
            .factors
            .available_methods(&dummy_id, tenant_id)
            .await;
        Ok(None)
    }
}
