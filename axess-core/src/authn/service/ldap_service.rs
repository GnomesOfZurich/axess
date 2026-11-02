//! LDAP bind verification on [`AuthnService`].

use super::{RequestAuthnService, outcomes::FactorOutcome};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType, AuthFailureReason},
    factor::{FactorConfig, FactorCredential, FactorKind},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

impl<I, F> RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Verify a password credential via LDAP simple bind.
    ///
    /// Called from `verify_factor` when the current factor is `LdapBind`.
    /// `reserved` is the count `reserve_guess` took for this attempt. A check
    /// that ends before the bind (no provider, an oversized password, a bad
    /// DN) keeps its reservation, so it counts as the failure it is.
    ///
    /// The user submits a `FactorCredential::Password`: same input as local
    /// password auth, but verified against the directory instead of a stored hash.
    #[tracing::instrument(skip(self, credential, config, session))]
    pub(crate) async fn verify_ldap_factor(
        &self,
        credential: &FactorCredential,
        config: &FactorConfig,
        user_id: &UserId,
        tenant_id: &TenantId,
        session: &AuthSession,
        reserved: Option<u32>,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let ldap = match &self.inner.ldap {
            Some(l) => l,
            None => {
                tracing::error!("LdapBind factor configured but no LdapProvider attached");
                return Ok(FactorOutcome::InvalidCredential);
            }
        };

        // Extract the password from the credential.
        let password: &str = match credential {
            FactorCredential::Password(p) => p.as_ref(),
            _ => return Ok(FactorOutcome::InvalidCredential),
        };

        // Reject oversized passwords before the network call.
        if password.len() > crate::validation::MAX_PASSWORD_BYTES {
            return Ok(FactorOutcome::InvalidCredential);
        }

        // Look up the user's identifier for the bind DN template and group filter.
        let user = self
            .inner
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        // Determine the bind DN: per-user override or provider template.
        let Some(bind_dn) = Self::ldap_bind_dn(ldap.as_ref(), config, &user, user_id) else {
            return Ok(FactorOutcome::InvalidCredential);
        };

        self.inner.metrics.factor_attempt();

        // Attempt the LDAP bind. Pass the clean identifier for group search.
        match ldap.verify_bind(&user.identifier, &bind_dn, password).await {
            Ok(result) => {
                self.ldap_bind_succeeded(result.groups, reserved, user_id, tenant_id, session)
                    .await
            }
            Err(axess_factors::ldap::LdapError::InvalidCredentials) => {
                // Route through the canonical failure helper so LDAP
                // matches the audit ordering (audit BEFORE counter increment)
                // and store-error muting. Earlier this arm hand-rolled
                // the same logic with the audit and counter calls swapped.
                self.record_factor_failure_after(
                    reserved,
                    user_id,
                    tenant_id,
                    &FactorKind::LdapBind,
                    session,
                )
                .await
            }
            Err(e) => {
                self.ldap_unavailable(&e, reserved, user_id, tenant_id)
                    .await
            }
        }
    }

    /// The DN to bind as: the factor's per-user override when it has one and
    /// the override is well formed, else the provider's template filled with
    /// the user's identifier. `None` refuses the credential: a malformed
    /// override, or a factor config that is not an LDAP bind.
    fn ldap_bind_dn(
        ldap: &dyn axess_factors::ldap::LdapProvider,
        config: &FactorConfig,
        user: &crate::authn::types::User,
        user_id: &UserId,
    ) -> Option<String> {
        match config {
            FactorConfig::LdapBind(cfg) => {
                if let Some(ref dn) = cfg.bind_dn {
                    // Validate the override has RFC 4514 DN structure: at least one
                    // RDN component (`key=value`), reasonable length, and only DN-safe
                    // characters (letters, digits, common DN punctuation). Rejects
                    // wildcards, parentheses, semicolons, and other chars that could
                    // alter LDAP behavior.
                    if dn.is_empty()
                        || dn.len() > 1024
                        || !dn.bytes().all(|b| {
                            matches!(b,
                                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
                                | b' ' | b'.' | b'-' | b'_' | b'@'
                                | b'=' | b',' | b'+' | b'\\' | b'#'
                                | b'"' | b':'
                            )
                        })
                        // Structural check: must contain at least one `=` (key=value).
                        || !dn.contains('=')
                    {
                        tracing::warn!(user_id = %user_id, "invalid LDAP bind_dn override rejected");
                        return None;
                    }
                    Some(dn.clone())
                } else {
                    Some(ldap.build_bind_dn(&user.identifier))
                }
            }
            _ => None,
        }
    }

    /// A bind the directory accepted: give back the reserved guess, write
    /// the audit row, keep the groups and advance the factor.
    async fn ldap_bind_succeeded(
        &self,
        groups: Vec<String>,
        reserved: Option<u32>,
        user_id: &UserId,
        tenant_id: &TenantId,
        session: &AuthSession,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        self.inner.metrics.factor_success();
        self.release_guess(reserved, user_id).await;

        // The audit row first: a failed write must leave the session
        // where it was, where the other order had already advanced it
        // (possibly to Authenticated) for a factor that was never
        // recorded.
        self.emit_audit(
            AuthEventBuilder::success(AuthEventType::FactorVerified)
                .attributed_to(user_id, tenant_id)
                .with_factor(FactorKind::LdapBind),
        )
        .await?;

        // The groups the directory returned for this bind, for the
        // application to map to roles: part of the login state, carried
        // into Authenticated by the advance below and read with
        // `AuthSession::ldap_groups`.
        session.set_ldap_groups(groups).await;

        session
            .advance_factor(
                &FactorKind::LdapBind,
                self.inner.clock.now(),
                &self.inner.preserved_custom_keys,
            )
            .await;

        self.complete_factor_step(user_id, tenant_id, session).await
    }

    /// A bind that failed for a reason other than the credential: the
    /// directory is unreachable or misbehaving.
    async fn ldap_unavailable(
        &self,
        e: &axess_factors::ldap::LdapError,
        reserved: Option<u32>,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        // Log the full error server-side for diagnostics; return a
        // generic message to callers to avoid leaking LDAP server
        // hostnames, connection details, or schema information.
        // The DN is the user's directory identity: it identifies the
        // person in a log line, so the user id stands in for it.
        tracing::error!(error = %e, user_id = %user_id, "LDAP bind failed (non-credential error)");
        self.inner.metrics.factor_failure();
        // An outage says nothing about the credential: the guess it
        // reserved is given back.
        self.release_guess(reserved, user_id).await;
        // An outage of the directory is still an attempt at this
        // factor: record it, so the trail shows the login stopped here.
        self.emit_audit(
            AuthEventBuilder::failure(AuthEventType::FactorVerified)
                .attributed_to(user_id, tenant_id)
                .with_factor(FactorKind::LdapBind)
                .with_error(AuthFailureReason::Other("external_service".to_owned())),
        )
        .await?;
        Err(AuthnError::ExternalService(
            "external authentication unavailable".to_string(),
        ))
    }
}

impl AuthSession {
    /// The group memberships the directory returned when this session's
    /// LDAP bind factor verified, or `None` when the session did not
    /// authenticate through an LDAP bind (or the provider has no
    /// [`LdapGroupSearch`](axess_factors::ldap::LdapGroupSearch), which
    /// gives an empty list).
    ///
    /// The groups are those of the login that produced this session; a
    /// later change in the directory is seen at the next login. Map them to
    /// roles or Cedar entities in the application.
    pub async fn ldap_groups(&self) -> Option<Vec<String>> {
        let guard = self.0.0.read().await;
        guard.data.auth_state.ldap_groups().map(<[String]>::to_vec)
    }

    /// Record the groups an LDAP bind returned on the login in flight; see
    /// `AuthState::set_ldap_groups`.
    pub(crate) async fn set_ldap_groups(&self, groups: Vec<String>) {
        let mut guard = self.0.0.write().await;
        guard.data.auth_state.set_ldap_groups(groups);
        guard.modified = true;
    }
}
