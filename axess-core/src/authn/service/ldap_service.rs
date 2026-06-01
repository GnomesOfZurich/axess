//! LDAP bind verification on [`AuthnService`].

use super::{AuthnService, outcomes::FactorOutcome};
use crate::authn::{
    error::AuthnError,
    event::{AuthEventBuilder, AuthEventType},
    factor::{FactorConfig, FactorCredential, FactorKind},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
};
use crate::session::extractor::AuthSession;

impl<I, F> AuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// Verify a password credential via LDAP simple bind.
    ///
    /// Called from `verify_factor` when the current factor is `LdapBind`.
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
    ) -> Result<FactorOutcome, AuthnError<I::Error>> {
        let ldap = match &self.ldap {
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
            .identity
            .get_user(user_id)
            .await
            .map_err(AuthnError::Store)?
            .ok_or(AuthnError::NoFlow)?;

        // Determine the bind DN: per-user override or provider template.
        let bind_dn = match config {
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
                        return Ok(FactorOutcome::InvalidCredential);
                    }
                    dn.clone()
                } else {
                    ldap.build_bind_dn(&user.identifier)
                }
            }
            _ => return Ok(FactorOutcome::InvalidCredential),
        };

        self.metrics.factor_attempt();

        // Attempt the LDAP bind. Pass the clean identifier for group search.
        match ldap.verify_bind(&user.identifier, &bind_dn, password).await {
            Ok(_result) => {
                self.metrics.factor_success();

                // Reset failed attempts on successful bind.
                session
                    .advance_factor(&FactorKind::LdapBind, self.clock.now())
                    .await;

                self.emit_audit(
                    AuthEventBuilder::success(AuthEventType::FactorVerified)
                        .attributed_to(user_id, tenant_id)
                        .with_factor(FactorKind::LdapBind),
                )
                .await;

                self.complete_factor_step(user_id, tenant_id, session).await
            }
            Err(axess_factors::ldap::LdapError::InvalidCredentials) => {
                // Route through the canonical failure helper so LDAP
                // matches the audit ordering (audit BEFORE counter increment)
                // and store-error muting. Earlier this arm hand-rolled
                // the same logic with the audit and counter calls swapped.
                self.record_factor_failure(user_id, tenant_id, &FactorKind::LdapBind, session)
                    .await
            }
            Err(e) => {
                // Log the full error server-side for diagnostics; return a
                // generic message to callers to avoid leaking LDAP server
                // hostnames, connection details, or schema information.
                tracing::error!(error = %e, bind_dn = %bind_dn, "LDAP bind failed (non-credential error)");
                self.metrics.factor_failure();
                Err(AuthnError::ExternalService(
                    "external authentication unavailable".to_string(),
                ))
            }
        }
    }
}
