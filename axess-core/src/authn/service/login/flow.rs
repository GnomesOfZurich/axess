//! The stamp that bounds a half-finished login.
//!
//! `begin_login` records when the flow began and an epoch of the credentials
//! it began against. Every later step checks both: a flow older than the
//! service's flow TTL, or begun against a password or method that has since
//! changed, is dropped and answers `NoFlow`. Without this an attacker holding
//! a session at the second factor outlived a password reset, and a flow begun
//! before a factor was enrolled finished without it.
//!
//! The stamp lives in the session's custom data, under [`FLOW_KEY`], which
//! only server code writes; a session without one (a flow begun by an
//! earlier release, or one the size cap refused) is treated as stale.
//!
//! The password enters the epoch by its identity (see [`password_identity`]),
//! which a rehash of the same password keeps, so a rehash is no change of
//! credential and needs no special case.

use crate::authn::{
    error::AuthnError,
    factor::{FactorConfig, FactorKind, FactorStep, PasswordConfig},
    ids::{TenantId, UserId},
    store::{FactorStore, IdentityStore},
    types::AuthnScope,
};
use crate::session::extractor::AuthSession;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Session custom key holding the [`FlowStamp`].
pub(crate) const FLOW_KEY: &str = crate::session::data::LOGIN_FLOW_KEY;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct FlowStamp {
    started_at: DateTime<Utc>,
    method: String,
    epoch: String,
    /// The steps the epoch was computed over, for a flow whose steps are
    /// not those of a stored method (a step-up); `None` reads the method's
    /// steps from the store at every check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    steps: Option<Vec<FactorStep>>,
}

/// The identity of a stored password: its `password_id`, or for a config
/// without one (a new password, or one stored before the field existed) a
/// digest of its hash. A rehash writes this value into the new config's
/// `password_id`, so the identity survives a rehash and changes with a new
/// password. An absent password is the identity of the empty hash.
pub(crate) fn password_identity(cfg: Option<&PasswordConfig>) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = |hash: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(hash))
    };
    match cfg {
        Some(PasswordConfig {
            password_id: Some(id),
            ..
        }) => id.clone(),
        Some(cfg) => digest(cfg.hash.as_ref()),
        None => digest(""),
    }
}

/// The canonical form of a method's steps that the epoch digests.
fn serialise_steps<E: std::error::Error + Send + Sync + 'static>(
    steps: &[FactorStep],
) -> Result<String, AuthnError<E>> {
    serde_json::to_string(steps)
        .map_err(|e| AuthnError::Internal(format!("factor steps cannot be serialised: {e}")))
}

/// The epoch digest over the password identity, the method and its steps.
fn epoch_digest(password: &str, method: &str, steps: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in [password, method, steps] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

impl<I, F> crate::authn::service::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// The identity of the user's password as stored now.
    async fn stored_password_identity(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<String, AuthnError<I::Error>> {
        let scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        let config = self
            .inner
            .factors
            .resolve_factor(&scope, FactorKind::Password)
            .await
            .map_err(AuthnError::Store)?
            .map(|r| r.config);
        Ok(match &config {
            Some(FactorConfig::Password(cfg)) => password_identity(Some(cfg)),
            _ => password_identity(None),
        })
    }

    /// The steps of the user's method `method` as stored now, in the form
    /// the epoch digests, or a marker for a method that is gone.
    async fn stored_method_steps(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        method: &str,
    ) -> Result<String, AuthnError<I::Error>> {
        let found = self
            .inner
            .factors
            .available_methods(user_id, tenant_id)
            .await
            .map_err(AuthnError::Store)?
            .into_iter()
            .find(|m| &*m.name == method);
        match found {
            Some(m) => serialise_steps(&m.steps),
            None => Ok("<method gone>".to_owned()),
        }
    }

    /// A digest of what a login of `method` for this user depends on: the
    /// stored password's identity and the method's steps. Replacing the
    /// password (reset, admin set), enrolling or removing a factor, or
    /// changing the method's policy changes it; using a factor or rehashing
    /// the password does not.
    pub(crate) async fn credential_epoch(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        method: &str,
    ) -> Result<String, AuthnError<I::Error>> {
        let password = self.stored_password_identity(user_id, tenant_id).await?;
        let steps = self.stored_method_steps(user_id, tenant_id, method).await?;
        Ok(epoch_digest(&password, method, &steps))
    }

    /// The stamp of a flow whose steps are given rather than read from a
    /// stored method (a step-up): its epoch covers the stored password's
    /// identity and `steps`, and the stamp carries `steps` so every later check
    /// computes the same epoch. Returns the stamp as the session value to
    /// write under [`FLOW_KEY`].
    pub(crate) async fn stamp_for_steps(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        method: &str,
        steps: &[FactorStep],
    ) -> Result<serde_json::Value, AuthnError<I::Error>> {
        let serialised = serialise_steps(steps)?;
        let password = self.stored_password_identity(user_id, tenant_id).await?;
        let stamp = FlowStamp {
            started_at: self.inner.clock.now(),
            epoch: epoch_digest(&password, method, &serialised),
            method: method.to_owned(),
            steps: Some(steps.to_vec()),
        };
        serde_json::to_value(&stamp)
            .map_err(|e| AuthnError::Internal(format!("flow stamp cannot be serialised: {e}")))
    }

    /// Whether `stamp` is current: its epoch is the one the credentials give
    /// now. A stamp carrying its own steps is judged on those; any other on
    /// the stored method's.
    async fn stamp_is_current(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        stamp: &FlowStamp,
    ) -> Result<bool, AuthnError<I::Error>> {
        let password = self.stored_password_identity(user_id, tenant_id).await?;
        let steps = match &stamp.steps {
            Some(steps) => serialise_steps(steps)?,
            None => {
                self.stored_method_steps(user_id, tenant_id, &stamp.method)
                    .await?
            }
        };
        Ok(epoch_digest(&password, &stamp.method, &steps) == stamp.epoch)
    }

    /// Stamp the flow just begun. Called with the epoch computed before the
    /// session moved, so a store error leaves the session untouched.
    pub(crate) async fn stamp_flow(&self, session: &AuthSession, method: &str, epoch: String) {
        let stamp = FlowStamp {
            started_at: self.inner.clock.now(),
            method: method.to_owned(),
            epoch,
            steps: None,
        };
        if let Ok(value) = serde_json::to_value(&stamp) {
            session.set_custom(FLOW_KEY, value).await;
        }
    }

    async fn read_flow_stamp(&self, session: &AuthSession) -> Option<FlowStamp> {
        let value = session.get_custom(FLOW_KEY).await?;
        serde_json::from_value(value).ok()
    }

    /// Require the flow in progress to be fresh and current.
    ///
    /// Returns `Ok(())` when the flow began within the flow TTL against the
    /// credentials as they are now. Otherwise the session is cleared (back
    /// to anonymous) and the answer is [`AuthnError::NoFlow`].
    pub(crate) async fn require_current_flow(
        &self,
        session: &AuthSession,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<(), AuthnError<I::Error>> {
        let Some(stamp) = self.read_flow_stamp(session).await else {
            session.clear().await;
            return Err(AuthnError::NoFlow);
        };
        let age = self.inner.clock.now() - stamp.started_at;
        let expired = age
            .to_std()
            .map(|a| a > self.inner.flow_ttl)
            // A start time in the future is a clock step or tampering.
            .unwrap_or(true);
        if expired {
            tracing::info!(user_id = %user_id, "login flow expired; dropping it");
            session.clear().await;
            return Err(AuthnError::NoFlow);
        }
        if !self.stamp_is_current(user_id, tenant_id, &stamp).await? {
            tracing::info!(
                user_id = %user_id,
                "credentials changed since the login began; dropping the flow"
            );
            session.clear().await;
            return Err(AuthnError::NoFlow);
        }
        Ok(())
    }

    /// Consume the flow stamp at the moment a session is registered, and
    /// report whether the credentials still match. `true` when there is no
    /// stamp (a login that did not go through `begin_login`).
    pub(crate) async fn flow_still_current(
        &self,
        session: &AuthSession,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) -> Result<bool, AuthnError<I::Error>> {
        let Some(value) = session.take_custom(FLOW_KEY).await else {
            return Ok(true);
        };
        let Ok(stamp) = serde_json::from_value::<FlowStamp>(value) else {
            return Ok(false);
        };
        self.stamp_is_current(user_id, tenant_id, &stamp).await
    }
}

#[cfg(test)]
mod stamp_tests {
    use super::*;
    use crate::authn::factor::{PasswordRules, ZeroizedString};

    fn config(hash: &str, password_id: Option<&str>) -> PasswordConfig {
        PasswordConfig {
            hash: ZeroizedString::new(hash),
            rules: PasswordRules::default(),
            password_id: password_id.map(str::to_owned),
        }
    }

    /// A rehash writes the identity of the config it replaces, so the
    /// identity survives the new hash; a new password (no carried id) is a
    /// new identity.
    #[test]
    fn a_rehash_keeps_the_identity_and_a_new_password_does_not() {
        let stored = config("$argon2id$old", None);
        let carried = password_identity(Some(&stored));
        let rehashed = config("$argon2id$new-params", Some(&carried));
        assert_eq!(password_identity(Some(&rehashed)), carried);
        let again = config("$argon2id$newer-params", Some(&carried));
        assert_eq!(password_identity(Some(&again)), carried);
        let changed = config("$argon2id$other-password", None);
        assert_ne!(password_identity(Some(&changed)), carried);
        assert_ne!(password_identity(None), carried);
    }

    /// A step-up stamp carries its steps as a list in the stamp itself, not
    /// as a JSON string inside it.
    #[test]
    fn a_step_up_stamp_carries_its_steps_as_a_list() {
        let stamp = FlowStamp {
            started_at: chrono::DateTime::UNIX_EPOCH,
            method: "step-up".into(),
            epoch: "e".into(),
            steps: Some(vec![FactorStep::Required(FactorKind::Totp)]),
        };
        let value = serde_json::to_value(&stamp).unwrap();
        assert!(value["steps"].is_array(), "{value}");
        let back: FlowStamp = serde_json::from_value(value).unwrap();
        assert_eq!(back.steps, stamp.steps);
    }
}
