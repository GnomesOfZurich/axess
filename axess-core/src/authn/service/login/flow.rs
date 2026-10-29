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

use crate::authn::{
    error::AuthnError,
    factor::{FactorConfig, FactorKind},
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
struct FlowStamp {
    started_at: DateTime<Utc>,
    method: String,
    epoch: String,
}

impl<I, F> crate::authn::service::RequestAuthnService<I, F>
where
    I: IdentityStore,
    F: FactorStore<Error = I::Error>,
{
    /// A digest of what a login of `method` for this user depends on: the
    /// stored password hash and the method's steps. Replacing the password
    /// (reset, admin set), enrolling or removing a factor, or changing the
    /// method's policy changes it; using a factor does not.
    pub(crate) async fn credential_epoch(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        method: &str,
    ) -> Result<String, AuthnError<I::Error>> {
        use base64::Engine as _;
        use sha2::Digest as _;
        let scope = AuthnScope::User {
            tenant_id: *tenant_id,
            user_id: *user_id,
        };
        let password_hash = match self
            .inner
            .factors
            .resolve_factor(&scope, FactorKind::Password)
            .await
            .map_err(AuthnError::Store)?
            .map(|r| r.config)
        {
            Some(FactorConfig::Password(cfg)) => {
                let hash: &str = cfg.hash.as_ref();
                hash.to_owned()
            }
            _ => String::new(),
        };
        let steps = self
            .inner
            .factors
            .available_methods(user_id, tenant_id)
            .await
            .map_err(AuthnError::Store)?
            .into_iter()
            .find(|m| &*m.name == method)
            .and_then(|m| serde_json::to_string(&m.steps).ok())
            .unwrap_or_else(|| "<method gone>".to_owned());
        let mut hasher = sha2::Sha256::new();
        for part in [password_hash.as_str(), method, steps.as_str()] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize()))
    }

    /// Stamp the flow just begun. Called with the epoch computed before the
    /// session moved, so a store error leaves the session untouched.
    pub(crate) async fn stamp_flow(&self, session: &AuthSession, method: &str, epoch: String) {
        let stamp = FlowStamp {
            started_at: self.inner.clock.now(),
            method: method.to_owned(),
            epoch,
        };
        if let Ok(value) = serde_json::to_value(&stamp) {
            session.set_custom(FLOW_KEY, value).await;
        }
    }

    /// Recompute the credential epoch of the flow in `session` and store it,
    /// keeping the flow's start time and method.
    ///
    /// For a change this service made to the credentials in the middle of the
    /// login itself (a password rehash). A session without a stamp is left
    /// alone, and a failure to read the store leaves the old epoch, which
    /// then fails the flow closed.
    pub(crate) async fn restamp_flow_epoch(
        &self,
        session: &AuthSession,
        user_id: &UserId,
        tenant_id: &TenantId,
    ) {
        let Some(mut stamp) = self.read_flow_stamp(session).await else {
            return;
        };
        match self
            .credential_epoch(user_id, tenant_id, &stamp.method)
            .await
        {
            Ok(epoch) => stamp.epoch = epoch,
            Err(_) => return,
        }
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
        let epoch = self
            .credential_epoch(user_id, tenant_id, &stamp.method)
            .await?;
        if epoch != stamp.epoch {
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
        let epoch = self
            .credential_epoch(user_id, tenant_id, &stamp.method)
            .await?;
        Ok(epoch == stamp.epoch)
    }
}
