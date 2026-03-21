//! Authentication-layer view of users and tenants.
//!
//! These are thin, auth-focused structs — not the application's domain models.
//! Application data (preferences, profile) lives in the app's own storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

/// A principal (user) as seen by the authentication layer.
///
/// This is a thin auth-layer view — not the application's domain user type.
/// Application domain data (profile, preferences) lives in the app's own models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Opaque unique user identifier.
    pub id: Arc<str>,
    /// The tenant this user belongs to.
    pub tenant_id: Arc<str>,
    /// The login identifier used for lookup (username, email, etc.).
    pub identifier: Arc<str>,
    /// Display name shown in UIs.
    pub display_name: Arc<str>,
    /// Current lifecycle state of the user account.
    pub status: EntityState,
    /// Stable opaque user handle for WebAuthn (FIDO2).
    ///
    /// Must be a random UUID assigned once at user creation and persisted.
    /// The WebAuthn spec requires this to be non-PII and stable across
    /// multiple credential registrations for the same user.
    /// `None` if the user has never been involved in a FIDO2 flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn_id: Option<uuid::Uuid>,
}

/// A tenant as seen by the authentication layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Opaque unique tenant identifier.
    pub id: Arc<str>,
    /// Slug or domain used for lookup.
    pub identifier: Arc<str>,
    /// Display name shown in UIs.
    pub display_name: Arc<str>,
    /// Current lifecycle state of the tenant.
    pub status: EntityState,
}

/// Account / tenant lifecycle state.
///
/// Follows the pattern: Guest → Candidate → Pending → Active,
/// with suspension/termination/archival as adverse transitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EntityState {
    /// Unauthenticated visitor — no account.
    #[default]
    Guest,
    /// Account created but not yet fully provisioned.
    Candidate,
    /// Provisioned but awaiting activation (e.g. email verification).
    Pending(StatusDetail),
    /// Fully active and operational.
    Active,
    /// Temporarily disabled (e.g. security hold, lockout).
    Suspended(StatusDetail),
    /// Permanently closed.
    Terminated(StatusDetail),
    /// Inactive and kept only for historical/audit purposes.
    Archived(StatusDetail),
}

impl EntityState {
    /// Return `true` if the account is in the `Active` state.
    pub fn is_active(&self) -> bool {
        matches!(self, EntityState::Active)
    }

    /// Return `true` if the account is `Suspended`.
    pub fn is_locked(&self) -> bool {
        matches!(self, EntityState::Suspended(_))
    }

    /// Return `true` if the account allows login (Active or Candidate).
    pub fn allows_login(&self) -> bool {
        matches!(self, EntityState::Active | EntityState::Candidate)
    }
}

/// Details attached to a non-nominal entity state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusDetail {
    /// Human-readable reason for the non-nominal state.
    pub reason: Arc<str>,
    /// When this state was entered.
    pub since: DateTime<Utc>,
    /// Optional expiry — `None` means indefinite.
    pub until: Option<DateTime<Utc>>,
}

/// Three-tier authorization scope — no generics, [`Arc<str>`] IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthnScope {
    /// Applies globally across all tenants.
    Global,
    /// Applies to a specific tenant.
    Tenant(Arc<str>),
    /// Applies to a specific user within a tenant.
    User {
        tenant_id: Arc<str>,
        user_id: Arc<str>,
    },
}

impl AuthnScope {
    /// Return a stable string key for use as a map key.
    pub fn key(&self) -> String {
        match self {
            AuthnScope::Global => "global".to_string(),
            AuthnScope::Tenant(t) => format!("tenant:{}", t),
            AuthnScope::User { tenant_id, user_id } => {
                format!("user:{}:{}", tenant_id, user_id)
            }
        }
    }
}

/// Lockout policy configuration.
///
/// Applied when verifying credentials to prevent brute-force attacks.
#[derive(Debug, Clone)]
pub struct LockoutPolicy {
    /// Maximum consecutive failed attempts before lockout.
    pub max_attempts: u32,
    /// Duration of the lockout. `None` means permanent until an admin resets.
    pub duration: Option<Duration>,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            duration: Some(Duration::from_secs(15 * 60)),
        }
    }
}
