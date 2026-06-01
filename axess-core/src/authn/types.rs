//! Authentication-layer view of users and tenants.
//!
//! These are thin, auth-focused structs, not the application's domain models.
//! Application data (preferences, profile) lives in the app's own storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

use super::ids::{IdError, TenantId, UserId};

/// A principal (user) as seen by the authentication layer.
///
/// This is a thin auth-layer view, not the application's domain user type.
/// Application domain data (profile, preferences) lives in the app's own models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Opaque unique user identifier.
    pub id: UserId,
    /// The tenant this user belongs to. [`TenantId::system()`] names the
    /// tenant that owns platform-operator principals.
    pub tenant_id: TenantId,
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
    /// Actor that created this user row. Typically [`UserId::system()`]
    /// for platform-seeded users, or the admin / signup user for
    /// self-service accounts.
    pub created_by: UserId,
    /// Wall-clock time of creation (from an injected `Clock`, not
    /// `Utc::now`, so deterministic-simulation tests control the value).
    pub created_at: DateTime<Utc>,
    /// Actor that last updated this row. Equals `created_by` immediately
    /// after creation; mutated by account-lifecycle operations.
    pub updated_by: UserId,
    /// Timestamp of the last update. Equals `created_at` immediately
    /// after creation.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new `User` with validation.
    ///
    /// `id` and `tenant_id` accept anything `UserId::try_new` / `TenantId::try_new`
    /// accept (non-empty, no control characters). `created_by` + `created_at`
    /// are captured as the audit metadata; `updated_by` / `updated_at`
    /// initialise to the same values.
    pub fn new(
        id: impl AsRef<str>,
        tenant_id: impl AsRef<str>,
        identifier: impl Into<Arc<str>>,
        display_name: impl Into<Arc<str>>,
        status: EntityState,
        created_by: UserId,
        created_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let user = Self {
            id: UserId::try_new(id).map_err(|e: IdError| format!("User.id: {e}"))?,
            tenant_id: TenantId::try_new(tenant_id)
                .map_err(|e: IdError| format!("User.tenant_id: {e}"))?,
            identifier: identifier.into(),
            display_name: display_name.into(),
            status,
            webauthn_id: None,
            created_by,
            created_at,
            updated_by: created_by,
            updated_at: created_at,
        };
        user.validate()?;
        Ok(user)
    }

    /// Validate that the free-form fields are well-formed.
    ///
    /// The identifier and display-name fields are still `Arc<str>` (they can
    /// legitimately hold emails, display strings, etc.) so they still need
    /// runtime validation. The typed `id` and `tenant_id` fields are guaranteed
    /// non-empty by construction, so they are not re-checked here.
    pub fn validate(&self) -> Result<(), String> {
        if self.identifier.is_empty() {
            return Err("User.identifier must be non-empty".to_string());
        }
        if self.identifier.contains(|c: char| c.is_control()) {
            return Err("User.identifier contains control characters".to_string());
        }
        if self.display_name.contains('\0') {
            return Err("User.display_name contains null byte".to_string());
        }
        Ok(())
    }

    /// Classify the user by scope: platform operator (`Scope::Global`) or
    /// tenant member (`Scope::Tenant(..)`).
    ///
    /// Prefer this over direct comparison against [`TenantId::system`].
    pub fn scope(&self) -> AuthnScope {
        if self.tenant_id.is_system() {
            AuthnScope::Global
        } else {
            AuthnScope::Tenant(self.tenant_id)
        }
    }
}

/// A tenant as seen by the authentication layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Opaque unique tenant identifier.
    pub id: TenantId,
    /// Slug or domain used for lookup.
    pub identifier: Arc<str>,
    /// Display name shown in UIs.
    pub display_name: Arc<str>,
    /// Current lifecycle state of the tenant.
    pub status: EntityState,
    /// Actor that created this tenant row. For self-service signups
    /// this is typically the first tenant admin; for operator-onboarded
    /// tenants it is [`UserId::system()`].
    pub created_by: UserId,
    /// Wall-clock time of creation.
    pub created_at: DateTime<Utc>,
    /// Actor that last updated this row.
    pub updated_by: UserId,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// Create a new `Tenant` with validation.
    pub fn new(
        id: impl AsRef<str>,
        identifier: impl Into<Arc<str>>,
        display_name: impl Into<Arc<str>>,
        status: EntityState,
        created_by: UserId,
        created_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let tenant = Self {
            id: TenantId::try_new(id).map_err(|e: IdError| format!("Tenant.id: {e}"))?,
            identifier: identifier.into(),
            display_name: display_name.into(),
            status,
            created_by,
            created_at,
            updated_by: created_by,
            updated_at: created_at,
        };
        tenant.validate()?;
        Ok(tenant)
    }

    /// Validate the free-form fields (`identifier`, `display_name`).
    ///
    /// The typed `id` field is guaranteed non-empty by construction.
    pub fn validate(&self) -> Result<(), String> {
        if self.identifier.is_empty() {
            return Err("Tenant.identifier must be non-empty".to_string());
        }
        if self.identifier.contains(|c: char| c.is_control()) {
            return Err("Tenant.identifier contains control characters".to_string());
        }
        Ok(())
    }
}

/// Account / tenant lifecycle state.
///
/// Follows the pattern: Guest → Candidate → Pending → Active,
/// with suspension/termination/archival as adverse transitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EntityState {
    /// Unauthenticated visitor; no account.
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

    /// Return `true` if the account allows login.
    ///
    /// Only `Active` accounts can authenticate. `Candidate` accounts must be
    /// explicitly activated by the application before login is permitted.
    pub fn allows_login(&self) -> bool {
        matches!(self, EntityState::Active)
    }
}

/// Details attached to a non-nominal entity state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusDetail {
    /// Human-readable reason for the non-nominal state.
    pub reason: Arc<str>,
    /// When this state was entered.
    pub since: DateTime<Utc>,
    /// Optional expiry: `None` means indefinite.
    pub until: Option<DateTime<Utc>>,
}

/// Three-tier authorization scope.
///
/// `Global` is the platform-operator scope: identifiers can be
/// [`TenantId::system`] / [`UserId::system`] at the storage boundary, but
/// application code should always pattern-match on this enum rather than
/// comparing ids directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthnScope {
    /// Applies globally across all tenants (platform-operator scope).
    Global,
    /// Applies to a specific tenant.
    Tenant(TenantId),
    /// Applies to a specific user within a tenant.
    User {
        /// Tenant containing the user.
        tenant_id: TenantId,
        /// User the scope is bound to.
        user_id: UserId,
    },
}

impl AuthnScope {
    /// Return a stable string key for use as a map key.
    pub fn key(&self) -> String {
        match self {
            AuthnScope::Global => "global".to_string(),
            AuthnScope::Tenant(t) => format!("tenant:{t}"),
            AuthnScope::User { tenant_id, user_id } => {
                format!("user:{tenant_id}:{user_id}")
            }
        }
    }

    /// Pair of `(user_id, tenant_id)` columns for storage backends that
    /// key scope-applicability data (factor configs, auth methods, etc.).
    ///
    /// **Both columns are `Option`**: `None` encodes "applies at this
    /// level and below": tenant-level rows with `user_id = None` apply
    /// to any user in the tenant; global rows with both `None` apply to
    /// any user in any tenant. This is the NULL-for-default convention
    /// the axess example backend uses.
    ///
    /// Note this is **distinct** from the tenant-ownership convention
    /// used by downstream applications for tenant-owned data, which use
    /// the reserved [`TenantId::system`] sentinel to preserve NOT NULL
    /// and FK integrity. Scope applicability is about "who does this
    /// rule apply to"; tenant ownership is about "who owns this row."
    pub fn as_columns(&self) -> ScopeColumns {
        match self {
            AuthnScope::Global => ScopeColumns {
                user_id: None,
                tenant_id: None,
            },
            AuthnScope::Tenant(t) => ScopeColumns {
                user_id: None,
                tenant_id: Some(*t),
            },
            AuthnScope::User { tenant_id, user_id } => ScopeColumns {
                user_id: Some(*user_id),
                tenant_id: Some(*tenant_id),
            },
        }
    }

    /// Ordered lookup chain for config resolution.
    ///
    /// Backends try each entry in order until one yields a hit. The
    /// chain always terminates at `(None, None)` so every scope falls
    /// back to the global default.
    pub fn lookup_chain(&self) -> Vec<ScopeColumns> {
        match self {
            AuthnScope::Global => vec![ScopeColumns {
                user_id: None,
                tenant_id: None,
            }],
            AuthnScope::Tenant(t) => vec![
                ScopeColumns {
                    user_id: None,
                    tenant_id: Some(*t),
                },
                ScopeColumns {
                    user_id: None,
                    tenant_id: None,
                },
            ],
            AuthnScope::User { tenant_id, user_id } => vec![
                ScopeColumns {
                    user_id: Some(*user_id),
                    tenant_id: Some(*tenant_id),
                },
                ScopeColumns {
                    user_id: None,
                    tenant_id: Some(*tenant_id),
                },
                ScopeColumns {
                    user_id: None,
                    tenant_id: None,
                },
            ],
        }
    }
}

/// Storage-layer projection of an [`AuthnScope`] onto `(user_id, tenant_id)`
/// columns for scope-applicability data (factor configs, auth methods).
///
/// Both fields are `Option`: `None` encodes "applies at this level and
/// below" per the NULL-for-default convention. Do not confuse this with
/// tenant-ownership storage, where `tenant_id` is always populated (with
/// the reserved [`TenantId::system`] sentinel for platform-owned rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeColumns {
    /// User column; `None` encodes "applies to any user at the tenant or global level".
    pub user_id: Option<UserId>,
    /// Tenant column; `None` encodes "applies globally across tenants".
    pub tenant_id: Option<TenantId>,
}

/// Lockout policy configuration.
///
/// Applied when verifying credentials to prevent brute-force attacks.
#[derive(Debug, Clone)]
pub struct LockoutPolicy {
    /// Maximum consecutive failed attempts within `attempt_window` before lockout.
    pub max_attempts: u32,
    /// Duration of the lockout. `None` means permanent until an admin resets.
    pub duration: Option<Duration>,
    /// Sliding window over which failed attempts accumulate. Implementations
    /// of [`IdentityAuthnLog::record_failed_attempt`](super::store::IdentityAuthnLog::record_failed_attempt)
    /// should treat any earlier failures as expired and not count them
    /// toward `max_attempts`. Without this a user who legitimately fails
    /// `max_attempts - 1` times today and once tomorrow gets locked, even
    /// though the failures are unrelated. Default: 1 hour.
    pub attempt_window: Duration,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            duration: Some(Duration::from_secs(15 * 60)),
            attempt_window: Duration::from_secs(60 * 60),
        }
    }
}

/// Per-tenant IP access policy.
///
/// Specifies allowed and/or denied IP addresses and CIDR ranges.
/// If `allow` is non-empty, only those IPs are permitted (allowlist mode).
/// If `allow` is empty and `deny` is non-empty, all IPs except those are
/// permitted (denylist mode). If both are empty, all IPs are permitted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpPolicy {
    /// Allowed IP addresses and CIDR ranges (e.g. `"10.0.0.0/8"`, `"192.168.1.1"`).
    /// If non-empty, only these IPs may authenticate.
    pub allow: Vec<Arc<str>>,
    /// Denied IP addresses and CIDR ranges.
    /// Checked only when `allow` is empty.
    pub deny: Vec<Arc<str>>,
}

impl IpPolicy {
    /// Check whether the given IP address is permitted by this policy.
    ///
    /// Returns `true` if the IP is allowed, `false` if denied.
    pub fn is_allowed(&self, ip: std::net::IpAddr) -> bool {
        if !self.allow.is_empty() {
            // Allowlist mode: IP must match at least one entry.
            return self.allow.iter().any(|entry| ip_matches(ip, entry));
        }
        if !self.deny.is_empty() {
            // Denylist mode: IP must not match any entry.
            return !self.deny.iter().any(|entry| ip_matches(ip, entry));
        }
        // No restrictions.
        true
    }
}

/// Check if an IP matches a CIDR range or exact address string.
fn ip_matches(ip: std::net::IpAddr, entry: &str) -> bool {
    // Try CIDR match first (e.g. "10.0.0.0/8").
    if let Some((network_str, prefix_str)) = entry.split_once('/')
        && let (Ok(network), Ok(prefix_len)) = (
            network_str.parse::<std::net::IpAddr>(),
            prefix_str.parse::<u32>(),
        )
    {
        return cidr_contains(network, prefix_len, ip);
    }
    // Fall back to exact match.
    entry.parse::<std::net::IpAddr>().is_ok_and(|e| e == ip)
}

/// Check if `ip` falls within the CIDR block `network/prefix_len`.
fn cidr_contains(network: std::net::IpAddr, prefix_len: u32, ip: std::net::IpAddr) -> bool {
    match (network, ip) {
        (std::net::IpAddr::V4(net), std::net::IpAddr::V4(addr)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (std::net::IpAddr::V6(net), std::net::IpAddr::V6(addr)) => {
            if prefix_len > 128 {
                return false;
            }
            let net_bits = u128::from(net);
            let addr_bits = u128::from(addr);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (net_bits & mask) == (addr_bits & mask)
        }
        _ => false, // v4/v6 mismatch
    }
}

#[cfg(test)]
mod ip_policy_tests {
    use super::*;

    #[test]
    fn empty_policy_allows_all() {
        let policy = IpPolicy::default();
        assert!(policy.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(policy.is_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn allowlist_permits_listed_ip() {
        let policy = IpPolicy {
            allow: vec!["10.0.0.0/8".into(), "192.168.1.1".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(policy.is_allowed("10.255.255.255".parse().unwrap()));
        assert!(policy.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!policy.is_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn denylist_blocks_listed_ip() {
        let policy = IpPolicy {
            allow: vec![],
            deny: vec!["10.0.0.0/8".into()],
        };
        assert!(!policy.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(policy.is_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn exact_ip_match() {
        let policy = IpPolicy {
            allow: vec!["192.168.1.100".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(!policy.is_allowed("192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr() {
        let policy = IpPolicy {
            allow: vec!["fd00::/8".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("fd00::1".parse().unwrap()));
        assert!(!policy.is_allowed("2001:db8::1".parse().unwrap()));
    }

    /// Pin the v4 prefix-length boundary at 32. Mask
    /// computation depends on `prefix_len <= 32`; an `>=`/`==`
    /// mutation would either reject the legitimate /32 host route
    /// or accept an invalid /33.
    #[test]
    fn cidr_v4_prefix_boundary_at_32() {
        let policy = IpPolicy {
            allow: vec!["192.168.1.100/32".into()],
            deny: vec![],
        };
        // /32 covers exactly one address; the exact match must work.
        assert!(policy.is_allowed("192.168.1.100".parse().unwrap()));
        // A different host inside the /24 must reject.
        assert!(!policy.is_allowed("192.168.1.101".parse().unwrap()));

        // /33 is structurally invalid and must reject everything.
        let bad = IpPolicy {
            allow: vec!["192.168.1.100/33".into()],
            deny: vec![],
        };
        assert!(!bad.is_allowed("192.168.1.100".parse().unwrap()));
    }

    /// Pin the v6 prefix-length boundary at 128. Same shape
    /// as the v4 test.
    #[test]
    fn cidr_v6_prefix_boundary_at_128() {
        let policy = IpPolicy {
            allow: vec!["fd00::1/128".into()],
            deny: vec![],
        };
        assert!(policy.is_allowed("fd00::1".parse().unwrap()));
        assert!(!policy.is_allowed("fd00::2".parse().unwrap()));

        let bad = IpPolicy {
            allow: vec!["fd00::1/129".into()],
            deny: vec![],
        };
        assert!(!bad.is_allowed("fd00::1".parse().unwrap()));
    }

    /// Pin the v6 mask shift `u128::MAX << (128 - prefix_len)`.
    /// A `-` to `/` mutation makes the shift `u128::MAX << (128 / prefix_len)`,
    /// which produces the wrong mask for any `prefix_len > 1`. Construct a
    /// case where original and mutant disagree.
    ///
    /// With prefix=8: original shift = 120 → mask = top 8 bits.
    /// Mutant shift = 128/8 = 16 → mask = top 112 bits.
    /// Address `fd80::` has top-8 bits = `0xFD` (matches `fd00::/8`) but
    /// differs from `fd00::` in bit 9. Original ACCEPTS; mutant REJECTS.
    #[test]
    fn cidr_v6_mask_uses_subtraction_not_division() {
        let policy = IpPolicy {
            allow: vec!["fd00::/8".into()],
            deny: vec![],
        };
        assert!(
            policy.is_allowed("fd80::".parse().unwrap()),
            "fd80:: must match fd00::/8 (kills `-` → `/` mutation on the v6 mask shift)"
        );
    }
}

#[cfg(test)]
mod authn_types_tests {
    use super::*;
    use crate::authn::ids::UserId;

    /// `EntityState::is_active` returns true ONLY for the
    /// `Active` variant. A `-> true` body mutation would silently
    /// allow login on every `Suspended`/`Terminated`/`Archived`/
    /// `Candidate` account.
    #[test]
    fn entity_state_is_active_only_for_active() {
        assert!(EntityState::Active.is_active());
        assert!(
            !EntityState::Suspended(StatusDetail {
                reason: "test".into(),
                since: chrono::Utc::now(),
                until: None,
            })
            .is_active()
        );
        assert!(
            !EntityState::Terminated(StatusDetail {
                reason: "test".into(),
                since: chrono::Utc::now(),
                until: None,
            })
            .is_active()
        );
        assert!(
            !EntityState::Archived(StatusDetail {
                reason: "test".into(),
                since: chrono::Utc::now(),
                until: None,
            })
            .is_active()
        );
        assert!(!EntityState::Candidate.is_active());
    }

    /// `lookup_chain` must return a non-empty ordered chain
    /// for each scope, terminating at `(None, None)`. The mutation
    /// `-> vec![]` would silently drop every fall-through branch:
    /// factor-config and method-resolution would only ever look at
    /// the most-specific row, never the tenant or global default.
    #[test]
    fn lookup_chain_returns_non_empty_terminated_chain_per_scope() {
        // Global → exactly the `(None, None)` row.
        let global = AuthnScope::Global.lookup_chain();
        assert_eq!(global.len(), 1);
        assert!(global[0].user_id.is_none() && global[0].tenant_id.is_none());

        // Tenant → tenant row, then global fallback.
        let tenant = axess_identity::testing::tenant("t1");
        let tenant_chain = AuthnScope::Tenant(tenant).lookup_chain();
        assert_eq!(tenant_chain.len(), 2);
        assert_eq!(tenant_chain[0].tenant_id.as_ref(), Some(&tenant));
        assert!(tenant_chain[0].user_id.is_none());
        assert!(tenant_chain[1].user_id.is_none() && tenant_chain[1].tenant_id.is_none());

        // User → user row, tenant row, global fallback.
        let user = axess_identity::testing::user("u1");
        let user_chain = AuthnScope::User {
            tenant_id: tenant,
            user_id: user,
        }
        .lookup_chain();
        assert_eq!(user_chain.len(), 3);
        assert_eq!(user_chain[0].user_id.as_ref(), Some(&user));
        assert_eq!(user_chain[0].tenant_id.as_ref(), Some(&tenant));
        assert!(user_chain[1].user_id.is_none());
        assert_eq!(user_chain[1].tenant_id.as_ref(), Some(&tenant));
        assert!(user_chain[2].user_id.is_none() && user_chain[2].tenant_id.is_none());
    }

    fn make_user_with_identifier(identifier: &str, display_name: &str) -> User {
        let now = chrono::Utc::now();
        User {
            id: axess_identity::testing::user("u-validate"),
            tenant_id: axess_identity::testing::tenant("t-validate"),
            identifier: identifier.into(),
            display_name: display_name.into(),
            status: EntityState::Active,
            webauthn_id: None,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        }
    }

    fn make_tenant_with_identifier(identifier: &str) -> Tenant {
        let now = chrono::Utc::now();
        Tenant {
            id: axess_identity::testing::tenant("t-validate"),
            identifier: identifier.into(),
            display_name: "Display".into(),
            status: EntityState::Active,
            created_by: UserId::system(),
            created_at: now,
            updated_by: UserId::system(),
            updated_at: now,
        }
    }

    /// Kill the `User::validate -> Ok(())` body replacement.
    /// The function must reject invalid identifiers and display names.
    #[test]
    fn user_validate_rejects_invalid_inputs() {
        // Empty identifier
        assert!(
            make_user_with_identifier("", "Display").validate().is_err(),
            "empty identifier must fail validation"
        );
        // Identifier with control character
        assert!(
            make_user_with_identifier("ab\nc", "Display")
                .validate()
                .is_err(),
            "control characters in identifier must fail validation"
        );
        // Display name with null byte
        assert!(
            make_user_with_identifier("alice", "bad\0name")
                .validate()
                .is_err(),
            "null byte in display_name must fail validation"
        );
        // Happy path: valid inputs pass
        assert!(
            make_user_with_identifier("alice", "Alice")
                .validate()
                .is_ok()
        );
    }

    /// Kill the `Tenant::validate -> Ok(())` body replacement.
    #[test]
    fn tenant_validate_rejects_invalid_inputs() {
        assert!(
            make_tenant_with_identifier("").validate().is_err(),
            "empty identifier must fail"
        );
        assert!(
            make_tenant_with_identifier("acme\nplc").validate().is_err(),
            "control character must fail"
        );
        assert!(make_tenant_with_identifier("acme").validate().is_ok());
    }

    /// Kill the `AuthnScope::key -> String::new()` and
    /// `-> "xyzzy".into()` body replacements. The key must:
    /// 1. Be non-empty for every variant (kills String::new()).
    /// 2. Match the documented prefix for each variant (kills
    ///    "xyzzy".into(); a fixed wrong value would lose the
    ///    `global` / `tenant:` / `user:` prefixes).
    /// 3. Interpolate the tenant/user ids (kills any fixed-string
    ///    mutation that ignores the variant data).
    #[test]
    fn authn_scope_key_per_variant_format() {
        let tenant = axess_identity::testing::tenant("t-key");
        let user = axess_identity::testing::user("u-key");

        assert_eq!(AuthnScope::Global.key(), "global");

        let tenant_key = AuthnScope::Tenant(tenant).key();
        assert!(
            tenant_key.starts_with("tenant:"),
            "Tenant key must start with `tenant:`, got {tenant_key:?}"
        );
        assert!(
            tenant_key.contains(&tenant.to_string()),
            "Tenant key must interpolate the tenant id, got {tenant_key:?}"
        );

        let user_key = AuthnScope::User {
            tenant_id: tenant,
            user_id: user,
        }
        .key();
        assert!(
            user_key.starts_with("user:"),
            "User key must start with `user:`, got {user_key:?}"
        );
        assert!(
            user_key.contains(&tenant.to_string()) && user_key.contains(&user.to_string()),
            "User key must interpolate both ids, got {user_key:?}"
        );
    }
}
