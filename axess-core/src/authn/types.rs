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

    /// Classify the user by scope: platform operator ([`AuthnScope::System`])
    /// or tenant member ([`AuthnScope::Tenant`]).
    ///
    /// Prefer this over direct comparison against [`TenantId::system`].
    pub fn scope(&self) -> AuthnScope {
        if self.tenant_id.is_system() {
            AuthnScope::System
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

/// Three-tier configuration scope, ordered from narrowest to broadest.
///
/// - [`User`](Self::User): a specific user in a specific tenant.
/// - [`Tenant`](Self::Tenant): every user in a specific tenant.
/// - [`System`](Self::System): platform-owned defaults that tenants adopt
///   explicitly at provisioning (or fork later). Storage-wise, System
///   rows live under the reserved [`TenantId::SYSTEM`] tenant: there is
///   no NULL-tenant encoding for configuration scope anywhere in axess.
///
/// Runtime resolution walks [`resolution_chain`](Self::resolution_chain)
/// from narrowest to broadest and returns the first hit. Backends
/// implementing [`FactorStore::resolve_factor`](super::store::FactorStore::resolve_factor)
/// do this in one query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthnScope {
    /// Platform-owned defaults, keyed under [`TenantId::SYSTEM`].
    System,
    /// Tenant-owned config; applies to every user in the tenant.
    Tenant(TenantId),
    /// User-owned config within a tenant.
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
            AuthnScope::System => "system".to_string(),
            AuthnScope::Tenant(t) => format!("tenant:{t}"),
            AuthnScope::User { tenant_id, user_id } => {
                format!("user:{tenant_id}:{user_id}")
            }
        }
    }

    /// Storage projection of this scope: `(tenant_id, user_id)` where
    /// `tenant_id` is ALWAYS populated (with [`TenantId::SYSTEM`] for
    /// [`AuthnScope::System`]) and `user_id` is populated only for
    /// [`AuthnScope::User`].
    ///
    /// There is no NULL-tenant encoding for configuration scope anywhere
    /// in axess. Rows always belong to a real tenant; the system tenant
    /// is what "platform-wide" means. FK integrity works uniformly and
    /// SQL callers never need `tenant_id IS NULL` special-cases.
    ///
    /// This is distinct from audit-event storage, where NULL `tenant_id`
    /// means "tenant not yet known" (pre-authenticated event), never
    /// "system scope."
    pub fn as_columns(&self) -> ScopeColumns {
        match self {
            AuthnScope::System => ScopeColumns {
                tenant_id: TenantId::SYSTEM,
                user_id: None,
            },
            AuthnScope::Tenant(t) => ScopeColumns {
                tenant_id: *t,
                user_id: None,
            },
            AuthnScope::User { tenant_id, user_id } => ScopeColumns {
                tenant_id: *tenant_id,
                user_id: Some(*user_id),
            },
        }
    }

    /// Ordered scope chain for runtime configuration resolution.
    ///
    /// Callers walking the chain in application code should generally
    /// prefer [`FactorStore::resolve_factor`](super::store::FactorStore::resolve_factor),
    /// which pushes the walk into the storage backend (one query
    /// instead of N sequential trips). Use this helper for admin/UI
    /// paths that need to enumerate the scopes explicitly.
    ///
    /// Order is narrowest → broadest. For a `User` scope: `[User, Tenant, System]`.
    /// For `Tenant`: `[Tenant, System]`. For `System`: `[System]`.
    pub fn resolution_chain(&self) -> Vec<AuthnScope> {
        match self {
            AuthnScope::System => vec![AuthnScope::System],
            AuthnScope::Tenant(t) => vec![AuthnScope::Tenant(*t), AuthnScope::System],
            AuthnScope::User { tenant_id, user_id } => vec![
                AuthnScope::User {
                    tenant_id: *tenant_id,
                    user_id: *user_id,
                },
                AuthnScope::Tenant(*tenant_id),
                AuthnScope::System,
            ],
        }
    }
}

/// Storage-layer projection of an [`AuthnScope`] onto `(tenant_id, user_id)`
/// columns for scope-applicability data (factor configs, auth methods).
///
/// `tenant_id` is always populated ([`TenantId::SYSTEM`] for
/// [`AuthnScope::System`]); only `user_id` can be absent: `None` means
/// "applies to any user at the tenant or system level". SQL callers never
/// need `tenant_id IS NULL` special-cases for configuration scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeColumns {
    /// Tenant column; always populated ([`TenantId::SYSTEM`] for the
    /// [`AuthnScope::System`] row).
    pub tenant_id: TenantId,
    /// User column; `None` encodes "applies to any user at the tenant or system level".
    pub user_id: Option<UserId>,
}

/// What to do when the failed-attempt counter store is unavailable.
///
/// [`IdentityAuthnLog::record_failed_attempt`](super::store::IdentityAuthnLog::record_failed_attempt)
/// can fail independently of the reads that got the login this far: the
/// read-replica split this library encourages puts reads on a replica and
/// this write on the primary, so a primary outage leaves logins working and
/// the counter dead. While that lasts, the count never rises and
/// `max_attempts` is never reached.
///
/// Neither choice below changes the response an attacker sees for a
/// *nonexistent* user: those are rejected at `begin_login` with timing
/// equalization and never reach the counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CounterUnavailable {
    /// Treat the attempt as locked. Brute force stays bounded during the
    /// outage; a user who mistypes their password is told they are locked
    /// and can retry once `duration` elapses. The default, because an
    /// authentication library should fail closed.
    ///
    /// Note the interaction with `duration: None`: an indefinite lockout
    /// plus a persistently broken counter store needs an administrator to
    /// clear each affected account. Deployments running indefinite lockouts
    /// should either monitor [`AuthnMetrics::factor_counter_store_outage`](crate::metrics::AuthnMetrics::factor_counter_store_outage)
    /// or choose [`Allow`](Self::Allow) knowingly.
    #[default]
    Lock,
    /// Treat the attempt as an ordinary failure. Logins keep working and
    /// lockout is disabled for the duration of the outage, which is an
    /// unbounded brute-force window precisely when monitoring is degraded.
    /// Choose this only with a compensating control, such as a
    /// `KeyExtractor::LoginIdentifier` rate limiter in front of the route.
    Allow,
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
    /// What to do when the counter store itself is unavailable.
    /// Default: [`CounterUnavailable::Lock`].
    pub on_counter_unavailable: CounterUnavailable,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            duration: Some(Duration::from_secs(15 * 60)),
            attempt_window: Duration::from_secs(60 * 60),
            on_counter_unavailable: CounterUnavailable::Lock,
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
mod authn_types_tests;
