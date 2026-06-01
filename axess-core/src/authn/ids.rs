//! Typed identifiers for tenants, users, and devices.
//!
//! Re-exports from [`axess_identity`] so the workspace has one
//! uniform `pub struct FooId(uuid::Uuid)` shape across auth principals
//! (axess-core), events (axess-events), and any adopter-declared ids
//! (via [`axess_identity::define_id!`]).
//!
//! Each id is 16 bytes (UUID v4 body), `Copy`, and produces a
//! hyphenated UUID string via `Display` / `serde` / `to_string()`. Fresh
//! ids mint through the DST-injectable
//! [`SecureRng`](axess_rng::SecureRng): production threads
//! `SystemRng`; tests inject `MockRng` for reproducible runs. The
//! UUIDv5 boundary helper
//! [`TenantId::from_namespaced_str`](axess_identity::TenantId::from_namespaced_str)
//! maps adopter-supplied non-UUID identifiers (slugs, OAuth subjects)
//! to stable Uuids without coordination.
//!
//! ## The reserved system tenant and user
//!
//! [`TenantId::SYSTEM`](axess_identity::TenantId::SYSTEM) and
//! [`UserId::SYSTEM`](axess_identity::UserId::SYSTEM) name the platform-operator
//! tenant and user. Both are real installed principals; applications are
//! expected to install corresponding rows in their `tenants` / `users`
//! tables so foreign-key constraints remain intact. The reserved Uuids
//! are distinct (`...0000` for the tenant, `...0001` for the user) so
//! applications installing both don't collapse them.
//!
//! ## Unknown attribution (pre-auth events, failed lookups)
//!
//! There is deliberately **no sentinel for "unknown user" or "unknown
//! tenant"**. When an audit event fires before a principal is resolved
//! (e.g. failed login for a non-existent user, OAuth callback with a
//! malformed subject), the correct type is `Option<UserId>` /
//! `Option<TenantId>` at the event level; see
//! [`AuthEvent`](crate::authn::event::AuthEvent). This keeps [`UserId`]
//! and [`TenantId`] honest: a value of either type always refers to a
//! real, validated principal.

pub use axess_identity::{DeviceId, IdError, TenantId, UserId, ensure_user_id_not_reserved};

/// Re-export the [`axess_identity::testing`] module: stable v5-derived
/// fixture builders (`tenant("alice")` → deterministic `TenantId`,
/// etc.). Available to integration tests without taking a direct
/// `axess-identity` dev-dep.
///
/// Gated on `cfg(any(test, feature = "testing"))` to mirror upstream:
/// `axess_identity::testing` only compiles under its own `testing`
/// feature, which `axess-core`'s `testing` feature forwards.
#[cfg(any(test, feature = "testing"))]
pub use axess_identity::testing;

#[cfg(test)]
mod tests {
    use super::*;
    use axess_identity::Uuid;

    #[test]
    fn system_tenant_is_nil() {
        assert!(TenantId::SYSTEM.is_nil());
        assert_eq!(TenantId::SYSTEM_STR, TenantId::SYSTEM.to_string());
    }

    #[test]
    fn system_user_distinct_from_system_tenant() {
        // Applications may install both as real rows (one in `users`, one
        // in `tenants`); using the same Uuid for both would collapse the
        // system principal with the system tenant.
        assert_ne!(UserId::SYSTEM.as_uuid(), TenantId::SYSTEM.as_uuid());
    }

    #[test]
    fn try_new_rejects_empty() {
        assert_eq!(TenantId::try_new(""), Err(IdError::Empty("TenantId")));
        assert_eq!(UserId::try_new(""), Err(IdError::Empty("UserId")));
    }

    #[test]
    fn try_new_accepts_uuid_shape() {
        let t = TenantId::try_new("1f0a7b2e-4c91-4e3f-9b2a-8d0123456789").unwrap();
        assert!(!t.is_nil());
        assert_eq!(t.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn try_new_rejects_non_uuid() {
        assert!(matches!(
            TenantId::try_new("ab\nc"),
            Err(IdError::NotAUuid(_))
        ));
        assert!(matches!(
            UserId::try_new("ab\0c"),
            Err(IdError::NotAUuid(_))
        ));
    }

    #[test]
    fn serde_round_trip_is_hyphenated_uuid() {
        let t = TenantId::try_new("1f0a7b2e-4c91-4e3f-9b2a-8d0123456789").unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"1f0a7b2e-4c91-4e3f-9b2a-8d0123456789\"");
        let back: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn from_str_works() {
        use std::str::FromStr;
        assert!(TenantId::from_str("1f0a7b2e-4c91-4e3f-9b2a-8d0123456789").is_ok());
        assert!(TenantId::from_str("").is_err());
    }

    #[test]
    fn ensure_user_id_not_reserved_blocks_system_user() {
        let res = ensure_user_id_not_reserved(&UserId::SYSTEM, &TenantId::from_uuid(Uuid::nil()));
        // Both args reserved; TenantId is checked first in the helper, but
        // either order surfaces some `Reserved(_)`. Accept any variant.
        assert!(matches!(res, Err(IdError::Reserved(_))));
    }

    #[test]
    fn ensure_user_id_not_reserved_accepts_normal_pair() {
        let user = UserId::try_new("1f0a7b2e-4c91-4e3f-9b2a-8d0123456789").unwrap();
        let tenant = TenantId::try_new("2a0b7b2e-4c91-4e3f-9b2a-8d0123456789").unwrap();
        assert!(ensure_user_id_not_reserved(&user, &tenant).is_ok());
    }

    #[test]
    fn device_id_round_trips_via_uuid() {
        let d = DeviceId::try_new("00000000-0000-4000-8000-000000000abc").unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "\"00000000-0000-4000-8000-000000000abc\"");
        let back: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
