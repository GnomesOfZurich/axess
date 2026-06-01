//! Test fixtures for the identity layer.
//!
//! Two surfaces in one module (single canonical location for everything
//! tests need from `axess-identity`):
//!
//! - **Deterministic-id helpers** ([`tenant`], [`user`], [`device`],
//!   [`session`], [`event`]): label → stable [`Uuid`] v5 mapping over a
//!   fixed test namespace. Same label → same id across the suite and
//!   across runs.
//! - **[`MockResolver`]**: a [`PrincipalResolver`] that returns a
//!   pre-built [`Principal`] (or a canned [`IdentityError`]) on every
//!   `resolve` call.
//!
//! Gated on the `testing` feature so production builds don't compile
//! this surface. Downstream crates enable via
//! `axess-identity = { ..., features = ["testing"] }` in their
//! `[dev-dependencies]` (or forward through their own `testing` feature).
//!
//! ```rust,ignore
//! use axess_identity::testing;
//!
//! let a = testing::tenant("acme");
//! let b = testing::tenant("acme");
//! let c = testing::tenant("other");
//! assert_eq!(a, b);
//! assert_ne!(a, c);
//! ```

use uuid::Uuid;

use crate::id::{DeviceId, EventId, SessionId, TenantId, UserId};
use crate::{IdentityError, Principal, PrincipalResolver};

// ── Deterministic-id helpers ─────────────────────────────────────────────────

/// Fixed namespace UUID for label → id mapping in tests. Stable across the
/// workspace so cross-crate test fixtures agree on the bytes a given
/// label produces.
pub const TEST_NAMESPACE: Uuid = Uuid::from_bytes([
    0x9a, 0x36, 0xb1, 0xfe, 0x3c, 0xf2, 0x4b, 0xa5, 0x88, 0x46, 0xe1, 0x47, 0x65, 0x09, 0xc7, 0x12,
]);

/// Stable [`TenantId`] derived from `label` via UUID v5.
#[inline]
pub fn tenant(label: &str) -> TenantId {
    TenantId::from_namespaced_str(TEST_NAMESPACE, label)
}

/// Stable [`UserId`] derived from `label` via UUID v5.
#[inline]
pub fn user(label: &str) -> UserId {
    UserId::from_namespaced_str(TEST_NAMESPACE, label)
}

/// Stable [`DeviceId`] derived from `label` via UUID v5.
#[inline]
pub fn device(label: &str) -> DeviceId {
    DeviceId::from_namespaced_str(TEST_NAMESPACE, label)
}

/// Stable [`SessionId`] derived from `label` via UUID v5. Useful for
/// fixture-driven session tests; production code must use
/// [`SessionId::new`] (cryptographic opacity is the security contract).
#[inline]
pub fn session(label: &str) -> SessionId {
    SessionId::from_namespaced_str(TEST_NAMESPACE, label)
}

/// Stable [`EventId`] derived from `label` via UUID v5.
#[inline]
pub fn event(label: &str) -> EventId {
    EventId::from_namespaced_str(TEST_NAMESPACE, label)
}

// ── MockResolver ─────────────────────────────────────────────────────────────

/// Mock [`PrincipalResolver`] returning a canned [`Principal`] or
/// [`IdentityError`] for tests.
#[derive(Debug, Clone)]
pub struct MockResolver {
    outcome: Result<Principal, MockErrorShape>,
}

/// Cloneable error shape mirroring the [`IdentityError`] variants that
/// make sense to return from a mock resolver (the parsing variants
/// don't; those are produced by validation paths, not by a resolver
/// that already holds a principal).
#[derive(Debug, Clone)]
enum MockErrorShape {
    NotAuthenticated,
    InvalidComponent(String),
}

impl MockErrorShape {
    fn rebuild(&self) -> IdentityError {
        match self {
            Self::NotAuthenticated => IdentityError::NotAuthenticated,
            Self::InvalidComponent(msg) => IdentityError::InvalidComponent(msg.clone()),
        }
    }
}

impl MockResolver {
    /// Construct a mock that returns `principal` on every `resolve`.
    pub fn new(principal: Principal) -> Self {
        Self {
            outcome: Ok(principal),
        }
    }

    /// Construct a mock that returns [`IdentityError::NotAuthenticated`]
    /// on every `resolve`. Useful for testing the
    /// no-authenticated-identity branch of consumer code.
    pub fn not_authenticated() -> Self {
        Self {
            outcome: Err(MockErrorShape::NotAuthenticated),
        }
    }

    /// Construct a mock that returns
    /// [`IdentityError::InvalidComponent`] with the supplied message.
    pub fn invalid_component(message: impl Into<String>) -> Self {
        Self {
            outcome: Err(MockErrorShape::InvalidComponent(message.into())),
        }
    }
}

impl PrincipalResolver for MockResolver {
    async fn resolve(&self) -> Result<Principal, IdentityError> {
        match &self.outcome {
            Ok(p) => Ok(p.clone()),
            Err(shape) => Err(shape.rebuild()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{HumanPrincipal, Issuer, TrustDomain, WorkloadId, WorkloadPrincipal};
    use crate::{TenantId, UserId};

    fn sample_human() -> Principal {
        Principal::Human(HumanPrincipal {
            user_id: UserId::from_bytes([1u8; 16]),
            tenant_id: TenantId::from_bytes([2u8; 16]),
            session_id: None,
            attributes: BTreeMap::new(),
        })
    }

    fn sample_workload() -> Principal {
        let trust = TrustDomain::new("gnomes.local").unwrap();
        let wid = WorkloadId::build(&trust, "compute-worker", "ekekrantz").unwrap();
        Principal::Workload(WorkloadPrincipal {
            workload_id: wid,
            trust_domain: trust,
            issuer: Issuer::Cli,
            tenant_id: TenantId::from_bytes([3u8; 16]),
            tenant_slug: "ekekrantz".to_string(),
            service_name: "compute-worker".to_string(),
            attributes: BTreeMap::new(),
        })
    }

    #[tokio::test]
    async fn mock_returns_canned_human_principal() {
        let canned = sample_human();
        let mock = MockResolver::new(canned.clone());
        let resolved = mock.resolve().await.unwrap();
        assert_eq!(resolved, canned);
    }

    #[tokio::test]
    async fn mock_returns_canned_workload_principal() {
        let canned = sample_workload();
        let mock = MockResolver::new(canned.clone());
        let resolved = mock.resolve().await.unwrap();
        assert_eq!(resolved, canned);
    }

    #[tokio::test]
    async fn mock_is_idempotent_across_calls() {
        let mock = MockResolver::new(sample_human());
        let a = mock.resolve().await.unwrap();
        let b = mock.resolve().await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn mock_not_authenticated_returns_error() {
        let mock = MockResolver::not_authenticated();
        let err = mock.resolve().await.unwrap_err();
        assert!(matches!(err, IdentityError::NotAuthenticated));
    }

    #[tokio::test]
    async fn mock_invalid_component_carries_message() {
        let mock = MockResolver::invalid_component("oops");
        let err = mock.resolve().await.unwrap_err();
        match err {
            IdentityError::InvalidComponent(msg) => assert_eq!(msg, "oops"),
            other => panic!("expected InvalidComponent, got {other:?}"),
        }
    }
}
