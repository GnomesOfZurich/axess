//! Human principals: users authenticated through an interactive
//! session.
//!
//! Built by a session-aware resolver (axess-core's `SessionResolver`
//! consumes an authenticated `AuthSession`; adopters with their own
//! session abstraction can implement [`PrincipalResolver`](crate::PrincipalResolver)
//! against their type). Constructed only when authentication has
//! actually completed; partially-authenticated state machines
//! produce no principal.

use std::collections::BTreeMap;

use crate::{SessionId, TenantId, UserId};

/// A human user authenticated through an interactive session.
///
/// Fields:
/// - [`user_id`](Self::user_id), [`tenant_id`](Self::tenant_id):
///   tenant-scoped identity from the session.
/// - [`session_id`](Self::session_id): the session that authenticated
///   this user. `None` for principals minted outside an HTTP request
///   context (background tasks acting on behalf of a user, scheduled
///   jobs replaying user-attributed actions).
/// - [`attributes`](Self::attributes): arbitrary key-value metadata.
///   Empty for baseline principals; future iterations may carry
///   claim-shaped data (e.g. `amr` per OIDC for the factors used at
///   authentication).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HumanPrincipal {
    /// The authenticated user.
    pub user_id: UserId,
    /// Tenant the user is acting within.
    pub tenant_id: TenantId,
    /// The session id, when the principal was built from an HTTP
    /// request. `None` for background-task and replay contexts.
    pub session_id: Option<SessionId>,
    /// Arbitrary key-value metadata supplied by the resolver.
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_principal_constructs_with_minimal_fields() {
        let h = HumanPrincipal {
            user_id: UserId::from_bytes([3u8; 16]),
            tenant_id: TenantId::from_bytes([4u8; 16]),
            session_id: None,
            attributes: BTreeMap::new(),
        };
        assert!(h.session_id.is_none());
        assert!(h.attributes.is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn human_principal_serde_round_trip() {
        let h = HumanPrincipal {
            user_id: UserId::from_bytes([5u8; 16]),
            tenant_id: TenantId::from_bytes([6u8; 16]),
            session_id: Some(SessionId::from_bytes([7u8; 16])),
            attributes: BTreeMap::new(),
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: HumanPrincipal = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }
}
