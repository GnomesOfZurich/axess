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

use crate::{SessionKey, TenantId, UserId};

/// A human user authenticated through an interactive session.
///
/// Fields:
/// - [`user_id`](Self::user_id), [`tenant_id`](Self::tenant_id):
///   tenant-scoped identity from the session.
/// - [`session_id`](Self::session_id): the key of the session that
///   authenticated this user. `None` for principals minted outside an HTTP
///   request context (background tasks acting on behalf of a user,
///   scheduled jobs replaying user-attributed actions).
/// - [`impersonator`](Self::impersonator): the administrator acting in
///   the user's name, when the session is an impersonation.
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
    /// The key of the session, when the principal was built from an HTTP
    /// request: the name the session's records carry, never the value its
    /// cookie carries. `None` for background-task and replay contexts.
    ///
    /// A principal an earlier release serialised (a decision log, a queue)
    /// holds the id of a session in this field; it reads as the key of that
    /// id, which names a session that no longer exists.
    #[cfg_attr(
        feature = "serde",
        serde(default, deserialize_with = "SessionKey::deserialize_recorded_option")
    )]
    pub session_id: Option<SessionKey>,
    /// The administrator acting in this user's name, for a principal built
    /// from an impersonated session; `None` for the user's own. Authorisation
    /// and audit read it to tell the user from the administrator using the
    /// user's session.
    pub impersonator: Option<UserId>,
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
            impersonator: None,
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
            session_id: Some(SessionKey::of(&crate::SessionId::from_bytes([7u8; 16]))),
            impersonator: None,
            attributes: BTreeMap::new(),
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: HumanPrincipal = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    /// The JSON of a principal with `session` in its `session_id` field.
    #[cfg(feature = "serde")]
    fn principal_json(session: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "user_id": UserId::from_bytes([5u8; 16]),
            "tenant_id": TenantId::from_bytes([6u8; 16]),
            "session_id": session,
            "impersonator": null,
            "attributes": {},
        })
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_principal_names_its_session_by_the_64_characters_of_its_key() {
        let key = SessionKey::of(&crate::SessionId::from_bytes([8u8; 16]));
        let h = HumanPrincipal {
            user_id: UserId::from_bytes([5u8; 16]),
            tenant_id: TenantId::from_bytes([6u8; 16]),
            session_id: Some(key),
            impersonator: None,
            attributes: BTreeMap::new(),
        };
        let json = serde_json::to_value(&h).unwrap();
        assert_eq!(json["session_id"], serde_json::json!(key.to_string()));
        assert_eq!(json["session_id"].as_str().map(str::len), Some(64));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_principal_an_earlier_release_serialised_reads_its_session_id_as_the_key_of_that_id() {
        let id = crate::SessionId::from_bytes([9u8; 16]);
        let read: HumanPrincipal =
            serde_json::from_value(principal_json(serde_json::json!(id.to_string()))).unwrap();
        assert_eq!(read.session_id, Some(SessionKey::of(&id)));

        let key = SessionKey::of(&id);
        let read: HumanPrincipal =
            serde_json::from_value(principal_json(serde_json::json!(key.to_string()))).unwrap();
        assert_eq!(read.session_id, Some(key));

        let read: HumanPrincipal =
            serde_json::from_value(principal_json(serde_json::Value::Null)).unwrap();
        assert_eq!(read.session_id, None);
        let mut missing = principal_json(serde_json::Value::Null);
        missing.as_object_mut().unwrap().remove("session_id");
        let read: HumanPrincipal = serde_json::from_value(missing).unwrap();
        assert_eq!(read.session_id, None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_principal_whose_session_is_neither_a_key_nor_an_id_is_refused() {
        let upper = SessionKey::of(&crate::SessionId::from_bytes([9u8; 16]))
            .to_string()
            .to_uppercase();
        for text in ["", "a session", "0123456789abcdef", upper.as_str()] {
            assert!(
                serde_json::from_value::<HumanPrincipal>(principal_json(serde_json::json!(text)))
                    .is_err(),
                "{text:?} is not read as a session"
            );
        }
    }
}
