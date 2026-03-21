//! Mock authorization components for deterministic simulation testing (DST).
//!
//! Use [`MockPolicyEvaluator`] to control Cedar policy decisions in tests
//! without loading any `.cedar` policy files. Use [`MockEntityProvider`] as a
//! no-op entity provider when the entity graph is irrelevant to what you are
//! testing (e.g. when you only want to verify that a handler propagates a denial
//! correctly).
//!
//! # Example
//!
//! ```rust
//! # tokio_test::block_on(async {
//! use axess_core::authz::{AuthzStore, AuthzDecision};
//! use axess_core::utils::testing::mock_policy::{MockEntityProvider, MockPolicyEvaluator};
//! use std::sync::Arc;
//!
//! // Build a decision table:
//! let evaluator = Arc::new(
//!     MockPolicyEvaluator::new()
//!         .permit_ns("TestApp", "ViewLedger", "Resource", "ledger-abc")
//! );
//!
//! let store = Arc::new(AuthzStore::new(
//!     evaluator,
//!     Arc::new(MockEntityProvider::new("TestApp")),
//!     "TestApp",
//! ));
//!
//! let authz = store.for_user_id("user-1").unwrap();
//! assert!(authz.is_permitted("ViewLedger", &"ledger-abc".to_string()).await);
//! # });
//! ```

use std::collections::HashMap;

use cedar_policy::{Context, Entities, EntityUid};

use crate::authz::{
    AuthzEntityProvider, AuthzError,
    store::{AuthzDecision, PolicyEvaluator},
};

// ── MockPolicyEvaluator ───────────────────────────────────────────────────────

/// Deterministic [`PolicyEvaluator`] for tests.
///
/// Decisions are keyed by `(action_uid_string, resource_uid_string)`. Any pair
/// not in the table falls back to `default` (deny-by-default unless you call
/// [`allow_all`][Self::allow_all]).
pub struct MockPolicyEvaluator {
    decisions: HashMap<(String, String), AuthzDecision>,
    default: AuthzDecision,
}

impl MockPolicyEvaluator {
    /// Create a deny-by-default evaluator with an empty decision table.
    pub fn new() -> Self {
        Self {
            decisions: HashMap::new(),
            default: AuthzDecision::Deny,
        }
    }

    /// Create an allow-by-default evaluator. Explicit denials can still be
    /// added via [`deny`][Self::deny].
    pub fn allow_all() -> Self {
        Self {
            decisions: HashMap::new(),
            default: AuthzDecision::Allow,
        }
    }

    /// Register an explicit `Allow` for a (action, resource) pair.
    ///
    /// Both strings are matched against the full Cedar `EntityUid` string
    /// representation, e.g. `"MyApp::Action::\"ViewLedger\""`.
    /// Use [`permit_simple`][Self::permit_simple] for namespace-free matching.
    pub fn permit(mut self, action_uid: &str, resource_uid: &str) -> Self {
        self.decisions.insert(
            (action_uid.to_string(), resource_uid.to_string()),
            AuthzDecision::Allow,
        );
        self
    }

    /// Register an explicit `Deny` for a (action, resource) pair.
    pub fn deny(mut self, action_uid: &str, resource_uid: &str) -> Self {
        self.decisions.insert(
            (action_uid.to_string(), resource_uid.to_string()),
            AuthzDecision::Deny,
        );
        self
    }

    /// Convenience variant of [`permit`][Self::permit] that accepts bare
    /// action and resource names and builds the full UID strings using the
    /// given namespace.
    ///
    /// ```rust
    /// use axess_core::utils::testing::mock_policy::MockPolicyEvaluator;
    /// let evaluator = MockPolicyEvaluator::new()
    ///     .permit_ns("TestApp", "ViewLedger", "Ledger", "ledger-1");
    /// ```
    pub fn permit_ns(
        mut self,
        namespace: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Self {
        self.decisions.insert(
            (
                format!(r#"{namespace}::Action::"{action}""#),
                format!(r#"{namespace}::{resource_type}::"{resource_id}""#),
            ),
            AuthzDecision::Allow,
        );
        self
    }

    /// Convenience variant of [`deny`][Self::deny] that accepts bare names.
    pub fn deny_ns(
        mut self,
        namespace: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> Self {
        self.decisions.insert(
            (
                format!(r#"{namespace}::Action::"{action}""#),
                format!(r#"{namespace}::{resource_type}::"{resource_id}""#),
            ),
            AuthzDecision::Deny,
        );
        self
    }
}

impl Default for MockPolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator for MockPolicyEvaluator {
    fn is_authorized(
        &self,
        _entities: &Entities,
        _principal: EntityUid,
        action: EntityUid,
        resource: EntityUid,
        _context: Context,
    ) -> AuthzDecision {
        let key = (action.to_string(), resource.to_string());
        self.decisions.get(&key).copied().unwrap_or(self.default)
    }
}

// ── MockEntityProvider ────────────────────────────────────────────────────────

/// No-op [`AuthzEntityProvider`] for tests where the entity graph is irrelevant.
///
/// Returns `Entities::empty()` for every call to `entities_for`. Suitable
/// when paired with [`MockPolicyEvaluator`] — the evaluator ignores the entity
/// set anyway.
///
/// `ResourceId` is `String` for simplicity; build UIDs as
/// `{namespace}::Resource::"id"`.
pub struct MockEntityProvider {
    namespace: String,
}

impl MockEntityProvider {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }
}

impl AuthzEntityProvider for MockEntityProvider {
    type ResourceId = String;
    type Error = AuthzError;

    async fn entities_for(
        &self,
        _principal: &EntityUid,
        _resource_id: &String,
        _action: &EntityUid,
    ) -> Result<Entities, AuthzError> {
        Ok(Entities::empty())
    }

    // Note: the compiler will warn about `async fn` in trait. The method is
    // declared as `fn ... -> impl Future` in the trait, but `async fn` in an
    // impl is compatible with that in Rust 2024 (RPIT in trait desugaring).

    fn resource_uid(&self, id: &String) -> Result<EntityUid, AuthzError> {
        use std::str::FromStr;
        EntityUid::from_str(&format!(r#"{}::Resource::"{id}""#, self.namespace))
            .map_err(|e| AuthzError::InvalidEntityUid(format!("Resource/{id}: {e:?}")))
    }
}
