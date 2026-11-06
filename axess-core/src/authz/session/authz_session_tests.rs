use super::*;
use crate::authz::store::PolicyStore;
use cedar_policy::{Entities, EntityUid, Schema};

const SCHEMA_JSON: &str = r#"{
    "TestApp": {
        "entityTypes": {
            "User": { "memberOfTypes": [] },
            "Resource": { "memberOfTypes": [] }
        },
        "actions": {
            "View": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Resource"]
                }
            }
        }
    }
}"#;

const POLICY_TEXT: &str = r#"permit(
    principal == TestApp::User::"alice",
    action == TestApp::Action::"View",
    resource == TestApp::Resource::"doc1"
);"#;

struct ErroringProvider;

impl AuthzEntityProvider for ErroringProvider {
    type ResourceId = String;
    type Error = std::convert::Infallible;

    async fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        tracing::trace!(
            target: "axess::authz::test_stub",
            ?principal,
            ?resource_id,
            ?action,
            "ErroringProvider::entities_for: returning empty entities",
        );
        Ok(Entities::empty())
    }

    async fn entities_for_tenant(
        &self,
        principal: &EntityUid,
        _tenant: Option<&str>,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        self.entities_for(principal, resource_id, action).await
    }

    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError> {
        super::super::store::make_uid("TestApp", "Resource", id)
    }

    fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
        tracing::trace!(
            target: "axess::authz::test_stub",
            ?schema,
            "ErroringProvider::validate_schema: synthetic failure",
        );
        Err(AuthzError::SchemaParse(
            "synthetic schema validation failure".to_string(),
        ))
    }
}

#[test]
fn validate_propagates_provider_validation_error() {
    // Pins `AuthzStore::validate -> Ok(())` mutation. The
    // mutation skips the inner `provider.validate_schema`
    // call. With a provider that errors, the genuine path returns
    // `Err`; the mutation would silently return `Ok(())` and
    // mask startup-time schema mismatches.
    let evaluator: Arc<dyn PolicyEvaluator> =
        Arc::new(PolicyStore::from_text(POLICY_TEXT, SCHEMA_JSON).unwrap());
    let store = AuthzStore::new_unvalidated(evaluator, Arc::new(ErroringProvider), "TestApp");
    let result = store.validate();
    assert!(
        matches!(result, Err(AuthzError::SchemaParse(_))),
        "validate() must propagate provider's validate_schema error, got {result:?}"
    );
}

/// Records the tenant it was asked for; refuses the resource id `bad`.
struct TenantRecordingProvider {
    seen: Mutex<Vec<Option<String>>>,
}

impl AuthzEntityProvider for TenantRecordingProvider {
    type ResourceId = String;
    type Error = std::convert::Infallible;

    async fn entities_for(
        &self,
        principal: &EntityUid,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        tracing::trace!(?principal, ?resource_id, ?action, "tenant-less path");
        self.seen.lock().unwrap().push(None);
        Ok(Entities::empty())
    }

    async fn entities_for_tenant(
        &self,
        principal: &EntityUid,
        tenant: Option<&str>,
        resource_id: &Self::ResourceId,
        action: &EntityUid,
    ) -> Result<Entities, Self::Error> {
        tracing::trace!(?principal, ?resource_id, ?action, "tenant path");
        self.seen.lock().unwrap().push(tenant.map(str::to_string));
        Ok(Entities::empty())
    }

    fn resource_uid(&self, id: &Self::ResourceId) -> Result<EntityUid, AuthzError> {
        if id == "bad" {
            return Err(AuthzError::InvalidEntityUid("bad".to_string()));
        }
        super::super::store::make_uid("TestApp", "Resource", id)
    }

    fn validate_schema(&self, schema: &Schema) -> Result<(), AuthzError> {
        tracing::trace!(?schema, "accepted");
        Ok(())
    }
}

fn tenant_store() -> Arc<AuthzStore<TenantRecordingProvider>> {
    let evaluator: Arc<dyn PolicyEvaluator> =
        Arc::new(PolicyStore::from_text(POLICY_TEXT, SCHEMA_JSON).unwrap());
    Arc::new(
        AuthzStore::try_new(
            evaluator,
            Arc::new(TenantRecordingProvider {
                seen: Mutex::new(Vec::new()),
            }),
            "TestApp",
        )
        .unwrap(),
    )
}

/// The tenant a session was opened for reaches the provider.
#[tokio::test]
async fn the_session_tenant_reaches_the_provider() {
    let store = tenant_store();
    let authz = store.for_user_in_tenant("alice", "tenant-a").unwrap();
    assert!(authz.is_permitted("View", &"doc1".to_string()).await);
    let authz = store.for_user_id("alice").unwrap();
    assert!(authz.is_permitted("View", &"doc1".to_string()).await);
    let seen = store.provider.seen.lock().unwrap().clone();
    assert_eq!(seen, vec![Some("tenant-a".to_string()), None]);
}

/// A denial before Cedar is asked still emits the decision event.
#[tokio::test]
async fn a_denial_before_evaluation_emits_a_decision_event() {
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Fields(String);
    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!("{}={value:?} ", field.name()));
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == super::super::audit::DECISION_TARGET {
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
        }
    }

    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let store = tenant_store();
    let authz = store.for_user_id("alice").unwrap();
    assert!(!authz.is_permitted("View", &"bad".to_string()).await);

    let events = capture.0.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| e.contains("invalid_resource") && e.contains("deny")),
        "events: {events:?}"
    );
}

/// A session nobody has logged into has no principal: that is the 401
/// `NoPrincipal`, not the 500 `InvalidEntityUid`.
#[tokio::test]
async fn an_unauthenticated_session_is_no_principal() {
    use crate::session::layer::{SessionHandle, SessionInner};
    let inner = SessionInner {
        id: crate::session::id::SessionId::new(&axess_rng::SystemRng),
        data: crate::session::data::SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
        consume: None,
    };
    let session =
        crate::session::AuthSession(SessionHandle(Arc::new(tokio::sync::RwLock::new(inner))));
    let result = tenant_store().for_session(&session, NoContext).await;
    assert!(
        matches!(result, Err(AuthzError::NoPrincipal)),
        "{:?}",
        result.err()
    );
}

/// The documented constructor validates the provider against the schema, so
/// a mismatch is a startup error instead of denials found in production.
#[test]
fn try_new_refuses_a_provider_that_fails_schema_validation() {
    let evaluator: Arc<dyn PolicyEvaluator> =
        Arc::new(PolicyStore::from_text(POLICY_TEXT, SCHEMA_JSON).unwrap());
    let refused = AuthzStore::try_new(evaluator.clone(), Arc::new(ErroringProvider), "TestApp");
    assert!(
        matches!(refused, Err(AuthzError::SchemaParse(_))),
        "a provider the schema rejects must not build a store"
    );
    let accepted = AuthzStore::try_new(
        evaluator,
        Arc::new(TenantRecordingProvider {
            seen: Mutex::new(Vec::new()),
        }),
        "TestApp",
    );
    assert!(accepted.is_ok());
}
