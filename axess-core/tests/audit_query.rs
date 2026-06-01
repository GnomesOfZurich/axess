#![cfg(feature = "testing")]
//! `AuditQuery` capability-trait semantics: tenant scoping, `include_unscoped`
//! platform-rail flag, and cross-tenant isolation against a tiny in-memory
//! implementor.

use axess_core::authn::event::{AuthEvent, AuthEventStatus, AuthEventType};
use axess_core::authn::ids::TenantId;
use axess_core::authn::store::{AuditQuery, EventQueryFilter};
use std::sync::{Arc, Mutex};

/// Tiny in-memory implementor used to prove the capability split
/// works at type-check time and at runtime for the tenant-scoping
/// rail. Lives in the test module: backends in the main crate are
/// free to add the impl when they grow audit-table support.
#[derive(Clone, Default)]
struct InMemAuditStore {
    events: Arc<Mutex<Vec<AuthEvent>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("never fails")]
struct InMemAuditError;

impl AuditQuery for InMemAuditStore {
    type Error = InMemAuditError;

    async fn query_events(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> Result<Vec<AuthEvent>, Self::Error> {
        let guard = self.events.lock().unwrap();
        let mut out: Vec<AuthEvent> = guard
            .iter()
            .filter(|e| {
                let tenant_ok = match &e.tenant_id {
                    Some(tid) => tid == tenant_id,
                    None => filter.include_unscoped,
                };
                let user_ok = match (&filter.user_id, &e.user_id) {
                    (Some(want), Some(have)) => want == have,
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                tenant_ok && user_ok
            })
            .cloned()
            .collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.event_time));
        if filter.limit > 0 {
            out.truncate(filter.limit as usize);
        }
        Ok(out)
    }
}

fn make_event(
    user: Option<&str>,
    tenant: Option<&str>,
    ty: AuthEventType,
    status: AuthEventStatus,
) -> AuthEvent {
    AuthEvent {
        user_id: user.map(axess_core::authn::ids::testing::user),
        tenant_id: tenant.map(axess_core::authn::ids::testing::tenant),
        session_id: None,
        event_type: ty,
        event_status: status,
        event_time: chrono::Utc::now().timestamp_micros(),
        factor_kind: None,
        ip_address: None,
        user_agent: None,
        request_id: None,
        geo_country: None,
        error: None,
        actor_id: None,
        device_id: None,
        factors_completed: vec![],
    }
}

/// include_unscoped=true returns both tenant-scoped and
/// platform-rail (tenant_id IS NULL) events.
#[tokio::test]
async fn includes_unscoped_when_flagged() {
    let store = InMemAuditStore::default();
    store.events.lock().unwrap().extend([
        make_event(
            Some("u-1"),
            Some("tenant-a"),
            AuthEventType::FactorVerified,
            AuthEventStatus::Success,
        ),
        make_event(
            None,
            None,
            AuthEventType::FactorVerified,
            AuthEventStatus::Failure,
        ),
        // Other-tenant event must NOT leak.
        make_event(
            Some("u-2"),
            Some("tenant-b"),
            AuthEventType::FactorVerified,
            AuthEventStatus::Success,
        ),
    ]);

    let tenant = axess_core::authn::ids::testing::tenant("tenant-a");
    let filter = EventQueryFilter {
        include_unscoped: true,
        ..Default::default()
    };
    let result = store.query_events(&tenant, &filter).await.unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.iter().any(|e| e.tenant_id.is_none()));
    assert!(
        result
            .iter()
            .any(|e| e.tenant_id == Some(axess_core::authn::ids::testing::tenant("tenant-a")))
    );
}

/// include_unscoped=false hides platform-rail events from
/// tenant audit views.
#[tokio::test]
async fn excludes_unscoped_when_flag_off() {
    let store = InMemAuditStore::default();
    store.events.lock().unwrap().extend([
        make_event(
            Some("u-1"),
            Some("tenant-a"),
            AuthEventType::FactorVerified,
            AuthEventStatus::Success,
        ),
        make_event(
            None,
            None,
            AuthEventType::FactorVerified,
            AuthEventStatus::Failure,
        ),
    ]);

    let tenant = axess_core::authn::ids::testing::tenant("tenant-a");
    let filter = EventQueryFilter {
        include_unscoped: false,
        ..Default::default()
    };
    let result = store.query_events(&tenant, &filter).await.unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].tenant_id.is_some());
}

/// Events from a different tenant never appear in the
/// caller's view, regardless of `include_unscoped`.
#[tokio::test]
async fn never_leaks_across_tenants() {
    let store = InMemAuditStore::default();
    store.events.lock().unwrap().push(make_event(
        Some("u-2"),
        Some("tenant-b"),
        AuthEventType::FactorVerified,
        AuthEventStatus::Success,
    ));

    let tenant = axess_core::authn::ids::testing::tenant("tenant-a");
    for include_unscoped in [true, false] {
        let filter = EventQueryFilter {
            include_unscoped,
            ..Default::default()
        };
        let result = store.query_events(&tenant, &filter).await.unwrap();
        assert!(
            result.is_empty(),
            "tenant-a query must not see tenant-b events (include_unscoped={include_unscoped})"
        );
    }
}
