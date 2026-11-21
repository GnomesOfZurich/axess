use std::sync::Arc;

use axum::http::{Request, StatusCode};
use tokio::sync::RwLock;

use super::*;
use crate::session::data::SessionData;
use crate::session::layer::{SessionHandle, SessionInner};
use crate::{AuthState, TenantId, UserId};
use axess_rng::SystemRng;

fn make_parts_with_session(data: SessionData) -> Parts {
    let inner = SessionInner {
        data,
        ..SessionInner::detached(std::sync::Arc::new(axess_rng::SystemRng))
    };
    let handle = SessionHandle(Arc::new(RwLock::new(inner)));
    let request = Request::builder()
        .uri("/")
        .extension(handle)
        .body(())
        .expect("build request");
    let (parts, _) = request.into_parts();
    parts
}

fn make_parts_without_session() -> Parts {
    let request = Request::builder().uri("/").body(()).expect("build request");
    let (parts, _) = request.into_parts();
    parts
}

fn authenticated(user_id: UserId, tenant_id: TenantId) -> SessionData {
    SessionData {
        auth_state: AuthState::Authenticated {
            user_id,
            tenant_id,
            authn_time: axess_clock::testing::MockClock::reference_time(),
            signed_in_at: axess_clock::testing::MockClock::reference_time(),
            factors_completed: Vec::new(),
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        },
        ..SessionData::default()
    }
}

/// Authenticated session resolves to a human principal.
#[tokio::test]
async fn auth_principal_resolves_human_from_session() {
    let user_id = UserId::new(&SystemRng);
    let tenant_id = TenantId::new(&SystemRng);
    let mut parts = make_parts_with_session(authenticated(user_id, tenant_id));

    let extracted = AuthPrincipal::from_request_parts(&mut parts, &()).await;
    let principal = extracted.expect("authenticated session must resolve").0;
    match principal {
        Principal::Human(h) => {
            assert_eq!(h.user_id, user_id);
            assert_eq!(h.tenant_id, tenant_id);
        }
        Principal::Workload(_) => panic!("session-backed extractor returned workload"),
    }
}

/// The principal names the session by the snapshot's key, and so does
/// its Cedar entity: the 64 characters of the key, never the id.
#[tokio::test]
async fn a_principal_carries_the_sessions_key() {
    let mut parts = make_parts_with_session(authenticated(
        UserId::new(&SystemRng),
        TenantId::new(&SystemRng),
    ));
    let handle = parts
        .extensions
        .get::<SessionHandle>()
        .cloned()
        .expect("handle");
    let snapshot = crate::AuthSession(handle)
        .snapshot()
        .await
        .expect("signed in");
    let human = AuthHumanPrincipal::from_request_parts(&mut parts, &())
        .await
        .expect("a human");
    assert_eq!(human.session_id, Some(snapshot.session_key));
    #[cfg(feature = "authz")]
    {
        use crate::ToCedarEntity as _;
        let entity = human.into_inner().to_cedar_entity().unwrap();
        let attribute = format!("{:?}", entity.attr("session_id").expect("set").unwrap());
        assert!(
            attribute.contains(&snapshot.session_key.to_string()),
            "{attribute}"
        );
    }
}

/// Guest session rejects with 401.
#[tokio::test]
async fn auth_principal_rejects_guest_session() {
    let mut parts = make_parts_with_session(SessionData::default());
    let err = AuthPrincipal::from_request_parts(&mut parts, &())
        .await
        .expect_err("guest session must reject");
    assert!(
        matches!(err, PrincipalRejection::NotAuthenticated),
        "got {err:?}"
    );
    assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
}

/// Missing session layer surfaces 500 (adopter wiring error).
#[tokio::test]
async fn auth_principal_rejects_missing_session_layer() {
    let mut parts = make_parts_without_session();
    let err = AuthPrincipal::from_request_parts(&mut parts, &())
        .await
        .expect_err("no session layer must reject");
    assert!(
        matches!(err, PrincipalRejection::SessionLayerMissing),
        "got {err:?}"
    );
    assert_eq!(
        err.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

/// Human-narrowing extractor succeeds when a human resolves.
#[tokio::test]
async fn auth_human_principal_succeeds_for_session() {
    let user_id = UserId::new(&SystemRng);
    let tenant_id = TenantId::new(&SystemRng);
    let mut parts = make_parts_with_session(authenticated(user_id, tenant_id));

    let human = AuthHumanPrincipal::from_request_parts(&mut parts, &())
        .await
        .expect("human extractor must succeed");
    assert_eq!(human.user_id, user_id);
}

/// Workload-narrowing extractor rejects with 403 when only a human
/// is available (no chain installed: the session alone).
#[tokio::test]
async fn auth_workload_principal_rejects_human() {
    let user_id = UserId::new(&SystemRng);
    let tenant_id = TenantId::new(&SystemRng);
    let mut parts = make_parts_with_session(authenticated(user_id, tenant_id));

    let err = AuthWorkloadPrincipal::from_request_parts(&mut parts, &())
        .await
        .expect_err("workload extractor over human session must reject");
    assert!(matches!(err, PrincipalRejection::WrongKind), "got {err:?}");
    assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
}
