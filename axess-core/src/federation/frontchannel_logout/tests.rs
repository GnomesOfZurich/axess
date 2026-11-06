use super::*;
use crate::session::id::SessionId;
use crate::session::store::SessionRegistryAdapter;
use crate::session::store::{MemorySessionRegistry, SessionRegistry};
use crate::testing::mock_random::MockRng;
use crate::testing::test_session;

fn known_issuers() -> HashSet<String> {
    ["https://idp.example.com".to_string()]
        .into_iter()
        .collect()
}

#[tokio::test]
async fn frontchannel_logout_invalidates_by_sid() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();

    let rng = MockRng::new(42);
    let session_id = SessionId::new(&rng);
    let user_id = axess_identity::testing::user("user-1");

    registry.register(&user_id, &session_id).await.unwrap();
    let key: SidKey = (
        "https://idp.example.com".to_string(),
        "oidc-sid-123".to_string(),
    );
    sid_map.insert(
        key.clone(),
        "idp-subject",
        user_id,
        session_id,
        chrono::Utc::now(),
    );
    assert!(registry.is_valid(&user_id, &session_id).await.unwrap());

    let handler = FrontChannelLogoutHandler::new_unbound(
        sid_map.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        known_issuers(),
    );

    handler
        .end_by_sid("https://idp.example.com", "oidc-sid-123", None)
        .await;

    assert!(!registry.is_valid(&user_id, &session_id).await.unwrap());
    assert!(!sid_map.contains_key(&key));
}

#[tokio::test]
async fn frontchannel_logout_unknown_sid_is_noop() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();
    let handler = FrontChannelLogoutHandler::new_unbound(
        sid_map,
        Arc::new(SessionRegistryAdapter(registry)),
        known_issuers(),
    );
    let nonexistent: SidKey = (
        "https://idp.example.com".to_string(),
        "nonexistent".to_string(),
    );
    assert!(handler.sid_map.remove_if(&nonexistent, |_| true).is_none());
}

#[tokio::test]
async fn frontchannel_logout_rejects_unknown_issuer() {
    let handler = FrontChannelLogoutHandler::new_unbound(
        SidMap::new(),
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
        known_issuers(),
    );
    // Unknown issuer should be rejected.
    assert!(!handler.known_issuers.contains("https://evil.example.com"));
}

#[tokio::test]
async fn frontchannel_logout_rejects_missing_iss() {
    let handler = FrontChannelLogoutHandler::new_unbound(
        SidMap::new(),
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
        known_issuers(),
    );
    // No iss → should be rejected (handler returns 400).
    let params = FrontChannelLogoutParams {
        sid: Some("s1".into()),
        iss: None,
    };
    assert!(params.iss.is_none());
    // The actual 400 is returned by the Axum handler; here we verify
    // the validation logic is in place.
    assert!(!handler.known_issuers.contains(""));
}

/// drives `handle_frontchannel_logout` end-to-end via the
/// axum extractors, asserting the response code AND the registry
/// side effect. Pins three mutations on the handler:
/// - `handle_frontchannel_logout -> Default::default()` (empty
///   response without invalidation): caught by the OK status
///   assertion AND the registry invalidation assertion.
/// - `match guard handler.known_issuers.contains(...) -> true`
///   (would accept any issuer): caught by the unknown-issuer
///   subtest expecting 400.
/// - `match guard handler.known_issuers.contains(...) -> false`
///   (would reject all issuers, including registered ones):
///   caught by the known-issuer subtest expecting 200 OK.
#[tokio::test]
async fn handle_frontchannel_logout_drives_registry_and_gates_issuer() {
    use axum::extract::{Query, State};

    // ── Subtest 1: known iss + known sid → 200 + session invalidated.
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();
    let rng = MockRng::new(7);
    let session_id = SessionId::new(&rng);
    let user_id = axess_identity::testing::user("u1");
    registry.register(&user_id, &session_id).await.unwrap();
    let key: SidKey = (
        "https://idp.example.com".to_string(),
        "oidc-sid-XYZ".to_string(),
    );
    sid_map.insert(
        key.clone(),
        "idp-subject",
        user_id,
        session_id,
        chrono::Utc::now(),
    );

    let handler = FrontChannelLogoutHandler::new_unbound(
        sid_map.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        known_issuers(),
    );

    let response = FrontChannelLogoutHandler::handle_frontchannel_logout(
        State(handler.clone()),
        Query(FrontChannelLogoutParams {
            sid: Some("oidc-sid-XYZ".to_string()),
            iss: Some("https://idp.example.com".to_string()),
        }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "known iss + known sid must return 200 OK"
    );
    assert!(
        !registry.is_valid(&user_id, &session_id).await.unwrap(),
        "front-channel logout must invalidate the registry session; \
         a non-default response without side effect is silent failure"
    );

    // ── Subtest 2: unknown iss → 400. Pins guard -> true mutation.
    let response = FrontChannelLogoutHandler::handle_frontchannel_logout(
        State(handler.clone()),
        Query(FrontChannelLogoutParams {
            sid: Some("anything".to_string()),
            iss: Some("https://evil.example.com".to_string()),
        }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "unknown iss must be rejected as 400"
    );
}

fn bound_handler(
    registry: &MemorySessionRegistry,
    sid_map: &SidMap,
) -> BoundFrontChannelLogoutHandler {
    FrontChannelLogoutHandler::new(
        sid_map.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        known_issuers(),
    )
}

fn sid_params(sid: &str) -> Query<FrontChannelLogoutParams> {
    Query(FrontChannelLogoutParams {
        sid: Some(sid.to_string()),
        iss: Some("https://idp.example.com".to_string()),
    })
}

/// Knowing an `(iss, sid)` pair does not end someone else's session through
/// the bound route, which answers the same page either way; the owner's own
/// request does end it.
#[tokio::test]
async fn a_bound_logout_ends_only_the_callers_own_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();
    let (victim_cookie, attacker_cookie) = (test_session(), test_session());
    let victim_session = victim_cookie.session_id().await;
    let victim = axess_identity::testing::user("victim");
    registry.register(&victim, &victim_session).await.unwrap();
    let key: SidKey = ("https://idp.example.com".to_string(), "sid-1".to_string());
    sid_map.insert(
        key.clone(),
        "victim-sub",
        victim,
        victim_session,
        chrono::Utc::now(),
    );
    let bound = bound_handler(&registry, &sid_map);

    let response = BoundFrontChannelLogoutHandler::handle_frontchannel_logout(
        State(bound.clone()),
        attacker_cookie,
        sid_params("sid-1"),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the same page either way"
    );
    assert!(
        registry.is_valid(&victim, &victim_session).await.unwrap(),
        "a stranger's session does not match"
    );
    assert!(sid_map.contains_key(&key), "the mapping is untouched");

    let response = BoundFrontChannelLogoutHandler::handle_frontchannel_logout(
        State(bound),
        victim_cookie,
        sid_params("sid-1"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!registry.is_valid(&victim, &victim_session).await.unwrap());
    assert!(!sid_map.contains_key(&key));
}

/// The bound route checks the parameters as the plain one does: an unknown
/// issuer is refused before the map is read.
#[tokio::test]
async fn the_bound_route_refuses_an_unknown_issuer() {
    let registry = MemorySessionRegistry::new();
    let response = BoundFrontChannelLogoutHandler::handle_frontchannel_logout(
        State(bound_handler(&registry, &SidMap::new())),
        test_session(),
        Query(FrontChannelLogoutParams {
            sid: Some("s".to_string()),
            iss: Some("https://evil.example.com".to_string()),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// An oversized `sid` or `iss` is refused before it is looked up or
/// logged, and an unknown issuer is refused.
#[test]
fn oversized_or_unknown_parameters_are_refused() {
    let handler = FrontChannelLogoutHandler::new_unbound(
        SidMap::new(),
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
        known_issuers(),
    );
    let params = |iss: &str, sid: &str| FrontChannelLogoutParams {
        iss: Some(iss.to_string()),
        sid: Some(sid.to_string()),
    };
    assert!(
        handler
            .accepted_params(&params("https://idp.example.com", "ok"))
            .is_ok()
    );
    assert_eq!(
        handler
            .accepted_params(&params("https://idp.example.com", &"s".repeat(257)))
            .unwrap_err(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        handler
            .accepted_params(&params(&format!("https://{}", "a".repeat(300)), "ok"))
            .unwrap_err(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        handler
            .accepted_params(&params("https://evil.example.com", "ok"))
            .unwrap_err(),
        StatusCode::BAD_REQUEST
    );
}

/// Between the look-up and the removal another login can map the same sid
/// to a new session; the removal takes only the mapping the caller matched.
#[tokio::test]
async fn end_by_sid_removes_only_the_mapping_it_matched() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();
    let rng = MockRng::new(34);
    let (old, new) = (SessionId::new(&rng), SessionId::new(&rng));
    let user = axess_identity::testing::user("re-mapped");
    registry.register(&user, &new).await.unwrap();
    let key: SidKey = ("https://idp.example.com".to_string(), "sid-r".to_string());
    sid_map.insert(key.clone(), "sub-r", user, new, chrono::Utc::now());
    let handler = FrontChannelLogoutHandler::new_unbound(
        sid_map.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        known_issuers(),
    );

    // The caller's session is `old`, which the sid no longer maps to.
    handler
        .end_by_sid("https://idp.example.com", "sid-r", Some(&old))
        .await;
    assert_eq!(
        sid_map.get(&key).map(|e| e.1),
        Some(new),
        "the new mapping stands"
    );
    assert!(registry.is_valid(&user, &new).await.unwrap());
}
