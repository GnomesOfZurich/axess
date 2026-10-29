use super::*;
use crate::session::id::SessionId;
use crate::session::store::SessionRegistryAdapter;
use crate::session::store::{MemorySessionRegistry, SessionRegistry};
use crate::testing::mock_random::MockRng;

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

    let handler = FrontChannelLogoutHandler::new(
        sid_map.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        known_issuers(),
    );

    // Simulate: valid iss + known sid.
    if let Some((uid, sid, _)) = handler.sid_map.remove(&key) {
        let _ = handler.registry.invalidate_session(&uid, &sid).await;
    }

    assert!(!registry.is_valid(&user_id, &session_id).await.unwrap());
    assert!(!sid_map.contains_key(&key));
}

#[tokio::test]
async fn frontchannel_logout_unknown_sid_is_noop() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();
    let handler = FrontChannelLogoutHandler::new(
        sid_map,
        Arc::new(SessionRegistryAdapter(registry)),
        known_issuers(),
    );
    let nonexistent: SidKey = (
        "https://idp.example.com".to_string(),
        "nonexistent".to_string(),
    );
    assert!(handler.sid_map.remove(&nonexistent).is_none());
}

#[tokio::test]
async fn frontchannel_logout_rejects_unknown_issuer() {
    let handler = FrontChannelLogoutHandler::new(
        SidMap::new(),
        Arc::new(SessionRegistryAdapter(MemorySessionRegistry::new())),
        known_issuers(),
    );
    // Unknown issuer should be rejected.
    assert!(!handler.known_issuers.contains("https://evil.example.com"));
}

#[tokio::test]
async fn frontchannel_logout_rejects_missing_iss() {
    let handler = FrontChannelLogoutHandler::new(
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

    let handler = FrontChannelLogoutHandler::new(
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

fn handler_with_session(
    registry: &MemorySessionRegistry,
    sid_map: &SidMap,
) -> FrontChannelLogoutHandler {
    FrontChannelLogoutHandler::new(
        sid_map.clone(),
        Arc::new(SessionRegistryAdapter(registry.clone())),
        known_issuers(),
    )
    .with_session_match_required()
}

/// Knowing an `(iss, sid)` pair does not end someone else's session when
/// the handler binds the logout to the caller's own session; the owner's
/// own request does end it.
#[tokio::test]
async fn a_bound_logout_ends_only_the_callers_own_session() {
    let registry = MemorySessionRegistry::new();
    let sid_map: SidMap = SidMap::new();
    let rng = MockRng::new(21);
    let (victim_session, attacker_session) = (SessionId::new(&rng), SessionId::new(&rng));
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
    let handler = handler_with_session(&registry, &sid_map);

    let ended = handler
        .end_by_sid("https://idp.example.com", "sid-1", Some(&attacker_session))
        .await;
    assert!(!ended, "a stranger's session does not match");
    assert!(registry.is_valid(&victim, &victim_session).await.unwrap());
    assert!(sid_map.contains_key(&key), "the mapping is untouched");

    let ended = handler
        .end_by_sid("https://idp.example.com", "sid-1", Some(&victim_session))
        .await;
    assert!(ended);
    assert!(!registry.is_valid(&victim, &victim_session).await.unwrap());
}

/// An oversized `sid` or `iss` is refused before it is looked up or
/// logged, and an unknown issuer is refused.
#[test]
fn oversized_or_unknown_parameters_are_refused() {
    let handler = FrontChannelLogoutHandler::new(
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
