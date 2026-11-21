//! The token cache and its single flight: a token is fetched once and served
//! until its refresh is due, a forced refresh replaces it, and callers that
//! arrive together share one fetch and its outcome.

use super::*;

#[tokio::test]
async fn first_call_fetches_and_caches() {
    let server = token_server_returning(json!({
        "access_token": "tok-alpha",
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
    .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess-feed-worker".into(),
            client_secret: "shh".into(),
        },
    )
    .expect("an HTTPS or loopback token URL")
    .with_clock(clock.clone());

    let token = client.get_access_token().await.expect("must fetch token");
    assert_eq!(token, "tok-alpha");

    // Second call; should hit cache, not the server. wiremock would
    // panic on .verify() if an unexpected request landed.
    let token2 = client.get_access_token().await.expect("cache hit");
    assert_eq!(token2, "tok-alpha");

    // Exactly one POST to /oauth2/token.
    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 1, "cache hit must not re-fetch");
}

#[tokio::test]
async fn cached_token_refreshes_when_clock_advances_past_threshold() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-first",
            "token_type": "Bearer",
            "expires_in": 100,
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-second",
            "token_type": "Bearer",
            "expires_in": 100,
        })))
        .mount(&server)
        .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .expect("an HTTPS or loopback token URL")
    .with_clock(clock.clone())
    .with_refresh_threshold(Duration::from_secs(30));

    let t1 = client.get_access_token().await.expect("first fetch");
    assert_eq!(t1, "tok-first");

    // Token has expires_in=100, refresh_threshold=30 → refresh due at
    // t0 + 70. Advancing 60s should NOT trigger refresh.
    clock.advance_secs(60);
    let t2 = client.get_access_token().await.expect("still cached");
    assert_eq!(t2, "tok-first", "60s in is still inside the cache window");

    // Advancing another 15s puts us at t0 + 75, past the refresh-due
    // mark. Now we expect a fresh fetch.
    clock.advance_secs(15);
    let t3 = client.get_access_token().await.expect("refresh");
    assert_eq!(t3, "tok-second", "past refresh threshold must refresh");
}

#[tokio::test]
async fn force_refresh_bypasses_cache() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-a",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-b",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&server)
        .await;

    let clock = Arc::new(MockClock::at(t0()));
    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .expect("an HTTPS or loopback token URL")
    .with_clock(clock.clone());

    let first = client.get_access_token().await.expect("first");
    assert_eq!(first, "tok-a");

    // Cache is still valid (3600s lifetime), but force_refresh must
    // ignore that.
    let second = client.force_refresh().await.expect("force refresh");
    assert_eq!(second, "tok-b");

    // Subsequent get_access_token returns the refreshed (cached) value.
    let third = client.get_access_token().await.expect("now cached");
    assert_eq!(third, "tok-b");
}

/// A token whose lifetime is at or under the refresh threshold is cached for
/// half its life, instead of being fetched anew on every call.
#[tokio::test]
async fn a_short_lived_token_is_cached_for_half_its_life() {
    let server = token_server_returning(json!({
        "access_token": "short", "token_type": "Bearer", "expires_in": 20
    }))
    .await;
    let clock = Arc::new(MockClock::at(t0()));
    // Threshold 30 s against a 20 s token: read literally, due at once.
    let client = loopback_new(token_url(&server), basic())
        .unwrap()
        .with_clock(clock.clone())
        .with_refresh_threshold(Duration::from_secs(30));

    assert_eq!(client.get_access_token().await.unwrap(), "short");
    clock.advance_secs(5);
    assert_eq!(client.get_access_token().await.unwrap(), "short");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "five seconds into a twenty-second token is still cached"
    );

    clock.advance_secs(6);
    client.get_access_token().await.unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "past half its life the refresh is due"
    );
}

/// Callers that arrive together after a `401` share one fetch.
#[tokio::test]
async fn concurrent_force_refreshes_share_one_fetch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(
                    json!({ "access_token": "fresh", "token_type": "Bearer", "expires_in": 3600 }),
                )
                .set_delay(Duration::from_millis(150)),
        )
        .mount(&server)
        .await;
    let client = Arc::new(loopback_new(token_url(&server), basic()).unwrap());

    let calls: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.force_refresh().await })
        })
        .collect();
    for call in calls {
        assert_eq!(call.await.unwrap().unwrap(), "fresh");
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "eight simultaneous force_refresh calls are one fetch"
    );
}

/// While one caller refreshes a token that is due but not expired, the others
/// are served the cached token without waiting for the fetch.
#[tokio::test]
async fn callers_are_served_the_unexpired_token_while_a_refresh_is_in_flight() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "first", "token_type": "Bearer", "expires_in": 100 }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(
                    json!({ "access_token": "second", "token_type": "Bearer", "expires_in": 100 }),
                )
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let clock = Arc::new(MockClock::at(t0()));
    let client = Arc::new(
        loopback_new(token_url(&server), basic())
            .unwrap()
            .with_clock(clock.clone())
            .with_refresh_threshold(Duration::from_secs(30)),
    );
    assert_eq!(client.get_access_token().await.unwrap(), "first");

    // Due (t0 + 75 > refresh_at 70) but not expired (< 100).
    clock.advance_secs(75);
    let refresher = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.get_access_token().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = axess_testing::stopwatch::Stopwatch::start();
    let served = client.get_access_token().await.unwrap();
    assert_eq!(served, "first", "served from the cache");
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "must not wait for the fetch in flight ({:?})",
        started.elapsed()
    );
    assert_eq!(refresher.await.unwrap().unwrap(), "second");
}

/// The token a `401` condemned is served to nobody while `force_refresh`
/// fetches its replacement: a caller that arrives during the fetch waits for
/// the fresh token instead of taking the condemned one from the cache.
#[tokio::test]
async fn callers_during_a_force_refresh_never_get_the_condemned_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "condemned", "token_type": "Bearer", "expires_in": 3600 }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(
                    json!({ "access_token": "fresh", "token_type": "Bearer", "expires_in": 3600 }),
                )
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let client = Arc::new(loopback_new(token_url(&server), basic()).unwrap());
    assert_eq!(client.get_access_token().await.unwrap(), "condemned");

    let refresher = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.force_refresh().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let during = client.get_access_token().await.unwrap();
    assert_eq!(
        during, "fresh",
        "a caller during the forced refresh must not get the condemned token"
    );
    assert_eq!(refresher.await.unwrap().unwrap(), "fresh");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

/// After a `force_refresh` that failed, the condemned token stays out of
/// service: the next call fetches instead of serving it from the cache.
#[tokio::test]
async fn a_failed_force_refresh_does_not_serve_the_condemned_token_afterwards() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "condemned", "token_type": "Bearer", "expires_in": 3600 }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "fresh", "token_type": "Bearer", "expires_in": 3600 }),
        ))
        .mount(&server)
        .await;
    let client = loopback_new(token_url(&server), basic()).unwrap();
    assert_eq!(client.get_access_token().await.unwrap(), "condemned");

    let failed = client.force_refresh().await;
    assert!(
        matches!(
            failed,
            Err(OAuthClientError::TokenEndpoint { status: 503, .. })
        ),
        "{failed:?}"
    );
    let next = client.get_access_token().await.unwrap();
    assert_eq!(
        next, "fresh",
        "the condemned token must not come back from the cache after a failed refresh"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

/// Callers that waited for a fetch that failed take its failure: one fetch,
/// one answer for all of them, not one fetch per waiter in turn, each under
/// the full request timeout.
#[tokio::test]
async fn waiters_on_a_failed_fetch_share_its_outcome_instead_of_fetching_in_turn() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(300)))
        .mount(&server)
        .await;
    let client = Arc::new(
        loopback_new(token_url(&server), basic())
            .unwrap()
            .with_request_timeout(Duration::from_secs(2)),
    );

    let started = axess_testing::stopwatch::Stopwatch::start();
    let calls: Vec<_> = (0..6)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.get_access_token().await })
        })
        .collect();
    for call in calls {
        let outcome = call.await.unwrap();
        assert!(
            matches!(
                outcome,
                Err(OAuthClientError::TokenEndpoint { status: 503, .. })
            ),
            "{outcome:?}"
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "six callers that arrived together are one fetch, failed or not"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "the waiters did not fetch in turn ({:?})",
        started.elapsed()
    );
}

/// A refresh that fails while the cached token is still unexpired is not an
/// error: the token serves until `expires_at`, and the next call tries the
/// endpoint again. Once it has expired, the failure reaches the caller.
#[tokio::test]
async fn an_unexpired_token_outlives_a_failed_refresh_until_it_expires() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "first", "token_type": "Bearer", "expires_in": 100 }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let clock = Arc::new(MockClock::at(t0()));
    let client = loopback_new(token_url(&server), basic())
        .unwrap()
        .with_clock(clock.clone())
        .with_refresh_threshold(Duration::from_secs(30));
    assert_eq!(client.get_access_token().await.unwrap(), "first");

    // Due (t0 + 75 > refresh_at 70), not expired (< 100): the failed
    // refresh answers the cached token.
    clock.advance_secs(75);
    let served = client.get_access_token().await;
    assert_eq!(
        served.as_deref().ok(),
        Some("first"),
        "a still-unexpired token answers a failed refresh: {served:?}"
    );
    // Each call tries again; the endpoint is still down.
    clock.advance_secs(10);
    assert_eq!(client.get_access_token().await.unwrap(), "first");
    assert_eq!(server.received_requests().await.unwrap().len(), 3);

    // Expired: nothing usable is cached, the failure is the answer.
    clock.advance_secs(20);
    let expired = client.get_access_token().await;
    assert!(
        matches!(
            expired,
            Err(OAuthClientError::TokenEndpoint { status: 503, .. })
        ),
        "{expired:?}"
    );
}

/// A `401` reported late, about a token another caller has already replaced,
/// condemns nothing: `force_refresh_of` keeps the replacement and makes no
/// fetch. The same call about the token in the cache condemns it.
#[tokio::test]
async fn force_refresh_of_a_replaced_token_keeps_the_replacement() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "first", "token_type": "Bearer", "expires_in": 3600 }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "second", "token_type": "Bearer", "expires_in": 3600 }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "access_token": "third", "token_type": "Bearer", "expires_in": 3600 }),
        ))
        .mount(&server)
        .await;
    let client = loopback_new(token_url(&server), basic()).unwrap();
    assert_eq!(client.get_access_token().await.unwrap(), "first");
    assert_eq!(client.force_refresh_of("first").await.unwrap(), "second");

    // A late 401 about "first": "second" is in place and stays.
    assert_eq!(client.force_refresh_of("first").await.unwrap(), "second");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);

    // A 401 about the token in the cache condemns it.
    assert_eq!(client.force_refresh_of("second").await.unwrap(), "third");
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}
