//! Tests for the JWKS cache.

use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_jwks_json() -> serde_json::Value {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "k1",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
        }],
    })
}

#[tokio::test]
async fn fetch_loads_jwks_from_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .mount(&server)
        .await;

    let client = openidconnect::reqwest::Client::new();
    let cache = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
        .await
        .expect("fetch ok");

    let handle = cache.handle();
    let jwks = handle.read().unwrap();
    assert_eq!(jwks.keys.len(), 1);
}

/// `refresh` collapses concurrent callers into a single outbound
/// fetch. The mock expects exactly one call: any wider count means
/// the debounce window collapsed.
#[tokio::test]
async fn refresh_debounces_within_window() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .expect(2) // initial fetch + one refresh; subsequent refreshes debounced
        .mount(&server)
        .await;

    let client = openidconnect::reqwest::Client::new();
    let cache = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
        .await
        .expect("fetch ok");

    cache.refresh().await.expect("first refresh ok");

    // Subsequent immediate refreshes coalesce; no additional GET.
    cache.refresh().await.expect("second refresh ok");
    cache.refresh().await.expect("third refresh ok");
}

#[tokio::test]
async fn fetch_propagates_parse_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let client = openidconnect::reqwest::Client::new();
    let err = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
        .await
        .expect_err("parse failure must propagate");
    assert!(
        matches!(err, OidcError::JwksParse(_)),
        "expected JwksParse, got {err:?}"
    );
}

#[tokio::test]
async fn fetch_refuses_non_success_status_even_with_valid_key_set_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(503).set_body_json(sample_jwks_json()))
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let err = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &client)
        .await
        .expect_err("a 503 must not seed the cache");
    assert!(matches!(err, OidcError::JwksFetch(_)), "got {err:?}");
}

#[tokio::test]
async fn refresh_keeps_cached_keys_when_endpoint_errors_with_key_set_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({ "keys": [] })))
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = JwksCache::from_parts(format!("{}/jwks.json", server.uri()), &client, seed);

    let err = cache.refresh().await.expect_err("a 500 must be an error");
    assert!(matches!(err, OidcError::JwksFetch(_)), "got {err:?}");
    assert_eq!(
        cache.handle().read().unwrap().keys.len(),
        1,
        "cached keys must survive a failed refresh"
    );
}

#[tokio::test]
async fn fetch_and_refresh_refuse_plain_http_to_a_remote_host() {
    let client = openidconnect::reqwest::Client::new();
    let err = JwksCache::fetch("http://keys.example.com/jwks.json", &client)
        .await
        .expect_err("plain http to a remote host must be refused");
    assert!(matches!(err, OidcError::NonHttpsIssuer(_)), "got {err:?}");

    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = JwksCache::from_parts("http://keys.example.com/jwks.json", &client, seed);
    let err = cache.refresh().await.expect_err("refresh must refuse too");
    assert!(matches!(err, OidcError::NonHttpsIssuer(_)), "got {err:?}");
}

#[tokio::test]
async fn refresh_through_from_parts_is_debounced_like_fetch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .expect(1)
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = JwksCache::from_parts(format!("{}/jwks.json", server.uri()), &client, seed);
    for _ in 0..5 {
        cache.refresh().await.expect("refresh ok");
    }
}

#[tokio::test]
async fn an_empty_key_set_does_not_evict_the_cached_keys() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [] })))
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = JwksCache::from_parts(format!("{}/jwks.json", server.uri()), &client, seed);
    cache.refresh().await.expect_err("an empty set is refused");
    assert_eq!(cache.handle().read().unwrap().keys.len(), 1);
}

/// Many concurrent callers against a failing endpoint produce one
/// request, not one each.
#[tokio::test]
async fn concurrent_refreshes_against_a_failing_endpoint_fetch_once() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let client = openidconnect::reqwest::Client::new();
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = Arc::new(JwksCache::from_parts(
        format!("{}/jwks.json", server.uri()),
        &client,
        seed,
    ));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let cache = cache.clone();
            tokio::spawn(async move { cache.refresh().await })
        })
        .collect();
    for task in tasks {
        assert!(task.await.unwrap().is_err());
    }
    assert_eq!(cache.handle().read().unwrap().keys.len(), 1);
}

fn mock_clock() -> Arc<axess_clock::testing::MockClock> {
    Arc::new(axess_clock::testing::MockClock::now())
}

fn cache_on(server: &MockServer, clock: Arc<axess_clock::testing::MockClock>) -> JwksCache {
    let client = openidconnect::reqwest::Client::new();
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    JwksCache::from_parts(format!("{}/jwks.json", server.uri()), &client, seed).with_clock(clock)
}

/// The debounce window is measured on the injected clock: advancing it past
/// the window allows exactly one more fetch, with no sleeping.
#[tokio::test]
async fn debounce_window_follows_the_injected_clock() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .expect(2)
        .mount(&server)
        .await;
    let clock = mock_clock();
    let cache = cache_on(&server, clock.clone());

    cache.refresh().await.expect("first fetches");
    clock.advance_secs(59);
    cache.refresh().await.expect("inside the window: coalesced");
    clock.advance_secs(2);
    cache.refresh().await.expect("past the window: fetches");
    cache.refresh().await.expect("and the new window coalesces");
}

#[tokio::test]
async fn failure_backoff_follows_the_injected_clock() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&server)
        .await;
    let clock = mock_clock();
    let cache = cache_on(&server, clock.clone());

    cache.refresh().await.expect_err("fetch fails");
    clock.advance_secs(4);
    cache.refresh().await.expect_err("suppressed, no request");
    clock.advance_secs(2);
    cache
        .refresh()
        .await
        .expect_err("back-off over: second request");
}

/// A clock that steps backwards must not freeze refreshing until real
/// time catches up with the old stamp.
#[tokio::test]
async fn a_clock_stepping_backwards_does_not_suppress_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .expect(2)
        .mount(&server)
        .await;
    let clock = mock_clock();
    let cache = cache_on(&server, clock.clone());

    cache.refresh().await.expect("first fetches");
    clock.advance_secs(-3600);
    cache
        .refresh()
        .await
        .expect("a stamp in the future is not a window");
}

// ── maximum age ──────────────────────────────────────────────────────────────

const HOUR: i64 = 3600;

/// A key set fetched at T verifies at T + 23 h and is refused at T + 25 h
/// until the next fetch, measured on the injected clock.
#[tokio::test]
async fn key_set_older_than_max_age_is_refused_until_a_refresh_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .mount(&server)
        .await;
    let clock = mock_clock();
    let cache = cache_on(&server, clock.clone());
    assert_eq!(cache.max_age(), DEFAULT_JWKS_MAX_AGE);

    cache.ensure_fresh().expect("fresh at T");
    clock.advance_secs(23 * HOUR);
    cache.fresh_handle().expect("still fresh at T + 23 h");

    clock.advance_secs(2 * HOUR);
    let err = cache.fresh_handle().expect_err("refused at T + 25 h");
    assert!(
        matches!(err, OidcError::JwksExpired { age_secs, max_age_secs }
            if age_secs == 25 * 3600 && max_age_secs == 24 * 3600),
        "got {err:?}"
    );
    assert!(cache.ensure_fresh().is_err(), "and it stays refused");

    cache.refresh().await.expect("refresh succeeds");
    cache.ensure_fresh().expect("fresh again after the fetch");
}

/// A failed refresh does not make an expired key set fresh.
#[tokio::test]
async fn failed_refresh_leaves_an_expired_key_set_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let clock = mock_clock();
    let cache = cache_on(&server, clock.clone());
    clock.advance_secs(25 * HOUR);

    cache.refresh().await.expect_err("endpoint is down");

    assert!(matches!(
        cache.ensure_fresh(),
        Err(OidcError::JwksExpired { .. })
    ));
}

#[tokio::test]
async fn max_age_is_configurable() {
    let server = MockServer::start().await;
    let clock = mock_clock();
    let cache =
        cache_on(&server, clock.clone()).with_max_age(std::time::Duration::from_secs(10 * 60));
    clock.advance_secs(9 * 60);
    cache.ensure_fresh().expect("inside 10 minutes");
    clock.advance_secs(2 * 60);
    cache.ensure_fresh().expect_err("past 10 minutes");
}

/// A clock that steps backwards does not make the key set look old.
#[tokio::test]
async fn a_clock_stepping_backwards_does_not_expire_the_key_set() {
    let server = MockServer::start().await;
    let clock = mock_clock();
    let cache = cache_on(&server, clock.clone());
    clock.advance_secs(-48 * HOUR);
    cache
        .ensure_fresh()
        .expect("a fetch time in the future is fresh");
}
