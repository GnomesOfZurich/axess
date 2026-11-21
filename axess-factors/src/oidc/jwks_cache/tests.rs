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

/// A client under the named opt-out, which reaches a mock on loopback.
fn local_client() -> ScreenedClient {
    EgressPolicy::unscreened()
        .build_client(|settings| settings)
        .expect("client")
}

/// A cache primed with `seed` that refreshes from `uri` through
/// [`local_client`].
fn seeded(uri: impl Into<String>, seed: JwkSet) -> JwksCache {
    JwksCache::from_parts(uri, &local_client(), seed).expect("a loopback key-set URL")
}

#[tokio::test]
async fn fetch_loads_jwks_from_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .mount(&server)
        .await;

    let cache = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &local_client())
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

    let cache = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &local_client())
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

    let err = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &local_client())
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
    let err = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &local_client())
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
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = seeded(format!("{}/jwks.json", server.uri()), seed);

    let err = cache.refresh().await.expect_err("a 500 must be an error");
    assert!(matches!(err, OidcError::JwksFetch(_)), "got {err:?}");
    assert_eq!(
        cache.handle().read().unwrap().keys.len(),
        1,
        "cached keys must survive a failed refresh"
    );
}

/// Plain HTTP to a remote host is refused before any request, by the fetch
/// and by a cache built around a key set in hand, under any policy.
#[tokio::test]
async fn a_plain_http_key_set_url_on_a_remote_host_is_refused() {
    let client = local_client();
    let err = JwksCache::fetch("http://keys.example.com/jwks.json", &client)
        .await
        .expect_err("plain http to a remote host must be refused");
    assert!(matches!(err, OidcError::NonHttpsIssuer(_)), "got {err:?}");

    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let err = JwksCache::from_parts("http://keys.example.com/jwks.json", &client, seed)
        .expect_err("a cache is not built around such a URL either");
    assert!(matches!(err, OidcError::NonHttpsIssuer(_)), "got {err:?}");
}

/// A refresh checks the transport rule again on the URL it holds, so the
/// rule does not rest on the constructor alone.
#[tokio::test]
async fn a_refresh_refuses_plain_http_to_a_remote_host() {
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = JwksCache::from_parts_raw(
        "http://keys.example.com/jwks.json".to_owned(),
        local_client().inner(),
        seed,
    );
    let err = cache.refresh().await.expect_err("refresh must refuse");
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
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = seeded(format!("{}/jwks.json", server.uri()), seed);
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
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = seeded(format!("{}/jwks.json", server.uri()), seed);
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
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = Arc::new(seeded(format!("{}/jwks.json", server.uri()), seed));
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
    Arc::new(axess_clock::testing::MockClock::at_reference())
}

fn cache_on(server: &MockServer, clock: Arc<axess_clock::testing::MockClock>) -> JwksCache {
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    seeded(format!("{}/jwks.json", server.uri()), seed).with_clock(clock)
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
        matches!(err, OidcError::JwksExpired { age, max_age }
            if age == Duration::from_secs(25 * 3600) && max_age == Duration::from_secs(24 * 3600)),
        "got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "cached JWKS is 90000 s old, past its 86400 s maximum age; refresh required",
        "the message reads as it did when the fields were counts of seconds"
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

/// A chunked response (no `Content-Length`) of `total` bytes of padding
/// inside a JSON string, served by a raw socket so the length is not declared.
async fn serve_chunked(total: usize) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut request = [0u8; 2048];
        let _ = socket.read(&mut request).await;
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                    transfer-encoding: chunked\r\nconnection: close\r\n\r\n";
        let _ = socket.write_all(head.as_bytes()).await;
        let mut sent = 0;
        while sent < total {
            let n = (total - sent).min(16 * 1024);
            let chunk = format!("{n:x}\r\n{}\r\n", "a".repeat(n));
            if socket.write_all(chunk.as_bytes()).await.is_err() {
                return;
            }
            sent += n;
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });
    format!("http://{addr}/jwks.json")
}

#[tokio::test]
async fn refresh_refuses_a_chunked_body_over_the_cap_and_keeps_the_old_keys() {
    let uri = serve_chunked(MAX_JWKS_BYTES + 1).await;
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = seeded(uri, seed);

    let err = cache.refresh().await.expect_err("oversized body");

    assert!(
        matches!(&err, OidcError::JwksFetch(m) if m == "JWKS body exceeds limit"),
        "got {err:?}"
    );
    assert_eq!(cache.handle().read().unwrap().keys.len(), 1);
}

#[tokio::test]
async fn refresh_refuses_a_declared_length_over_the_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(vec![b'a'; MAX_JWKS_BYTES + 1], "application/json"),
        )
        .mount(&server)
        .await;
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = seeded(format!("{}/jwks.json", server.uri()), seed);

    let err = cache.refresh().await.expect_err("oversized body");

    assert!(
        matches!(&err, OidcError::JwksFetch(m) if m == "JWKS body exceeds limit"),
        "got {err:?}"
    );
}

/// A key set exactly at the cap is read (and then fails to parse as keys,
/// which is a parse error, not a size error).
#[tokio::test]
async fn a_body_at_the_cap_is_read_in_full() {
    let uri = serve_chunked(MAX_JWKS_BYTES).await;
    let seed: JwkSet = serde_json::from_value(sample_jwks_json()).unwrap();
    let cache = seeded(uri, seed);

    let err = cache.refresh().await.expect_err("padding is not a key set");

    assert!(matches!(err, OidcError::JwksParse(_)), "got {err:?}");
}

/// A server whose key-set path answers `302` to a key set on another server.
async fn redirecting_key_set() -> (MockServer, MockServer) {
    let hidden = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hidden.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .mount(&hidden)
        .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/hidden.json", hidden.uri()).as_str()),
        )
        .mount(&server)
        .await;
    (server, hidden)
}

/// A client the policy built follows no redirect, so a redirecting key-set
/// URL answers `302` and the fetch refuses it by name.
#[tokio::test]
async fn a_redirected_key_set_is_refused_by_name() {
    let (server, hidden) = redirecting_key_set().await;

    let refused = JwksCache::fetch(format!("{}/jwks.json", server.uri()), &local_client()).await;

    match refused {
        Ok(cache) => panic!(
            "the redirected key set was accepted: {} keys",
            cache.handle().read().unwrap().keys.len()
        ),
        Err(OidcError::JwksFetch(m)) => assert!(m.contains("redirect"), "{m}"),
        Err(other) => panic!("refused, but not by name: {other:?}"),
    }
    drop(hidden);
}

/// The key-set fetch takes no answer that did not come from the URL it asked
/// for, whatever client made the request: a client that follows redirects,
/// which no public entry point accepts, is refused here too.
#[tokio::test]
async fn the_key_set_fetch_refuses_an_answer_from_another_url() {
    let (server, hidden) = redirecting_key_set().await;
    let following = openidconnect::reqwest::Client::new();

    let refused = JwksCache::fetch_raw(format!("{}/jwks.json", server.uri()), &following).await;

    match refused {
        Ok(cache) => panic!(
            "the redirected key set was accepted: {} keys",
            cache.handle().read().unwrap().keys.len()
        ),
        Err(OidcError::JwksFetch(m)) => assert!(m.contains("another URL"), "{m}"),
        Err(other) => panic!("refused, but not by name: {other:?}"),
    }
    drop(hidden);
}

/// The key-set URL is checked against the client's policy before any request
/// is made: a private address is refused by the name of the setting and the
/// range, not by a connection error.
#[tokio::test]
async fn a_screened_client_refuses_a_private_key_set_url_by_name() {
    let client = EgressPolicy::screened()
        .build_client(|settings| settings.timeout(std::time::Duration::from_secs(2)))
        .expect("client");

    let err = JwksCache::fetch("https://10.0.0.5/jwks.json", &client)
        .await
        .unwrap_err();

    match err {
        OidcError::EgressRefused { setting, range } => {
            assert_eq!((setting.as_str(), range.as_str()), ("jwks_uri", "private"));
        }
        other => panic!("refused, but not by name: {other:?}"),
    }
}

/// A key set in hand is kept with a client that carries its policy, and
/// refreshes from the URL the policy accepted.
#[tokio::test]
async fn a_cache_from_parts_with_a_screened_client_refreshes_through_it() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_jwks_json()))
        .mount(&server)
        .await;
    let client = EgressPolicy::screened_allowing_loopback_http()
        .build_client(|settings| settings.timeout(std::time::Duration::from_secs(2)))
        .expect("client");
    let seed: JwkSet = serde_json::from_value(serde_json::json!({ "keys": [] })).unwrap();

    let cache = JwksCache::from_parts(format!("{}/jwks.json", server.uri()), &client, seed)
        .expect("a loopback key-set URL under the opt-in");
    cache.refresh().await.expect("refresh");

    assert_eq!(cache.handle().read().unwrap().keys.len(), 1);
}
