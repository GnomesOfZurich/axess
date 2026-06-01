//! Discovery metadata and Axum router tests for the production
//! `LocalIdp`.
//!
//! Covers `metadata`, `with_base_url`, `with_metadata_field`,
//! `Metadata::to_json` / `to_json_string`, `discovery_url` / `jwks_url`,
//! and the `/.well-known/openid-configuration` + `/jwks.json` handlers
//! mounted by `router`.

use super::super::*;

#[tokio::test]
async fn metadata_defaults_base_url_to_issuer() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");
    let meta = idp.metadata().await;
    assert_eq!(meta.issuer, "https://idp.local");
    assert_eq!(
        meta.jwks_uri, "https://idp.local/jwks.json",
        "default base_url is the issuer string"
    );
}

#[tokio::test]
async fn with_base_url_overrides_jwks_uri_in_metadata() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_base_url("https://public.example.com/idp");
    let meta = idp.metadata().await;
    assert_eq!(meta.issuer, "https://idp.local", "issuer claim unchanged");
    assert_eq!(meta.jwks_uri, "https://public.example.com/idp/jwks.json");
}

#[tokio::test]
async fn metadata_signing_algs_mirror_verifier_algorithms() {
    let rsa = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let ec = LocalIdpSigningKey::generate_es256().with_key_id("ec-1");
    let store = MemoryLocalIdpKeyStore::with_keys(rsa, vec![ec]);
    let idp = LocalIdp::from_key_store("https://idp.local", store)
        .await
        .expect("load");
    let meta = idp.metadata().await;
    assert_eq!(meta.id_token_signing_alg_values_supported[0], "RS256");
    assert!(
        meta.id_token_signing_alg_values_supported
            .contains(&"ES256".to_string())
    );
    assert_eq!(meta.id_token_signing_alg_values_supported.len(), 2);
}

#[tokio::test]
async fn with_metadata_field_accumulates_in_insertion_order() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_metadata_field("scopes_supported", serde_json::json!(["openid", "email"]))
    .with_metadata_field("subject_types_supported", serde_json::json!(["public"]));

    let meta = idp.metadata().await;
    assert_eq!(meta.extra.len(), 2);
    assert_eq!(meta.extra[0].0, "scopes_supported");
    assert_eq!(meta.extra[1].0, "subject_types_supported");
}

#[tokio::test]
async fn metadata_to_json_includes_auto_fields_then_extras() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_metadata_field("scopes_supported", serde_json::json!(["openid"]));

    let json = idp.metadata().await.to_json();
    let obj = json.as_object().expect("metadata serialises to an object");
    assert_eq!(obj["issuer"], "https://idp.local");
    assert_eq!(obj["jwks_uri"], "https://idp.local/jwks.json");
    assert_eq!(obj["id_token_signing_alg_values_supported"][0], "RS256");
    assert_eq!(obj["scopes_supported"], serde_json::json!(["openid"]));
}

#[tokio::test]
async fn metadata_to_json_string_round_trips_through_serde_json() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");
    let s = idp.metadata().await.to_json_string();
    let parsed: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert_eq!(parsed["issuer"], "https://idp.local");
}

#[tokio::test]
async fn discovery_url_and_jwks_url_combine_base_url_with_standard_paths() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");
    assert_eq!(
        idp.discovery_url(),
        "https://idp.local/.well-known/openid-configuration"
    );
    assert_eq!(idp.jwks_url(), "https://idp.local/jwks.json");
}

#[tokio::test]
async fn base_url_with_trailing_slash_does_not_double_up_paths() {
    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_base_url("https://idp.example.com/");
    assert_eq!(idp.jwks_url(), "https://idp.example.com/jwks.json");
    assert_eq!(
        idp.discovery_url(),
        "https://idp.example.com/.well-known/openid-configuration"
    );
}

#[tokio::test]
async fn openid_configuration_endpoint_returns_discovery_json() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load")
    .with_metadata_field("scopes_supported", serde_json::json!(["openid"]));

    let router = idp.router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("Content-Type header");
    assert!(
        content_type
            .to_str()
            .unwrap()
            .starts_with("application/json"),
        "axum::Json sets application/json content type"
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON");
    assert_eq!(parsed["issuer"], "https://idp.local");
    assert_eq!(parsed["jwks_uri"], "https://idp.local/jwks.json");
    assert_eq!(parsed["scopes_supported"], serde_json::json!(["openid"]));
}

#[tokio::test]
async fn jwks_endpoint_returns_current_jwk_set() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");

    let response = idp
        .router()
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse JSON");
    let keys = parsed["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], "rsa-1");
    assert!(
        keys[0].get("d").is_none(),
        "private exponent must not leak through HTTP"
    );
}

#[tokio::test]
async fn jwks_endpoint_reflects_rotation_through_live_state() {
    // The handler reads the live state, not a snapshot taken at
    // router-build time. A rotation between two requests on the same
    // router must surface in the second response.
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(k1),
    )
    .await
    .expect("load");

    let kids_at = |router: axum::Router<()>| async move {
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/jwks.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse");
        parsed["keys"]
            .as_array()
            .expect("keys array")
            .iter()
            .map(|k| k["kid"].as_str().expect("kid").to_string())
            .collect::<Vec<_>>()
    };

    let before = kids_at(idp.router()).await;
    assert_eq!(before, vec!["rsa-1"]);

    idp.rotate_signing_key(k2).await.expect("rotate");
    let after = kids_at(idp.router()).await;
    assert_eq!(
        after,
        vec!["rsa-2", "rsa-1"],
        "JWKS handler reads live state: must reflect rotation"
    );
}

#[tokio::test]
async fn router_serves_both_endpoints_independently() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let key = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(key),
    )
    .await
    .expect("load");

    let disc = idp
        .router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot")
        .status();
    let jwks = idp
        .router()
        .oneshot(
            Request::builder()
                .uri("/jwks.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot")
        .status();
    assert_eq!(disc, StatusCode::OK);
    assert_eq!(jwks, StatusCode::OK);
}

#[tokio::test]
async fn repeated_rotation_appends_each_demoted_key_in_order() {
    // Three rotations: starts with k1, rotate to k2, then k3, then k4.
    // Historical order must be oldest→newest (k1, k2, k3) so the JWKS
    // layout is current-first then historical-by-age, matching the
    // `rotate_signing_key` ordering documented on the type.
    let k1 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-1");
    let k2 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-2");
    let k3 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-3");
    let k4 = LocalIdpSigningKey::generate_rsa().with_key_id("rsa-4");
    let idp = LocalIdp::from_key_store(
        "https://idp.local",
        MemoryLocalIdpKeyStore::with_current(k1),
    )
    .await
    .expect("load");

    idp.rotate_signing_key(k2).await.expect("rotate 1→2");
    idp.rotate_signing_key(k3).await.expect("rotate 2→3");
    idp.rotate_signing_key(k4).await.expect("rotate 3→4");

    let jwks = idp.jwks().await;
    let kids: Vec<_> = jwks
        .keys
        .iter()
        .filter_map(|k| k.common.key_id.as_deref())
        .collect();
    assert_eq!(
        kids,
        vec!["rsa-4", "rsa-1", "rsa-2", "rsa-3"],
        "current first, then historical oldest→newest"
    );
}
