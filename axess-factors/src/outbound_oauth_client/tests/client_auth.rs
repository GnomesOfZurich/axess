//! How the client authenticates at the token endpoint and what it sends:
//! `client_secret_basic`, `client_secret_post`, `private_key_jwt` and the
//! scopes, with the Basic credential redacted.

use super::*;

#[tokio::test]
async fn client_secret_basic_sends_authorization_header() {
    let server = MockServer::start().await;
    // Match on the exact Authorization header value. RFC 6749 §2.3.1
    // form-urlencodes id and secret before the Basic encoding, so the `+`
    // travels as `%2B`: base64("axess-id:Sample2%2B").
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(header(
            "authorization",
            "Basic YXhlc3MtaWQ6U2FtcGxlMiUyQg==",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess-id".into(),
            client_secret: "Sample2+".into(),
        },
    )
    .expect("an HTTPS or loopback token URL");
    let _ = client.get_access_token().await.expect("auth header sent");
    // MockServer drop-time check enforces the .expect(1).
}

#[tokio::test]
async fn client_secret_post_sends_secret_in_form_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("client_id=axess-id"))
        // `+` in a form value URL-encodes to `%2B` on the wire.
        .and(body_string_contains("client_secret=Sample2%2B"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretPost {
            client_id: "axess-id".into(),
            client_secret: "Sample2+".into(),
        },
    )
    .expect("an HTTPS or loopback token URL");
    let _ = client
        .get_access_token()
        .await
        .expect("secret-in-body sent");
}

// An RSA key, so the build has to sign with RSA (the client assertion's
// module documentation).
#[cfg(any(feature = "jwt-aws-lc", feature = "client-assertion-rsa"))]
#[tokio::test]
async fn private_key_jwt_sends_the_signers_assertion_for_the_token_url() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let public_key = private_key.to_public_key();
    let der = private_key
        .to_pkcs1_der()
        .expect("pkcs1 der")
        .as_bytes()
        .to_vec();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .and(body_string_contains("client_assertion="))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "tok-jwt",
                "token_type": "Bearer",
                "expires_in": 3600,
            })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::PrivateKeyJwt(Box::new(
            crate::client_assertion::ClientAssertionSigner::new(
                "axess-fapi",
                jsonwebtoken::EncodingKey::from_rsa_der(&der),
                jsonwebtoken::Algorithm::RS256,
            )
            .expect("an RSA key signs RS256")
            .with_key_id("kid-1")
            .with_x5t_s256("cert-thumbprint"),
        )),
    )
    .expect("an HTTPS or loopback token URL");
    let token = client.get_access_token().await.expect("jwt assertion sent");
    assert_eq!(token, "tok-jwt");

    // Sanity-pluck the assertion JWT from the recorded request body.
    let req = &server
        .received_requests()
        .await
        .expect("rcv")
        .first()
        .expect("at least one request")
        .body
        .clone();
    let body = String::from_utf8(req.clone()).expect("utf8 body");
    let assertion_param = body
        .split('&')
        .find(|p| p.starts_with("client_assertion="))
        .expect("client_assertion in body");
    let assertion = assertion_param
        .strip_prefix("client_assertion=")
        .expect("strip prefix");

    // Header + payload should decode and roundtrip the claims.
    let parts: Vec<&str> = assertion.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have three dot-separated parts");
    let header_json = URL_SAFE_NO_PAD.decode(parts[0]).expect("base64 header");
    let header_val: serde_json::Value = serde_json::from_slice(&header_json).expect("json header");
    assert_eq!(header_val["alg"], "RS256");
    assert_eq!(header_val["kid"], "kid-1");
    // The signer's certificate thumbprint, which Microsoft Entra finds the
    // credential by, reaches the outbound client's assertion too.
    assert_eq!(header_val["x5t#S256"], "cert-thumbprint");

    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).expect("base64 payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_json).expect("json payload");
    assert_eq!(payload["iss"], "axess-fapi");
    assert_eq!(payload["sub"], "axess-fapi");
    assert_eq!(
        payload["aud"].as_str().unwrap(),
        format!("{}/oauth2/token", server.uri())
    );
    assert!(payload["jti"].is_string());
    assert!(payload["exp"].is_number());
    assert!(payload["iat"].is_number());

    // Sanity: the assertion is verifiable against the actual public
    // key. Confirms axess didn't accidentally sign with a different
    // key or send a malformed signature.
    // Raw components rather than PEM: `DecodingKey::from_rsa_pem` sits
    // behind `jsonwebtoken`'s `use_pem` feature, which this workspace
    // does not enable because no production path parses a PEM through
    // `jsonwebtoken` (`LocalIdpSigningKey` uses the `rsa` / `p256`
    // crates directly). Taking it here would put `pem` + `simple_asn1`
    // in every adopter's build for one assertion.
    use rsa::traits::PublicKeyParts;
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_raw_components(
        &public_key.n().to_bytes_be(),
        &public_key.e().to_bytes_be(),
    );
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[format!("{}/oauth2/token", server.uri())]);
    let _ = crate::jwt::decode::<serde_json::Value>(assertion, &decoding_key, &validation)
        .expect("signature verifies");
}

#[tokio::test]
async fn scopes_are_sent_in_form_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("scope=read+write"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = loopback_new(
        token_url(&server),
        ClientAuthMethod::ClientSecretBasic {
            client_id: "axess".into(),
            client_secret: "shh".into(),
        },
    )
    .expect("an HTTPS or loopback token URL")
    .with_scopes(["read", "write"]);
    let _ = client.get_access_token().await.expect("scope sent");
}

/// The Basic credential is the secret in another spelling: it is zeroized
/// on drop and redacted in `Debug`.
#[test]
fn basic_credentials_are_redacted_in_debug() {
    let credentials = basic_credentials("axess-id", "Sample2+");
    assert_eq!(&*credentials, "YXhlc3MtaWQ6U2FtcGxlMiUyQg==");
    assert!(
        !format!("{credentials:?}").contains("YXhlc3MtaWQ6"),
        "the credential is in Debug output: {credentials:?}"
    );
}

/// The header built from the Basic credential is marked sensitive, so it
/// is redacted wherever the request's headers are printed.
#[test]
fn the_basic_authorization_header_is_sensitive() {
    let header = basic_authorization("axess-id", "Sample2+").unwrap();
    assert_eq!(
        header.to_str().unwrap(),
        "Basic YXhlc3MtaWQ6U2FtcGxlMiUyQg=="
    );
    assert!(header.is_sensitive(), "the header is marked sensitive");
}
