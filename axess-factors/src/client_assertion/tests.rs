use super::*;
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use axess_rng::testing::MockRng;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A P-256 key from `openssl ecparam -name prime256v1 -genkey | openssl
/// pkcs8 -topk8 -nocrypt`, made for this test only.
const EC_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaIdz1CBm27c+a2Q
4lwMZOSeBZnbM1KkbBPv4xizy4WhRANCAAQZIaDN9tHlIbqHc9mOKzezhVGVY+CJ
AOvrqvniGAwR3I6EXZI5vT/mB8JRD6e+Ir1nRbrutHGH5kyENsRjhn9P
-----END PRIVATE KEY-----
";

fn rsa_pems() -> (String, String) {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa key");
    (
        key.to_pkcs1_pem(Default::default())
            .expect("pkcs1")
            .to_string(),
        key.to_pkcs8_pem(Default::default())
            .expect("pkcs8")
            .to_string(),
    )
}

fn clock_and_rng() -> (MockClock, MockRng) {
    (
        MockClock::at(Timestamp::from_unix_seconds(1_700_000_000).unwrap()),
        MockRng::new(7),
    )
}

fn payload(jwt: &str) -> serde_json::Value {
    let part = jwt.split('.').nth(1).expect("payload part");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

fn header(jwt: &str) -> serde_json::Value {
    let part = jwt.split('.').next().expect("header part");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

#[cfg(any(feature = "jwt-aws-lc", feature = "client-assertion-rsa"))]
#[test]
fn pkcs1_and_pkcs8_rsa_pems_both_sign() {
    let (pkcs1, pkcs8) = rsa_pems();
    let (clock, rng) = clock_and_rng();
    for pem in [pkcs1, pkcs8] {
        let signer =
            ClientAssertionSigner::from_pem("c", &pem, Algorithm::RS256).expect("an RSA PEM");
        let jwt = signer
            .mint("https://idp/token", &clock, &rng)
            .expect("signs");
        assert_eq!(header(&jwt)["alg"], "RS256");
    }
}

#[test]
fn an_ec_pkcs8_pem_signs_es256() {
    let (clock, rng) = clock_and_rng();
    let signer =
        ClientAssertionSigner::from_pem("c", EC_PKCS8, Algorithm::ES256).expect("an EC PEM");
    let jwt = signer
        .mint("https://idp/token", &clock, &rng)
        .expect("signs");
    assert_eq!(header(&jwt)["alg"], "ES256");
}

#[test]
fn a_label_that_does_not_suit_the_algorithm_is_refused() {
    let (pkcs1, _) = rsa_pems();
    assert!(ClientAssertionSigner::from_pem("c", &pkcs1, Algorithm::ES256).is_err());
    assert!(ClientAssertionSigner::from_pem("c", EC_PKCS8, Algorithm::HS256).is_err());
    assert!(ClientAssertionSigner::from_pem("c", "not pem", Algorithm::RS256).is_err());
    let unclosed = "-----BEGIN PRIVATE KEY-----\nAAAA\n";
    assert!(ClientAssertionSigner::from_pem("c", unclosed, Algorithm::ES256).is_err());
    let encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n";
    assert!(ClientAssertionSigner::from_pem("c", encrypted, Algorithm::RS256).is_err());
}

#[test]
fn the_assertion_follows_the_injected_clock_and_rng() {
    let (clock, rng) = clock_and_rng();
    let signer = ClientAssertionSigner::from_pem("axess-client", EC_PKCS8, Algorithm::ES256)
        .expect("an EC PEM")
        .with_key_id("k1")
        .with_x5t_s256("thumb256")
        .with_assertion_ttl(Duration::from_secs(30))
        .expect("a whole number of seconds");
    let jwt = signer
        .mint("https://idp/token", &clock, &rng)
        .expect("signs");

    let claims = payload(&jwt);
    assert_eq!(claims["iss"], "axess-client");
    assert_eq!(claims["sub"], "axess-client");
    assert_eq!(claims["aud"], "https://idp/token");
    assert_eq!(claims["iat"], 1_700_000_000);
    assert_eq!(claims["exp"], 1_700_000_030);

    let mut expected = [0u8; 16];
    MockRng::new(7).fill_bytes(&mut expected);
    let jti = uuid::Builder::from_random_bytes(expected)
        .into_uuid()
        .to_string();
    assert_eq!(claims["jti"], jti);

    let head = header(&jwt);
    assert_eq!(head["kid"], "k1");
    assert_eq!(head["x5t#S256"], "thumb256");
}

#[test]
fn a_fixed_audience_wins_over_the_endpoint() {
    let (clock, rng) = clock_and_rng();
    let signer = ClientAssertionSigner::from_pem("c", EC_PKCS8, Algorithm::ES256)
        .expect("an EC PEM")
        .with_audience("https://issuer");
    let jwt = signer
        .mint("https://idp/token", &clock, &rng)
        .expect("signs");
    assert_eq!(payload(&jwt)["aud"], "https://issuer");
}

/// A symmetric algorithm is refused when the signer is built: an `HS256`
/// assertion is `client_secret_jwt`, never `private_key_jwt`, and it would
/// otherwise have been minted at the first request.
#[test]
fn a_symmetric_algorithm_is_refused_at_construction() {
    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let built = ClientAssertionSigner::new("c", EncodingKey::from_secret(b"shared"), alg);
        assert_eq!(built.err(), Some(ClientAssertionError::Symmetric(alg)));
        assert_eq!(
            ClientAssertionSigner::from_pem("c", EC_PKCS8, alg).err(),
            Some(ClientAssertionError::Symmetric(alg))
        );
    }
}

/// A key that does not sign under the algorithm fails when the signer is
/// built, not at the first request; the same key under its own algorithm
/// builds.
#[cfg(any(feature = "jwt-aws-lc", feature = "client-assertion-rsa"))]
#[test]
fn a_key_that_does_not_suit_the_algorithm_fails_at_construction() {
    let (_, pkcs8) = rsa_pems();
    let ec_der = {
        let (_, der) = decode_pem(EC_PKCS8).expect("pem");
        der
    };
    assert!(
        ClientAssertionSigner::new("c", EncodingKey::from_ec_der(&ec_der), Algorithm::ES256)
            .is_ok()
    );
    let built =
        ClientAssertionSigner::new("c", EncodingKey::from_ec_der(&ec_der), Algorithm::RS256);
    assert!(
        matches!(
            built,
            Err(ClientAssertionError::KeyMismatch {
                algorithm: Algorithm::RS256,
                ..
            })
        ),
        "{built:?}"
    );
    assert!(ClientAssertionSigner::from_pem("c", &pkcs8, Algorithm::PS256).is_ok());
}

/// The typed refusals of `from_pem` name what was wrong.
#[cfg(any(feature = "jwt-aws-lc", feature = "client-assertion-rsa"))]
#[test]
fn from_pem_refusals_are_typed() {
    let (pkcs1, _) = rsa_pems();
    assert_eq!(
        ClientAssertionSigner::from_pem("c", "not pem", Algorithm::RS256).err(),
        Some(ClientAssertionError::NotPem)
    );
    assert_eq!(
        ClientAssertionSigner::from_pem("c", &pkcs1, Algorithm::ES256).err(),
        Some(ClientAssertionError::LabelMismatch {
            algorithm: Algorithm::ES256,
            label: "RSA PRIVATE KEY".to_string()
        })
    );
    let unclosed = "-----BEGIN PRIVATE KEY-----\nAAAA\n";
    assert_eq!(
        ClientAssertionSigner::from_pem("c", unclosed, Algorithm::ES256).err(),
        Some(ClientAssertionError::Unclosed)
    );
    let encrypted = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n";
    assert_eq!(
        ClientAssertionSigner::from_pem("c", encrypted, Algorithm::RS256).err(),
        Some(ClientAssertionError::Encrypted)
    );
}

/// A stored spec gives the signer its headers, audience and lifetime, and
/// reads back from the JSON shape a record has always had.
#[test]
fn a_spec_shapes_the_signer_and_keeps_the_stored_json() {
    let (clock, rng) = clock_and_rng();
    let spec: SignerSpec = serde_json::from_value(serde_json::json!({
        "algorithm": "ES256",
        "key_id": "k1",
        "x5t_s256": "thumb256",
        "x5t": "thumb1",
        "audience": "https://issuer",
    }))
    .expect("the stored shape reads");
    assert_eq!(spec.assertion_ttl, None);
    let jwt = ClientAssertionSigner::from_spec("c", EC_PKCS8, &spec)
        .expect("builds")
        .mint("https://idp/token", &clock, &rng)
        .expect("signs");
    let head = header(&jwt);
    assert_eq!(head["kid"], "k1");
    assert_eq!(head["x5t#S256"], "thumb256");
    assert_eq!(head["x5t"], "thumb1");
    assert_eq!(payload(&jwt)["aud"], "https://issuer");
    assert_eq!(payload(&jwt)["exp"], 1_700_000_060);

    let short = SignerSpec {
        assertion_ttl: Some(Duration::from_secs(20)),
        ..SignerSpec::new(Algorithm::ES256)
    };
    let jwt = ClientAssertionSigner::from_spec("c", EC_PKCS8, &short)
        .expect("builds")
        .mint("https://idp/token", &clock, &rng)
        .expect("signs");
    assert_eq!(payload(&jwt)["exp"], 1_700_000_020);
    assert_eq!(payload(&jwt)["aud"], "https://idp/token");
    let stored = serde_json::to_value(SignerSpec::new(Algorithm::ES256)).unwrap();
    assert!(stored.get("assertion_ttl_secs").is_none(), "{stored}");
    let stored = serde_json::to_value(&short).unwrap();
    assert_eq!(stored["assertion_ttl_secs"], 20, "{stored}");
    let read: SignerSpec = serde_json::from_value(stored).unwrap();
    assert_eq!(read, short);
}

/// An assertion lifetime is a whole, non-zero number of seconds, since `exp`
/// is whole seconds after `iat`: no time, or a fraction of a second, is
/// refused by name, from a stored spec and from the builder, and is not
/// stored.
#[test]
fn an_assertion_lifetime_that_is_no_time_or_not_whole_seconds_is_refused() {
    for ttl in [
        Duration::ZERO,
        Duration::from_millis(20_500),
        Duration::from_nanos(1),
    ] {
        let spec = SignerSpec {
            assertion_ttl: Some(ttl),
            ..SignerSpec::new(Algorithm::ES256)
        };
        let refused = ClientAssertionSigner::from_spec("c", EC_PKCS8, &spec).err();
        assert_eq!(
            refused,
            Some(ClientAssertionError::AssertionTtl(ttl)),
            "{ttl:?}"
        );
        let refused = ClientAssertionSigner::from_pem("c", EC_PKCS8, Algorithm::ES256)
            .expect("an EC PEM")
            .with_assertion_ttl(ttl)
            .err();
        assert_eq!(
            refused,
            Some(ClientAssertionError::AssertionTtl(ttl)),
            "{ttl:?}"
        );
        assert!(
            refused.unwrap().to_string().contains("assertion_ttl"),
            "the refusal names the setting"
        );
        if !ttl.is_zero() {
            assert!(
                serde_json::to_value(&spec).is_err(),
                "{ttl:?} is not stored"
            );
        }
    }
}

/// The choice is made per algorithm: every RSA one is refused where the
/// build does not sign with RSA, and passes where it does; the EC and
/// Edwards algorithms pass either way.
#[test]
fn an_rsa_algorithm_is_refused_where_the_build_did_not_choose_it() {
    for algorithm in RSA_ALGORITHMS {
        assert_eq!(
            check_rsa_choice(algorithm, false),
            Err(ClientAssertionError::RsaNotChosen(algorithm))
        );
        assert_eq!(check_rsa_choice(algorithm, true), Ok(()));
    }
    for algorithm in [Algorithm::ES256, Algorithm::ES384, Algorithm::EdDSA] {
        assert_eq!(check_rsa_choice(algorithm, false), Ok(()));
    }
}

/// Every RSA algorithm `private_key_jwt` takes.
const RSA_ALGORITHMS: [Algorithm; 6] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// On `jwt-rust-crypto` without the choice, a signer for every RSA
/// algorithm is refused by name before its key is read, through each of
/// the three constructors: text that is no PEM at all is refused as an RSA
/// algorithm, not as text, and so is a key handed in already built. An EC
/// key still signs.
#[cfg(not(any(feature = "jwt-aws-lc", feature = "client-assertion-rsa")))]
#[test]
fn an_rsa_signer_is_refused_before_its_key_is_read_on_the_pure_rust_backend() {
    let (pkcs1, pkcs8) = rsa_pems();
    for algorithm in RSA_ALGORITHMS {
        let refused = Some(ClientAssertionError::RsaNotChosen(algorithm));
        assert_eq!(
            ClientAssertionSigner::from_pem("c", "not pem", algorithm).err(),
            refused,
            "{algorithm:?} from text that is no PEM"
        );
        for pem in [&pkcs1, &pkcs8] {
            assert_eq!(
                ClientAssertionSigner::from_pem("c", pem, algorithm).err(),
                refused,
                "{algorithm:?} from an RSA PEM"
            );
        }
        assert_eq!(
            ClientAssertionSigner::new("c", EncodingKey::from_rsa_der(&[]), algorithm).err(),
            refused,
            "{algorithm:?} from a built key"
        );
        let spec = SignerSpec::new(algorithm);
        assert_eq!(
            ClientAssertionSigner::from_spec("c", &pkcs1, &spec).err(),
            refused,
            "{algorithm:?} from a spec"
        );
        assert_eq!(
            ClientAssertionSigner::from_spec("c", "not pem", &spec).err(),
            refused,
            "{algorithm:?} from a spec with text that is no PEM"
        );
    }
    let message = ClientAssertionError::RsaNotChosen(Algorithm::RS256).to_string();
    assert!(message.contains("client-assertion-rsa"), "{message}");
    assert!(message.contains("RUSTSEC-2023-0071"), "{message}");
    let (clock, rng) = clock_and_rng();
    let signer =
        ClientAssertionSigner::from_pem("c", EC_PKCS8, Algorithm::ES256).expect("EC signs");
    assert!(signer.mint("https://idp/token", &clock, &rng).is_ok());
}

/// Where the build chose RSA (the aws-lc backend, or `client-assertion-rsa`
/// on the pure-Rust one), an RSA key signs assertions under every RSA
/// algorithm, each carrying its algorithm.
#[cfg(any(feature = "jwt-aws-lc", feature = "client-assertion-rsa"))]
#[test]
fn an_rsa_signer_signs_where_the_build_chose_it() {
    let (pkcs1, pkcs8) = rsa_pems();
    let (clock, rng) = clock_and_rng();
    for algorithm in RSA_ALGORITHMS {
        for pem in [&pkcs1, &pkcs8] {
            let signer =
                ClientAssertionSigner::from_pem("c", pem, algorithm).expect("an RSA signer");
            let jwt = signer
                .mint("https://idp/token", &clock, &rng)
                .expect("signs");
            assert_eq!(header(&jwt)["alg"], format!("{algorithm:?}"));
        }
    }
}
