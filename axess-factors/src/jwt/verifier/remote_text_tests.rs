//! A token's custom claims that do not fit the caller's type are refused
//! with serde's message cut: the claims are the issuer's text.

use super::tests::{handle, rsa_keypair, sign};
use super::*;
use axess_clock::Timestamp;
use axess_clock::testing::MockClock;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Numbered {
    level: u64,
}

#[tokio::test]
async fn custom_claims_that_do_not_fit_are_reported_bounded() {
    let (der, jwks, kid) = rsa_keypair();
    let t0 = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let with_level = |level: serde_json::Value| {
        sign(
            &serde_json::json!({
                "iss": "https://idp.example.com",
                "sub": "workload-42",
                "aud": "my-svc",
                "exp": t0.unix_seconds() + 300,
                "iat": t0.unix_seconds(),
                "level": level,
            }),
            &kid,
            &der,
        )
    };
    let token = with_level("A".repeat(4096).into());
    let verifier = JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc")
        .with_clock(Arc::new(MockClock::at(t0)));

    // The control: the same token with a number where the type wants one.
    let fits = verifier
        .verify::<Numbered>(&with_level(3.into()))
        .await
        .expect("a number fits");
    assert_eq!(fits.custom.level, 3);

    let err = verifier
        .verify::<Numbered>(&token)
        .await
        .expect_err("a string where a number belongs")
        .to_string();

    assert!(err.contains("custom claims"), "{err}");
    assert!(err.len() <= 512, "{} bytes in one error", err.len());
    assert!(!err.contains(&"A".repeat(300)), "the value is quoted whole");
}

/// A `jti` the token's sender wrote to forge a log line and to fill one.
fn forged_jti() -> String {
    format!(
        "tok\nWARN forged line\r\u{1b}[31m\u{2028}{}",
        "A".repeat(4096)
    )
}

fn is_raw(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// A store that refuses every key as replayed.
struct AlwaysReplayed;

impl JtiReplayStore for AlwaysReplayed {
    async fn check_and_record(&self, jti: &str, _: Duration) -> Result<(), JtiReplayError> {
        Err(JtiReplayError::already_used(jti))
    }
}

/// A store whose backend error quotes the key it was handed.
struct BackendQuotingTheKey;

impl JtiReplayStore for BackendQuotingTheKey {
    async fn check_and_record(&self, jti: &str, _: Duration) -> Result<(), JtiReplayError> {
        Err(JtiReplayError::Backend(format!("SET {jti} failed")))
    }
}

async fn refusal_through<R: JtiReplayStore + 'static>(store: R) -> String {
    let (der, jwks, kid) = rsa_keypair();
    let t0 = Timestamp::from_unix_seconds(1_700_000_000).unwrap();
    let token = sign(
        &serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "workload-42",
            "aud": "my-svc",
            "exp": t0.unix_seconds() + 300,
            "iat": t0.unix_seconds(),
            "jti": forged_jti(),
        }),
        &kid,
        &der,
    );
    JwtVerifier::new(handle(jwks))
        .with_issuer("https://idp.example.com")
        .with_audience("my-svc")
        .with_clock(Arc::new(MockClock::at(t0)))
        .with_replay_store(store)
        .verify::<serde_json::Value>(&token)
        .await
        .expect_err("the store refuses the token")
        .to_string()
}

/// The `jti` is the sender's text. A replay refusal carries it escaped and
/// cut, and so does a backend error that quotes the key.
#[tokio::test]
async fn a_replay_refusal_carries_the_jti_cut_and_escaped() {
    let refusals = [
        refusal_through(AlwaysReplayed).await,
        refusal_through(BackendQuotingTheKey).await,
    ];
    for text in refusals {
        assert!(text.contains("jti replay"), "{text}");
        assert!(text.len() <= 512, "{} bytes in one error", text.len());
        assert!(!text.contains(&"A".repeat(300)), "quoted whole");
        assert!(!text.chars().any(is_raw), "{text:?}");
        assert!(text.contains("tok\\nWARN forged line\\r"), "{text}");
    }
}

/// The constructor keeps no more of the key than the bound, escaped, and
/// the message prints what is kept. The variant has no other way in: what
/// it holds has no public constructor.
#[test]
fn the_replay_error_holds_and_prints_a_bounded_key() {
    let key = forged_jti();
    let error = JtiReplayError::already_used(&key);
    let printed = error.to_string();
    let JtiReplayError::AlreadyUsed(kept) = error else {
        panic!("the constructor builds AlreadyUsed");
    };
    let kept = kept.as_str();
    assert!(kept.len() <= MAX_JTI_ECHO_BYTES, "{} bytes", kept.len());
    assert!(!kept.chars().any(is_raw), "{kept:?}");
    assert!(kept.starts_with("tok\\nWARN forged line\\r"), "{kept}");
    assert!(kept.ends_with("..."), "the cut is marked: {kept}");

    assert_eq!(printed, format!("JWT `jti` already used: {kept}"));
    assert_eq!(
        JtiReplayError::already_used("tok-1").to_string(),
        "JWT `jti` already used: tok-1"
    );
}

/// With no replay store the verifier says so at trace level, and the line
/// carries the `jti` cut and escaped.
#[tokio::test]
async fn the_no_replay_trace_line_carries_the_jti_cut_and_escaped() {
    let printed = axess_testing::mock_tracing::LineCapture::install();
    NoReplay
        .check_and_record(&forged_jti(), Duration::from_secs(60))
        .await
        .expect("NoReplay accepts every jti");

    let lines = printed.lines();
    let line = lines
        .iter()
        .find(|line| line.contains("replay detection disabled"))
        .unwrap_or_else(|| panic!("no trace line in {lines:?}"));
    assert!(line.contains("tok\\nWARN forged line\\r"), "{line}");
    assert!(!line.contains(&"A".repeat(MAX_JTI_ECHO_BYTES)), "{line}");
    assert!(!line.chars().any(is_raw), "{line:?}");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("forged line"))
            .count(),
        1,
        "the forged text starts no line of its own: {lines:?}"
    );
}
