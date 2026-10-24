//! A refreshed session carries the time of the original authentication, not
//! the time of the refresh.

use super::test_support::{fixture_tenant, fixture_user, test_config};
use super::*;
use crate::testing::{MemoryRefreshTokenStore, mock_random::MockRng};

/// Relative to the real clock: the in-memory store expires rows by it.
fn login_time() -> DateTime<Utc> {
    static LOGIN: std::sync::OnceLock<DateTime<Utc>> = std::sync::OnceLock::new();
    *LOGIN.get_or_init(|| Utc::now() - Duration::days(25))
}

async fn issue_at_login(store: &MemoryRefreshTokenStore, rng: &MockRng) -> String {
    let (plaintext, _) = issue_refresh_token(
        IssueRequest {
            user_id: &fixture_user(),
            tenant_id: &fixture_tenant(),
            device_info: None,
            family_id: None,
            device_id: None,
        },
        &test_config(),
        store,
        rng,
        login_time(),
    )
    .await
    .unwrap();
    plaintext
}

fn authn_time_of(session: &SessionData) -> DateTime<Utc> {
    match &session.auth_state {
        AuthState::Authenticated { authn_time, .. } => *authn_time,
        other => panic!("expected an authenticated session, got {other:?}"),
    }
}

#[tokio::test]
async fn refreshed_session_keeps_the_login_time_across_a_long_rotation_chain() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(7);
    let mut plaintext = issue_at_login(&store, &rng).await;

    // Refresh every ten days, three times: the chain is 29 days old at the end.
    let mut now = login_time();
    for _ in 0..3 {
        now += Duration::days(10) - Duration::hours(8);
        let (session, next) = refresh_session(&plaintext, &store, &config, &rng, now, None)
            .await
            .unwrap();
        assert_eq!(
            authn_time_of(&session),
            login_time(),
            "a refresh is not a login: authn_time must stay at the original sign-in"
        );
        let (next_plaintext, next_record) = next.expect("rotation is on");
        assert_eq!(next_record.authn_time, Some(login_time()));
        assert!(next_record.issued_at > login_time());
        plaintext = next_plaintext;
    }
    assert!(now - login_time() > Duration::days(20));
}

#[tokio::test]
async fn a_row_without_authn_time_reads_as_its_issue_time() {
    let store = MemoryRefreshTokenStore::new();
    let config = test_config();
    let rng = MockRng::new(8);
    let plaintext = issue_at_login(&store, &rng).await;

    let (session, _) = refresh_session(
        &plaintext,
        &store,
        &config,
        &rng,
        login_time() + Duration::days(2),
        None,
    )
    .await
    .unwrap();
    assert_eq!(authn_time_of(&session), login_time());
}
