use super::*;

#[test]
fn issue_refuses_a_huge_lifetime_and_a_missing_audience() {
    let now = chrono::Utc::now();
    // These used to reach `now + Duration::seconds(..)`, which panics
    // on overflow, or minted a token with no audience.
    for ttl in [i64::MAX, i64::MIN, 0, -1, MAX_TTL_SECS + 1] {
        let err = validated_expiry(now, ttl, Some("api")).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST, "ttl {ttl}");
    }
    for aud in [None, Some(""), Some("  ")] {
        let err = validated_expiry(now, 60, aud).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST, "aud {aud:?}");
    }
    assert_eq!(
        validated_expiry(now, MAX_TTL_SECS, Some("api")).unwrap(),
        now + Duration::seconds(MAX_TTL_SECS)
    );
}

#[test]
fn a_kid_cannot_name_another_path() {
    for bad in [
        "",
        "../escape",
        "a/b",
        "a\\b",
        "..",
        "v1.pem",
        "a b",
        &"k".repeat(65),
    ] {
        assert!(!valid_kid(bad), "{bad:?} must be refused");
    }
    for good in ["v1", "2026-10_rotation", "K"] {
        assert!(valid_kid(good), "{good:?} must be accepted");
    }
}

#[test]
fn a_private_key_file_is_never_overwritten_and_is_owner_only() {
    let dir = std::env::temp_dir().join(format!("local-idp-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("k.pem");
    write_private_key(&path, b"first").unwrap();
    assert!(write_private_key(&path, b"second").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"first");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "group/other bits must be clear: {mode:o}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

// ── Key lifecycle guards ────────────────────────────────────────────────

async fn state_in(dir: &Path) -> AppState {
    state_in_with_clock(dir, Arc::new(SystemClock)).await
}

async fn state_in_with_clock(dir: &Path, clock: Arc<dyn Clock>) -> AppState {
    bootstrap_initial_key(dir).unwrap();
    let store = FileLocalIdpKeyStore::new(dir, clock.clone());
    let idp = LocalIdp::from_key_store(ISSUER, store.clone())
        .await
        .unwrap()
        .with_max_ttl(Duration::seconds(MAX_TTL_SECS));
    AppState {
        idp,
        store,
        clock,
        admin_token: "unused-in-these-tests".into(),
    }
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "local-idp-{name}-{}-{}",
        std::process::id(),
        uuid_like()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn uuid_like() -> u128 {
    let mut bytes = [0u8; 16];
    axess::SecureRng::fill_bytes(&axess::SystemRng, &mut bytes);
    u128::from_be_bytes(bytes)
}

async fn rotate(state: &AppState, kid: &str) -> Result<(), StatusCode> {
    rotate_handler(
        State(state.clone()),
        Json(RotateRequest {
            new_kid: kid.into(),
        }),
    )
    .await
    .map(|_| ())
    .map_err(|(status, _)| status)
}

async fn retire(state: &AppState, kid: &str) -> Result<StatusCode, StatusCode> {
    retire_handler(
        State(state.clone()),
        Json(RetireRequest { kid: kid.into() }),
    )
    .await
    .map_err(|(status, _)| status)
}

/// Pretend `kid` stopped being current long enough ago for every token
/// it signed to have expired.
fn age_rotation(store: &FileLocalIdpKeyStore, kid: &str) {
    let dir = store.root.join("rotated_at");
    std::fs::create_dir_all(&dir).unwrap();
    let long_ago = store.clock.now() - Duration::seconds(2 * MAX_TTL_SECS);
    std::fs::write(dir.join(kid), long_ago.to_rfc3339()).unwrap();
}

#[tokio::test]
async fn a_key_is_not_retired_before_its_tokens_have_expired() {
    let dir = scratch_dir("early");
    let state = state_in(&dir).await;
    rotate(&state, "v2").await.unwrap();

    let early = retire(&state, "v1").await;
    assert_eq!(early, Err(StatusCode::CONFLICT), "retired straight away");
    assert!(state.store.key_path("v1").exists());

    age_rotation(&state.store, "v1");
    assert_eq!(retire(&state, "v1").await, Ok(StatusCode::NO_CONTENT));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_retired_kid_cannot_be_used_again() {
    let dir = scratch_dir("reuse");
    let state = state_in(&dir).await;
    rotate(&state, "v2").await.unwrap();
    age_rotation(&state.store, "v1");
    assert_eq!(retire(&state, "v1").await, Ok(StatusCode::NO_CONTENT));
    let archived = std::fs::read(dir.join("retired/v1.pem")).unwrap();

    let again = rotate(&state, "v1").await;
    assert!(again.is_err(), "a retired kid was accepted for a new key");
    assert_eq!(
        std::fs::read(dir.join("retired/v1.pem")).unwrap(),
        archived,
        "the archived key changed"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_failed_rotation_leaves_no_key_to_publish() {
    let dir = scratch_dir("failed");
    let state = state_in(&dir).await;
    // The pointer flip writes `current.kid.tmp`; a directory there makes
    // the store refuse after the new key file is already on disk.
    std::fs::create_dir(dir.join("current.kid.tmp")).unwrap();

    assert!(rotate(&state, "v2").await.is_err());
    assert!(
        !state.store.key_path("v2").exists(),
        "the key of the failed rotation is still in historical/"
    );
    let kids = state.store.list_kids().unwrap();
    assert_eq!(kids, vec!["v1".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A key minted for a rotation that never reached the pointer flip (a
/// crash in between) is not on disk where `load_all` reads, so the next
/// start does not publish a key that has no rotation record.
#[tokio::test]
async fn a_key_minted_but_never_rotated_in_is_not_published() {
    let dir = scratch_dir("crash");
    let state = state_in(&dir).await;
    mint_and_persist_new_key(&state.store, "v2").unwrap();

    assert_eq!(state.store.list_kids().unwrap(), vec!["v1".to_string()]);
    let loaded = state.store.load_all().await.unwrap();
    assert!(loaded.historical.is_empty(), "the unrotated key was loaded");
    assert!(state.store.kid_taken("v2"), "its kid is still reserved");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The moment a rotation is stamped and the moment the retire check reads
/// are one clock, the one the state holds.
#[tokio::test]
async fn the_rotation_is_stamped_by_the_clock_the_retire_check_reads() {
    let dir = scratch_dir("clock");
    let t0 = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let clock = axess_clock::testing::MockClock::at(t0);
    let state = state_in_with_clock(&dir, Arc::new(clock.clone())).await;
    rotate(&state, "v2").await.unwrap();

    let stamped = std::fs::read_to_string(state.store.rotated_at_path("v1")).unwrap();
    assert_eq!(stamped, t0.to_rfc3339());
    assert_eq!(retire(&state, "v1").await, Err(StatusCode::CONFLICT));
    clock.advance_secs(MAX_TTL_SECS + 1);
    assert_eq!(retire(&state, "v1").await, Ok(StatusCode::NO_CONTENT));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A historical key left by a store that kept no rotation record is
/// stamped when the store first reads it, so it can retire once its
/// longest-lived token has expired instead of never.
#[tokio::test]
async fn a_historical_key_with_no_record_is_stamped_and_then_retires() {
    let dir = scratch_dir("legacy");
    let t0 = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let clock = axess_clock::testing::MockClock::at(t0);
    let state = state_in_with_clock(&dir, Arc::new(clock.clone())).await;
    rotate(&state, "v2").await.unwrap();
    // The state of a store written before rotation times were recorded.
    std::fs::remove_dir_all(dir.join("rotated_at")).unwrap();
    assert_eq!(retire(&state, "v1").await, Err(StatusCode::CONFLICT));

    state.store.load_all().await.unwrap();
    assert_eq!(retire(&state, "v1").await, Err(StatusCode::CONFLICT));
    clock.advance_secs(MAX_TTL_SECS + 1);
    assert_eq!(retire(&state, "v1").await, Ok(StatusCode::NO_CONTENT));
    std::fs::remove_dir_all(&dir).unwrap();
}
