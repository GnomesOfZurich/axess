//! Tests for the parent `extractor` module.
//!
//! Lives in a sibling sub-module. Tests reach the
//! `pub(crate)` `SessionInner` / `SessionHandle` shape, so they stay
//! inside the crate. Two original cfg-test mods (`custom_bag_tests`
//! and `extractor_tests`) are preserved verbatim under this file.

#[cfg(test)]
mod custom_bag_tests {
    use super::super::*;
    use crate::session::layer::SessionInner;
    use tokio::sync::RwLock;

    fn make_session() -> AuthSession {
        let inner = SessionInner {
            id: SessionId::new(&axess_rng::SystemRng),
            data: SessionData::default(),
            modified: false,
            regenerate: false,
            pre_cycle_id: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
        };
        AuthSession(crate::session::layer::SessionHandle(Arc::new(RwLock::new(
            inner,
        ))))
    }

    /// Closure-form accessor borrows the state without
    /// cloning. We can't observe the absence of a clone directly, but
    /// we can prove the closure runs and returns the projected value.
    #[tokio::test]
    async fn with_auth_state_borrows_and_projects() {
        let session = make_session();
        // Default state is Guest.
        let is_guest = session.with_auth_state(|s| s.is_guest()).await;
        assert!(is_guest);
    }

    /// with_data sees mutations applied via the public mutators.
    #[tokio::test]
    async fn with_data_sees_set_custom() {
        let session = make_session();
        session.set_custom("key", serde_json::json!("value")).await;
        let observed = session
            .with_data(|d| {
                d.custom
                    .get("key")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .await;
        assert_eq!(observed.as_deref(), Some("value"));
    }

    /// Mutate_custom runs the closure under one write lock and
    /// removes multiple keys atomically (observable: every targeted
    /// key is gone after the call).
    #[tokio::test]
    async fn mutate_custom_removes_keys_atomically() {
        let session = make_session();
        session.set_custom("a", serde_json::json!(1)).await;
        session.set_custom("b", serde_json::json!(2)).await;
        session.set_custom("c", serde_json::json!(3)).await;
        session
            .mutate_custom(|obj| {
                obj.remove("a");
                obj.remove("b");
            })
            .await;
        let after = session.with_data(|d| d.custom.clone()).await;
        let map = after.as_object().expect("custom is an object");
        assert!(!map.contains_key("a"));
        assert!(!map.contains_key("b"));
        assert!(map.contains_key("c"));
    }

    /// Mutate_custom marks the session modified when the
    /// closure changes the bag (so the layer flushes on response).
    #[tokio::test]
    async fn mutate_custom_marks_modified_when_changed() {
        let session = make_session();
        session.set_custom("k", serde_json::json!("v")).await;
        // Reset modified to observe just the next operation.
        {
            let mut g = session.0.0.write().await;
            g.modified = false;
        }
        session
            .mutate_custom(|obj| {
                obj.remove("k");
            })
            .await;
        let modified = { session.0.0.read().await.modified };
        assert!(modified, "removing a key should mark session modified");
    }

    /// A no-op closure does NOT mark modified (the JSON byte
    /// length is unchanged, so we skip the dirty flag).
    #[tokio::test]
    async fn mutate_custom_no_op_does_not_mark_modified() {
        let session = make_session();
        session.set_custom("k", serde_json::json!("v")).await;
        {
            let mut g = session.0.0.write().await;
            g.modified = false;
        }
        session.mutate_custom(|_obj| { /* noop */ }).await;
        let modified = { session.0.0.read().await.modified };
        assert!(!modified, "no-op mutate_custom should not mark modified");
    }
}

#[cfg(test)]
mod extractor_tests {
    use super::super::*;
    use crate::session::layer::SessionInner;
    use tokio::sync::RwLock;

    fn make_session() -> AuthSession {
        let inner = SessionInner {
            id: SessionId::new(&axess_rng::SystemRng),
            data: SessionData::default(),
            modified: false,
            regenerate: false,
            pre_cycle_id: None,
            pending_fingerprint: None,
            max_custom_bytes: 64 * 1024,
        };
        AuthSession(crate::session::layer::SessionHandle(Arc::new(RwLock::new(
            inner,
        ))))
    }

    /// `snapshot()` returns `Some(AuthSnapshot)` for an
    /// `Authenticated` state with the live `(user, tenant, session_id,
    /// authn_time)` quadruple. Pins the function body and the
    /// `Authenticated` match arm against `-> None` and
    /// `delete match arm` mutations.
    #[tokio::test]
    async fn snapshot_returns_some_for_authenticated_state() {
        let session = make_session();
        let user = axess_identity::testing::user("u-1");
        let tenant = axess_identity::testing::tenant("t-1");
        let now = chrono::Utc::now();
        session.set_authenticated(user, tenant, now).await;

        let snap = session
            .snapshot()
            .await
            .expect("authenticated must yield Some");
        assert_eq!(snap.user_id, user);
        assert_eq!(snap.tenant_id, tenant);
        assert_eq!(snap.authn_time, now);
        assert_eq!(snap.session_id, session.session_id().await);
    }

    /// `snapshot()` returns `None` for non-Authenticated
    /// states. Pairs with the Some-test to discriminate the
    /// `-> None` mutation from the `delete match arm` mutation.
    #[tokio::test]
    async fn snapshot_returns_none_for_guest_state() {
        let session = make_session();
        assert!(session.snapshot().await.is_none());
    }

    /// `record_attempt_at` increments `attempt_count` by 1
    /// and stamps `last_attempt`. Three successive calls land at 1,
    /// 2, 3: discriminates `+= → *=` (which would fix the count at
    /// 0 since `0 * 1 == 0`) from the original.
    #[tokio::test]
    async fn record_attempt_at_increments_and_stamps_time() {
        let session = make_session();
        let user = axess_identity::testing::user("u");
        let tenant = axess_identity::testing::tenant("t");
        session
            .begin_authenticating(user, tenant, Arc::from("password"), vec![])
            .await;

        let t1 = chrono::Utc::now();
        for expected_count in 1u32..=3 {
            session.record_attempt_at(t1).await;
            let count = session
                .with_auth_state(|s| match s {
                    AuthState::Authenticating {
                        attempt_count,
                        last_attempt,
                        ..
                    } => Some((*attempt_count, *last_attempt)),
                    _ => None,
                })
                .await
                .expect("Authenticating state");
            assert_eq!(count.0, expected_count, "attempt_count must increment by 1");
            assert_eq!(count.1, Some(t1), "last_attempt must be stamped");
        }
    }

    /// `set_identifying` transitions Guest → Identifying
    /// with the provided ids. Mutation `-> ()` would leave the
    /// state at Guest and the test would observe no transition.
    #[tokio::test]
    async fn set_identifying_transitions_state() {
        let session = make_session();
        assert!(session.with_auth_state(|s| s.is_guest()).await);

        let user = axess_identity::testing::user("alice");
        let tenant = axess_identity::testing::tenant("acme");
        session.set_identifying(user, tenant).await;

        let saw = session
            .with_auth_state(|s| match s {
                AuthState::Identifying { user_id, tenant_id } => Some((*user_id, *tenant_id)),
                _ => None,
            })
            .await
            .expect("expected Identifying state");
        assert_eq!(saw.0, user);
        assert_eq!(saw.1, tenant);
    }

    /// `clear_custom` empties the custom JSON bag. Mutation
    /// `-> ()` would leave the bag populated.
    #[tokio::test]
    async fn clear_custom_wipes_the_bag() {
        let session = make_session();
        session.set_custom("k1", serde_json::json!("v1")).await;
        session.set_custom("k2", serde_json::json!(2)).await;
        assert!(session.get_custom("k1").await.is_some());

        session.clear_custom().await;

        assert!(session.get_custom("k1").await.is_none());
        assert!(session.get_custom("k2").await.is_none());
        let bag = session.with_data(|d| d.custom.clone()).await;
        let map = bag.as_object().expect("custom is object");
        assert!(map.is_empty(), "clear_custom must yield an empty object");
    }

    /// `remove_custom` returns `true` only if a key was
    /// actually removed. Pins both `-> true` and `-> false` body
    /// mutations: present-key returns true, absent-key returns false.
    #[tokio::test]
    async fn remove_custom_returns_true_only_when_key_present() {
        let session = make_session();
        session.set_custom("present", serde_json::json!(1)).await;

        // Absent key first; original returns false; `-> true` mutation flips.
        let absent = session.remove_custom("never-set").await;
        assert!(!absent, "remove_custom on absent key must return false");

        // Present key; original returns true; `-> false` mutation flips.
        let present = session.remove_custom("present").await;
        assert!(present, "remove_custom on present key must return true");

        // Idempotent: second remove is now absent.
        let again = session.remove_custom("present").await;
        assert!(!again);
    }

    /// `set_custom` rejects a write that would push the bag
    /// **strictly above** `max_custom_bytes`. At exactly the limit the
    /// write succeeds; one byte over fails. Pins the `>` operator
    /// against `>=` (which would reject at exactly the limit).
    #[tokio::test]
    async fn set_custom_size_boundary_is_strict_greater_than() {
        let session = make_session();
        // Shrink the cap so the test runs fast.
        const CAP: usize = 256;
        {
            let mut g = session.0.0.write().await;
            g.max_custom_bytes = CAP;
        }
        // Empty object is ~2 bytes ("{}"). With key "k" and a string
        // value "v...v" of length N, total ≈ 8 + N. Aim for exactly CAP.
        // Compute the value length so the full JSON ends up at
        // exactly CAP bytes. Empirically `{"k":"<value>"}` = 8 + len.
        let target_value_len = CAP - 8;
        let exactly_at_cap = "v".repeat(target_value_len);
        let just_over_cap = "v".repeat(target_value_len + 1);

        let ok = session
            .set_custom("k", serde_json::json!(exactly_at_cap))
            .await;
        assert!(
            ok,
            "at exactly max_custom_bytes the write must succeed (> not >=)"
        );

        // Now overwriting with one byte more must fail.
        let rejected = session
            .set_custom("k", serde_json::json!(just_over_cap))
            .await;
        assert!(!rejected, "one byte over max_custom_bytes must reject");
        // And the original value remains.
        let stored = session
            .get_custom("k")
            .await
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        assert_eq!(stored, Some(exactly_at_cap));
    }

    /// max_custom_bytes == 0 means "no limit". Mutation `> → >=` would
    /// turn that into "always reject", silently dropping every custom
    /// value. Pin the unlimited semantics by writing a value larger
    /// than any plausible default cap.
    #[tokio::test]
    async fn set_custom_with_zero_limit_accepts_any_size() {
        let session = make_session();
        {
            let mut g = session.0.0.write().await;
            g.max_custom_bytes = 0;
        }
        let large_value = "v".repeat(10_000);
        let stored = session
            .set_custom("k", serde_json::json!(large_value))
            .await;
        assert!(
            stored,
            "limit == 0 means unlimited; mutation `>= 0` would always reject"
        );
    }

    /// `is_authenticated()` reflects the AuthState flag. Kills the
    /// `-> bool with true` mutation by asserting the default (Guest)
    /// session is NOT authenticated.
    #[tokio::test]
    async fn is_authenticated_false_for_default_guest_session() {
        let session = make_session();
        assert!(!session.is_authenticated().await);
    }

    /// `is_authenticated()` returns true after promoting to Authenticated.
    #[tokio::test]
    async fn is_authenticated_true_after_set_authenticated() {
        let session = make_session();
        let user = axess_identity::testing::user("u-isauth");
        let tenant = axess_identity::testing::tenant("t-isauth");
        session
            .set_authenticated(user, tenant, chrono::Utc::now())
            .await;
        assert!(session.is_authenticated().await);
    }

    /// `auth_state()` returns the live state. Kills the
    /// `-> Default::default()` mutation by asserting a non-default
    /// state after promoting.
    #[tokio::test]
    async fn auth_state_reflects_set_authenticated() {
        let session = make_session();
        let user = axess_identity::testing::user("u-state");
        let tenant = axess_identity::testing::tenant("t-state");
        session
            .set_authenticated(user, tenant, chrono::Utc::now())
            .await;
        let state = session.auth_state().await;
        assert!(matches!(state, AuthState::Authenticated { .. }));
    }

    /// `data()` returns the live `SessionData`. Kills the
    /// `-> Default::default()` mutation: after `set_custom`,
    /// `data()` must observe the value (default would not).
    #[tokio::test]
    async fn data_reflects_set_custom() {
        let session = make_session();
        session.set_custom("k", serde_json::json!("v")).await;
        let data = session.data().await;
        assert_eq!(data.custom.get("k").and_then(|v| v.as_str()), Some("v"));
    }

    /// `authenticated_ids()` returns `(user, tenant)` for the
    /// Authenticated arm. Kills the `-> None` mutation and the
    /// `delete match arm` mutation simultaneously.
    #[tokio::test]
    async fn authenticated_ids_returns_some_for_authenticated() {
        let session = make_session();
        let user = axess_identity::testing::user("u-ids");
        let tenant = axess_identity::testing::tenant("t-ids");
        session
            .set_authenticated(user, tenant, chrono::Utc::now())
            .await;
        let ids = session.authenticated_ids().await;
        assert_eq!(ids, Some((user, tenant)));
    }

    #[tokio::test]
    async fn authenticated_ids_returns_none_for_guest() {
        let session = make_session();
        assert_eq!(session.authenticated_ids().await, None);
    }

    /// `set_pending_workflow` transitions to `PendingWorkflow`. The
    /// `-> ()` mutation drops the side effect; pin via a downstream
    /// state observation.
    #[tokio::test]
    async fn set_pending_workflow_transitions_state() {
        use crate::session::data::{WorkflowKind, WorkflowState};
        let session = make_session();
        let user = axess_identity::testing::user("u-pend");
        let tenant = axess_identity::testing::tenant("t-pend");
        let workflow = WorkflowState::new(WorkflowKind::Signup, 3, chrono::Utc::now());
        session.set_pending_workflow(user, tenant, workflow).await;
        let state = session.auth_state().await;
        assert!(matches!(state, AuthState::PendingWorkflow { .. }));
    }

    /// `clear()` resets the session to Guest with empty data. The
    /// `-> ()` mutation skips the wipe.
    #[tokio::test]
    async fn clear_resets_to_guest_and_drops_custom() {
        let session = make_session();
        let user = axess_identity::testing::user("u-clr");
        let tenant = axess_identity::testing::tenant("t-clr");
        session
            .set_authenticated(user, tenant, chrono::Utc::now())
            .await;
        session.set_custom("k", serde_json::json!("v")).await;
        session.clear().await;
        assert!(matches!(session.auth_state().await, AuthState::Guest));
        assert!(session.get_custom("k").await.is_none());
    }

    /// `regenerate()` flags the session for ID-cycle on save. The
    /// `-> ()` mutation skips the flag set.
    #[tokio::test]
    async fn regenerate_sets_the_regenerate_flag() {
        let session = make_session();
        session.regenerate().await;
        let g = session.0.0.read().await;
        assert!(g.regenerate);
    }

    /// `take_custom` removes the key and returns it; absent key
    /// returns `None`. Kills the `-> None` and
    /// `-> Some(Default::default())` mutations.
    #[tokio::test]
    async fn take_custom_returns_and_removes_present_value() {
        let session = make_session();
        session.set_custom("k", serde_json::json!("v")).await;
        let taken = session.take_custom("k").await;
        assert_eq!(taken, Some(serde_json::json!("v")));
        assert!(session.get_custom("k").await.is_none());
    }

    #[tokio::test]
    async fn take_custom_returns_none_for_absent_key() {
        let session = make_session();
        assert!(session.take_custom("missing").await.is_none());
    }

    /// `device_id()` returns the value stored on `SessionData`,
    /// not the unconditional `None` the `-> None` body-replacement
    /// mutation produces.
    #[tokio::test]
    async fn device_id_returns_session_data_value() {
        let session = make_session();
        // Default Guest session: no device.
        assert!(session.device_id().await.is_none());

        // Populate device_id directly on the inner data and re-read.
        let device = axess_identity::testing::device("dev-extractor");
        {
            session.0.0.write().await.data.device_id = Some(device);
        }
        assert_eq!(
            session.device_id().await,
            Some(device),
            "device_id must reflect SessionData; `-> None` mutation would always return None"
        );
    }

    /// `SessionMissing::into_response` MUST emit a non-default
    /// HTTP response: specifically a 500-equivalent. The mutation
    /// `-> Default::default()` would produce an empty 200 OK, hiding
    /// the misconfiguration (missing `SessionLayer`) from operators.
    #[test]
    fn session_missing_into_response_is_internal_server_error() {
        use axum::response::IntoResponse;
        let response = SessionMissing.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "SessionMissing must surface as 500, not Default::default()"
        );
    }
}
