//! A rotation whose second read of the old id is an error, not an answer.

use super::registry::move_registry_entry;
use super::*;
use crate::authn::ids::testing as ids;
use crate::session::data::SessionData;
use crate::session::layer::UnknownLiveness;
use crate::session::store::{
    MemorySessionStore, RevocationError, SessionRegistryHandle, SessionRevoker, SessionStore,
};
use crate::testing::mock_random::MockRng;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Answers `Valid` for the old id the first time and `Unknown` afterwards:
/// the registry fails between the check and the re-read.
struct FailsOnReread {
    old: SessionId,
    reads_of_old: AtomicUsize,
    held: Mutex<Vec<SessionId>>,
}

impl SessionRevoker for FailsOnReread {
    fn invalidate_user<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        self.held.lock().unwrap().clear();
        Box::pin(async { Ok(()) })
    }
    fn invalidate_session<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        self.held.lock().unwrap().retain(|held| held != id);
        Box::pin(async { Ok(()) })
    }
}

impl SessionRegistryHandle for FailsOnReread {
    fn is_valid<'a>(
        &'a self,
        user: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { self.liveness(user, id).await == SessionLiveness::Valid })
    }
    fn liveness<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        let answer = if *id == self.old {
            if self.reads_of_old.fetch_add(1, Ordering::SeqCst) == 0 {
                SessionLiveness::Valid
            } else {
                SessionLiveness::Unknown
            }
        } else if self.held.lock().unwrap().contains(id) {
            SessionLiveness::Valid
        } else {
            SessionLiveness::Gone
        };
        Box::pin(async move { answer })
    }
    fn register<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.held.lock().unwrap().push(*id);
        Box::pin(async { true })
    }
    fn held_sessions<'a>(
        &'a self,
        _: &'a crate::authn::ids::UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionId>, RevocationError>> + Send + 'a>> {
        let held = self.held.lock().unwrap().clone();
        Box::pin(async move { Ok(held) })
    }
}

async fn rotate(unknown: UnknownLiveness) -> (bool, Arc<FailsOnReread>, bool) {
    let store = MemorySessionStore::new();
    let (old, new) = (
        SessionId::new(&MockRng::new(4)),
        SessionId::new(&MockRng::new(5)),
    );
    let mut data = SessionData::default();
    data.auth_state
        .set_authenticated(ids::user("u"), ids::tenant("t"), chrono::Utc::now());
    store
        .save(&new, &data, Duration::from_secs(600))
        .await
        .unwrap();
    let registry = Arc::new(FailsOnReread {
        old,
        reads_of_old: AtomicUsize::new(0),
        held: Mutex::new(vec![old]),
    });
    let cookie = move_registry_entry(
        &store,
        &*registry,
        &Rotation {
            user_id: ids::user("u"),
            old_id: old,
            new_id: new,
            was_authenticated: true,
        },
        unknown,
    )
    .await;
    let row_kept = store.load(&new).await.unwrap().is_some();
    (cookie, registry, row_kept)
}

/// When the registry cannot say, on the re-read, whether the old id is still
/// held, the default policy ends the rotation instead of letting it go ahead.
#[tokio::test]
async fn a_failed_reread_after_registering_ends_a_rejecting_rotation() {
    let (cookie, registry, row_kept) = rotate(UnknownLiveness::Reject).await;
    assert!(!cookie, "an unconfirmed rotation gets no cookie");
    assert!(!row_kept, "the row under the new id is deleted");
    assert!(
        !registry
            .held
            .lock()
            .unwrap()
            .iter()
            .any(|id| *id != registry.old),
        "the new id must not stay registered"
    );
}

/// A service that accepts an unanswering registry keeps the session.
#[tokio::test]
async fn a_failed_reread_is_accepted_when_the_service_accepts_unknown() {
    let (cookie, _, row_kept) = rotate(UnknownLiveness::Accept).await;
    assert!(cookie);
    assert!(row_kept);
}
