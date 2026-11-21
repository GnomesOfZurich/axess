//! The handle's own answer for a cut-off it has no one-step form of.

use super::*;
use crate::authn::ids::UserId;
use axess_testing::mock_tracing::TracingCapture;

/// A handle that answers every call and leaves the cut-off of a user's other
/// sessions to the trait's provided body.
struct WithoutCutOff;

impl SessionRevoker for WithoutCutOff {
    fn invalidate_user<'a>(
        &'a self,
        _: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn invalidate_session<'a>(
        &'a self,
        _: &'a UserId,
        _: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevocationError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn current_key<'a>(
        &'a self,
        _: &'a UserId,
        session: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SessionKey>, RevocationError>> + Send + 'a>>
    {
        Box::pin(async move { Ok(Some(*session)) })
    }
}

impl SessionRegistryHandle for WithoutCutOff {
    fn is_valid<'a>(
        &'a self,
        _: &'a UserId,
        _: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { true })
    }

    fn liveness<'a>(
        &'a self,
        _: &'a UserId,
        _: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = SessionLiveness> + Send + 'a>> {
        Box::pin(async { SessionLiveness::Valid })
    }

    fn register<'a>(
        &'a self,
        _: &'a UserId,
        _: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { true })
    }

    fn move_session<'a>(
        &'a self,
        _: &'a UserId,
        _: &'a SessionKey,
        _: &'a SessionKey,
    ) -> Pin<Box<dyn Future<Output = Result<MoveOutcome, RevocationError>> + Send + 'a>> {
        Box::pin(async { Ok(MoveOutcome::Moved) })
    }

    fn held_sessions<'a>(
        &'a self,
        _: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SessionKey>, RevocationError>> + Send + 'a>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// The provided cut-off refuses, and its line names the session to keep by
/// the first eight characters of its key and nothing more.
#[tokio::test]
async fn the_provided_cut_off_refuses_and_names_the_kept_session_by_a_prefix() {
    let capture = TracingCapture::install();
    let keep = SessionKey::from_bytes([0x3c; 32]);
    let answer = WithoutCutOff
        .invalidate_other_sessions(&UserId::system(), &keep)
        .await;
    assert!(answer.is_err(), "{answer:?}");
    let events = capture.events();
    let refusal = events
        .iter()
        .find(|event| event.message.contains("cannot end a user's other sessions"))
        .expect("the refusal is logged");
    assert!(
        refusal.message.contains(&keep.prefix().to_string()),
        "{refusal}"
    );
    assert!(!refusal.message.contains(&keep.to_string()), "{refusal}");
}
