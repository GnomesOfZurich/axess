//! A login whose records the sid store cannot write is refused, as a login
//! the session registry cannot register is: no Authenticated session, no
//! registry entry, no record in the sid store, no `Authenticated` row, and
//! the mapping it would have displaced still in place.

use super::super::helpers::compute_claim_lock;
use crate::authn::error::AuthnError;
use crate::authn::event::AuthEventType;
use crate::authn::ids::{TenantId, UserId};
use crate::authn::service::AuthnService;
use crate::federation::sid_map::{DisplacedSid, SidEntry, SidKey, SidMap};
use crate::federation::sid_store::{SidFuture, SidStore, SidStoreError};
use crate::session::id::SessionKey;
use crate::session::{MemorySessionRegistry, store::SessionRegistry};
use crate::testing::{
    mock_authn::{MockFactorStore, MockIdentityStore},
    tenant_record_at, test_session, user_record_at,
};
use axess_clock::Timestamp;
use axess_factors::oauth::{OAuthClaims, types::keys as oauth_keys};
use std::sync::{Arc, Mutex};

/// The one write of the store that fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Write {
    Subject,
    Mapping,
}

/// A sid store that fails the write it is armed with and hands every other
/// call to an in-process map.
struct FailingSid {
    inner: SidMap,
    armed: Mutex<Option<Write>>,
}

impl FailingSid {
    fn fails(&self, write: Write) -> bool {
        *self.armed.lock().unwrap() == Some(write)
    }
}

fn down<'a, T: Send + 'a>() -> SidFuture<'a, T> {
    Box::pin(async { Err(SidStoreError("the sid store is down".to_string())) })
}

impl SidStore for FailingSid {
    fn insert_displacing<'a>(
        &'a self,
        key: SidKey,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
        inserted_at: Timestamp,
    ) -> SidFuture<'a, Option<DisplacedSid>> {
        if self.fails(Write::Mapping) {
            return down();
        }
        SidStore::insert_displacing(
            &self.inner,
            key,
            subject,
            tenant,
            user,
            session,
            inserted_at,
        )
    }

    fn restore_if_vacant(&self, key: SidKey, displaced: DisplacedSid) -> SidFuture<'_, bool> {
        SidStore::restore_if_vacant(&self.inner, key, displaced)
    }

    fn get<'a>(
        &'a self,
        key: &'a SidKey,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>> {
        SidStore::get(&self.inner, key, scope)
    }

    fn remove_if_session<'a>(
        &'a self,
        key: &'a SidKey,
        session: &'a SessionKey,
    ) -> SidFuture<'a, Option<SidEntry>> {
        SidStore::remove_if_session(&self.inner, key, session)
    }

    fn register_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
    ) -> SidFuture<'a, ()> {
        if self.fails(Write::Subject) {
            return down();
        }
        SidStore::register_subject_session(&self.inner, issuer, subject, tenant, user, session)
    }

    fn forget_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        user: &'a UserId,
        session: &'a SessionKey,
    ) -> SidFuture<'a, bool> {
        SidStore::forget_subject_session(&self.inner, issuer, user, session)
    }

    fn subject_sessions<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionKey)>> {
        SidStore::subject_sessions(&self.inner, issuer, subject, scope)
    }

    fn sweep_subject_candidates(
        &self,
        max: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionKey)>> {
        SidStore::sweep_subject_candidates(&self.inner, max)
    }

    fn remove_session<'a>(&'a self, session: &'a SessionKey) -> SidFuture<'a, usize> {
        SidStore::remove_session(&self.inner, session)
    }

    fn evict_inserted_before(
        &self,
        cutoff: Timestamp,
        max: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        SidStore::evict_inserted_before(&self.inner, cutoff, max)
    }

    fn evict_oldest(&self, max: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        SidStore::evict_oldest(&self.inner, max)
    }

    fn mapping_count(&self) -> SidFuture<'_, usize> {
        SidStore::mapping_count(&self.inner)
    }
}

fn claims() -> OAuthClaims {
    OAuthClaims {
        provider: "test".into(),
        subject: "external-sub".into(),
        email: None,
        email_verified: None,
        name: None,
        groups: vec![],
        roles: vec![],
        access_token: None,
        refresh_token: None,
        oidc_sid: Some("idp-sid-1".to_string()),
        id_token_hint: None,
        additional_claims: serde_json::Value::Null,
        nonce: None,
        dpop_key: None,
    }
}

/// One user logs in with the store working, mapping `idp-sid-1`; the store
/// then fails `write`, and a second user's login under the same `sid` is
/// refused. Every check of what that refusal leaves is made here.
async fn a_second_login_against_a_failing(write: Write) {
    let at = axess_clock::testing::MockClock::reference_time();
    let (first, second) = (
        user_record_at("u1", "t1", at),
        user_record_at("u2", "t1", at),
    );
    let identity = MockIdentityStore::new()
        .with_tenant(tenant_record_at("t1", at))
        .with_user(first.clone())
        .with_user(second.clone());
    let registry = MemorySessionRegistry::new();
    let store = Arc::new(FailingSid {
        inner: SidMap::new(),
        armed: Mutex::new(None),
    });
    let svc = AuthnService::builder(identity.clone(), MockFactorStore::new())
        .with_registry(registry.clone())
        .with_sid_store(store.clone())
        .build();
    let req = svc.with_audit_context(crate::authn::event::AuditContext::default());
    let c = claims();

    let first_session = test_session();
    let lock = compute_claim_lock("test", &c.subject, &first_session).await;
    first_session
        .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
        .await;
    req.complete_oauth_login(&first, &c, &first_session)
        .await
        .expect("the first login, with the store working");
    let first_key = first_session.session_key().await;
    let sid_key = ("test".to_string(), "idp-sid-1".to_string());
    let mapped = store.inner.get(&sid_key).expect("mapped after the login");

    *store.armed.lock().unwrap() = Some(write);
    let second_session = test_session();
    let lock = compute_claim_lock("test", &c.subject, &second_session).await;
    second_session
        .set_custom(oauth_keys::CLAIM_LOCK, serde_json::Value::String(lock))
        .await;
    let second_key = second_session.session_key().await;
    let res = req.complete_oauth_login(&second, &c, &second_session).await;

    assert!(
        matches!(res, Err(AuthnError::NoFlow)),
        "{write:?}: the login is refused as a failed registration is: {res:?}"
    );
    assert!(
        !second_session.is_authenticated().await,
        "{write:?}: the session is a guest"
    );
    assert!(
        registry
            .active_sessions(&second.id)
            .await
            .unwrap()
            .is_empty(),
        "{write:?}: the registry holds no entry for the refused login"
    );
    assert!(
        !registry.is_valid(&second.id, &second_key).await.unwrap(),
        "{write:?}: the refused session is not valid"
    );
    let listed = store.inner.subject_sessions("test", "external-sub");
    assert_eq!(
        listed,
        vec![(first.id, first_key)],
        "{write:?}: the store holds no record of the refused session"
    );
    let still = store.inner.get(&sid_key).expect("the mapping stays");
    assert_eq!(
        (still.0, still.1, still.2),
        (mapped.0, mapped.1, mapped.2),
        "{write:?}: the first login's mapping is in place"
    );
    assert!(
        registry.is_valid(&first.id, &first_key).await.unwrap(),
        "{write:?}: the first login's session is not ended"
    );
    let authenticated = identity
        .events()
        .iter()
        .filter(|e| e.event_type == AuthEventType::Authenticated)
        .count();
    assert_eq!(
        authenticated, 1,
        "{write:?}: only the first login wrote an Authenticated row"
    );
}

/// The subject record is the login's first write: when it fails, the login
/// is refused before anything is taken out of the map.
#[tokio::test]
async fn a_login_whose_subject_record_is_not_written_is_refused() {
    a_second_login_against_a_failing(Write::Subject).await;
}

/// The `sid` mapping is written after the subject record: when it fails, the
/// login is refused and the subject record it left goes with it.
#[tokio::test]
async fn a_login_whose_sid_mapping_is_not_written_is_refused() {
    a_second_login_against_a_failing(Write::Mapping).await;
}
