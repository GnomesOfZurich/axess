//! What [`super::SessionValidator::enforce`] does with a session it refuses:
//! a signed-in session is ended through the session layer's ending
//! protocol, and on a handle no layer stands behind its record goes to the
//! validator's own sink, with the cause as the reason. Anything else is
//! refused and ends nothing.

use super::*;
use crate::authn::factor::{FactorKind, FactorStep};
use crate::session::layer::{LayerSessionEnded, SessionHandle, SessionInner};
use crate::session::store::{MemorySessionRegistry, SessionRegistry, SessionRegistryAdapter};
use std::sync::Mutex;
use tokio::sync::RwLock;

/// A sink that records what it is told.
#[derive(Default)]
struct Told(Mutex<Vec<LayerSessionEnded>>);

impl Told {
    fn reasons(&self) -> Vec<SessionEndReason> {
        self.0.lock().unwrap().iter().map(|e| e.reason).collect()
    }
}

impl SessionEndAudit for Told {
    fn session_ended<'a>(
        &'a self,
        ended: &'a LayerSessionEnded,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.0.lock().unwrap().push(ended.clone());
        Box::pin(std::future::ready(Ok(())))
    }
}

fn user() -> UserId {
    axess_identity::testing::user("u-ending")
}

fn tenant() -> TenantId {
    axess_identity::testing::tenant("t-ending")
}

fn admin() -> UserId {
    axess_identity::testing::user("admin-ending")
}

fn session() -> AuthSession {
    let inner = SessionInner::detached(Arc::new(axess_rng::SystemRng));
    AuthSession(SessionHandle(Arc::new(RwLock::new(inner))))
}

async fn signed_in(tenant: TenantId) -> AuthSession {
    let s = session();
    s.set_authenticated(
        user(),
        tenant,
        axess_clock::testing::MockClock::reference_time(),
    )
    .await;
    s
}

/// An identity store that names `0` as the user's tenant (`None`: it does
/// not know the user, or could not answer).
struct Names(Option<TenantId>);

impl IdentityHandle for Names {
    fn get_user_tenant<'a>(
        &'a self,
        _: &'a UserId,
    ) -> Pin<Box<dyn Future<Output = Option<TenantId>> + Send + 'a>> {
        Box::pin(std::future::ready(self.0))
    }
}

/// A validator over `registry`, with `identity` when given, telling `told`.
fn validator(
    registry: Option<MemorySessionRegistry>,
    identity: Option<Names>,
    told: &Arc<Told>,
) -> SessionValidator {
    SessionValidator {
        registry: registry
            .map(|r| -> Arc<dyn SessionRegistryHandle> { Arc::new(SessionRegistryAdapter(r)) }),
        identity: identity.map(|names| -> Arc<dyn IdentityHandle> { Arc::new(names) }),
        audit: told.clone(),
    }
}

/// A session the registry no longer holds, on a handle no layer stands
/// behind: the validator's own sink is told once, naming the administrator
/// of an impersonation, and the handle is a guest's.
#[tokio::test]
async fn a_revoked_session_is_recorded_once_by_the_validators_own_sink() {
    let told = Arc::new(Told::default());
    let v = validator(Some(MemorySessionRegistry::new()), None, &told);
    let s = signed_in(tenant()).await;
    let key = s.session_key().await;
    assert!(
        s.set_impersonator(admin(), axess_clock::testing::MockClock::reference_time())
            .await
    );

    assert!(!v.enforce(&s).await);

    let ended = told.0.lock().unwrap().clone();
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0].reason, SessionEndReason::NotRegistered);
    assert_eq!(ended[0].session_id, key);
    assert_eq!(ended[0].impersonator, Some(admin()));
    assert!(!s.is_authenticated().await);
    assert_ne!(
        s.session_key().await,
        key,
        "the key rotated, as `clear` does"
    );
}

/// The tenant check's ending has a reason of its own: for a user the store
/// names another tenant for, and for a user it no longer knows.
#[tokio::test]
async fn the_tenant_checks_ending_is_recorded_as_tenant_not_confirmed() {
    let other = axess_identity::testing::tenant("t-other");
    for identity in [Names(Some(other)), Names(None)] {
        let told = Arc::new(Told::default());
        let v = validator(None, Some(identity), &told);
        let s = signed_in(tenant()).await;

        assert!(!v.enforce(&s).await);

        assert_eq!(told.reasons(), vec![SessionEndReason::TenantNotConfirmed]);
        assert!(!s.is_authenticated().await);
    }
}

/// Both checks failing are named for the registry.
#[tokio::test]
async fn a_session_neither_check_confirms_is_named_for_the_registry() {
    let told = Arc::new(Told::default());
    let v = validator(Some(MemorySessionRegistry::new()), Some(Names(None)), &told);
    let s = signed_in(tenant()).await;

    assert!(!v.enforce(&s).await);

    assert_eq!(told.reasons(), vec![SessionEndReason::NotRegistered]);
}

/// A valid session, a guest and a session in a step-up that has not
/// completed pass through `enforce` with no record and no change.
#[tokio::test]
async fn the_validator_ends_nothing_else() {
    let told = Arc::new(Told::default());
    let registry = MemorySessionRegistry::new();
    let v = validator(Some(registry.clone()), None, &told);

    let valid = signed_in(tenant()).await;
    registry
        .register(&user(), &valid.session_key().await)
        .await
        .unwrap();
    let valid_key = valid.session_key().await;
    assert!(v.enforce(&valid).await);
    assert!(valid.is_authenticated().await);
    assert_eq!(valid.session_key().await, valid_key);

    let guest = session();
    let guest_key = guest.session_key().await;
    assert!(!v.enforce(&guest).await);
    assert_eq!(
        guest.session_key().await,
        guest_key,
        "a guest is not touched"
    );

    let stepping = signed_in(tenant()).await;
    assert!(
        stepping
            .0
            .0
            .write()
            .await
            .data
            .auth_state
            .begin_step_up(vec![FactorStep::Required(FactorKind::Password)])
    );
    let stepping_data = stepping.data().await;
    let stepping_key = stepping.session_key().await;
    assert!(!v.enforce(&stepping).await);
    assert_eq!(stepping.session_key().await, stepping_key);
    assert_eq!(
        serde_json::to_value(stepping.data().await).unwrap(),
        serde_json::to_value(stepping_data).unwrap(),
        "a step-up that has not completed is not touched"
    );

    assert!(told.reasons().is_empty());
}
