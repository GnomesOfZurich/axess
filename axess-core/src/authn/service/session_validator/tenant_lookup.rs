//! The tenant cross-check asks the identity store for the user's tenant
//! only, never for the whole user.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::authn::ids::{TenantId, UserId};
use crate::authn::types::{EntityState, Tenant, User};
use crate::session::data::SessionData;
use crate::session::extractor::AuthSession;
use crate::session::layer::{SessionHandle, SessionInner};
use tokio::sync::RwLock;

/// A lookup whose `get_user` must not be called: only the narrow tenant
/// projection is implemented.
struct TenantOnly {
    tenant: TenantId,
    tenant_calls: AtomicUsize,
}

impl IdentityLookup for TenantOnly {
    type Error = Infallible;

    async fn find_user(&self, _: &str, _: &TenantId) -> Result<Option<User>, Infallible> {
        unreachable!("not used by the validator")
    }
    async fn get_user(&self, _: &UserId) -> Result<Option<User>, Infallible> {
        unreachable!("the tenant cross-check must not load the whole user")
    }
    async fn get_user_tenant(&self, _: &UserId) -> Result<Option<TenantId>, Infallible> {
        self.tenant_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.tenant))
    }
    async fn get_tenant(&self, _: &TenantId) -> Result<Option<Tenant>, Infallible> {
        unreachable!("not used by the validator")
    }
    async fn find_tenant(&self, _: &str) -> Result<Option<Tenant>, Infallible> {
        unreachable!("not used by the validator")
    }
    async fn default_tenant(&self) -> Result<Tenant, Infallible> {
        unreachable!("not used by the validator")
    }
    async fn account_status(&self, _: &UserId) -> Result<EntityState, Infallible> {
        unreachable!("not used by the validator")
    }
}

async fn session_in(tenant: TenantId) -> AuthSession {
    let inner = SessionInner {
        id: crate::session::id::SessionId::new(&axess_rng::SystemRng),
        data: SessionData::default(),
        modified: false,
        needs_persist: false,
        regenerate: false,
        pre_cycle_id: None,
        rng: std::sync::Arc::new(axess_rng::SystemRng),
        pending_fingerprint: None,
        max_custom_bytes: 64 * 1024,
        consume: None,
    };
    let session = AuthSession(SessionHandle(Arc::new(RwLock::new(inner))));
    session
        .set_authenticated(
            axess_identity::testing::user("u"),
            tenant,
            chrono::Utc::now(),
        )
        .await;
    session
}

#[tokio::test]
async fn the_cross_check_reads_only_the_tenant() {
    let tenant = axess_identity::testing::tenant("t");
    let store = Arc::new(TenantOnly {
        tenant,
        tenant_calls: AtomicUsize::new(0),
    });
    let validator = SessionValidator {
        registry: None,
        identity: Some(Arc::new(IdentityWrapper(store.clone()))),
    };

    assert!(validator.is_valid(&session_in(tenant).await).await);
    assert_eq!(store.tenant_calls.load(Ordering::SeqCst), 1);

    let other = axess_identity::testing::tenant("other");
    assert!(
        !validator.is_valid(&session_in(other).await).await,
        "a session stating another tenant is invalid"
    );
}
