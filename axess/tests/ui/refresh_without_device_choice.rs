// A refresh says what it does about the device a token names before it can
// run: it is given the device store, or the named opt-out. One that says
// neither has no `run`, so a token that names a device is never refreshed
// unchecked by omission.
use axess_core::session::RefreshTokenStore;
use axess_core::session::refresh::{Refresh, RefreshTokenConfig};
use axess_core::{SystemRng, TenantId};
use axess_core::Timestamp;

async fn refresh<S: RefreshTokenStore>(
    store: &S,
    token: &str,
    tenant: &TenantId,
    config: &RefreshTokenConfig,
    now: Timestamp,
) -> bool {
    Refresh::new(token, tenant, |_| async { true })
        .run(store, config, &SystemRng, now)
        .await
        .is_ok()
}

fn main() {}
