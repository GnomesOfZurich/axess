//! The refresh ticker under a stall: one run after unblocking, not one per
//! missed tick.

use super::spawn_refresh_loop;
use axess_factors::oauth::{
    DpopSigner, OAuthClaims, OAuthError, OAuthProvider, RefreshOutcome, UserInfoClaims,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

/// A provider whose `refresh_jwks` counts its runs and, while `blocked`,
/// waits for `gate`.
struct Counting {
    name: Arc<str>,
    runs: Arc<AtomicUsize>,
    blocked: Arc<AtomicBool>,
    gate: Arc<Notify>,
}

impl OAuthProvider for Counting {
    fn name(&self) -> &Arc<str> {
        &self.name
    }
    fn scopes(&self) -> &[String] {
        &[]
    }
    fn ceremony_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
    fn binds_to_dpop(&self) -> bool {
        false
    }
    fn refresh_token_unchecked<'a>(
        &'a self,
        _refresh_token: &'a str,
        _original_nonce: Option<&'a str>,
        _dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<RefreshOutcome, OAuthError>> + Send + 'a>> {
        Box::pin(async { Err(OAuthError::Config("counting".into())) })
    }
    fn exchange_code<'a>(
        &'a self,
        _code: &'a str,
        _pkce_verifier: String,
        _nonce: String,
        _dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<OAuthClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async { Err(OAuthError::Config("counting".into())) })
    }
    fn fetch_userinfo_unchecked<'a>(
        &'a self,
        _access_token: &'a str,
        _dpop: Option<DpopSigner<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<UserInfoClaims, OAuthError>> + Send + 'a>> {
        Box::pin(async { Err(OAuthError::Config("counting".into())) })
    }
    fn refresh_jwks<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthError>> + Send + 'a>> {
        Box::pin(async move {
            self.runs.fetch_add(1, Ordering::SeqCst);
            if self.blocked.load(Ordering::SeqCst) {
                self.gate.notified().await;
            }
            Ok(())
        })
    }
}

/// A refresh that stalls across five intervals is followed by exactly one
/// run once it is unblocked (the one tick that was due), then the normal
/// spacing resumes; the five missed ticks do not fire back to back against
/// the IdP.
#[tokio::test(start_paused = true)]
async fn a_stall_across_five_intervals_is_followed_by_one_run_not_five() {
    let runs = Arc::new(AtomicUsize::new(0));
    let blocked = Arc::new(AtomicBool::new(true));
    let gate = Arc::new(Notify::new());
    let provider: Arc<dyn OAuthProvider> = Arc::new(Counting {
        name: Arc::from("counting"),
        runs: runs.clone(),
        blocked: blocked.clone(),
        gate: gate.clone(),
    });
    let interval = Duration::from_secs(10);
    let _loop = spawn_refresh_loop(move || vec![provider.clone()], interval);

    tokio::time::sleep(interval + Duration::from_millis(1)).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "the first run started and is blocked"
    );

    tokio::time::sleep(interval * 5).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "still blocked, nothing else ran"
    );

    blocked.store(false, Ordering::SeqCst);
    gate.notify_one();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "exactly one run follows the stall, not one per missed tick"
    );
    tokio::time::sleep(interval / 2).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "and the spacing is the interval again"
    );

    tokio::time::sleep(interval).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        3,
        "the next run is one interval later"
    );
}
