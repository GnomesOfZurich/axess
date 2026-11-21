//! `refresh_providers_jwks` reports every provider whose refresh did not
//! succeed, one that panicked included.

use super::*;
use crate::oauth::types::{DpopSigner, OAuthClaims, RefreshOutcome, UserInfoClaims};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How a scripted provider's refresh ends.
#[derive(Clone, Copy)]
enum Refresh {
    Succeeds,
    Fails,
    Panics,
}

/// How many refreshes are under way at once, and the most there ever were.
#[derive(Default)]
struct Gauge {
    under_way: AtomicUsize,
    peak: AtomicUsize,
}

/// A provider that only refreshes: every other operation is out of scope.
struct Scripted {
    name: Arc<str>,
    refresh: Refresh,
    scopes: Vec<String>,
    /// Counts this provider's refresh while it is under way.
    gauge: Option<Arc<Gauge>>,
}

impl Scripted {
    fn provider(name: &str, refresh: Refresh) -> Arc<dyn OAuthProvider> {
        Arc::new(Self {
            name: Arc::from(name),
            refresh,
            scopes: Vec::new(),
            gauge: None,
        })
    }

    /// A provider whose refresh succeeds after staying under way for a few
    /// turns of the scheduler, counted in `gauge` meanwhile.
    fn gauged(name: &str, gauge: &Arc<Gauge>) -> Arc<dyn OAuthProvider> {
        Arc::new(Self {
            name: Arc::from(name),
            refresh: Refresh::Succeeds,
            scopes: Vec::new(),
            gauge: Some(Arc::clone(gauge)),
        })
    }
}

type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, OAuthError>> + Send + 'a>>;

impl OAuthProvider for Scripted {
    fn name(&self) -> &Arc<str> {
        &self.name
    }

    fn scopes(&self) -> &[String] {
        &self.scopes
    }

    fn ceremony_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }

    fn binds_to_dpop(&self) -> bool {
        false
    }

    fn refresh_jwks(&self) -> Pending<'_, ()> {
        let refresh = self.refresh;
        let gauge = self.gauge.clone();
        Box::pin(async move {
            if let Some(gauge) = gauge {
                let under_way = gauge.under_way.fetch_add(1, Ordering::SeqCst) + 1;
                gauge.peak.fetch_max(under_way, Ordering::SeqCst);
                for _ in 0..3 {
                    tokio::task::yield_now().await;
                }
                gauge.under_way.fetch_sub(1, Ordering::SeqCst);
            }
            match refresh {
                Refresh::Succeeds => Ok(()),
                Refresh::Fails => Err(OAuthError::Discovery("keys unavailable".to_string())),
                Refresh::Panics => panic!("a malformed key set"),
            }
        })
    }

    fn refresh_token_unchecked<'a>(
        &'a self,
        _: &'a str,
        _: Option<&'a str>,
        _: Option<DpopSigner<'a>>,
    ) -> Pending<'a, RefreshOutcome> {
        unimplemented!("a scripted provider only refreshes its keys")
    }

    fn exchange_code<'a>(
        &'a self,
        _: &'a str,
        _: String,
        _: String,
        _: Option<DpopSigner<'a>>,
    ) -> Pending<'a, OAuthClaims> {
        unimplemented!("a scripted provider only refreshes its keys")
    }

    fn fetch_userinfo_unchecked<'a>(
        &'a self,
        _: &'a str,
        _: Option<DpopSigner<'a>>,
    ) -> Pending<'a, UserInfoClaims> {
        unimplemented!("a scripted provider only refreshes its keys")
    }
}

fn names(failures: &[(Arc<str>, OAuthError)]) -> Vec<String> {
    let mut names: Vec<String> = failures.iter().map(|(name, _)| name.to_string()).collect();
    names.sort();
    names
}

/// An empty result means every refresh succeeded, so a provider whose refresh
/// panicked is in it, beside the one that returned an error.
#[tokio::test]
async fn refresh_providers_jwks_reports_a_panicking_provider() {
    let providers = [
        Scripted::provider("ok", Refresh::Succeeds),
        Scripted::provider("boom", Refresh::Panics),
        Scripted::provider("bad", Refresh::Fails),
    ];

    let failures = refresh_providers_jwks(&providers).await;

    assert_eq!(names(&failures), ["bad", "boom"]);
}

/// More providers than the pass runs at once, and a panic among them, still
/// reports exactly the ones that failed.
#[tokio::test]
async fn a_panic_beyond_the_first_batch_is_reported_too() {
    let mut providers: Vec<Arc<dyn OAuthProvider>> = (0..JWKS_REFRESH_CONCURRENCY + 4)
        .map(|i| Scripted::provider(&format!("ok-{i}"), Refresh::Succeeds))
        .collect();
    providers.insert(
        JWKS_REFRESH_CONCURRENCY + 2,
        Scripted::provider("late-boom", Refresh::Panics),
    );

    let failures = refresh_providers_jwks(&providers).await;

    assert_eq!(names(&failures), ["late-boom"]);
}

#[tokio::test]
async fn a_pass_over_healthy_providers_reports_nothing() {
    let providers = [
        Scripted::provider("one", Refresh::Succeeds),
        Scripted::provider("two", Refresh::Succeeds),
    ];

    assert!(refresh_providers_jwks(&providers).await.is_empty());
}

/// A pass refreshes as many providers at once as its bound says, and never
/// one more.
#[tokio::test]
async fn a_pass_runs_as_many_refreshes_at_once_as_its_bound_and_no_more() {
    let gauge = Arc::new(Gauge::default());
    let providers: Vec<Arc<dyn OAuthProvider>> = (0..3 * JWKS_REFRESH_CONCURRENCY)
        .map(|i| Scripted::gauged(&format!("p-{i}"), &gauge))
        .collect();

    assert!(refresh_providers_jwks(&providers).await.is_empty());

    assert_eq!(gauge.peak.load(Ordering::SeqCst), JWKS_REFRESH_CONCURRENCY);
    assert_eq!(gauge.under_way.load(Ordering::SeqCst), 0);
}

/// A provider's name may be a tenant's text: every line a pass writes about
/// a provider carries it escaped, whether its refresh succeeded, failed or
/// panicked.
#[tokio::test]
async fn a_provider_name_reaches_the_log_escaped() {
    let capture = axess_testing::mock_tracing::TracingCapture::install();
    let forged = "acme\nWARN forged\u{202E}";
    let providers = [
        Scripted::provider(forged, Refresh::Succeeds),
        Scripted::provider(forged, Refresh::Fails),
        Scripted::provider(forged, Refresh::Panics),
    ];

    let failures = refresh_providers_jwks(&providers).await;

    assert_eq!(failures.len(), 2);
    let events = capture.events();
    assert!(events.len() >= 3, "{events:?}");
    for event in events {
        assert!(
            !event.message.chars().any(crate::log_text::escapes),
            "{:?}",
            event.message
        );
    }
}
