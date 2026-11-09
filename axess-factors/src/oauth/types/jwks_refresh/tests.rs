//! `refresh_providers_jwks` reports every provider whose refresh did not
//! succeed, one that panicked included.

use super::*;
use crate::oauth::types::{DpopSigner, OAuthClaims, RefreshOutcome, UserInfoClaims};
use std::future::Future;
use std::pin::Pin;

/// How a scripted provider's refresh ends.
#[derive(Clone, Copy)]
enum Refresh {
    Succeeds,
    Fails,
    Panics,
}

/// A provider that only refreshes: every other operation is out of scope.
struct Scripted {
    name: Arc<str>,
    refresh: Refresh,
    scopes: Vec<String>,
}

impl Scripted {
    fn provider(name: &str, refresh: Refresh) -> Arc<dyn OAuthProvider> {
        Arc::new(Self {
            name: Arc::from(name),
            refresh,
            scopes: Vec::new(),
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
        Box::pin(async move {
            match refresh {
                Refresh::Succeeds => Ok(()),
                Refresh::Fails => Err(OAuthError::Discovery("keys unavailable".to_string())),
                Refresh::Panics => panic!("a malformed key set"),
            }
        })
    }

    fn refresh_token_unchecked<'a>(
        &'a self,
        _refresh_token: &'a str,
        _original_nonce: Option<&'a str>,
        _dpop: Option<DpopSigner<'a>>,
    ) -> Pending<'a, RefreshOutcome> {
        unimplemented!("a scripted provider only refreshes its keys")
    }

    fn exchange_code<'a>(
        &'a self,
        _code: &'a str,
        _pkce_verifier: String,
        _nonce: String,
        _dpop: Option<DpopSigner<'a>>,
    ) -> Pending<'a, OAuthClaims> {
        unimplemented!("a scripted provider only refreshes its keys")
    }

    fn fetch_userinfo_unchecked<'a>(
        &'a self,
        _access_token: &'a str,
        _dpop: Option<DpopSigner<'a>>,
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
