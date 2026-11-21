//! The agent's JWT bundles as key sets for
//! [`JwtVerifier`](axess_factors::jwt::verifier::JwtVerifier).
//!
//! A verifier is built on a shared `JwkSet`; [`JwtBundleSource::key_set`]
//! gives one for a trust domain, and the watcher rewrites it with every
//! bundle set the agent sends. Verification stays where it is, in
//! `axess-factors`; what changes is where the keys come from.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use axess_identity::TrustDomain;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};

use super::bundle::{JwtBundle, JwtBundleSet};
use super::source::JwtBundleSource;
use super::transport::TARGET;

/// The key set a `JwtVerifier` is built on.
type KeySet = Arc<RwLock<JwkSet>>;

/// The key sets handed out so far, by trust domain, and the bundle set they
/// were last written from.
#[derive(Default)]
pub(crate) struct KeySets {
    state: Mutex<KeySetsState>,
}

#[derive(Default)]
struct KeySetsState {
    /// The bundle set the watcher stored last; `None` before the first.
    latest: Option<Arc<JwtBundleSet>>,
    handed_out: BTreeMap<String, (TrustDomain, KeySet)>,
}

impl KeySets {
    /// The key set of `trust_domain`, made from the latest bundle set when
    /// it is the first request for that trust domain. The latest set and the
    /// key sets change under one lock, so a key set made here is never
    /// older than a bundle set already stored.
    fn key_set(&self, trust_domain: &TrustDomain) -> KeySet {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((_, key_set)) = state.handed_out.get(trust_domain.as_str()) {
            return key_set.clone();
        }
        let keys = state
            .latest
            .as_deref()
            .and_then(|bundles| bundles.get(trust_domain))
            .map(keys_of)
            .unwrap_or_else(no_keys);
        let key_set = Arc::new(RwLock::new(keys));
        state.handed_out.insert(
            trust_domain.as_str().to_owned(),
            (trust_domain.clone(), key_set.clone()),
        );
        key_set
    }

    /// Take `bundles` as the latest set and rewrite every key set handed out
    /// from it. A trust domain the set no longer holds is left with no keys,
    /// so its tokens stop verifying.
    pub(crate) fn replace(&self, bundles: &Arc<JwtBundleSet>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for (trust_domain, key_set) in state.handed_out.values() {
            let keys = bundles
                .get(trust_domain)
                .map(keys_of)
                .unwrap_or_else(no_keys);
            *key_set.write().unwrap_or_else(PoisonError::into_inner) = keys;
        }
        state.latest = Some(bundles.clone());
    }

    /// Forget the latest set and leave every key set handed out with no
    /// keys: the bundle set went stale, and keys the agent may have
    /// withdrawn since are not verified with.
    pub(crate) fn clear(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for (_, key_set) in state.handed_out.values() {
            *key_set.write().unwrap_or_else(PoisonError::into_inner) = no_keys();
        }
        state.latest = None;
    }
}

fn no_keys() -> JwkSet {
    JwkSet { keys: Vec::new() }
}

/// The keys of a bundle as the JOSE library reads them. A key it cannot
/// verify with is left out and logged, so one such key does not take the
/// trust domain's other keys with it: an entry that is no key at all, and
/// one the library reads as a key of a type it does not know (which is also
/// how it reads a key of a known type with a parameter missing).
fn keys_of(bundle: &JwtBundle) -> JwkSet {
    let mut keys = Vec::new();
    let listed = bundle
        .jwks()
        .get("keys")
        .and_then(serde_json::Value::as_array);
    for key in listed.into_iter().flatten() {
        match serde_json::from_value::<Jwk>(key.clone()) {
            Ok(key) if !matches!(key.algorithm, AlgorithmParameters::Other(_)) => keys.push(key),
            Ok(_) | Err(_) => tracing::warn!(
                target: TARGET,
                trust_domain = %bundle.trust_domain(),
                "a key of the JWT bundle is not one the JOSE library reads; left out",
            ),
        }
    }
    JwkSet { keys }
}

impl JwtBundleSource {
    /// The JWT signing keys of `trust_domain` as a shared key set, to build
    /// a [`JwtVerifier`](axess_factors::jwt::verifier::JwtVerifier) on. The
    /// watcher rewrites the set with every bundle set the agent sends, so a
    /// verifier built once follows the agent's key rotation.
    ///
    /// The set holds no key until the source has a bundle for the trust
    /// domain, again when the agent stops serving one, and again when the
    /// source's bundle set goes stale (the agent has not confirmed it within
    /// the client's maximum bundle age): tokens of a trust domain without
    /// keys are refused. Asking for the key set of a
    /// federated trust domain is how a deployment decides to verify that
    /// trust domain's tokens; build one verifier per trust domain, each on
    /// its own key set, so that a token is only ever checked against the
    /// keys of the trust domain it names.
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use axess_core::workload::spire::{Endpoint, SpireClient};
    /// use axess_factors::jwt::verifier::JwtVerifier;
    /// use axess_identity::TrustDomain;
    ///
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let trust_domain = TrustDomain::new("prod.example.com")?;
    /// let client = SpireClient::builder(Endpoint::from_env()?, trust_domain.clone()).build();
    /// let bundles = client.watch_jwt_bundles()?;
    /// bundles.ready().await;
    ///
    /// let verifier = Arc::new(
    ///     JwtVerifier::new(bundles.key_set(&trust_domain))
    ///         .with_issuer("https://spire.prod.example.com")
    ///         .with_audience("https://api.example.com"),
    /// );
    /// # let _ = verifier;
    /// # Ok(())
    /// # }
    /// ```
    pub fn key_set(&self, trust_domain: &TrustDomain) -> Arc<RwLock<JwkSet>> {
        self.key_sets.key_set(trust_domain)
    }
}

#[cfg(all(test, unix))]
mod tests;
