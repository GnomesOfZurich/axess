//! Sources: what the agent serves, kept current, and read without waiting.
//!
//! Each source is a handle on a watcher ([`super::watcher`] has the rules
//! the watcher follows). Reading one is a clone of an `Arc`.

use std::sync::Arc;

use axess_clock::Clock;
use axess_clock::{SignedDuration, Timestamp};
use zeroize::Zeroizing;

use super::bundle::{JwtBundleSet, X509BundleSet};
use super::client::ClientInner;
use super::error::SpireError;
use super::feed::{JwtBundleFeed, JwtSvidFeed, X509BundleFeed, X509Feed};
use super::svid::{JwtSvid, X509Context, X509Svid};
use super::watcher::{Handle, Lifetime};
use crate::metrics::WorkloadCredentialKind;

/// The client's maximum bundle age, as the clock counts it.
fn bundle_age(inner: &ClientInner) -> SignedDuration {
    SignedDuration::try_from(inner.max_bundle_age).unwrap_or(SignedDuration::MAX)
}

/// Gives the X.509 bundles a verifier checks a peer against, as they are
/// now. Implemented by [`X509Source`] and [`X509BundleSource`], which follow
/// the agent, and by a fixed [`X509BundleSet`] behind an `Arc`.
pub trait X509BundleProvider: Send + Sync + 'static {
    /// The bundle set as it is now.
    fn x509_bundles(&self) -> Result<Arc<X509BundleSet>, SpireError>;
}

impl X509BundleProvider for Arc<X509BundleSet> {
    fn x509_bundles(&self) -> Result<Arc<X509BundleSet>, SpireError> {
        Ok(self.clone())
    }
}

/// The workload's X.509 SVID and the bundles that came with it, kept
/// current by a watcher on `FetchX509SVID`.
///
/// Cheap to clone; the watcher stops when the last clone is dropped. A read
/// never waits for the agent: it returns what the watcher last accepted, or
/// says why there is nothing to return ([`SpireError::NotYetFetched`]
/// before the first answer, [`SpireError::Expired`] once the SVID's
/// `notAfter` has passed on the client's clock with no replacement).
///
/// The SVID is served until it expires. The bundles that came with it are
/// held to the bound of every bundle set: once the agent has not confirmed
/// them within the client's maximum bundle age, [`bundles`](Self::bundles)
/// and [`context`](Self::context) answer [`SpireError::Stale`], and
/// [`svid`](Self::svid) goes on answering.
#[derive(Clone)]
pub struct X509Source {
    handle: Handle<X509Context>,
    bundle_age: SignedDuration,
}

impl X509Source {
    pub(crate) fn start(inner: Arc<ClientInner>, feed: X509Feed) -> Result<Self, SpireError> {
        let bundle_age = bundle_age(&inner);
        Ok(Self {
            handle: Handle::start(
                inner,
                feed,
                Lifetime::Own(|context: &X509Context| context.svid().not_after()),
            )?,
            bundle_age,
        })
    }

    /// The current SVID.
    pub fn svid(&self) -> Result<Arc<X509Svid>, SpireError> {
        Ok(self.handle.current()?.svid().clone())
    }

    /// What the slot holds, unless its bundles have gone unconfirmed for
    /// the maximum bundle age.
    fn confirmed(&self) -> Result<Arc<X509Context>, SpireError> {
        let (context, confirmed_at) = self.handle.current_confirmed()?;
        let end = confirmed_at.and_then(|at| at.checked_add(self.bundle_age));
        if end.is_none_or(|end| self.handle.clock().now() >= end) {
            return Err(SpireError::Stale(WorkloadCredentialKind::X509Bundles));
        }
        Ok(context)
    }

    /// The current SVID with everything that came with it. The other SVIDs
    /// of the context are checked against the clock at each read, as the
    /// current one is: one that has expired is not in it. A context whose
    /// bundles are stale is not served.
    pub fn context(&self) -> Result<Arc<X509Context>, SpireError> {
        let context = self.confirmed()?;
        Ok(match context.without_expired(self.handle.clock().now()) {
            Some(unexpired) => Arc::new(unexpired),
            None => context,
        })
    }

    /// The bundles that came with the current SVID: the workload's own
    /// trust domain and those federated with it.
    pub fn bundles(&self) -> Result<Arc<X509BundleSet>, SpireError> {
        Ok(self.confirmed()?.bundles().clone())
    }

    /// When the agent last sent what the source holds, or sent it again:
    /// the instant the maximum bundle age of its bundles is counted from.
    pub fn confirmed_at(&self) -> Option<Timestamp> {
        self.handle.confirmed_at()
    }

    /// Wait until the source holds an SVID.
    pub async fn ready(&self) {
        self.handle.ready().await;
    }

    /// How many times the source has changed: every rotation and every
    /// expiry counts one.
    pub fn generation(&self) -> u64 {
        self.handle.generation()
    }

    /// Wait until the source has changed more than `after` times, and
    /// return the count.
    pub async fn updated(&self, after: u64) -> u64 {
        self.handle.updated(after).await
    }

    /// Whether the watcher is running; `false` only if its task panicked.
    pub fn is_watching(&self) -> bool {
        self.handle.is_watching()
    }

    /// The clock the source judges expiry by.
    #[cfg(feature = "outbound-mtls")]
    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        self.handle.clock()
    }
}

impl std::fmt::Debug for X509Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509Source")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl X509BundleProvider for X509Source {
    fn x509_bundles(&self) -> Result<Arc<X509BundleSet>, SpireError> {
        self.bundles()
    }
}

/// The X.509 bundles the agent serves, kept current by a watcher on
/// `FetchX509Bundles`.
///
/// A bundle set has no expiry of its own, so the source bounds how long it
/// serves one the agent has stopped confirming: past the client's maximum
/// bundle age a read answers [`SpireError::Stale`], and verification built
/// on the source fails closed until the agent answers again. The watcher
/// confirms the set well inside that age, on a second request beside the
/// open stream, which is also how a stream that has stalled is found out.
#[derive(Clone)]
pub struct X509BundleSource {
    handle: Handle<X509BundleSet>,
}

impl X509BundleSource {
    pub(crate) fn start(inner: Arc<ClientInner>, feed: X509BundleFeed) -> Result<Self, SpireError> {
        let lifetime = Lifetime::Confirmed(bundle_age(&inner));
        Ok(Self {
            handle: Handle::start(inner, feed, lifetime)?,
        })
    }

    /// The current bundle set.
    pub fn bundles(&self) -> Result<Arc<X509BundleSet>, SpireError> {
        self.handle.current()
    }

    /// Wait until the source holds a bundle set.
    pub async fn ready(&self) {
        self.handle.ready().await;
    }

    /// How many times the bundle set has changed: every new set, and the
    /// set going stale, counts one.
    pub fn generation(&self) -> u64 {
        self.handle.generation()
    }

    /// When the agent last sent the set the source holds, or sent it
    /// again: the instant the maximum bundle age is counted from.
    pub fn confirmed_at(&self) -> Option<Timestamp> {
        self.handle.confirmed_at()
    }

    /// Wait until the set has changed more than `after` times, and return
    /// the count.
    pub async fn updated(&self, after: u64) -> u64 {
        self.handle.updated(after).await
    }

    /// Whether the watcher is running; `false` only if its task panicked.
    pub fn is_watching(&self) -> bool {
        self.handle.is_watching()
    }
}

impl std::fmt::Debug for X509BundleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509BundleSource")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl X509BundleProvider for X509BundleSource {
    fn x509_bundles(&self) -> Result<Arc<X509BundleSet>, SpireError> {
        self.bundles()
    }
}

/// The JWT bundles the agent serves, kept current by a watcher on
/// `FetchJWTBundles`.
///
/// As with the X.509 bundles, a set the agent has not confirmed within the
/// client's maximum bundle age is no longer served: a read answers
/// [`SpireError::Stale`], and the key sets made from the source are emptied
/// until the agent answers again.
#[derive(Clone)]
pub struct JwtBundleSource {
    handle: Handle<JwtBundleSet>,
    /// The key sets handed to verifiers; the watcher's feed holds the same.
    #[cfg(feature = "jwt")]
    pub(crate) key_sets: Arc<super::jwks::KeySets>,
}

impl JwtBundleSource {
    pub(crate) fn start(inner: Arc<ClientInner>, feed: JwtBundleFeed) -> Result<Self, SpireError> {
        #[cfg(feature = "jwt")]
        let key_sets = feed.key_sets.clone();
        let lifetime = Lifetime::Confirmed(bundle_age(&inner));
        Ok(Self {
            handle: Handle::start(inner, feed, lifetime)?,
            #[cfg(feature = "jwt")]
            key_sets,
        })
    }

    /// The current bundle set.
    pub fn bundles(&self) -> Result<Arc<JwtBundleSet>, SpireError> {
        self.handle.current()
    }

    /// Wait until the source holds a bundle set.
    pub async fn ready(&self) {
        self.handle.ready().await;
    }

    /// How many times the bundle set has changed: every new set, and the
    /// set going stale, counts one.
    pub fn generation(&self) -> u64 {
        self.handle.generation()
    }

    /// When the agent last sent the set the source holds, or sent it
    /// again: the instant the maximum bundle age is counted from.
    pub fn confirmed_at(&self) -> Option<Timestamp> {
        self.handle.confirmed_at()
    }

    /// Wait until the set has changed more than `after` times, and return
    /// the count.
    pub async fn updated(&self, after: u64) -> u64 {
        self.handle.updated(after).await
    }

    /// Whether the watcher is running; `false` only if its task panicked.
    pub fn is_watching(&self) -> bool {
        self.handle.is_watching()
    }
}

impl std::fmt::Debug for JwtBundleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtBundleSource")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

/// A JWT SVID for one audience, kept current by a watcher that asks
/// `FetchJWTSVID` again at each refresh point.
///
/// Cheap to clone; the watcher stops when the last clone is dropped. A read
/// never waits for the agent, and never returns a token past its `exp` on
/// the client's clock.
#[derive(Clone)]
pub struct JwtSvidSource {
    handle: Handle<JwtSvid>,
}

impl JwtSvidSource {
    pub(crate) fn start(inner: Arc<ClientInner>, feed: JwtSvidFeed) -> Result<Self, SpireError> {
        Ok(Self {
            handle: Handle::start(inner, feed, Lifetime::Own(JwtSvid::expires_at))?,
        })
    }

    /// The current SVID.
    pub fn svid(&self) -> Result<Arc<JwtSvid>, SpireError> {
        self.handle.current()
    }

    /// The current token, to present as a bearer credential. The copy is
    /// wiped when it is dropped.
    pub fn token(&self) -> Result<Zeroizing<String>, SpireError> {
        Ok(Zeroizing::new(self.svid()?.token().to_owned()))
    }

    /// Wait until the source holds an SVID.
    pub async fn ready(&self) {
        self.handle.ready().await;
    }

    /// How many times the source has changed: every rotation and every
    /// expiry counts one.
    pub fn generation(&self) -> u64 {
        self.handle.generation()
    }

    /// Wait until the source has changed more than `after` times, and
    /// return the count.
    pub async fn updated(&self, after: u64) -> u64 {
        self.handle.updated(after).await
    }

    /// Whether the watcher is running; `false` only if its task panicked.
    pub fn is_watching(&self) -> bool {
        self.handle.is_watching()
    }
}

impl std::fmt::Debug for JwtSvidSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSvidSource")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}
