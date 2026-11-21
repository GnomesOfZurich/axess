//! Feeds: the four things a watcher can keep current, each with the method
//! that serves it and the check an answer has to pass.

use std::sync::Arc;

use axess_clock::Timestamp;
use axess_identity::WorkloadId;

use super::bundle::{JwtBundleSet, SkippedBundle, X509BundleSet};
use super::client::{ClientInner, admit_jwt_response, jwt_request};
use super::error::SpireError;
use super::proto;
use super::svid::{JwtSvid, X509Context, admit_x509};
use crate::metrics::WorkloadCredentialKind;

/// One kind of thing a watcher keeps current: how it is asked for, how an
/// answer is checked, and what about it the watcher needs to know.
pub(crate) trait Feed: Send + Sync + 'static {
    /// What the slot holds.
    type Item: Send + Sync + 'static;
    /// The label of the feed's counters.
    const KIND: WorkloadCredentialKind;
    /// The Workload API method.
    const METHOD: &'static str;
    /// Whether the method streams, or answers once and is asked again.
    const STREAMING: bool;
    /// The kind of the bundles an item carries beside something that
    /// expires by itself, as an X.509 context does. Such bundles are served
    /// for the maximum bundle age after the agent last confirmed them,
    /// whatever the validity of the SVID they came with.
    const CARRIED_BUNDLES: Option<WorkloadCredentialKind> = None;

    /// The request message.
    fn request(&self, inner: &ClientInner) -> Vec<u8>;
    /// Check one answer and make an item of it.
    fn admit(&self, inner: &ClientInner, message: &[u8]) -> Result<Self::Item, SpireError>;
    /// The validity of an item that expires by itself: from when, until
    /// when, with the start never after the end. `None` for a bundle set,
    /// which is served for the client's maximum bundle age after the agent
    /// last confirmed it.
    fn validity(item: &Self::Item) -> Option<(Timestamp, Timestamp)>;
    /// Whether the agent sent again what the slot already holds.
    fn unchanged(held: &Self::Item, sent: &Self::Item) -> bool;
    /// The SPIFFE ID of an SVID, for the event.
    fn spiffe_id(item: &Self::Item) -> Option<&WorkloadId>;
    /// How many trust domains the item carries bundles for, for the event.
    fn trust_domains(item: &Self::Item) -> usize;
    /// The bundle entries left out of the item because they did not read.
    fn skipped(item: &Self::Item) -> &[SkippedBundle];
    /// Called with an item just before the slot takes it, so that whatever
    /// the feed keeps beside the slot has changed by the time readers
    /// waiting for the change are woken.
    fn stored(&self, item: &Arc<Self::Item>) {
        let _ = item;
    }
    /// Called when the slot was emptied because what it held expired or
    /// went stale, so that whatever the feed keeps beside the slot stops
    /// being served with it.
    fn lost(&self) {}
}

/// The feed of [`X509Source`](super::X509Source): `FetchX509SVID`.
pub(crate) struct X509Feed;

impl Feed for X509Feed {
    type Item = X509Context;
    const KIND: WorkloadCredentialKind = WorkloadCredentialKind::X509Svid;
    const METHOD: &'static str = proto::FETCH_X509_SVID;
    const STREAMING: bool = true;
    const CARRIED_BUNDLES: Option<WorkloadCredentialKind> =
        Some(WorkloadCredentialKind::X509Bundles);

    fn request(&self, _: &ClientInner) -> Vec<u8> {
        Vec::new()
    }

    fn admit(&self, inner: &ClientInner, message: &[u8]) -> Result<X509Context, SpireError> {
        admit_x509(
            proto::decode_x509_svid_response(message)?,
            &inner.trust_domain,
            &inner.selector,
            inner.clock.now(),
        )
    }

    fn validity(item: &X509Context) -> Option<(Timestamp, Timestamp)> {
        Some((item.svid().not_before(), item.svid().not_after()))
    }

    fn unchanged(held: &X509Context, sent: &X509Context) -> bool {
        // Everything a reader can see: which SVID is the chosen one, every
        // SVID's certificates and hint, and the bundles. A rotation of an
        // SVID the selector did not choose is a change, and so is a hint
        // that moved, which may move the choice with it.
        held.selected() == sent.selected()
            && held.svids().len() == sent.svids().len()
            && held.svids().iter().zip(sent.svids()).all(|(held, sent)| {
                held.cert_chain() == sent.cert_chain() && held.hint() == sent.hint()
            })
            && held.bundles() == sent.bundles()
    }

    fn spiffe_id(item: &X509Context) -> Option<&WorkloadId> {
        Some(item.svid().spiffe_id())
    }

    fn trust_domains(item: &X509Context) -> usize {
        item.bundles().len()
    }

    fn skipped(item: &X509Context) -> &[SkippedBundle] {
        item.bundles().skipped()
    }
}

/// The feed of [`X509BundleSource`](super::X509BundleSource): `FetchX509Bundles`.
pub(crate) struct X509BundleFeed;

impl Feed for X509BundleFeed {
    type Item = X509BundleSet;
    const KIND: WorkloadCredentialKind = WorkloadCredentialKind::X509Bundles;
    const METHOD: &'static str = proto::FETCH_X509_BUNDLES;
    const STREAMING: bool = true;

    fn request(&self, _: &ClientInner) -> Vec<u8> {
        Vec::new()
    }

    fn admit(&self, inner: &ClientInner, message: &[u8]) -> Result<X509BundleSet, SpireError> {
        X509BundleSet::from_raw(
            proto::decode_x509_bundles_response(message)?,
            &inner.trust_domain,
            inner.clock.now(),
        )
    }

    fn validity(_: &X509BundleSet) -> Option<(Timestamp, Timestamp)> {
        None
    }

    fn unchanged(held: &X509BundleSet, sent: &X509BundleSet) -> bool {
        held == sent
    }

    fn spiffe_id(_: &X509BundleSet) -> Option<&WorkloadId> {
        None
    }

    fn trust_domains(item: &X509BundleSet) -> usize {
        item.len()
    }

    fn skipped(item: &X509BundleSet) -> &[SkippedBundle] {
        item.skipped()
    }
}

/// The feed of [`JwtBundleSource`](super::JwtBundleSource): `FetchJWTBundles`.
#[derive(Default)]
pub(crate) struct JwtBundleFeed {
    /// The key sets handed to verifiers, rewritten with every bundle set.
    #[cfg(feature = "jwt")]
    pub(crate) key_sets: Arc<super::jwks::KeySets>,
}

impl Feed for JwtBundleFeed {
    type Item = JwtBundleSet;
    const KIND: WorkloadCredentialKind = WorkloadCredentialKind::JwtBundles;
    const METHOD: &'static str = proto::FETCH_JWT_BUNDLES;
    const STREAMING: bool = true;

    fn request(&self, _: &ClientInner) -> Vec<u8> {
        Vec::new()
    }

    fn admit(&self, inner: &ClientInner, message: &[u8]) -> Result<JwtBundleSet, SpireError> {
        JwtBundleSet::from_raw(
            proto::decode_jwt_bundles_response(message)?,
            &inner.trust_domain,
        )
    }

    fn validity(_: &JwtBundleSet) -> Option<(Timestamp, Timestamp)> {
        None
    }

    fn unchanged(held: &JwtBundleSet, sent: &JwtBundleSet) -> bool {
        held == sent
    }

    fn spiffe_id(_: &JwtBundleSet) -> Option<&WorkloadId> {
        None
    }

    fn trust_domains(item: &JwtBundleSet) -> usize {
        item.len()
    }

    fn skipped(item: &JwtBundleSet) -> &[SkippedBundle] {
        item.skipped()
    }

    #[cfg(feature = "jwt")]
    fn stored(&self, item: &Arc<JwtBundleSet>) {
        self.key_sets.replace(item);
    }

    /// A stale bundle set takes its key sets with it: a verifier built on
    /// one has no keys until the agent confirms a set again.
    #[cfg(feature = "jwt")]
    fn lost(&self) {
        self.key_sets.clear();
    }
}

/// The feed of [`JwtSvidSource`](super::JwtSvidSource): `FetchJWTSVID`,
/// asked again at each refresh point. The audience was checked when the
/// source was started.
pub(crate) struct JwtSvidFeed {
    pub(crate) audience: Vec<String>,
}

impl Feed for JwtSvidFeed {
    type Item = JwtSvid;
    const KIND: WorkloadCredentialKind = WorkloadCredentialKind::JwtSvid;
    const METHOD: &'static str = proto::FETCH_JWT_SVID;
    const STREAMING: bool = false;

    fn request(&self, inner: &ClientInner) -> Vec<u8> {
        jwt_request(inner, &self.audience)
    }

    fn admit(&self, inner: &ClientInner, message: &[u8]) -> Result<JwtSvid, SpireError> {
        admit_jwt_response(inner, message, &self.audience)
    }

    fn validity(item: &JwtSvid) -> Option<(Timestamp, Timestamp)> {
        Some((item.issued_at(), item.expires_at()))
    }

    fn unchanged(held: &JwtSvid, sent: &JwtSvid) -> bool {
        held.token() == sent.token()
    }

    fn spiffe_id(item: &JwtSvid) -> Option<&WorkloadId> {
        Some(item.spiffe_id())
    }

    fn trust_domains(_: &JwtSvid) -> usize {
        0
    }

    fn skipped(_: &JwtSvid) -> &[SkippedBundle] {
        &[]
    }
}
