//! An inner `tower` service that is not ready, for a test that a middleware
//! passes its inner service's readiness on instead of answering for it.
//!
//! A middleware that answers `Ready` over an inner service that is not
//! takes requests the inner service has no room for, and one that swallows
//! the inner service's readiness error hides a dead backend from the server
//! in front of it. Every test double that is always ready leaves both
//! unseen. Wrap [`Unready`] in the layer under test and ask the result once
//! with [`poll_ready_once`]:
//!
//! ```
//! use axess_testing::readiness::{NotReady, Unready, poll_ready_once};
//! use std::task::Poll;
//!
//! // Stands in for the service a layer under test returns: it hands the
//! // question to the service it wraps.
//! struct Wrapped<S>(S);
//!
//! impl<S: tower_service::Service<&'static str>> tower_service::Service<&'static str> for Wrapped<S> {
//!     type Response = S::Response;
//!     type Error = S::Error;
//!     type Future = S::Future;
//!
//!     fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), S::Error>> {
//!         self.0.poll_ready(cx)
//!     }
//!
//!     fn call(&mut self, request: &'static str) -> S::Future {
//!         self.0.call(request)
//!     }
//! }
//!
//! let inner = Unready::<()>::pending();
//! let mut service = Wrapped(inner.clone());
//! assert!(poll_ready_once::<_, &'static str>(&mut service).is_pending());
//! assert_eq!(inner.polls(), 1, "the inner service was asked");
//!
//! let mut service = Wrapped(Unready::<()>::failing());
//! assert_eq!(
//!     poll_ready_once::<_, &'static str>(&mut service),
//!     Poll::Ready(Err(NotReady::Failed))
//! );
//! ```

use std::future::{Ready, ready};
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use tower_service::Service;

/// The error of an [`Unready`] service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReady {
    /// What [`Unready::failing`] answers when asked whether it is ready.
    Failed,
    /// What `call` answers: the service was called though it never said it
    /// was ready.
    Called,
}

impl std::fmt::Display for NotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Failed => "the inner service failed to become ready",
            Self::Called => "the inner service was called before it was ready",
        })
    }
}

impl std::error::Error for NotReady {}

/// A service answering `Res` that never becomes ready: asked, it is either
/// pending for good ([`pending`](Self::pending)) or fails
/// ([`failing`](Self::failing)).
///
/// It takes any request type, so one double serves every middleware, and it
/// counts how often it was asked across its clones, so a test can tell a
/// middleware that passed the question on from one that answered by itself.
/// A pending service wakes nobody, because it never has anything to say.
pub struct Unready<Res> {
    failing: bool,
    polls: Arc<AtomicUsize>,
    response: PhantomData<fn() -> Res>,
}

impl<Res> Unready<Res> {
    /// A service that is pending every time it is asked.
    pub fn pending() -> Self {
        Self::answering(false)
    }

    /// A service whose readiness fails with [`NotReady::Failed`] every time
    /// it is asked.
    pub fn failing() -> Self {
        Self::answering(true)
    }

    fn answering(failing: bool) -> Self {
        Self {
            failing,
            polls: Arc::default(),
            response: PhantomData,
        }
    }

    /// How many times this service or a clone of it was asked whether it is
    /// ready.
    pub fn polls(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }
}

impl<Res> Clone for Unready<Res> {
    fn clone(&self) -> Self {
        Self {
            failing: self.failing,
            polls: Arc::clone(&self.polls),
            response: PhantomData,
        }
    }
}

impl<Res> std::fmt::Debug for Unready<Res> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unready")
            .field("failing", &self.failing)
            .field("polls", &self.polls())
            .finish()
    }
}

impl<Req, Res> Service<Req> for Unready<Res> {
    type Response = Res;
    type Error = NotReady;
    type Future = Ready<Result<Res, NotReady>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), NotReady>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.failing {
            Poll::Ready(Err(NotReady::Failed))
        } else {
            // The answer of a future that never completes: nothing here
            // will change, so nobody is woken.
            std::pin::pin!(std::future::pending()).poll(cx)
        }
    }

    fn call(&mut self, request: Req) -> Self::Future {
        drop(request);
        ready(Err(NotReady::Called))
    }
}

/// Ask `service` once whether it is ready, on a waker that does nothing.
///
/// No runtime is needed: the answer is the one poll's.
pub fn poll_ready_once<S, Req>(service: &mut S) -> Poll<Result<(), S::Error>>
where
    S: Service<Req>,
{
    service.poll_ready(&mut Context::from_waker(Waker::noop()))
}
