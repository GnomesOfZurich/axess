//! The watcher: the task behind a source, and the slot it fills.
//!
//! A source is a handle on a slot and on the task that fills it. Reading is
//! a clone of an `Arc` and never waits for the agent. The task keeps one
//! stream open (a JWT SVID has none: it is asked for, and asked for again)
//! and follows these rules:
//!
//! - What the agent sends replaces what the slot holds once it has been
//!   checked. An answer that is refused changes nothing.
//! - A failure (the agent is down, the stream drops, the answer is refused)
//!   is counted, reported and retried with back-off. The slot keeps serving
//!   what it holds for as long as that is valid. A stream that had been
//!   delivering and is cut is opened again at once, as the Workload API
//!   asks of a client; the back-off paces what follows a failed attempt.
//! - Two answers of the agent are not failures to wait out. When it says it
//!   no longer issues what the slot holds (`PERMISSION_DENIED`, or an answer
//!   without the selected identity), the slot is emptied: a client ceases
//!   to use what the agent has redacted. When it answers
//!   `INVALID_ARGUMENT` or `UNIMPLEMENTED`, the watcher asks no more: the
//!   Workload Endpoint standard has a client report those and not retry.
//! - The injected clock decides when to stop waiting for the agent and ask:
//!   at a share of an SVID's lifetime, or of the time a bundle set may go
//!   unconfirmed. The ask is a second request beside the open stream, which
//!   is kept: it is replaced only by a stream that brought something the
//!   open one had not delivered, so an agent that is merely not due yet is
//!   not made to start over.
//! - The next ask is tied to the end. When the agent has nothing newer, it
//!   is asked again at a slowing pace; when what the slot holds runs out,
//!   it is asked at once, whatever wait was under way.
//! - Nothing past its end is served: an SVID past its expiry, a bundle set
//!   the agent has not confirmed within the maximum bundle age, the bundles
//!   that came with an X.509 SVID included. The read itself compares the
//!   end with the clock, so this holds between two checks of the task.
//!
//! The waits between attempts and between checks are `tokio::time` timers;
//! what is decided at each of them is read from the clock.

use std::pin::Pin;
use std::sync::Arc;

use axess_clock::{Clock, SignedDuration, Timestamp, Until};
use axess_identity::WorkloadId;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, Sleep};

use super::backoff::Backoff;
use super::client::ClientInner;
use super::error::{GrpcCode, SpireError};
use super::feed::Feed;
use super::observe::WorkloadApiEvent;
pub(crate) use super::slot::Lifetime;
use super::slot::{Lost, Shared};
use super::transport::{Message, Responses, TARGET};

/// Stops the watcher when the last handle of its source is dropped.
struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A source's handle: the slot, and the watcher's lifetime.
pub(crate) struct Handle<T> {
    shared: Arc<Shared<T>>,
    task: Arc<TaskGuard>,
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            task: self.task.clone(),
        }
    }
}

impl<T: Send + Sync + 'static> Handle<T> {
    /// Start a watcher on `feed` and give the handle on its slot, which
    /// serves what it holds for `lifetime`.
    pub(crate) fn start<F: Feed<Item = T>>(
        inner: Arc<ClientInner>,
        feed: F,
        lifetime: Lifetime<T>,
    ) -> Result<Self, SpireError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| SpireError::NoRuntime)?;
        let shared = Arc::new(Shared::new(F::KIND, inner.clock.clone(), lifetime));
        let watcher = Watcher {
            failures: Backoff::new(inner.backoff),
            repeats: Backoff::new(inner.backoff),
            inner,
            feed,
            shared: shared.clone(),
            stream: None,
            ask_at: None,
            ask_timer: None,
            carried_end: None,
            stopped: false,
            reconnected: false,
        };
        let task = Arc::new(TaskGuard(runtime.spawn(watcher.run())));
        Ok(Self { shared, task })
    }

    /// What the watcher last accepted, unless there is nothing yet or it
    /// is past its end by the clock.
    pub(crate) fn current(&self) -> Result<Arc<T>, SpireError> {
        self.shared.current()
    }

    /// Wait until the slot holds a value.
    pub(crate) async fn ready(&self) {
        self.shared.ready().await;
    }

    /// How many times the slot has changed.
    pub(crate) fn generation(&self) -> u64 {
        self.shared.generation()
    }

    /// Wait until the slot has changed more than `after` times.
    pub(crate) async fn updated(&self, after: u64) -> u64 {
        self.shared.updated(after).await
    }

    /// When the agent last sent what the slot holds, or sent it again.
    pub(crate) fn confirmed_at(&self) -> Option<Timestamp> {
        self.shared.confirmed_at()
    }

    /// As [`current`](Self::current), with when the agent last confirmed
    /// it.
    pub(crate) fn current_confirmed(&self) -> Result<(Arc<T>, Option<Timestamp>), SpireError> {
        self.shared.current_confirmed()
    }

    /// Whether the watcher task is still running. It runs until the last
    /// handle is dropped; `false` means it panicked.
    pub(crate) fn is_watching(&self) -> bool {
        !self.task.0.is_finished()
    }

    /// The clock the slot judges its end by.
    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        self.shared.clock.clone()
    }
}

/// What an accepted answer did to the slot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    /// It replaced what the slot held.
    Newer,
    /// It was what the slot holds already.
    Same,
}

/// The task of one source.
struct Watcher<F: Feed> {
    inner: Arc<ClientInner>,
    feed: F,
    shared: Arc<Shared<F::Item>>,
    /// The open stream of a streaming feed. `None` before the first answer
    /// and after the stream failed, and always for a feed that is asked.
    stream: Option<Responses>,
    /// Paces the asks after failures. Its steps are the failures in a row.
    failures: Backoff,
    /// Paces the asks after answers that brought nothing newer.
    repeats: Backoff,
    /// When the clock says to stop waiting for the agent and ask.
    ask_at: Option<Until>,
    /// The wait before the next paced ask, after a failure or after an
    /// answer that brought nothing newer.
    ask_timer: Option<Pin<Box<Sleep>>>,
    /// When the bundles the slot's item carries go stale unless the agent
    /// confirms them first. `None` for a feed whose items carry none, and
    /// once their going stale has been reported.
    carried_end: Option<Until>,
    /// The agent answered with a status that is not retried: no more asks.
    stopped: bool,
    /// A cut stream was opened again at once since the last check of the
    /// clock. One such reconnection for each check interval: an agent that
    /// cuts every stream it opens is not asked in a loop.
    reconnected: bool,
}

impl<F: Feed> Watcher<F> {
    async fn run(mut self) {
        let mut ticker = tokio::time::interval(self.inner.check_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.ask().await;
        loop {
            // `biased`: the branches are polled in the order written, so
            // the same events give the same outcome on every run. An answer
            // that has arrived is taken before a timer or the clock is
            // consulted.
            tokio::select! {
                biased;
                next = next_message(&mut self.stream) => self.on_stream(next),
                () = elapsed(&mut self.ask_timer) => self.ask().await,
                _ = ticker.tick() => {
                    self.reconnected = false;
                    if self.due() {
                        self.ask().await;
                    }
                }
            }
        }
    }

    /// Ask the agent on a new request, and take its first answer. The open
    /// stream, if there is one, is left as it is unless the new one brought
    /// something it had not delivered.
    async fn ask(&mut self) {
        self.ask_timer = None;
        self.ask_at = None;
        if self.stopped {
            return;
        }
        let request = self.feed.request(&self.inner);
        let (message, stream) = match open::<F>(&self.inner, &request).await {
            Ok(answer) => answer,
            Err(error) => {
                self.failed(&error);
                return;
            }
        };
        match self.accept(&message) {
            Ok(Change::Newer) => {
                // The open stream had not delivered this: it has stalled,
                // or there was none. The stream that did deliver takes over.
                if stream.is_some() {
                    self.stream = stream;
                }
            }
            Ok(Change::Same) => {
                // Nothing the open stream missed: it stays, and the new one
                // is closed. Where no stream is open, the new one is kept.
                if self.stream.is_none() {
                    self.stream = stream;
                }
            }
            Err(error) => self.failed(&error),
        }
    }

    /// What the open stream delivered: a message, its end, or its failure.
    fn on_stream(&mut self, next: Result<Option<Message>, SpireError>) {
        match next {
            Ok(Some(message)) => {
                if let Err(error) = self.accept(&message) {
                    self.failed(&error);
                }
            }
            Ok(None) => {
                self.stream = None;
                self.cut(&SpireError::Transport(
                    "the agent ended the stream".to_owned(),
                ));
            }
            Err(error @ SpireError::Transport(_)) => {
                self.stream = None;
                self.cut(&error);
            }
            Err(error) => {
                self.stream = None;
                self.failed(&error);
            }
        }
    }

    /// Check one answer, put it in the slot, and set when to ask next.
    fn accept(&mut self, message: &[u8]) -> Result<Change, SpireError> {
        let item = self.feed.admit(&self.inner, message)?;
        let now = self.inner.clock.now();
        // The agent answered with something this client accepts: whatever
        // run of failures there was is over.
        self.failures.reset();
        self.schedule(&item, now);
        if self
            .shared
            .held()
            .is_some_and(|(held, _)| F::unchanged(&held, &item))
        {
            self.shared.confirm(now);
            return Ok(Change::Same);
        }
        let expires_at = F::validity(&item).map(|(_, until)| until);
        let trust_domains = F::trust_domains(&item);
        let item = Arc::new(item);
        self.feed.stored(&item);
        self.shared.put(item.clone(), now);
        self.inner.metrics.workload_credential_rotated(F::KIND);
        self.inner.listener.on_event(&WorkloadApiEvent::Rotated {
            kind: F::KIND,
            spiffe_id: F::spiffe_id(&item),
            expires_at,
            trust_domains,
        });
        tracing::info!(
            target: TARGET,
            kind = F::KIND.as_str(),
            spiffe_id = F::spiffe_id(&item).map(WorkloadId::as_str),
            expires_at = expires_at.map(|at| at.to_rfc3339_numeric_offset()),
            trust_domains,
            "workload API credential rotated",
        );
        for skipped in F::skipped(&item) {
            self.inner.metrics.workload_bundle_skipped(F::KIND);
            self.inner
                .listener
                .on_event(&WorkloadApiEvent::BundleSkipped {
                    kind: F::KIND,
                    key: skipped.key(),
                    error: skipped.error(),
                });
            tracing::warn!(
                target: TARGET,
                kind = F::KIND.as_str(),
                key = skipped.key(),
                error = %skipped.error(),
                "workload API bundle entry left out",
            );
        }
        Ok(Change::Newer)
    }

    /// Set when to ask next, from what the agent just sent.
    fn schedule(&mut self, item: &F::Item, now: Timestamp) {
        // Bundles are served from now, when the agent confirmed them, for
        // the maximum bundle age, and confirmed again at the recheck point
        // of that age.
        let confirmed_until = Until::after(now, self.inner.max_bundle_age);
        let confirm_at = match confirmed_until {
            Until::At(end) => Until::At(refresh_point(now, end, self.inner.recheck_percent)),
            // A share of an age that never ends never comes.
            Until::Forever => Until::Forever,
        };
        let point = match F::validity(item) {
            None => confirm_at,
            // An SVID is asked for at a share of its own validity, and
            // sooner when it carries bundles that are due first.
            Some((from, until)) => {
                let percent = if F::STREAMING {
                    self.inner.recheck_percent
                } else {
                    self.inner.jwt_refresh_percent
                };
                let own = Until::At(refresh_point(from, until, percent));
                if F::CARRIED_BUNDLES.is_some() {
                    self.carried_end = Some(confirmed_until);
                    own.min(confirm_at)
                } else {
                    own
                }
            }
        };
        if point > Until::At(now) {
            self.repeats.reset();
            self.ask_at = Some(point);
            self.ask_timer = None;
        } else {
            // Valid, and already past the point at which the next one is
            // due: the agent has nothing newer yet. Ask again after a wait,
            // a longer one each time. The clock cuts the wait short when
            // what the slot holds runs out first.
            let wait = self.repeats.next_wait(self.inner.rng.as_ref());
            self.ask_at = None;
            self.ask_timer = Some(Box::pin(tokio::time::sleep(wait)));
        }
    }

    /// Read the clock: report a loss, and say whether to ask now. What the
    /// slot held running out is a reason to ask at once.
    fn due(&mut self) -> bool {
        let now = self.inner.clock.now();
        let lost = self.expire(now);
        let stale = self.carried_stale(now);
        // The grace of a withdrawal has run out with the identity not back.
        let lapsed = self
            .shared
            .withdraw_at()
            .is_some_and(|at| Until::At(now) >= at);
        if lapsed {
            self.withdraw();
        }
        lost || stale || lapsed || self.ask_at.is_some_and(|at| Until::At(now) >= at)
    }

    /// Report, once, that the bundles the slot's item carries have gone
    /// unconfirmed for the maximum bundle age: the source stops serving
    /// them, and goes on serving the SVID. Whether it did.
    fn carried_stale(&mut self, now: Timestamp) -> bool {
        let (Some(kind), Some(ended_at)) = (F::CARRIED_BUNDLES, self.carried_end) else {
            return false;
        };
        // An age that never ends is never stale.
        let Until::At(ended_at) = ended_at else {
            return false;
        };
        if now < ended_at {
            return false;
        }
        self.carried_end = None;
        if self.shared.held().is_none() {
            // The item ran out first, and that was reported.
            return false;
        }
        self.inner.metrics.workload_credential_expired(kind);
        self.inner.listener.on_event(&WorkloadApiEvent::Expired {
            kind,
            spiffe_id: None,
            expired_at: ended_at,
        });
        tracing::error!(
            target: TARGET,
            kind = kind.as_str(),
            ended_at = %ended_at.to_rfc3339_numeric_offset(),
            "workload API bundles went stale with no confirmation",
        );
        true
    }

    /// Empty the slot when what it holds is past its end, and report it
    /// once. Whether it did.
    fn expire(&mut self, now: Timestamp) -> bool {
        let Some((held, confirmed_at)) = self.shared.held() else {
            return false;
        };
        let (ended_at, lost) = self.shared.end(&held, confirmed_at);
        if now < ended_at {
            return false;
        }
        self.feed.lost();
        self.shared.clear(lost);
        self.inner.metrics.workload_credential_expired(F::KIND);
        self.inner.listener.on_event(&WorkloadApiEvent::Expired {
            kind: F::KIND,
            spiffe_id: F::spiffe_id(&held),
            expired_at: ended_at,
        });
        tracing::error!(
            target: TARGET,
            kind = F::KIND.as_str(),
            spiffe_id = F::spiffe_id(&held).map(WorkloadId::as_str),
            ended_at = %ended_at.to_rfc3339_numeric_offset(),
            "workload API credential ran out with no replacement",
        );
        true
    }

    /// The open stream was cut: the connection closed, or the agent ended
    /// the call with no error status. The Workload API has a client
    /// establish a new connection at once, so a stream that had been
    /// delivering is asked for again with no wait, once for each check of
    /// the clock; anything else is paced by the back-off.
    fn cut(&mut self, error: &SpireError) {
        let at_once = self.failures.steps() == 0 && !self.reconnected;
        self.reconnected |= at_once;
        self.report_failure(error, at_once);
    }

    /// Take a failed refresh for what it is: a status that is not retried,
    /// a withdrawal, or a failure to retry after a wait. The open stream,
    /// where there is one, goes on being read meanwhile.
    fn failed(&mut self, error: &SpireError) {
        if let SpireError::Status {
            code: GrpcCode::InvalidArgument | GrpcCode::Unimplemented,
            ..
        } = error
        {
            self.stop(error);
            return;
        }
        match error {
            // The agent's answer holds SVIDs and not the selected one: a
            // positive statement, honoured at once.
            SpireError::NotIssued(_) => self.withdraw(),
            SpireError::Status {
                code: GrpcCode::PermissionDenied,
                ..
            } => self.withdraw_after_grace(),
            _ => {}
        }
        self.report_failure(error, false);
    }

    /// Ask no more: the agent's answer says that asking again cannot help.
    fn stop(&mut self, error: &SpireError) {
        self.stopped = true;
        self.stream = None;
        self.ask_at = None;
        self.ask_timer = None;
        self.shared.stop(error);
        self.inner
            .metrics
            .workload_credential_refresh_failed(F::KIND);
        self.inner.listener.on_event(&WorkloadApiEvent::Stopped {
            kind: F::KIND,
            error,
        });
        tracing::error!(
            target: TARGET,
            kind = F::KIND.as_str(),
            error = %error,
            "workload API answered with a status that is not retried; the watcher asks no more",
        );
    }

    /// The agent answered `PERMISSION_DENIED`. With no withdrawal grace, the
    /// default, what the slot holds is withdrawn now. With one, it is served
    /// until the grace ends (and never past its own end), and the deferral
    /// is reported once, however many times the agent answers so while it
    /// runs.
    fn withdraw_after_grace(&mut self) {
        let grace = self.inner.withdrawal_grace;
        let Some((held, _)) = self.shared.held() else {
            return;
        };
        if grace.is_zero() {
            self.withdraw();
            return;
        }
        let until = Until::after(self.inner.clock.now(), grace);
        if !self.shared.defer_withdrawal(until) {
            return;
        }
        self.inner
            .metrics
            .workload_credential_withdrawal_deferred(F::KIND);
        self.inner
            .listener
            .on_event(&WorkloadApiEvent::WithdrawalDeferred {
                kind: F::KIND,
                spiffe_id: F::spiffe_id(&held),
                until,
            });
        tracing::warn!(
            target: TARGET,
            kind = F::KIND.as_str(),
            spiffe_id = F::spiffe_id(&held).map(WorkloadId::as_str),
            until = %until.to_timestamp().to_rfc3339_numeric_offset(),
            "workload API withdrew the credential; served under the withdrawal grace",
        );
    }

    /// Stop serving what the slot holds: the agent no longer issues it.
    fn withdraw(&mut self) {
        let Some((held, _)) = self.shared.held() else {
            return;
        };
        self.feed.lost();
        self.carried_end = None;
        self.shared.clear(Lost::Withdrawn);
        self.inner.metrics.workload_credential_expired(F::KIND);
        self.inner.listener.on_event(&WorkloadApiEvent::Withdrawn {
            kind: F::KIND,
            spiffe_id: F::spiffe_id(&held),
        });
        tracing::error!(
            target: TARGET,
            kind = F::KIND.as_str(),
            spiffe_id = F::spiffe_id(&held).map(WorkloadId::as_str),
            "workload API withdrew the credential; it is no longer served",
        );
    }

    /// Report a failed refresh and set the wait before the next ask: none
    /// when `at_once`, the back-off's otherwise.
    fn report_failure(&mut self, error: &SpireError, at_once: bool) {
        let paced = self.failures.next_wait(self.inner.rng.as_ref());
        let wait = if at_once {
            std::time::Duration::ZERO
        } else {
            paced
        };
        let still_serving = self.shared.current().is_ok();
        self.inner
            .metrics
            .workload_credential_refresh_failed(F::KIND);
        self.inner
            .listener
            .on_event(&WorkloadApiEvent::RefreshFailed {
                kind: F::KIND,
                error,
                consecutive_failures: self.failures.steps(),
                retry_in: wait,
                still_serving,
            });
        tracing::warn!(
            target: TARGET,
            kind = F::KIND.as_str(),
            error = %error,
            consecutive_failures = self.failures.steps(),
            retry_in_ms = wait.as_millis() as u64,
            still_serving,
            "workload API refresh failed",
        );
        self.ask_at = None;
        self.ask_timer = Some(Box::pin(tokio::time::sleep(wait)));
    }
}

/// Send `request` to the method of feed `F`, and wait for the first answer:
/// with the stream it opened, for a method that streams.
///
/// A function of the client alone, and not of the watcher: the wait borrows
/// nothing of the watcher, whose open stream is not shared between threads.
async fn open<F: Feed>(
    inner: &ClientInner,
    request: &[u8],
) -> Result<(Message, Option<Responses>), SpireError> {
    if F::STREAMING {
        let (message, responses) = inner.first_message(F::METHOD, request).await?;
        Ok((message, Some(responses)))
    } else {
        let message = inner.unary(F::METHOD, request).await?;
        Ok((message, None))
    }
}

/// Completes when `timer` does; never, when there is none.
async fn elapsed(timer: &mut Option<Pin<Box<Sleep>>>) {
    match timer {
        Some(timer) => timer.as_mut().await,
        None => std::future::pending().await,
    }
}

/// The next message of the open stream; never, when there is none.
async fn next_message(stream: &mut Option<Responses>) -> Result<Option<Message>, SpireError> {
    match stream {
        Some(stream) => stream.next_message().await,
        None => std::future::pending().await,
    }
}

/// The instant `percent` of the way from `from` to `until`, never after
/// `until`. A validity that does not run forwards has its point at its end,
/// so what carries it is due at once.
pub(crate) fn refresh_point(from: Timestamp, until: Timestamp, percent: u8) -> Timestamp {
    let lifetime = until.since(from);
    if lifetime <= SignedDuration::ZERO {
        return until;
    }
    lifetime
        .checked_div(100)
        .and_then(|hundredth| hundredth.checked_mul(i32::from(percent)))
        .and_then(|elapsed| from.checked_add(elapsed))
        .map_or(until, |point| point.min(until))
}

#[cfg(all(test, unix))]
mod tests;
