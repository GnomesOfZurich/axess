//! One subscriber connection shared by every revocation watcher of a
//! [`ValkeySessionRegistry`](super::ValkeySessionRegistry).
//!
//! The connection is opened by the first watcher, subscribes once to the
//! pattern of every revocation channel under the registry's prefix, and is
//! closed when the last watcher is gone. A single dispatcher task owns the
//! connection's message receiver and routes each message to the watchers of
//! that message's channel only: every watcher registers one wake-up slot
//! under its user channel and its session channel, so N watchers cost one
//! connection and one receiver, and a revocation for somebody else wakes
//! none of them.
//!
//! A burst larger than the receiver's buffer drops messages, and a dropped
//! message may have been a watcher's. The dispatcher then flags every watcher
//! for a recheck; each one asks the registry after its own delay (the
//! registry draws it from its injected random source), so the checks do not
//! land on the server in one instant.
//!
//! A connection that has died is not reused: the next watcher to join finds
//! it disconnected, opens a new one and flags the watchers already waiting for
//! a recheck, because they missed whatever was published meanwhile.

use fred::prelude::*;
use fred::types::Message;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Quit `client` on the current runtime, if there is one. Used from `Drop`,
/// where nothing can be awaited; with no runtime the client's tasks are gone
/// with it.
fn quit_in_background(client: Client) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            let _ = client.quit().await;
        });
    }
}

/// A client that is quit when this guard drops, unless it is taken out first.
/// Covers a watcher aborted while the connection is still being set up.
struct QuitOnDrop(Option<Client>);

impl Drop for QuitOnDrop {
    fn drop(&mut self) {
        if let Some(client) = self.0.take() {
            quit_in_background(client);
        }
    }
}

/// What the dispatcher tells one watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event {
    /// A revocation for one of the watcher's channels arrived.
    Revoked,
    /// Messages were dropped, so the registry has to be asked.
    Recheck,
    /// The connection ended; the watcher keeps waiting for a replacement.
    Closed,
}

/// One watcher's wake-up slot: the dispatcher sets a flag and notifies, the
/// watcher reads the flag. `Notify` keeps one permit, so a notification sent
/// before the watcher waits is not lost.
#[derive(Default)]
pub(super) struct Slot {
    notify: Notify,
    revoked: AtomicBool,
    recheck: AtomicBool,
    closed: AtomicBool,
    /// Times the dispatcher woke this slot (tests only).
    #[cfg(test)]
    pub(super) wakeups: std::sync::atomic::AtomicUsize,
}

impl Slot {
    fn wake(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::SeqCst);
        #[cfg(test)]
        self.wakeups.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Wait for the next event for this watcher.
    pub(super) async fn next(&self) -> Event {
        loop {
            if self.revoked.swap(false, Ordering::SeqCst) {
                return Event::Revoked;
            }
            if self.recheck.swap(false, Ordering::SeqCst) {
                return Event::Recheck;
            }
            if self.closed.swap(false, Ordering::SeqCst) {
                return Event::Closed;
            }
            self.notify.notified().await;
        }
    }
}

struct Connection {
    client: Client,
    dispatcher: JoinHandle<()>,
}

/// How long a subscriber connection gets to answer a `PING` before it is
/// taken for dead.
const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// True when `client` answers a `PING`. A killed or half-open connection can
/// keep reporting a connected state while it answers nothing, so the
/// state flag alone is not evidence of a live connection.
async fn answers_ping(client: &Client) -> bool {
    client.is_connected()
        && matches!(
            tokio::time::timeout(PING_TIMEOUT, client.ping::<Value>(None)).await,
            Ok(Ok(_))
        )
}

impl Connection {
    fn shut_down(self) {
        self.dispatcher.abort();
        quit_in_background(self.client);
    }
}

#[derive(Default)]
struct State {
    /// Watchers currently holding a [`Watch`], including one still
    /// connecting.
    watchers: usize,
    /// The shared connection, once it is subscribed.
    connection: Option<Connection>,
    /// Every watcher's slot, under the user and session channel it watches.
    routes: HashMap<String, Vec<Arc<Slot>>>,
}

/// The shared subscriber of one registry and its clones.
pub(super) struct SharedSubscriber {
    state: Mutex<State>,
    /// Serialises connection setup so concurrent first watchers open one
    /// connection.
    connecting: tokio::sync::Mutex<()>,
}

/// A watcher's hold on the shared connection. Dropping it, including when the
/// watching future is aborted, removes its slot from the routes and releases
/// the hold; the last one out shuts the connection down.
struct Hold {
    shared: Arc<SharedSubscriber>,
    slot: Arc<Slot>,
    channels: [String; 2],
}

impl Drop for Hold {
    fn drop(&mut self) {
        let last = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for channel in &self.channels {
                if let Some(slots) = state.routes.get_mut(channel) {
                    slots.retain(|s| !Arc::ptr_eq(s, &self.slot));
                    if slots.is_empty() {
                        state.routes.remove(channel);
                    }
                }
            }
            state.watchers = state.watchers.saturating_sub(1);
            if state.watchers == 0 {
                state.connection.take()
            } else {
                None
            }
        };
        if let Some(connection) = last {
            connection.shut_down();
        }
    }
}

/// A watcher joined to the shared connection.
pub(super) struct Watch {
    _hold: Hold,
    /// The watcher's wake-up slot.
    pub(super) slot: Arc<Slot>,
}

/// Escape the glob metacharacters of a channel-pattern fragment.
fn escape_glob(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl SharedSubscriber {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            connecting: tokio::sync::Mutex::new(()),
        })
    }

    /// Number of watchers holding the connection.
    #[cfg(test)]
    pub(super) fn watcher_count(&self) -> usize {
        self.lock().watchers
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Add a watcher for `channels` and return its hold, without touching
    /// the connection. The hold exists before anything is awaited, so an
    /// abort during setup releases it.
    fn register(self: &Arc<Self>, channels: [String; 2]) -> Hold {
        let slot = Arc::new(Slot::default());
        let mut state = self.lock();
        state.watchers += 1;
        for channel in &channels {
            state
                .routes
                .entry(channel.clone())
                .or_default()
                .push(slot.clone());
        }
        Hold {
            shared: self.clone(),
            slot,
            channels,
        }
    }

    /// Wake the watchers of `channel` with a revocation.
    fn dispatch_message(&self, channel: &str) {
        let slots = self.lock().routes.get(channel).cloned().unwrap_or_default();
        for slot in slots {
            slot.wake(&slot.revoked);
        }
    }

    /// Every watcher, once: a slot sits under two channels.
    fn all_slots(&self) -> Vec<Arc<Slot>> {
        let state = self.lock();
        let mut slots: Vec<Arc<Slot>> = Vec::new();
        for slot in state.routes.values().flatten() {
            if !slots.iter().any(|s| Arc::ptr_eq(s, slot)) {
                slots.push(slot.clone());
            }
        }
        slots
    }

    /// Messages were dropped: every watcher asks the registry.
    fn dispatch_lag(&self) {
        for slot in self.all_slots() {
            slot.wake(&slot.recheck);
        }
    }

    /// The connection ended: tell every watcher, and forget the connection
    /// so the next watcher opens a new one.
    fn dispatch_closed(&self) {
        let dead = self.lock().connection.take();
        if let Some(connection) = dead {
            quit_in_background(connection.client);
        }
        for slot in self.all_slots() {
            slot.wake(&slot.closed);
        }
    }

    /// Join the shared connection, opening and subscribing it first if no
    /// watcher has or if the one that exists no longer answers. `base`
    /// is the registry's client, cloned for the new connection; `prefix` is
    /// the registry prefix whose `revoked-session:` and `revoked-user:`
    /// channels are subscribed; `channels` are this watcher's user and
    /// session channels.
    ///
    /// `None` when the connection cannot be opened or subscribed; the caller
    /// then falls back to the next request's validity check.
    pub(super) async fn join(
        self: &Arc<Self>,
        base: &Client,
        prefix: &str,
        channels: [String; 2],
    ) -> Option<Watch> {
        let _connecting = self.connecting.lock().await;
        let hold = self.register(channels);
        let slot = hold.slot.clone();

        // The existing connection is reused only if its dispatcher still runs
        // and the connection answers.
        let existing = self
            .lock()
            .connection
            .as_ref()
            .filter(|c| !c.dispatcher.is_finished())
            .map(|c| c.client.clone());
        if let Some(client) = existing
            && answers_ping(&client).await
        {
            return Some(Watch { _hold: hold, slot });
        }
        let replaced = self.lock().connection.take();
        let had_dead_connection = replaced.is_some();
        if let Some(dead) = replaced {
            dead.shut_down();
        }

        let subscriber = base.clone_new();
        let mut pending = QuitOnDrop(Some(subscriber.clone()));
        subscriber.init().await.ok()?;
        let messages = subscriber.message_rx();
        let escaped = escape_glob(prefix);
        let patterns = vec![
            format!("{escaped}:revoked-session:*"),
            format!("{escaped}:revoked-user:*"),
        ];
        subscriber.psubscribe(patterns).await.ok()?;

        let dispatcher = tokio::spawn(dispatch(messages, Arc::downgrade(self)));
        pending.0 = None;
        self.lock().connection = Some(Connection {
            client: subscriber,
            dispatcher,
        });
        if had_dead_connection {
            // The watchers already waiting missed what was published while
            // there was no connection.
            self.dispatch_lag();
        }
        Some(Watch { _hold: hold, slot })
    }
}

/// Route the connection's messages until it ends or the subscriber is gone.
async fn dispatch(
    mut messages: tokio::sync::broadcast::Receiver<Message>,
    shared: Weak<SharedSubscriber>,
) {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        let received = messages.recv().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        match received {
            Ok(message) => shared.dispatch_message(&message.channel),
            Err(RecvError::Lagged(_)) => shared.dispatch_lag(),
            Err(RecvError::Closed) => {
                shared.dispatch_closed();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests;
