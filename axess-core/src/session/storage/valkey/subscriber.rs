//! One subscriber connection shared by every revocation watcher of a
//! [`ValkeySessionRegistry`](super::ValkeySessionRegistry).
//!
//! The connection is opened by the first watcher, subscribes once to the
//! pattern of every revocation channel under the registry's prefix, and is
//! closed when the last watcher is gone. Each watcher takes its own receiver
//! from the connection's local broadcast and keeps the messages for its two
//! channels, so N watchers cost one connection rather than N.

use fred::prelude::*;
use fred::types::Message;
use std::sync::{Arc, Mutex, PoisonError};

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

#[derive(Default)]
struct State {
    /// Watchers currently holding a [`Watch`], including one still
    /// connecting.
    watchers: usize,
    /// The shared connection, once it is subscribed.
    client: Option<Client>,
}

/// The shared subscriber of one registry and its clones.
pub(super) struct SharedSubscriber {
    state: Mutex<State>,
    /// Serialises connection setup so concurrent first watchers open one
    /// connection.
    connecting: tokio::sync::Mutex<()>,
}

/// A watcher's hold on the shared connection. Dropping it, including when the
/// watching future is aborted, releases the hold; the last one out quits the
/// connection.
struct Hold(Arc<SharedSubscriber>);

impl Drop for Hold {
    fn drop(&mut self) {
        let last = {
            let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.watchers = state.watchers.saturating_sub(1);
            if state.watchers == 0 {
                state.client.take()
            } else {
                None
            }
        };
        if let Some(client) = last {
            quit_in_background(client);
        }
    }
}

/// A watcher joined to the shared connection.
pub(super) struct Watch {
    _hold: Hold,
    /// The messages the shared connection receives.
    pub(super) messages: tokio::sync::broadcast::Receiver<Message>,
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
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .watchers
    }

    /// Join the shared connection, opening and subscribing it first if no
    /// watcher has. `base` is the registry's client, cloned for the new
    /// connection; `channel_prefix` is the registry prefix whose
    /// `revoked-session:` and `revoked-user:` channels are subscribed.
    ///
    /// `None` when the connection cannot be opened or subscribed; the caller
    /// then falls back to the next request's validity check.
    pub(super) async fn join(self: &Arc<Self>, base: &Client, prefix: &str) -> Option<Watch> {
        let _connecting = self.connecting.lock().await;
        // The hold exists before anything is awaited, so an abort during
        // setup releases it.
        let hold = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.watchers += 1;
            let hold = Hold(self.clone());
            if let Some(client) = &state.client {
                return Some(Watch {
                    _hold: hold,
                    messages: client.message_rx(),
                });
            }
            hold
        };

        let subscriber = base.clone_new();
        let mut pending = QuitOnDrop(Some(subscriber.clone()));
        subscriber.init().await.ok()?;
        let escaped = escape_glob(prefix);
        let patterns = vec![
            format!("{escaped}:revoked-session:*"),
            format!("{escaped}:revoked-user:*"),
        ];
        subscriber.psubscribe(patterns).await.ok()?;

        let messages = subscriber.message_rx();
        pending.0 = None;
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .client = Some(subscriber);
        Some(Watch {
            _hold: hold,
            messages,
        })
    }
}
