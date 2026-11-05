//! Tracing test subscriber that captures events for assertion.
//!
//! Use [`TracingCapture::install`] in tests to capture `tracing` events,
//! then assert on them with [`TracingCapture::events`].
//!
//! ```rust,ignore
//! let capture = TracingCapture::install();
//! // ... exercise code that emits tracing events ...
//! let events = capture.events();
//! assert!(events.iter().any(|e| e.contains("session registry")));
//! ```

use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;

/// Captured tracing events for test assertions.
pub struct TracingCapture {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
    // `_guard` is a struct-field carve-out from the workspace's no-`_` rule.
    // `DefaultGuard` is held purely for its `Drop` side-effect (restoring the
    // previous default subscriber); reading the field is meaningless. The `_`
    // prefix is the language-idiomatic way to express "RAII hold, never read"
    // without `#[allow(dead_code)]`.
    _guard: tracing::subscriber::DefaultGuard,
}

/// A single captured tracing event.
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    /// The log level (ERROR, WARN, INFO, DEBUG, TRACE).
    pub level: Level,
    /// The formatted message.
    pub message: String,
    /// The target module path.
    pub target: String,
    /// Whether the event fired inside an enclosing tracing span. Lets
    /// tests that span their work assert that emissions land in the
    /// expected scope, separating span-scoped logs from top-level
    /// noise.
    pub in_span: bool,
}

impl std::fmt::Display for CapturedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.level, self.target, self.message)
    }
}

impl TracingCapture {
    /// Install a capturing subscriber as the default for the current thread.
    ///
    /// The subscriber is active until the returned `TracingCapture` is dropped.
    /// Call [`events`](Self::events) to retrieve captured events.
    pub fn install() -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        anchor();
        let guard = tracing::subscriber::set_default(subscriber);
        // The callsites registered before the anchor existed were cached
        // through whichever thread hit them first; ask them again now that
        // this capture is live.
        tracing::callsite::rebuild_interest_cache();
        Self {
            events,
            _guard: guard,
        }
    }

    /// Retrieve all captured events.
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Check whether any captured event's message (which includes its
    /// recorded fields as `name=value`) contains the given substring. The
    /// event's target is not searched: a needle equal to a module path would
    /// otherwise match every event from that module whatever it said. Read
    /// [`CapturedEvent::target`] to assert on the target.
    pub fn contains(&self, needle: &str) -> bool {
        self.events().iter().any(|e| e.message.contains(needle))
    }

    /// Check whether any captured event at the given level has a message
    /// containing the substring (see [`contains`](Self::contains)).
    pub fn contains_at_level(&self, level: Level, needle: &str) -> bool {
        self.events()
            .iter()
            .any(|e| e.level == level && e.message.contains(needle))
    }
}

// ── The anchor ───────────────────────────────────────────────────────────────

/// Keep a second dispatcher registered for the life of the process, so a
/// capture is never the only one.
///
/// tracing-core caches each callsite's interest the first time any thread
/// hits it. While exactly one dispatcher is registered, that first hit is
/// resolved through the hitting thread's own default subscriber: a sibling
/// test running with no subscriber caches "never" for the callsite, and the
/// macro then drops the event on the capturing thread without asking the
/// capture. With the anchor registered there are always at least two, every
/// rebuild walks the registered dispatchers instead, and the anchor's
/// "sometimes" keeps each callsite open so the hit asks the hitting thread's
/// default, which on the capturing thread is the capture.
fn anchor() {
    static ANCHOR: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    ANCHOR.get_or_init(|| tracing::Dispatch::new(Anchor));
}

/// Interested in every callsite, enabled for none.
struct Anchor;

impl tracing::Subscriber for Anchor {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(u64::MAX)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

// ── Layer implementation ─────────────────────────────────────────────────────

struct CaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    // Pull `LevelFilter::current()` up to TRACE for the lifetime of this
    // subscriber. Without this, a sibling test in the same process that
    // installed a fmt subscriber hinting INFO (or higher) leaves the
    // process-wide max-level hint pinned there; `tracing::trace!` macros
    // short-circuit before `on_event` ever runs and capture comes back
    // empty even though the subscriber is correctly installed on this
    // thread.
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let captured = CapturedEvent {
            level: *event.metadata().level(),
            message: visitor.0,
            target: event.metadata().target().to_string(),
            in_span: ctx.event_span(event).is_some(),
        };

        if let Ok(mut events) = self.events.lock() {
            events.push(captured);
        }
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if field.name() == "message" {
            self.0.push_str(&format!("{value:?}"));
        } else {
            self.0.push_str(&format!("{}={value:?}", field.name()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            self.0.push_str(&format!("{}={value}", field.name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_warn_event() {
        let capture = TracingCapture::install();
        tracing::warn!("something went wrong");
        assert!(capture.contains("something went wrong"));
        assert!(capture.contains_at_level(Level::WARN, "something went wrong"));
        assert!(!capture.contains_at_level(Level::ERROR, "something went wrong"));
    }

    #[test]
    fn captures_structured_fields() {
        let capture = TracingCapture::install();
        tracing::info!(user_id = "alice", "login attempt");
        let events = capture.events();
        assert_eq!(events.len(), 1);
        assert!(events[0].message.contains("login attempt"));
        assert!(events[0].message.contains("alice"));
    }

    /// A target name on its own is not a match: only what the event said is.
    #[test]
    fn a_target_name_alone_does_not_match() {
        let capture = TracingCapture::install();
        tracing::warn!(target: "axess::audit::archive", "unrelated text");
        assert!(!capture.contains("axess::audit::archive"));
        assert!(!capture.contains_at_level(Level::WARN, "axess::audit"));
        assert!(capture.contains("unrelated text"));
        assert_eq!(capture.events()[0].target, "axess::audit::archive");
    }

    /// A callsite first hit on a thread with no subscriber is still captured
    /// when this thread hits it afterwards.
    #[test]
    fn a_callsite_first_hit_elsewhere_is_still_captured_here() {
        fn hit() {
            tracing::warn!("first seen on another thread");
        }
        let capture = TracingCapture::install();
        std::thread::spawn(hit).join().expect("the other thread");
        assert!(
            capture.events().is_empty(),
            "the other thread's event is not this thread's"
        );
        hit();
        assert!(capture.contains_at_level(Level::WARN, "first seen on another thread"));
    }

    #[test]
    fn empty_when_no_events() {
        let capture = TracingCapture::install();
        assert!(capture.events().is_empty());
        assert!(!capture.contains("anything"));
    }
}
