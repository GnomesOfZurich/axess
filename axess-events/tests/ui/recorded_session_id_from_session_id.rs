// `EventSubject::Session` holds a `RecordedSessionId`, not a session id: a
// new event names a session by its key.
use axess_events::{EventSubject, SessionId};

fn main() {
    let _ = EventSubject::Session(SessionId::NIL);
}
