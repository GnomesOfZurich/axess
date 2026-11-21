// No conversion makes a `RecordedSessionId` from a session id: the type
// does not implement `From<SessionId>`.
use axess_events::{RecordedSessionId, SessionId};

fn converted<T: From<SessionId>>(id: SessionId) -> T {
    T::from(id)
}

fn main() {
    let _: RecordedSessionId = converted(SessionId::NIL);
}
