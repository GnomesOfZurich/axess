// `RecordedSessionId`'s field is private: only the decoders of a stored
// event build one.
use axess_events::{RecordedSessionId, SessionId};

fn main() {
    let _ = RecordedSessionId(SessionId::NIL);
}
