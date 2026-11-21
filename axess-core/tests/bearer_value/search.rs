//! The bearer values a run handed out, read from its `Set-Cookie` headers,
//! and the search of what the doors recorded for any form of them.

use std::collections::BTreeSet;

use axess_core::session::{SessionId, SessionKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// The session cookie's name under the layer's defaults.
pub const SESSION_COOKIE: &str = "__Host-axess.sid";

/// The bearer value a session cookie's value carries: the base64 part
/// before the dot is the id's 16 bytes.
pub fn bearer_of(cookie_value: &str) -> SessionId {
    let (id, _) = cookie_value.split_once('.').expect("id.mac");
    let bytes: [u8; 16] = URL_SAFE_NO_PAD
        .decode(id)
        .expect("base64")
        .try_into()
        .expect("16 bytes");
    SessionId::from_bytes(bytes)
}

/// Every form a bearer value could take in a recorded text or byte string:
/// the hyphenated text in either case, the 32 hexadecimal digits in either
/// case, the base64 the cookie carries, the 16 raw bytes, and the first
/// eight digits with three dots (the form a log line printed before the key
/// existed).
pub fn forms(id: &SessionId) -> Vec<(String, Vec<u8>)> {
    let hyphenated = id.to_string();
    let simple = hyphenated.replace('-', "");
    let mut forms: Vec<(String, Vec<u8>)> = [
        ("hyphenated", hyphenated.clone()),
        ("hyphenated, upper case", hyphenated.to_uppercase()),
        ("32 digits", simple.clone()),
        ("32 digits, upper case", simple.to_uppercase()),
        ("the cookie's base64", URL_SAFE_NO_PAD.encode(id.as_bytes())),
        ("the old log form", format!("{}...", &simple[..8])),
    ]
    .into_iter()
    .map(|(name, text)| (name.to_owned(), text.into_bytes()))
    .collect();
    forms.push(("16 raw bytes".to_owned(), id.as_bytes().to_vec()));
    forms
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The bearer values of every session a run's cookies named.
#[derive(Default)]
pub struct Bearers(BTreeSet<[u8; 16]>);

impl Bearers {
    pub fn note(&mut self, id: SessionId) {
        self.0.insert(*id.as_bytes());
    }

    pub fn ids(&self) -> Vec<SessionId> {
        self.0.iter().map(|b| SessionId::from_bytes(*b)).collect()
    }

    pub fn keys(&self) -> Vec<SessionKey> {
        self.ids().iter().map(SessionKey::of).collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Every form of a bearer value that `door` recorded, one line each.
    pub fn found(&self, door: &str, recorded: &[Vec<u8>]) -> Vec<String> {
        if recorded.is_empty() {
            return vec![format!("{door} recorded nothing")];
        }
        let mut found = Vec::new();
        for id in self.ids() {
            for (form, needle) in forms(&id) {
                for (n, entry) in recorded.iter().enumerate() {
                    if holds(entry, &needle) {
                        found.push(format!(
                            "{door}: entry {n} holds the bearer value {id} as {form}: {}",
                            String::from_utf8_lossy(entry)
                        ));
                    }
                }
            }
        }
        found
    }

    /// No form of any bearer value is in anything `door` recorded.
    pub fn assert_absent(&self, door: &str, recorded: &[Vec<u8>]) {
        let found = self.found(door, recorded);
        assert!(found.is_empty(), "{found:#?}");
    }
}

/// Whether `recorded` holds the 64 characters of `key`.
pub fn saw_key(recorded: &[Vec<u8>], key: &SessionKey) -> bool {
    let text = key.to_string();
    recorded.iter().any(|entry| holds(entry, text.as_bytes()))
}

/// Whether `recorded` holds `key`'s log form, its first eight characters
/// and three dots.
pub fn saw_prefix(recorded: &[Vec<u8>], key: &SessionKey) -> bool {
    let text = key.prefix().to_string();
    recorded.iter().any(|entry| holds(entry, text.as_bytes()))
}
