#![cfg(all(
    feature = "testing",
    feature = "memory",
    feature = "device-keys",
    feature = "oauth"
))]
//! Nothing a session store, a registry, a sid store, an audit sink or a log
//! receives holds a session id.
//!
//! A session's id is the value its cookie carries; whoever holds it holds
//! the session. Every value that leaves the session layer and the service
//! leaves through one of five doors: the session store, the registry, the
//! sid store, the audit sinks and the log. One run puts a recorder at each,
//! drives every flow that names a session through the real layer and the
//! real service with random ids, reads every id the run's cookies carried,
//! and searches everything recorded for any form of any of them. The
//! positive half (each door saw the keys of the sessions it was handed)
//! keeps a recorder that recorded nothing from passing.

mod doors;
mod flows;
#[path = "../hotp_code/mod.rs"]
mod hotp_code;
#[cfg(feature = "valkey")]
mod live;
mod search;
#[path = "../totp_code/mod.rs"]
mod totp_code;
mod world;

use std::sync::Arc;

use axess_core::federation::sid_map::SidMap;
use axess_core::session::store::MemorySessionStore;
use axess_core::testing::registry_double::RegistryDouble;
use axess_testing::mock_tracing::LineCapture;

use doors::{RecordingSid, RecordingStore};
use search::{saw_key, saw_prefix};

/// Every door's records, by name.
pub struct Records {
    pub doors: Vec<(&'static str, Vec<Vec<u8>>)>,
    pub log: Vec<Vec<u8>>,
}

#[tokio::test]
async fn no_door_receives_a_session_id() {
    let lines = LineCapture::install();
    let clock = axess_core::testing::fixtures::test_clock();
    let store = RecordingStore::over(MemorySessionStore::new().with_clock(Arc::new(clock.clone())));
    let registry = RegistryDouble::over(
        axess_core::MemorySessionRegistry::new().with_clock(Arc::new(clock.clone())),
    );
    let sid = RecordingSid::over(Arc::new(SidMap::new()));
    let w = world::world(clock, store.clone(), registry.clone(), sid.clone());
    let expected = flows::run(&w, &store).await;
    // The endings the layer runs in tasks of their own finish first.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let registry_seen: Vec<Vec<u8>> = registry
        .calls()
        .iter()
        .flat_map(|call| {
            let mut texts = vec![format!("{call:?}").into_bytes()];
            if let Some(key) = call.session() {
                texts.push(key.to_string().into_bytes());
            }
            texts
        })
        .collect();
    let audited: Vec<Vec<u8>> = w
        .identity
        .events()
        .iter()
        .map(|event| serde_json::to_vec(event).expect("an event serialises"))
        .collect();
    let metrics = vec![format!("{:?}", w.metrics.calls()).into_bytes()];
    let records = Records {
        doors: vec![
            ("the session store", store.seen.all()),
            ("the registry", registry_seen),
            ("the sid store", sid.seen.all()),
            ("the layer's session-end sink", w.ends.all()),
            ("the logout sink", w.logouts.all()),
            ("the identity log", audited),
            ("the metrics", metrics),
        ],
        log: lines.lines().into_iter().map(String::into_bytes).collect(),
    };
    let bearers = w.bearers.lock().unwrap();
    assert!(
        bearers.len() >= 10,
        "the run handed out its sessions: {}",
        bearers.len()
    );

    // Every door is searched before the test fails, so a value that
    // reached several doors names each of them.
    let mut found: Vec<String> = records
        .doors
        .iter()
        .flat_map(|(door, recorded)| bearers.found(door, recorded))
        .collect();
    found.extend(bearers.found("the log", &records.log));
    assert!(found.is_empty(), "{found:#?}");
    // A key is a name, not a credential, but a log line prints only its
    // first eight characters: no key any door was handed is in a line whole.
    for key in bearers.keys() {
        let whole = key.to_string();
        for (n, line) in records.log.iter().enumerate() {
            assert!(
                !line.windows(whole.len()).any(|w| w == whole.as_bytes()),
                "log line {n} prints a whole key: {}",
                String::from_utf8_lossy(line)
            );
        }
    }

    assert!(
        expected.mismatches.is_empty(),
        "the flows did not run as expected: {:#?}",
        expected.mismatches
    );

    let door = |name: &str| {
        &records
            .doors
            .iter()
            .find(|(door, _)| *door == name)
            .expect("a door")
            .1
    };
    for (name, keys) in [
        ("the session store", &expected.stored),
        ("the registry", &expected.registered),
        ("the sid store", &expected.mapped),
        ("the layer's session-end sink", &expected.ended),
        ("the logout sink", &expected.logged_out),
        ("the identity log", &expected.audited),
    ] {
        assert!(!keys.is_empty(), "{name} is expected to see a session");
        for key in keys {
            assert!(saw_key(door(name), key), "{name} saw {key:?}");
        }
    }
    for [loaded, rotated] in &expected.ended_either {
        let told = door("the layer's session-end sink");
        assert!(
            saw_key(told, loaded) || saw_key(told, rotated),
            "the failed rotation reached the sink"
        );
    }
    for key in &expected.logged {
        assert!(saw_prefix(&records.log, key), "a log line names {key:?}");
    }
}
