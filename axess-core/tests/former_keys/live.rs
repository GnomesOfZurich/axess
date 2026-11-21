//! The scenarios on a live Valkey: the registry and the sid store under a
//! prefix no earlier run used, one fresh prefix per world, and every key
//! under them removed when the run ends, also when a scenario fails.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axess_core::ValkeySessionRegistry;
use axess_core::federation::sid_map::SidMap;
use axess_core::federation::sid_store::SidStore;
use axess_core::federation::valkey_logout::ValkeySidStore;
use axess_core::testing::fixtures as common;
use axess_core::testing::valkey_sweep::KeySweep;
use fred::prelude::{Client, ClientLike, Config};
use fred::types::{ClusterHash, CustomCommand};

use crate::scenarios::{self, ROTATIONS};
use crate::world::{World, world};

fn live_url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

async fn connect() -> Client {
    let client = Client::new(Config::from_url(&live_url()).unwrap(), None, None, None);
    client.init().await.expect("connect");
    client
}

/// A world whose registry and sid store live under `{run}-{n}`.
async fn valkey(run: &str, n: usize) -> World {
    with_sid(run, n, true).await
}

/// A world whose registry lives under `{run}-{n}`, with the in-process sid
/// store. The sweep of the subject records is the in-process store's: the
/// Valkey sid store hands it no candidates, since its records expire by
/// time, so the sweep's questions to the live registry are asked through
/// this one.
async fn valkey_registry(run: &str, n: usize) -> World {
    with_sid(run, n, false).await
}

async fn with_sid(run: &str, n: usize, live_sid: bool) -> World {
    let clock = common::test_clock();
    let client = connect().await;
    let prefix = format!("{run}-{n}");
    let registry = ValkeySessionRegistry::with_options(
        client.clone(),
        format!("{{{prefix}}}:registry"),
        Duration::from_secs(3600),
    )
    .await
    .expect("a registry")
    .with_clock(Arc::new(clock.clone()));
    let sid: Arc<dyn SidStore> = if live_sid {
        Arc::new(ValkeySidStore::new(client).with_prefix(format!("{prefix}:logout")))
    } else {
        Arc::new(SidMap::new())
    };
    world(clock, registry, sid)
}

/// Every key whose name holds `run`.
async fn names_holding(client: &Client, run: &str) -> Vec<String> {
    let pattern = format!("*{run}*");
    let mut cursor = "0".to_string();
    let mut found = Vec::new();
    loop {
        let (next, mut page): (String, Vec<String>) = client
            .custom(
                CustomCommand::new_static("SCAN", ClusterHash::FirstKey, false),
                vec![cursor.as_str(), "MATCH", pattern.as_str(), "COUNT", "1000"],
            )
            .await
            .expect("SCAN");
        found.append(&mut page);
        if next == "0" {
            return found;
        }
        cursor = next;
    }
}

/// Run `body` with a fresh run name, then remove every key it wrote, and
/// only then report its failure, if any. The run name is a sweep's prefix:
/// dropping the sweep removes every key whose name holds it.
async fn swept<F, Fut>(body: F)
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let sweep = KeySweep::node(live_url(), "former");
    let run = sweep.prefix().to_owned();
    let outcome = tokio::spawn(body(run.clone())).await;
    drop(sweep);
    let client = connect().await;
    let left = names_holding(&client, &run).await;
    client.quit().await.ok();
    if let Err(failure) = outcome {
        std::panic::resume_unwind(failure.into_panic());
    }
    assert!(left.is_empty(), "keys left behind: {left:?}");
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_backchannel_logout_after_each_rotation_ends_the_session() {
    swept(|run| async move {
        let cases = ROTATIONS
            .into_iter()
            .flat_map(|rotation| [(rotation, true), (rotation, false)]);
        for (n, (rotation, by_sid)) in cases.enumerate() {
            scenarios::backchannel_after(&valkey(&run, n).await, rotation, by_sid).await;
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_frontchannel_logout_after_a_step_up_ends_the_session() {
    swept(|run| async move {
        scenarios::frontchannel_after_a_step_up(&valkey(&run, 0).await).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_frontchannel_logout_from_another_sessions_browser_ends_nothing() {
    swept(|run| async move {
        scenarios::frontchannel_from_another_session(&valkey(&run, 0).await).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_sweep_keeps_the_subject_record_of_a_rotated_session() {
    swept(|run| async move {
        scenarios::the_sweep_keeps_a_rotated_session(&valkey_registry(&run, 0).await).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_the_sweep_forgets_the_subject_record_of_an_ended_session() {
    swept(|run| async move {
        scenarios::the_sweep_forgets_an_ended_session(&valkey_registry(&run, 0).await).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_kick_of_a_key_listed_before_a_rotation_ends_the_session() {
    swept(|run| async move {
        scenarios::a_kick_after_a_rotation(&valkey(&run, 0).await).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires a running Valkey (VALKEY_URL)"]
async fn valkey_a_backchannel_logout_for_a_session_that_is_gone_records_nothing() {
    swept(|run| async move {
        for (n, by_sid) in [true, false].into_iter().enumerate() {
            scenarios::a_logout_for_a_session_that_is_gone(&valkey(&run, n).await, by_sid).await;
        }
    })
    .await;
}
