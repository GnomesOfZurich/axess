//! The scenarios on the memory registry and the in-process sid store.

use std::sync::Arc;

use axess_core::federation::sid_map::SidMap;
use axess_core::session::store::MemorySessionRegistry;
use axess_core::testing::fixtures as common;

use crate::scenarios::{self, ROTATIONS};
use crate::world::{World, world};

fn memory() -> World {
    let clock = common::test_clock();
    let registry = MemorySessionRegistry::new().with_clock(Arc::new(clock.clone()));
    world(clock, registry, Arc::new(SidMap::new()))
}

#[tokio::test]
async fn a_backchannel_logout_by_sid_after_a_step_up_ends_the_session() {
    scenarios::backchannel_after(&memory(), ROTATIONS[0], true).await;
}

#[tokio::test]
async fn a_backchannel_logout_by_sub_after_a_step_up_ends_the_session() {
    scenarios::backchannel_after(&memory(), ROTATIONS[0], false).await;
}

#[tokio::test]
async fn a_backchannel_logout_after_rotate_session_or_regenerate_ends_the_session() {
    for rotation in &ROTATIONS[1..] {
        for by_sid in [true, false] {
            scenarios::backchannel_after(&memory(), *rotation, by_sid).await;
        }
    }
}

#[tokio::test]
async fn a_frontchannel_logout_after_a_step_up_ends_the_session() {
    scenarios::frontchannel_after_a_step_up(&memory()).await;
}

#[tokio::test]
async fn a_frontchannel_logout_from_another_sessions_browser_ends_nothing() {
    scenarios::frontchannel_from_another_session(&memory()).await;
}

#[tokio::test]
async fn the_sweep_keeps_the_subject_record_of_a_rotated_session() {
    scenarios::the_sweep_keeps_a_rotated_session(&memory()).await;
}

#[tokio::test]
async fn the_sweep_forgets_the_subject_record_of_an_ended_session() {
    scenarios::the_sweep_forgets_an_ended_session(&memory()).await;
}

#[tokio::test]
async fn a_kick_of_a_key_listed_before_a_rotation_ends_the_session() {
    scenarios::a_kick_after_a_rotation(&memory()).await;
}

#[tokio::test]
async fn a_backchannel_logout_by_sid_for_a_session_that_is_gone_records_nothing() {
    scenarios::a_logout_for_a_session_that_is_gone(&memory(), true).await;
}

#[tokio::test]
async fn a_backchannel_logout_by_sub_for_a_session_that_is_gone_records_nothing() {
    scenarios::a_logout_for_a_session_that_is_gone(&memory(), false).await;
}
