//! The checks of the store kit, held against stores that address a row by
//! less than its whole key, and against stores that drop part of what they
//! were handed: each fault is caught by name.

use super::*;
use crate::session::data::{AuthFlow, AuthState};
use crate::session::store::{CycleOutcome, MemorySessionStore};
use std::sync::{Arc, Mutex};

/// How a faulty store misuses the key it is given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// None: the store under it, as it is.
    Sound,
    /// Names a row by the first 36 characters of the key's text, the length
    /// of a session id's text.
    FirstThirtySixCharacters,
    /// Names a row by the key's text without its first two characters.
    WithoutTheFirstByte,
    /// Deletes by a pattern that matches every row.
    DeletesByPattern,
    /// Lists a session under another name than it was saved under.
    ListsAnotherName,
    /// Drops the ending claim of the row a conditional write stores.
    DropsTheClaimOnAConditionalWrite,
    /// Stores the pending state of a step-up a rotation moves as a login.
    DropsTheFlowOnARotation,
    /// Rebuilds the key binding a rotation moves from its device, its key
    /// and its time, naming another person as the one it was made for.
    RebuildsTheBindingOnARotation,
}

/// A memory store behind a fault.
#[derive(Clone)]
struct Faulty {
    inner: MemorySessionStore,
    fault: Fault,
    saved: Arc<Mutex<Vec<SessionKey>>>,
}

impl Faulty {
    fn with(fault: Fault) -> Self {
        Self {
            inner: MemorySessionStore::new(),
            fault,
            saved: Arc::default(),
        }
    }

    /// The name this store keeps a row under.
    fn name(&self, key: &SessionKey) -> SessionKey {
        let mut bytes = *key.as_bytes();
        match self.fault {
            // 36 hexadecimal characters are 18 bytes.
            Fault::FirstThirtySixCharacters => bytes[18..].fill(0),
            Fault::WithoutTheFirstByte => bytes[0] = 0,
            Fault::Sound
            | Fault::DeletesByPattern
            | Fault::ListsAnotherName
            | Fault::DropsTheClaimOnAConditionalWrite
            | Fault::DropsTheFlowOnARotation
            | Fault::RebuildsTheBindingOnARotation => {}
        }
        SessionKey::from_bytes(bytes)
    }
}

impl SessionStore for Faulty {
    type Error = <MemorySessionStore as SessionStore>::Error;

    async fn load(&self, key: &SessionKey) -> Result<Option<SessionData>, Self::Error> {
        self.inner.load(&self.name(key)).await
    }

    async fn save(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<(), Self::Error> {
        self.saved
            .lock()
            .expect("the list of saved keys")
            .push(self.name(key));
        self.inner.save(&self.name(key), data, ttl).await
    }

    async fn delete(&self, key: &SessionKey) -> Result<(), Self::Error> {
        if self.fault == Fault::DeletesByPattern {
            let saved = self.saved.lock().expect("the list of saved keys").clone();
            for row in saved {
                self.inner.delete(&row).await?;
            }
        }
        self.inner.delete(&self.name(key)).await
    }

    async fn update(
        &self,
        key: &SessionKey,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<bool, Self::Error> {
        self.inner.update(&self.name(key), data, ttl).await
    }

    async fn update_if_revision(
        &self,
        key: &SessionKey,
        expected_revision: u64,
        data: &SessionData,
        ttl: Duration,
    ) -> Result<ConditionalUpdate, Self::Error> {
        let mut data = data.clone();
        if self.fault == Fault::DropsTheClaimOnAConditionalWrite {
            data.ending = None;
        }
        self.inner
            .update_if_revision(&self.name(key), expected_revision, &data, ttl)
            .await
    }

    async fn cycle(
        &self,
        old: &SessionKey,
        new: &SessionKey,
        data: &SessionData,
        ttl: Duration,
        require_old: bool,
    ) -> Result<CycleOutcome, Self::Error> {
        let mut data = data.clone();
        if self.fault == Fault::DropsTheFlowOnARotation
            && let AuthState::Authenticating { flow, .. } = &mut data.auth_state
        {
            *flow = AuthFlow::Login;
        }
        if self.fault == Fault::RebuildsTheBindingOnARotation
            && let Some(binding) = &mut data.key_binding
        {
            binding.owner = "00000000-0000-4000-8000-0000000000c1"
                .parse()
                .expect("a user id");
        }
        self.inner
            .cycle(&self.name(old), &self.name(new), &data, ttl, require_old)
            .await
    }

    async fn prune_expired(&self) -> Result<u64, Self::Error> {
        self.inner.prune_expired().await
    }

    async fn find_sessions_for_user(
        &self,
        user_id: &UserId,
        limit: usize,
    ) -> Result<Vec<(SessionKey, SessionData)>, Self::Error> {
        let mut found = self.inner.find_sessions_for_user(user_id, limit).await?;
        if self.fault == Fault::ListsAnotherName {
            for (key, _) in &mut found {
                let mut bytes = *key.as_bytes();
                bytes[31] ^= 1;
                *key = SessionKey::from_bytes(bytes);
            }
        }
        Ok(found)
    }
}

#[tokio::test]
async fn a_store_that_names_a_row_by_its_whole_key_passes() {
    assert_key_addressing_contract(&MemorySessionStore::new()).await;
    assert_key_addressing_contract(&Faulty::with(Fault::Sound)).await;
    assert_stored_state_contract(&MemorySessionStore::new()).await;
    assert_stored_state_contract(&Faulty::with(Fault::Sound)).await;
    assert_update_if_revision_contract(&Faulty::with(Fault::Sound)).await;
}

#[tokio::test]
#[should_panic(
    expected = "a session must not load under the key with a bit of its last byte flipped"
)]
async fn a_store_keyed_by_the_first_36_characters_is_caught() {
    assert_key_addressing_contract(&Faulty::with(Fault::FirstThirtySixCharacters)).await;
}

/// Every runner of the kit runs the addressing check: the compare-and-swap
/// check ends with it.
#[tokio::test]
#[should_panic(
    expected = "a session must not load under the key with a bit of its last byte flipped"
)]
async fn the_compare_and_swap_check_runs_the_addressing_check() {
    assert_update_if_revision_contract(&Faulty::with(Fault::FirstThirtySixCharacters)).await;
}

#[tokio::test]
#[should_panic(
    expected = "a session must not load under the key with a bit of its first byte flipped"
)]
async fn a_store_keyed_without_the_first_byte_is_caught() {
    assert_key_addressing_contract(&Faulty::with(Fault::WithoutTheFirstByte)).await;
}

#[tokio::test]
#[should_panic(
    expected = "a write or a delete under the key of another id must leave the session as it was"
)]
async fn a_store_that_deletes_by_pattern_is_caught() {
    assert_key_addressing_contract(&Faulty::with(Fault::DeletesByPattern)).await;
}

#[tokio::test]
#[should_panic(expected = "a store that lists must return the keys the sessions were saved under")]
async fn a_store_that_lists_another_name_is_caught() {
    assert_key_addressing_contract(&Faulty::with(Fault::ListsAnotherName)).await;
}

#[tokio::test]
#[should_panic(
    expected = "a store must keep an ending claim through update_if_revision: the ending claim differs"
)]
async fn a_store_that_drops_the_claim_on_a_conditional_write_is_caught() {
    assert_stored_state_contract(&Faulty::with(Fault::DropsTheClaimOnAConditionalWrite)).await;
}

#[tokio::test]
#[should_panic(expected = "a store must keep a step-up's flow through cycle: the state differs")]
async fn a_store_that_drops_the_flow_on_a_rotation_is_caught() {
    assert_stored_state_contract(&Faulty::with(Fault::DropsTheFlowOnARotation)).await;
}

/// Every runner of the kit runs the check of what a store keeps: the
/// compare-and-swap check ends with it.
#[tokio::test]
#[should_panic(
    expected = "a store must keep an ending claim through update_if_revision: the ending claim differs"
)]
async fn the_compare_and_swap_check_runs_the_stored_state_check() {
    assert_update_if_revision_contract(&Faulty::with(Fault::DropsTheClaimOnAConditionalWrite))
        .await;
}

#[tokio::test]
#[should_panic(expected = "a rotation must deliver the binding under the new key")]
async fn a_store_that_rebuilds_the_binding_for_another_person_is_caught() {
    assert_key_binding_contract(&Faulty::with(Fault::RebuildsTheBindingOnARotation)).await;
}

#[tokio::test]
async fn a_store_that_keeps_the_binding_whole_passes_the_binding_check() {
    assert_key_binding_contract(&MemorySessionStore::new()).await;
    assert_key_binding_contract(&Faulty::with(Fault::Sound)).await;
}
