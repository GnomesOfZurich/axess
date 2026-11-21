//! A session registry of an adopter's own, written against the facade's
//! paths alone, and held to the registry contract the facade names under
//! `axess::testing`.

#![cfg(feature = "testing")]

use axess::authn::UserId;
use axess::session::MAX_MOVE_RECORDS_PER_USER;
use axess::{CutOff, MoveOutcome, SessionKey, SessionRegistry};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// One user's sessions in registration order, and the records of their
/// moves (former key, key now) in the order the moves were made.
#[derive(Default)]
struct Book {
    sessions: Vec<SessionKey>,
    moves: Vec<(SessionKey, SessionKey)>,
}

impl Book {
    /// The key the session once under `session` is under now.
    fn current(&self, session: &SessionKey) -> Option<SessionKey> {
        if self.sessions.contains(session) {
            return Some(*session);
        }
        self.moves
            .iter()
            .find(|(former, _)| former == session)
            .map(|(_, now)| *now)
            .filter(|now| self.sessions.contains(now))
    }
}

/// A registry with no lifetimes: every entry lives until it is ended. Each
/// method takes the one lock once, so each is one step.
#[derive(Clone, Default)]
struct OwnRegistry {
    books: Arc<Mutex<HashMap<UserId, Book>>>,
}

/// The registry cannot fail.
type Never = std::convert::Infallible;

impl SessionRegistry for OwnRegistry {
    type Error = Never;

    async fn register(&self, user: &UserId, session: &SessionKey) -> Result<(), Never> {
        let mut books = self.books.lock().unwrap();
        let book = books.entry(*user).or_default();
        if !book.sessions.contains(session) {
            book.sessions.push(*session);
        }
        book.moves.retain(|(former, _)| former != session);
        Ok(())
    }

    async fn is_valid(&self, user: &UserId, session: &SessionKey) -> Result<bool, Never> {
        let books = self.books.lock().unwrap();
        Ok(books
            .get(user)
            .is_some_and(|book| book.sessions.contains(session)))
    }

    async fn invalidate_user(&self, user: &UserId) -> Result<(), Never> {
        self.books.lock().unwrap().remove(user);
        Ok(())
    }

    async fn invalidate_session(&self, user: &UserId, session: &SessionKey) -> Result<(), Never> {
        let mut books = self.books.lock().unwrap();
        if let Some(book) = books.get_mut(user) {
            let target = book.current(session);
            book.sessions.retain(|s| s != session && Some(*s) != target);
            book.moves
                .retain(|(former, now)| former != session && Some(*now) != target);
        }
        Ok(())
    }

    async fn invalidate_other_sessions(
        &self,
        user: &UserId,
        keep: &SessionKey,
    ) -> Result<CutOff, Never> {
        let mut books = self.books.lock().unwrap();
        let Some(book) = books.get_mut(user) else {
            return Ok(CutOff::NotHeld);
        };
        if book.sessions.contains(keep) {
            let ended = book
                .sessions
                .iter()
                .filter(|s| *s != keep)
                .copied()
                .collect();
            book.sessions.retain(|s| s == keep);
            book.moves.retain(|(_, now)| now == keep);
            return Ok(CutOff::KeptOne(ended));
        }
        if book.current(keep).is_none() {
            return Ok(CutOff::NotHeld);
        }
        let ended = book.sessions.clone();
        books.remove(user);
        Ok(CutOff::KeptNone(ended))
    }

    async fn move_session(
        &self,
        user: &UserId,
        old: &SessionKey,
        new: &SessionKey,
    ) -> Result<MoveOutcome, Never> {
        let mut books = self.books.lock().unwrap();
        let Some(book) = books.get_mut(user) else {
            return Ok(MoveOutcome::OldGone);
        };
        let Some(at) = book.sessions.iter().position(|s| s == old) else {
            return Ok(MoveOutcome::OldGone);
        };
        if old == new {
            return Ok(MoveOutcome::Moved);
        }
        if book.moves.len() >= MAX_MOVE_RECORDS_PER_USER {
            // The earliest record whose session was seen before is not that
            // session's first former key.
            let mut seen = HashSet::new();
            match book.moves.iter().position(|(_, now)| !seen.insert(*now)) {
                Some(given_up) => {
                    book.moves.remove(given_up);
                }
                None => return Ok(MoveOutcome::Full),
            }
        }
        book.sessions[at] = *new;
        if let Some(other) = book
            .sessions
            .iter()
            .enumerate()
            .position(|(n, s)| s == new && n != at)
        {
            book.sessions.remove(other);
        }
        for (_, now) in &mut book.moves {
            if now == old {
                *now = *new;
            }
        }
        book.moves
            .retain(|(former, _)| former != new && former != old);
        book.moves.push((*old, *new));
        Ok(MoveOutcome::Moved)
    }

    async fn current_key(
        &self,
        user: &UserId,
        session: &SessionKey,
    ) -> Result<Option<SessionKey>, Never> {
        let books = self.books.lock().unwrap();
        Ok(books.get(user).and_then(|book| book.current(session)))
    }

    async fn active_sessions(&self, user: &UserId) -> Result<Vec<SessionKey>, Never> {
        let books = self.books.lock().unwrap();
        Ok(books
            .get(user)
            .map(|book| book.sessions.clone())
            .unwrap_or_default())
    }
}

#[tokio::test]
async fn a_registry_of_ones_own_keeps_the_registry_contract_through_the_facade() {
    axess::testing::registry_contract::assert_registry_contract(&OwnRegistry::default()).await;
}
