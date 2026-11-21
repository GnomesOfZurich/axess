//! What a handler and the authentication service know of the registry entry
//! behind a session: the key the registry holds it under, as far as this
//! request knows, and whether the session layer moves that entry when the
//! session's key rotates.
//!
//! A rotation within a request changes the key the response cookie names
//! at once, but the registry keeps holding the key the request arrived with
//! (or the one a login in this request registered) until the layer moves
//! the entry, after the row has moved. Whatever asks the registry about the
//! session during the request asks for the key it holds.

use super::AuthSession;
use crate::authn::ids::UserId;
use crate::session::id::SessionKey;
use crate::session::layer::{LayerSessionEnded, SessionEndReason};

impl AuthSession {
    /// The key the registry holds this session under, as far as this
    /// request knows: the key the request arrived with, or the one a login
    /// in this request registered, whatever was rotated since. What a
    /// cut-off of the other sessions keeps, and what a registry check of
    /// this request asks for.
    ///
    /// For a session nothing is known to be registered for (a guest, or a
    /// session another person signed in on in this request without a
    /// registration) it is [`session_key`](Self::session_key). Reading it
    /// marks the session as needed beyond this request, as `session_key`
    /// does.
    pub async fn registered_key(&self) -> SessionKey {
        let mut guard = self.0.0.write().await;
        guard.needs_persist = true;
        guard.registered_key()
    }

    /// The entry behind [`registered_key`](Self::registered_key), when one
    /// is known.
    pub(crate) async fn registered(&self) -> Option<(UserId, SessionKey)> {
        self.0.0.read().await.registered
    }

    /// A handler registered, or moved, the session's entry under `key`
    /// itself. Returns the entry this replaces when that entry was another
    /// user's: the caller ends it, since the session is no longer that
    /// user's.
    pub(crate) async fn note_registered(
        &self,
        user_id: &UserId,
        key: SessionKey,
    ) -> Option<(UserId, SessionKey)> {
        let mut guard = self.0.0.write().await;
        guard
            .registered
            .replace((*user_id, key))
            .filter(|(replaced, _)| replaced != user_id)
    }

    /// Whether the layer moves the entry of a rotated session.
    pub(crate) async fn layer_moves_registry(&self) -> bool {
        self.0.0.read().await.layer_moves_registry
    }

    /// End the session through the layer: the handle becomes a guest's at
    /// once (as [`clear`](Self::clear) makes it), and the stored session is
    /// ended by the finish with its record. Returns the record when no
    /// stored row and no layer stand behind this handle, for the caller to
    /// hand to its own sink.
    pub(crate) async fn end_through_layer(
        &self,
        reason: SessionEndReason,
    ) -> Option<LayerSessionEnded> {
        self.0.0.write().await.end_through_layer(reason)
    }
}
