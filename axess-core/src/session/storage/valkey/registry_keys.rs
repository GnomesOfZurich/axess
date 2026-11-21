//! The names of one user's registry keys, and the check that they share a
//! cluster slot.

use super::internal::ValkeyStoreError;
use crate::authn::ids::UserId;
use fred::util::redis_keyslot;

/// The keys that hold one user's registry entries, all in one cluster slot.
pub(super) struct UserKeys {
    /// The sorted set of the user's sessions, scored by when each was last
    /// seen: liveness.
    pub(super) registry: String,
    /// The sorted set beside it that holds when each session was
    /// registered, never moved by use. The registry set's score slides
    /// forward as a session is used, so it says when the session was last
    /// seen; this one says which session is the oldest.
    pub(super) registered_at: String,
    /// The hash of the user's move records: field = a former key, value =
    /// the key that session is under now.
    pub(super) forward: String,
    /// The sorted set beside it that holds the same former keys, each
    /// scored by its place in the order the user's moves were made.
    pub(super) forward_order: String,
}

impl UserKeys {
    /// The four keys in the order the registry's scripts take them:
    /// `[registry, registered_at, forward, forward_order]`.
    pub(super) fn all(&self) -> Vec<String> {
        vec![
            self.registry.clone(),
            self.registered_at.clone(),
            self.forward.clone(),
            self.forward_order.clone(),
        ]
    }
}

/// The text of the refusal of a prefix under which one user's registry keys
/// would not share a cluster slot.
pub(super) const PREFIX_SPLITS_A_USER: &str = "the registry's key prefix opens a hash tag it does not close: one user's keys would lie in different cluster slots";

/// Build the keys of `user`'s registry entries under `prefix`, or refuse
/// when they would not share a cluster slot.
///
/// Every per-user key is `prefix || ":<name>:{" || <user> || "}"`, where
/// `<user>` is the hyphenated text of the id, formatted here: a `UserId` is a
/// UUID, whose text is `0-9a-f` and `-` only, so it holds no brace whoever
/// the caller is. A cluster hashes a key by the text between its first `{`
/// and the first `}` after it when that text is not empty, and by the whole
/// key otherwise. So:
///
/// - a prefix with no `{`: the first `{` is the one before `<user>` and the
///   first `}` after it closes `<user>`, so every key hashes by the user id
///   alone and a user's keys share its slot;
/// - a prefix whose first `{` is closed inside it around at least one
///   character (`{axess}`): that tag decides for every key, and every user's
///   keys share the tag's one slot, as the adopter chose by tagging it;
/// - any other prefix (one that opens a brace it does not close, `a{b`, or
///   holds `{}` first): the tag, or the whole key, spans the key's own name,
///   and the keys can hash apart.
///
/// The guarantee is therefore not assumed from the prefix's text but made
/// here for every prefix: the slot of each key built is computed and the
/// keys are returned only when every slot is the same. A registry call
/// either runs on keys in one slot or runs nothing and fails with
/// [`ValkeyStoreError::Unsupported`]. The check does not ask whether the
/// client is clustered: it is a property of the keys, so a deployment learns
/// it on a single node before it moves to a cluster.
pub(super) fn user_keys(prefix: &str, user: &UserId) -> Result<UserKeys, ValkeyStoreError> {
    let keys = UserKeys {
        registry: format!("{prefix}:reg:{{{user}}}"),
        registered_at: format!("{prefix}:reg-at:{{{user}}}"),
        forward: format!("{prefix}:fwd:{{{user}}}"),
        forward_order: format!("{prefix}:fwd-at:{{{user}}}"),
    };
    let slots = [
        &keys.registry,
        &keys.registered_at,
        &keys.forward,
        &keys.forward_order,
    ]
    .map(|key| redis_keyslot(key.as_bytes()));
    if slots.iter().all(|slot| *slot == slots[0]) {
        Ok(keys)
    } else {
        Err(ValkeyStoreError::Unsupported(PREFIX_SPLITS_A_USER))
    }
}
