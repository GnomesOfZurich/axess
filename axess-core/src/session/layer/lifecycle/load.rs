//! The row behind a verified session cookie: read it, vet it, and end the
//! session it holds when the checks refuse it.
//!
//! [`load_stored_session`] is the store half of
//! [`load_session`](super::load_session). It answers with the row it
//! trusts, or with a fresh guest: for no row, a row below the current
//! schema version, a store that cannot answer, a session another request is
//! ending, and a session it ended itself. [`load_current`] is the read every
//! other step of the layer makes of a stored row.

use crate::session::config::SessionConfig;
use crate::session::data::{SESSION_DATA_VERSION, SessionData};
use crate::session::id::SessionKey;
use crate::session::layer::audit::SessionEndReason;
use crate::session::layer::swap::StoreError;
use crate::session::store::SessionStore;

use super::{LoadPolicy, SessionVerdict, authenticated_session_verdict, ending};

/// The stored record behind a verified session cookie, as the load found it.
pub(super) struct StoredSession {
    /// The row under the cookie's session is trusted so far.
    pub(super) stored: bool,
    pub(super) data: SessionData,
    /// The row as the store held it, before re-binding.
    pub(super) loaded_row: Option<SessionData>,
    /// The row was refused as revoked or too old, and this request ended
    /// it: recorded, then removed.
    pub(super) session_ended: bool,
}

impl StoredSession {
    /// No trusted row: the request runs as a fresh guest.
    pub(super) fn fresh() -> Self {
        Self {
            stored: false,
            data: SessionData::default(),
            loaded_row: None,
            session_ended: false,
        }
    }
}

/// Load and vet the row of a session whose cookie verified. Any failure (no
/// row, a row below the current schema version, a store error, a revoked or
/// over-age record) yields a fresh guest. A row below the version is no
/// session of this release, whoever put it there: it is counted and logged,
/// and left as it lies (not written, not deleted, not claimed, so no ending
/// is made outside the ending protocol and no audit row names it); it
/// expires with its lifetime. A revoked or over-age session is ended on the way: claimed,
/// recorded and removed, in that order ([`ending::StoredEnding`]). One that
/// another request is ending, or whose ending could not be recorded, is
/// refused and its row left alone. One that carries a claim older than its
/// lease is ended here, for the reason the claim holds, whatever the
/// checks would say of it now.
pub(super) async fn load_stored_session<S>(
    store: &S,
    key: &SessionKey,
    config: &SessionConfig,
    policy: &LoadPolicy<'_>,
) -> StoredSession
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match store.load(key).await {
        Ok(Some(data)) if data.version < SESSION_DATA_VERSION => {
            if let Some(m) = policy.metrics {
                m.session.session_row_refused();
            }
            tracing::warn!(
                session = %key.prefix(),
                version = data.version,
                current = SESSION_DATA_VERSION,
                "a stored session below the current schema version was not served"
            );
            StoredSession::fresh()
        }
        Ok(Some(mut data)) => {
            // Whether a request proved the device is that request's own
            // answer. No row says it for the next one, whatever a store
            // that keeps the value as it was handed over returns.
            data.device_proven = false;
            data.device_key = None;
            data.key_proven = false;
            let row = data.clone();
            let now = policy.clock.now();
            if let Some(claim) = row.ending {
                if claim.holds_at(now) {
                    tracing::debug!("another request is ending this session; refusing it");
                    return StoredSession::fresh();
                }
                // The request that claimed the session did not finish. The
                // claim is the decision to end it and the audit row may
                // already be written, so this request finishes the ending
                // and the session is not judged again.
                tracing::info!("finishing the ending of a session an earlier request claimed");
                let decided = Decided {
                    row,
                    key: *key,
                    reason: claim.reason,
                    now,
                    resumed: true,
                };
                return end_at_load(store, config, policy, decided).await;
            }
            match authenticated_session_verdict(&data, config, policy, key).await {
                SessionVerdict::Keep => StoredSession {
                    stored: true,
                    data,
                    loaded_row: Some(row),
                    session_ended: false,
                },
                SessionVerdict::End(reason) => {
                    let decided = Decided {
                        row,
                        key: *key,
                        reason,
                        now,
                        resumed: false,
                    };
                    end_at_load(store, config, policy, decided).await
                }
                SessionVerdict::Distrust => StoredSession::fresh(),
            }
        }
        Ok(None) => StoredSession::fresh(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "session store load failed; falling back to empty session"
            );
            StoredSession::fresh()
        }
    }
}

/// Read the row under `key`, refusing one below the current schema
/// version: it is no session of this release, whoever put it there.
///
/// Every read of a stored row after the load goes through this (the merge
/// of a rotation, the merging write, the release of a claim, the ending of
/// a failed rotation), so a row put under the key while the request ran is
/// held to the same rule as the row the load read. Such a row is an error,
/// which each caller handles as the store error it already handles.
pub(crate) async fn load_current<S>(
    store: &S,
    key: &SessionKey,
) -> Result<Option<SessionData>, StoreError>
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    match store.load(key).await.map_err(StoreError::from)? {
        Some(data) if data.version < SESSION_DATA_VERSION => Err(Box::new(BelowVersion {
            version: data.version,
        })),
        row => Ok(row),
    }
}

/// A stored row below the current schema version, read where a session was
/// expected.
#[derive(Debug, thiserror::Error)]
#[error(
    "the stored session is below the current schema version \
     (version {version}, current {SESSION_DATA_VERSION})"
)]
struct BelowVersion {
    version: u8,
}

/// A stored session the load has decided to end.
struct Decided {
    /// The row as the store holds it.
    row: SessionData,
    /// The key of the session the cookie names.
    key: SessionKey,
    reason: SessionEndReason,
    /// The layer's clock at the load.
    now: axess_clock::Timestamp,
    /// The decision was an earlier request's, read from the claim it left.
    resumed: bool,
}

/// End a stored session: revoked or too old, its row must not stay
/// `Authenticated`. The request runs as a fresh guest whatever becomes of
/// the ending; its cookie is replaced only when this request ended the
/// session.
async fn end_at_load<S>(
    store: &S,
    config: &SessionConfig,
    policy: &LoadPolicy<'_>,
    decided: Decided,
) -> StoredSession
where
    S: SessionStore + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Decided {
        row,
        key,
        reason,
        now,
        resumed,
    } = decided;
    let entries = ending::entries_left(&row, key);
    let Some(ended) = ending::ended_record(&row, key, reason) else {
        // Not a signed-in session, so its ending is nobody's audit row.
        // The layer claims signed-in sessions only; a claim found on any
        // other row is cleared by removing the row, so that it cannot keep
        // the cookie refused.
        if resumed && let Err(e) = store.delete(&key).await {
            tracing::error!(
                error = %e,
                "deleting a claimed session that is not signed in failed"
            );
        }
        return StoredSession::fresh();
    };
    let stored_ending = ending::StoredEnding {
        store: store.clone(),
        audit: policy.audit.clone(),
        what: ending::Ending {
            row,
            ended,
            now,
            ttl: config.ttl,
            resumed,
        },
    };
    match stored_ending.run_detached().await {
        ending::Ended::Done => {
            ending::release_entries(policy.registry, &entries).await;
            StoredSession {
                session_ended: true,
                ..StoredSession::fresh()
            }
        }
        ending::Ended::Deferred => StoredSession::fresh(),
    }
}
