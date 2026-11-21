//! Valkey implementations of [`SidStore`] and [`LogoutReplayLog`], so
//! back-channel logout works across instances.
//!
//! Every operation is one Lua script, so a mapping, its session record and
//! its indexes change together. Scripts address keys beyond the ones they
//! are passed (the subject and session records they read out of a record),
//! so on a cluster every key of the store must hash to one slot. The store
//! puts its whole prefix in a hash tag, so its keys share one slot on any
//! cluster with no setting of the operator's; a prefix that is empty or
//! begins with `}` would split them and is refused. The replay log's keys
//! are single: each of its scripts takes one key.
//!
//! # Keys
//!
//! `<prefix>` is the store's prefix (default `axess:logout`); the braces
//! around it are literal characters, the hash tag. `<key>` is the session's
//! [`SessionKey`], 64 hexadecimal characters.
//!
//! - `{<prefix>}:v2:sid:<issuer>:<sid>`: the mapping, one JSON record that
//!   names its session by the key, expiring after the `sid` time to live.
//! - `{<prefix>}:v2:sub:<issuer>:<subject>`: a hash from session key to
//!   `{user, tenant}`, the subject registry.
//! - `{<prefix>}:v2:ses:<key>`: the session's subject record, and
//!   `{<prefix>}:v2:ses:<key>:sids`: the set of mapping keys that name it.
//! - `<prefix>:jti:<issuer>:<jti>`: one replay-log pair, under the replay
//!   log's own prefix.
//!
//! Strings that come from a token are length-prefixed in a key, so two
//! different pairs never share one. No key, field or value of the store
//! holds a session id. Records an earlier release wrote under
//! `<prefix>:sid:`, `<prefix>:sub:` and `<prefix>:ses:` named sessions by
//! their ids; they are never read, and expire by their time to live.

use std::time::Duration;

use axess_clock::Timestamp;
use fred::prelude::*;
use serde::{Deserialize, Serialize};

use super::replay_log::{LogoutReplayLog, Recorded, ReplayFuture, ReplayLogError};
use super::sid_map::{DisplacedSid, SidEntry, SidKey};
use super::sid_store::{SidFuture, SidStore, SidStoreError};
use crate::authn::ids::{TenantId, UserId};
use crate::session::id::SessionKey;
use axess_factors::oidc::logout_token::JTI_RETENTION;

/// Default time to live of a `sid` mapping: a day and an hour, past the
/// in-process map's 24 hour prune.
pub const DEFAULT_SID_TTL: Duration = Duration::from_secs(25 * 3600);

/// Default time to live of a subject record: thirty days. A session that
/// outlives it is no longer found by a `sub` logout.
pub const DEFAULT_SUBJECT_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long a pair stays in flight if its instance dies before settling it.
const IN_FLIGHT_SECS: u64 = 120;

const DEFAULT_PREFIX: &str = "axess:logout";

/// What every method of a [`ValkeySidStore`] answers when its prefix cannot
/// be put in a hash tag.
const REFUSED_PREFIX: &str = "the sid store's key prefix is empty or begins with a closing brace: \
     its keys would lie in different cluster slots";

const INSERT: &str = r#"
local old = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SADD', KEYS[2], KEYS[1])
redis.call('EXPIRE', KEYS[2], ARGV[2])
if old then
  local o = cjson.decode(old)
  if o.s ~= ARGV[3] then
    redis.call('SREM', ARGV[4] .. o.s .. ':sids', KEYS[1])
  end
  return old
end
return false
"#;

const RESTORE: &str = r#"
if redis.call('EXISTS', KEYS[2]) == 0 then return 0 end
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SADD', KEYS[3], KEYS[1])
redis.call('EXPIRE', KEYS[3], ARGV[2])
return 1
"#;

const REMOVE_IF: &str = r#"
local cur = redis.call('GET', KEYS[1])
if not cur then return false end
local rec = cjson.decode(cur)
if rec.s ~= ARGV[1] then return false end
redis.call('DEL', KEYS[1])
redis.call('SREM', ARGV[2] .. rec.s .. ':sids', KEYS[1])
return cur
"#;

const REGISTER: &str = r#"
local old = redis.call('GET', KEYS[1])
if old then
  local o = cjson.decode(old)
  if o.k ~= KEYS[2] then redis.call('HDEL', o.k, ARGV[3]) end
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[4])
redis.call('HSET', KEYS[2], ARGV[3], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[4])
return 1
"#;

const FORGET: &str = r#"
local cur = redis.call('GET', KEYS[1])
if not cur then return 0 end
local r = cjson.decode(cur)
if r.i ~= ARGV[1] or r.u ~= ARGV[2] then return 0 end
redis.call('HDEL', r.k, ARGV[3])
redis.call('DEL', KEYS[1])
return 1
"#;

const REMOVE_SESSION: &str = r#"
local n = 0
for _, ek in ipairs(redis.call('SMEMBERS', KEYS[2])) do
  local cur = redis.call('GET', ek)
  if cur and cjson.decode(cur).s == ARGV[1] then
    redis.call('DEL', ek)
    n = n + 1
  end
end
redis.call('DEL', KEYS[2])
local cur = redis.call('GET', KEYS[1])
if cur then
  local r = cjson.decode(cur)
  redis.call('HDEL', r.k, ARGV[1])
  redis.call('DEL', KEYS[1])
end
return n
"#;

const RECORD_JTI: &str = r#"
local cur = redis.call('GET', KEYS[1])
if not cur then
  redis.call('SET', KEYS[1], 'f', 'EX', ARGV[1])
  return 'new'
end
if cur == 'f' then return 'inflight' end
return 'replay'
"#;

/// One `sid` mapping as stored.
#[derive(Serialize, Deserialize)]
struct SidRecord {
    /// IdP subject.
    sub: String,
    /// Tenant, when the login was recorded for one.
    t: Option<String>,
    /// Local user.
    u: String,
    /// The local session's key, 64 hexadecimal characters.
    s: String,
    /// Insertion time, microseconds since the epoch.
    at: i64,
}

/// One session's subject record as stored.
#[derive(Serialize)]
struct SessionRecord<'a> {
    /// Issuer.
    i: &'a str,
    /// Local user.
    u: String,
    /// The subject hash this session is listed in.
    k: &'a str,
}

/// One subject-registry value as stored.
#[derive(Serialize, Deserialize)]
struct SubjectValue {
    u: String,
    t: Option<String>,
}

/// A part of a key that came from a token: length-prefixed, so two different
/// parts never run together.
fn part(s: &str) -> String {
    format!("{}:{s}", s.len())
}

/// The text every key of a [`ValkeySidStore`] begins with: `{<prefix>}:v2`.
///
/// Why this puts every key of the store in one cluster slot. A cluster hashes
/// a key by the text between its first `{` and the first `}` after that one,
/// when that text is not empty, and by the whole key otherwise. The first
/// `{` of every key built here is the one this function writes, at the
/// start. The first `}` after it is the first `}` inside the prefix when the
/// prefix holds one, and else the one this function writes after the prefix.
/// Either way the tag is the prefix up to its first `}`, a text that depends
/// on the prefix alone and is not empty unless the prefix is empty or begins
/// with `}`. What follows the stem (an issuer, a subject, a `sid` a provider
/// chose, braces included) cannot move either brace, so for every other
/// prefix all keys of the store share one slot, whatever the token held.
/// The two forms that would leave the tag empty are refused here, and every
/// method fails before it sends anything.
///
/// The `v2` part keeps the names of this release apart from those an
/// earlier release wrote, whose records named a session by its id: none of
/// those is ever read.
fn key_stem(prefix: &str) -> Result<String, SidStoreError> {
    if prefix.is_empty() || prefix.starts_with('}') {
        return Err(SidStoreError(REFUSED_PREFIX.to_string()));
    }
    Ok(format!("{{{prefix}}}:v2"))
}

fn fail(e: impl std::fmt::Display) -> SidStoreError {
    SidStoreError(e.to_string())
}

fn secs(ttl: Duration) -> String {
    ttl.as_secs().max(1).to_string()
}

fn micros(at: Timestamp) -> i64 {
    at.unix_micros()
}

fn from_micros(at: i64) -> Timestamp {
    Timestamp::from_unix_micros(at).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// A [`SidStore`] on Valkey (or Redis). See the [module docs](self).
#[derive(Clone)]
pub struct ValkeySidStore {
    client: Client,
    prefix: String,
    sid_ttl: Duration,
    subject_ttl: Duration,
}

impl ValkeySidStore {
    /// A store on `client`, which the caller built and `init()`ed.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.to_string(),
            sid_ttl: DEFAULT_SID_TTL,
            subject_ttl: DEFAULT_SUBJECT_TTL,
        }
    }

    /// Key prefix (default `axess:logout`). The store puts it in a hash tag
    /// (`{<prefix>}`), so every key it writes lies in one cluster slot. A
    /// prefix that is empty or begins with `}` cannot be: every method of a
    /// store given one answers a [`SidStoreError`] and sends nothing.
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        if key_stem(&self.prefix).is_err() {
            tracing::error!(
                "ValkeySidStore::with_prefix: {REFUSED_PREFIX}; every call of this store fails"
            );
        }
        self
    }

    /// Time to live of a `sid` mapping (default [`DEFAULT_SID_TTL`]).
    #[must_use]
    pub fn with_sid_ttl(mut self, ttl: Duration) -> Self {
        self.sid_ttl = ttl;
        self
    }

    /// Time to live of a subject record (default [`DEFAULT_SUBJECT_TTL`]).
    #[must_use]
    pub fn with_subject_ttl(mut self, ttl: Duration) -> Self {
        self.subject_ttl = ttl;
        self
    }

    fn sid_key(&self, key: &SidKey) -> Result<String, SidStoreError> {
        let stem = key_stem(&self.prefix)?;
        Ok(format!("{stem}:sid:{}:{}", part(&key.0), part(&key.1)))
    }

    fn subject_key(&self, issuer: &str, subject: &str) -> Result<String, SidStoreError> {
        let stem = key_stem(&self.prefix)?;
        Ok(format!("{stem}:sub:{}:{}", part(issuer), part(subject)))
    }

    fn session_record_key(&self, session: &SessionKey) -> Result<String, SidStoreError> {
        Ok(format!("{}{session}", self.sessions_stem()?))
    }

    fn sids_key(&self, session: &SessionKey) -> Result<String, SidStoreError> {
        Ok(format!("{}:sids", self.session_record_key(session)?))
    }

    /// The stem the scripts append `<key>:sids` to.
    fn sessions_stem(&self) -> Result<String, SidStoreError> {
        Ok(format!("{}:ses:", key_stem(&self.prefix)?))
    }

    async fn run<T: FromValue>(
        &self,
        script: &'static str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> Result<T, SidStoreError> {
        self.client.eval(script, keys, args).await.map_err(fail)
    }

    /// The entry a stored mapping names. Its session is a key's 64
    /// characters; any other text was not written by this store and fails
    /// the call.
    fn entry(record: &SidRecord) -> Result<SidEntry, SidStoreError> {
        Ok((
            record.u.parse::<UserId>().map_err(fail)?,
            record.s.parse::<SessionKey>().map_err(fail)?,
            from_micros(record.at),
        ))
    }

    fn tenant_of(record: &SidRecord) -> Option<TenantId> {
        record.t.as_deref().and_then(|t| t.parse().ok())
    }

    /// Whether a record recorded for `recorded` is visible to `scope`.
    fn visible(recorded: Option<&str>, scope: Option<&TenantId>) -> bool {
        match scope {
            None => true,
            Some(tenant) => recorded == Some(tenant.to_string().as_str()),
        }
    }

    async fn insert_record(
        &self,
        key: &SidKey,
        subject: &str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
        at: Timestamp,
    ) -> Result<Option<SidRecord>, SidStoreError> {
        key_stem(&self.prefix)?;
        let record = SidRecord {
            sub: subject.to_string(),
            t: tenant.map(|t| t.to_string()),
            u: user.to_string(),
            s: session.to_string(),
            at: micros(at),
        };
        let json = serde_json::to_string(&record).map_err(fail)?;
        let old: Option<String> = self
            .run(
                INSERT,
                vec![self.sid_key(key)?, self.sids_key(&session)?],
                vec![
                    json,
                    secs(self.sid_ttl),
                    session.to_string(),
                    self.sessions_stem()?,
                ],
            )
            .await?;
        old.map(|o| serde_json::from_str(&o).map_err(fail))
            .transpose()
    }
}

impl SidStore for ValkeySidStore {
    fn insert_displacing<'a>(
        &'a self,
        key: SidKey,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
        inserted_at: Timestamp,
    ) -> SidFuture<'a, Option<DisplacedSid>> {
        Box::pin(async move {
            let Some(old) = self
                .insert_record(&key, subject, tenant, user, session, inserted_at)
                .await?
            else {
                return Ok(None);
            };
            let (user, session, at) = Self::entry(&old)?;
            Ok(Some(DisplacedSid {
                subject: old.sub.clone(),
                tenant: Self::tenant_of(&old),
                user,
                session,
                inserted_at: at,
            }))
        })
    }

    fn restore_if_vacant(&self, key: SidKey, displaced: DisplacedSid) -> SidFuture<'_, bool> {
        Box::pin(async move {
            key_stem(&self.prefix)?;
            let record = SidRecord {
                sub: displaced.subject,
                t: displaced.tenant.map(|t| t.to_string()),
                u: displaced.user.to_string(),
                s: displaced.session.to_string(),
                at: micros(displaced.inserted_at),
            };
            let json = serde_json::to_string(&record).map_err(fail)?;
            let restored: i64 = self
                .run(
                    RESTORE,
                    vec![
                        self.sid_key(&key)?,
                        self.session_record_key(&displaced.session)?,
                        self.sids_key(&displaced.session)?,
                    ],
                    vec![json, secs(self.sid_ttl)],
                )
                .await?;
            Ok(restored == 1)
        })
    }

    fn get<'a>(
        &'a self,
        key: &'a SidKey,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Option<SidEntry>> {
        Box::pin(async move {
            let raw: Option<String> = self.client.get(self.sid_key(key)?).await.map_err(fail)?;
            let Some(raw) = raw else { return Ok(None) };
            let record: SidRecord = serde_json::from_str(&raw).map_err(fail)?;
            if !Self::visible(record.t.as_deref(), scope) {
                return Ok(None);
            }
            Self::entry(&record).map(Some)
        })
    }

    fn remove_if_session<'a>(
        &'a self,
        key: &'a SidKey,
        session: &'a SessionKey,
    ) -> SidFuture<'a, Option<SidEntry>> {
        Box::pin(async move {
            let removed: Option<String> = self
                .run(
                    REMOVE_IF,
                    vec![self.sid_key(key)?],
                    vec![session.to_string(), self.sessions_stem()?],
                )
                .await?;
            let Some(raw) = removed else { return Ok(None) };
            let record: SidRecord = serde_json::from_str(&raw).map_err(fail)?;
            let entry = Self::entry(&record)?;
            self.forget_subject_session(&key.0, &entry.0, session)
                .await?;
            Ok(Some(entry))
        })
    }

    fn register_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        tenant: Option<TenantId>,
        user: UserId,
        session: SessionKey,
    ) -> SidFuture<'a, ()> {
        Box::pin(async move {
            let subject_key = self.subject_key(issuer, subject)?;
            let record_key = self.session_record_key(&session)?;
            let record = serde_json::to_string(&SessionRecord {
                i: issuer,
                u: user.to_string(),
                k: &subject_key,
            })
            .map_err(fail)?;
            let value = serde_json::to_string(&SubjectValue {
                u: user.to_string(),
                t: tenant.map(|t| t.to_string()),
            })
            .map_err(fail)?;
            let _: i64 = self
                .run(
                    REGISTER,
                    vec![record_key, subject_key],
                    vec![record, value, session.to_string(), secs(self.subject_ttl)],
                )
                .await?;
            Ok(())
        })
    }

    fn forget_subject_session<'a>(
        &'a self,
        issuer: &'a str,
        user: &'a UserId,
        session: &'a SessionKey,
    ) -> SidFuture<'a, bool> {
        Box::pin(async move {
            let forgot: i64 = self
                .run(
                    FORGET,
                    vec![self.session_record_key(session)?],
                    vec![issuer.to_string(), user.to_string(), session.to_string()],
                )
                .await?;
            Ok(forgot == 1)
        })
    }

    fn subject_sessions<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        scope: Option<&'a TenantId>,
    ) -> SidFuture<'a, Vec<(UserId, SessionKey)>> {
        Box::pin(async move {
            let flat: Vec<String> = self
                .client
                .hgetall(self.subject_key(issuer, subject)?)
                .await
                .map_err(fail)?;
            let mut out = Vec::new();
            for pair in flat.chunks(2) {
                let [session, value] = pair else { continue };
                let value: SubjectValue = serde_json::from_str(value).map_err(fail)?;
                if !Self::visible(value.t.as_deref(), scope) {
                    continue;
                }
                out.push((
                    value.u.parse::<UserId>().map_err(fail)?,
                    session.parse::<SessionKey>().map_err(fail)?,
                ));
            }
            out.sort_unstable();
            Ok(out)
        })
    }

    fn sweep_subject_candidates(
        &self,
        _: usize,
    ) -> SidFuture<'_, Vec<(String, UserId, SessionKey)>> {
        // Subject records expire with their time to live.
        Box::pin(async move {
            key_stem(&self.prefix)?;
            Ok(Vec::new())
        })
    }

    fn remove_session<'a>(&'a self, session: &'a SessionKey) -> SidFuture<'a, usize> {
        Box::pin(async move {
            let removed: i64 = self
                .run(
                    REMOVE_SESSION,
                    vec![self.session_record_key(session)?, self.sids_key(session)?],
                    vec![session.to_string()],
                )
                .await?;
            Ok(usize::try_from(removed).unwrap_or(0))
        })
    }

    fn evict_inserted_before(
        &self,
        _: Timestamp,
        _: usize,
    ) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async move {
            key_stem(&self.prefix)?;
            Ok(Vec::new())
        })
    }

    fn evict_oldest(&self, _: usize) -> SidFuture<'_, Vec<(SidKey, SidEntry)>> {
        Box::pin(async move {
            key_stem(&self.prefix)?;
            Ok(Vec::new())
        })
    }

    fn mapping_count(&self) -> SidFuture<'_, usize> {
        Box::pin(async move {
            key_stem(&self.prefix)?;
            Ok(0)
        })
    }
}

/// A [`LogoutReplayLog`] on Valkey (or Redis). See the [module docs](self).
#[derive(Clone)]
pub struct ValkeyReplayLog {
    client: Client,
    prefix: String,
}

impl ValkeyReplayLog {
    /// A log on `client`, which the caller built and `init()`ed.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            prefix: DEFAULT_PREFIX.to_string(),
        }
    }

    /// Key prefix (default `axess:logout`).
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, issuer: &str, jti: &str) -> String {
        format!("{}:jti:{}:{}", self.prefix, part(issuer), part(jti))
    }
}

fn replay_fail(e: impl std::fmt::Display) -> ReplayLogError {
    ReplayLogError(e.to_string())
}

impl LogoutReplayLog for ValkeyReplayLog {
    fn record<'a>(
        &'a self,
        issuer: &'a str,
        jti: &'a str,
        _: Timestamp,
    ) -> ReplayFuture<'a, Recorded> {
        Box::pin(async move {
            let verdict: String = self
                .client
                .eval(
                    RECORD_JTI,
                    vec![self.key(issuer, jti)],
                    vec![IN_FLIGHT_SECS.to_string()],
                )
                .await
                .map_err(replay_fail)?;
            match verdict.as_str() {
                "new" => Ok(Recorded::New),
                "inflight" => Ok(Recorded::InFlight),
                "replay" => Ok(Recorded::Replay),
                other => Err(ReplayLogError(format!("unexpected reply {other:?}"))),
            }
        })
    }

    fn settle<'a>(&'a self, issuer: &'a str, jti: &'a str) -> ReplayFuture<'a, ()> {
        Box::pin(async move {
            let _: () = self
                .client
                .set(
                    self.key(issuer, jti),
                    "s",
                    Some(Expiration::EX(
                        i64::try_from(JTI_RETENTION.as_secs()).unwrap_or(i64::MAX),
                    )),
                    None,
                    false,
                )
                .await
                .map_err(replay_fail)?;
            Ok(())
        })
    }

    fn forget<'a>(&'a self, issuer: &'a str, jti: &'a str) -> ReplayFuture<'a, ()> {
        Box::pin(async move {
            let _: i64 = self
                .client
                .del(self.key(issuer, jti))
                .await
                .map_err(replay_fail)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod name_tests;
