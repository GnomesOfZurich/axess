//! `OurBackend`; implements both [`IdentityStore`] and [`FactorStore`] against SQLite.
//!
//! This is the only application-specific type needed for authentication.
//! All identity and factor data live in the same SQLite pool. Each trait
//! group is split into its own sub-module to keep the surface readable:
//!
//! - [`identity`] ; `IdentityLookup`, `IdentityAuthnLog`, `IdentityAdmin`
//! - [`factors`]  ; `FactorStore`
//! - [`audit`]    ; `AuditQuery`
//! - [`refresh`]  ; `RefreshTokenStore`
//! - [`seed`]     ; first-boot data: a default tenant + alice/bob test users

use axess::authn::{EntityState, StatusDetail, Tenant, TenantId, User, UserId};
use axess::{Clock, SystemClock};
use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;

mod audit;
mod factors;
mod identity;
mod refresh;
mod seed;

pub use seed::seed;

// ── OurBackend ────────────────────────────────────────────────────────────────

/// SQLite-backed identity and factor store.
///
/// Implements both [`IdentityStore`] and [`FactorStore`]. Pass `backend.clone()` for
/// both type parameters when constructing `AuthnService`.
#[derive(Clone)]
pub struct OurBackend {
    pool: SqlitePool,
    // Source of `now` for audit timestamps, lock-expiry checks, and every
    // other time-of-write decision in the trait impls. Defaults to
    // `SystemClock`; swap in a `MockClock` to run DST tests against this
    // backend without monkey-patching `chrono`.
    clock: Arc<dyn Clock>,
}

impl OurBackend {
    /// Default ctor; uses wall-clock time via `SystemClock`.
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            clock: Arc::new(SystemClock),
        }
    }

    /// Swap the clock. Tests pin time by passing a `MockClock`; production
    /// keeps the default `SystemClock` from [`new`].
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Return a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Borrow the injected clock so handlers can mint timestamps that route
    /// through the same DST surface as the backend's internal writes
    /// (lock checks, audit `created_at`, etc.).
    pub fn clock(&self) -> &dyn Clock {
        &*self.clock
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// `FactorStore::save_method` / `remove_method` / `set_method_enabled`
    /// do not accept `AuthnScope::Global`; methods must be materialised
    /// per tenant (see `docs/tenancy.md`).
    #[error("auth methods cannot be stored at global scope")]
    InvalidGlobalMethod,
}

// ── Shared row codecs ────────────────────────────────────────────────────────
//
// Used by both `identity` (User/Tenant rows) and `refresh` (parse_db_datetime
// on issued_at/expires_at). Kept here so a future submodule can pick them up
// without re-deriving the parsing rules.

pub(super) fn user_from_row(clock: &dyn Clock, row: &sqlx::sqlite::SqliteRow) -> User {
    let id: String = row.get("id");
    let tenant_id: String = row.get("tenant_id");
    let identifier: String = row.get("identifier");
    let display_name: String = row.get("display_name");
    let status: String = row.get("status");
    let locked_until: Option<String> = row.get("locked_until");
    let created_by: String = row.get("created_by");
    let created_at: String = row.get("created_at");
    let updated_by: String = row.get("updated_by");
    let updated_at: String = row.get("updated_at");

    User {
        // The DB schema enforces NOT NULL / non-empty via CHECK constraints,
        // so these .expect() calls guard against data-corruption scenarios only.
        id: UserId::try_new(id.as_str()).expect("users.id must be a valid UserId"),
        tenant_id: TenantId::try_new(tenant_id.as_str())
            .expect("users.tenant_id must be a valid TenantId"),
        identifier: Arc::from(identifier.as_str()),
        display_name: Arc::from(display_name.as_str()),
        status: entity_state_from_db(clock, &status, locked_until.as_deref()),
        webauthn_id: None,
        created_by: UserId::try_new(created_by.as_str()).expect("users.created_by invalid"),
        created_at: parse_db_datetime(clock, &created_at),
        updated_by: UserId::try_new(updated_by.as_str()).expect("users.updated_by invalid"),
        updated_at: parse_db_datetime(clock, &updated_at),
    }
}

pub(super) fn tenant_from_row(clock: &dyn Clock, row: &sqlx::sqlite::SqliteRow) -> Tenant {
    let id: String = row.get("id");
    let identifier: String = row.get("identifier");
    let name: String = row.get("name");
    let status: String = row.get("status");
    let created_by: String = row.get("created_by");
    let created_at: String = row.get("created_at");
    let updated_by: String = row.get("updated_by");
    let updated_at: String = row.get("updated_at");

    Tenant {
        id: TenantId::try_new(id.as_str()).expect("tenants.id must be a valid TenantId"),
        identifier: Arc::from(identifier.as_str()),
        display_name: Arc::from(name.as_str()),
        status: entity_state_from_db(clock, &status, None),
        created_by: UserId::try_new(created_by.as_str()).expect("tenants.created_by invalid"),
        created_at: parse_db_datetime(clock, &created_at),
        updated_by: UserId::try_new(updated_by.as_str()).expect("tenants.updated_by invalid"),
        updated_at: parse_db_datetime(clock, &updated_at),
    }
}

/// Parse a `datetime('now')`-style SQLite timestamp.
///
/// SQLite's default uses `YYYY-MM-DD HH:MM:SS` (no timezone). Rows inserted
/// by the application use RFC 3339. Accept either; on parse failure fall
/// back to "now" rather than panic; corrupt audit timestamps shouldn't
/// take the service down.
pub(super) fn parse_db_datetime(clock: &dyn Clock, s: &str) -> DateTime<Utc> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.into();
    }
    // SQLite default format: "YYYY-MM-DD HH:MM:SS" in UTC.
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return dt.and_utc();
    }
    tracing::warn!(value = %s, "unparseable timestamp in DB row; falling back to now");
    clock.now()
}

/// Map the DB status string (and optional `locked_until` datetime) to [`EntityState`].
pub(super) fn entity_state_from_db(
    clock: &dyn Clock,
    status: &str,
    locked_until: Option<&str>,
) -> EntityState {
    let now = clock.now();
    // A locked_until in the future takes priority over the status column.
    if let Some(until_str) = locked_until
        && let Ok(until) = DateTime::parse_from_rfc3339(until_str)
    {
        let until: DateTime<Utc> = until.into();
        if until > now {
            return EntityState::Suspended(StatusDetail {
                reason: "account locked due to failed login attempts".into(),
                since: now,
                until: Some(until),
            });
        }
    }

    match status {
        "active" => EntityState::Active,
        "candidate" => EntityState::Candidate,
        "pending" => EntityState::Pending(StatusDetail {
            reason: "account pending activation".into(),
            since: now,
            until: None,
        }),
        "suspended" => EntityState::Suspended(StatusDetail {
            reason: "account suspended".into(),
            since: now,
            until: None,
        }),
        "terminated" => EntityState::Terminated(StatusDetail {
            reason: "account terminated".into(),
            since: now,
            until: None,
        }),
        "archived" => EntityState::Archived(StatusDetail {
            reason: "account archived".into(),
            since: now,
            until: None,
        }),
        _ => EntityState::Guest,
    }
}
