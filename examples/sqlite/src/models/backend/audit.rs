//! `AuditQuery` impl: tenant-scoped read with optional platform-rail
//! (`tenant_id IS NULL`) inclusion. Every returned row satisfies
//! `tenant_id = ? OR (filter.include_unscoped AND tenant_id IS NULL)`;
//! other-tenant rows are never reachable. If you copy this pattern into a
//! different backend, keep that invariant.

use axess::authn::{
    AuditQuery, AuthEvent, AuthEventStatus, AuthEventType, EventQueryFilter, FactorKind, TenantId,
    UserId,
};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Row};
use std::str::FromStr;
use tracing::warn;

use super::{BackendError, OurBackend};

impl AuditQuery for OurBackend {
    type Error = BackendError;

    async fn query_events(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> Result<Vec<AuthEvent>, Self::Error> {
        // SQLite has no real bool, so encode `include_unscoped` directly
        // into the SQL via a conditional clause. Building the WHERE string
        // from typed inputs keeps the query parameterised.
        let mut sql = String::from(
            "SELECT id, user_id, tenant_id, session_id, event_type, event_status, \
             event_time, factor_kind, ip_address, user_agent, request_id, \
             geo_country, error \
             FROM auth_events \
             WHERE (tenant_id = ?1",
        );
        if filter.include_unscoped {
            sql.push_str(" OR tenant_id IS NULL");
        }
        sql.push(')');

        // Build remaining filter clauses with positional ?N binds. The
        // bind-index counter starts at 2 because ?1 is `tenant_id`.
        let mut next = 2u32;
        let user_id_str = filter.user_id.as_ref().map(|u| u.to_string());
        if user_id_str.is_some() {
            sql.push_str(&format!(" AND user_id = ?{next}"));
            next += 1;
        }
        let event_type_str = filter.event_type.as_ref().map(|t| t.to_string());
        if event_type_str.is_some() {
            sql.push_str(&format!(" AND event_type = ?{next}"));
            next += 1;
        }
        let status_str = filter.status.as_ref().map(|s| s.to_string());
        if status_str.is_some() {
            sql.push_str(&format!(" AND event_status = ?{next}"));
            next += 1;
        }
        let from_str = filter.from.map(|t| t.to_rfc3339());
        if from_str.is_some() {
            sql.push_str(&format!(" AND event_time >= ?{next}"));
            next += 1;
        }
        let until_str = filter.until.map(|t| t.to_rfc3339());
        if until_str.is_some() {
            sql.push_str(&format!(" AND event_time < ?{next}"));
            next += 1;
        }

        // Newest first; cap with a safe default if caller didn't specify.
        sql.push_str(" ORDER BY event_time DESC LIMIT ?");
        sql.push_str(&next.to_string());
        let limit = if filter.limit == 0 {
            1000
        } else {
            filter.limit
        };

        let mut q = sqlx::query(AssertSqlSafe(sql.as_str())).bind(tenant_id.to_string());
        if let Some(u) = &user_id_str {
            q = q.bind(u);
        }
        if let Some(t) = &event_type_str {
            q = q.bind(t);
        }
        if let Some(s) = &status_str {
            q = q.bind(s);
        }
        if let Some(f) = &from_str {
            q = q.bind(f);
        }
        if let Some(u) = &until_str {
            q = q.bind(u);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(self.pool()).await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let user_id: Option<String> = row.get("user_id");
            let tenant_id: Option<String> = row.get("tenant_id");
            let session_id: Option<String> = row.get("session_id");
            let event_type: String = row.get("event_type");
            let event_status: String = row.get("event_status");
            let event_time: String = row.get("event_time");
            let factor_kind: Option<String> = row.get("factor_kind");
            let ip_address: Option<String> = row.get("ip_address");
            let user_agent: Option<String> = row.get("user_agent");
            let request_id: Option<String> = row.get("request_id");
            let geo_country: Option<String> = row.get("geo_country");
            let error: Option<String> = row.get("error");

            // A row that fails to parse means a writer corrupted the table
            // or upgraded the enum; surface as a soft warn and skip rather
            // than poisoning the entire query result.
            let event_type = match AuthEventType::from_str(&event_type) {
                Ok(t) => t,
                Err(e) => {
                    warn!(value = %event_type, error = %e, "audit row: unknown event_type, skipping");
                    continue;
                }
            };
            let event_status = match AuthEventStatus::from_str(&event_status) {
                Ok(s) => s,
                Err(e) => {
                    warn!(value = %event_status, error = %e, "audit row: unknown event_status, skipping");
                    continue;
                }
            };
            let event_time = match DateTime::parse_from_rfc3339(&event_time) {
                Ok(t) => t.with_timezone(&Utc).timestamp_micros(),
                Err(e) => {
                    warn!(value = %event_time, error = %e, "audit row: bad event_time, skipping");
                    continue;
                }
            };
            // FactorKind has no `FromStr`; round-trip is best-effort for
            // the kinds the example UI exercises. Anything unrecognised
            // becomes `None` rather than dropping the event.
            let factor_kind = factor_kind.as_deref().and_then(parse_factor_kind);

            out.push(AuthEvent {
                user_id: user_id.and_then(|u| UserId::try_new(u).ok()),
                tenant_id: tenant_id.and_then(|t| TenantId::try_new(t).ok()),
                session_id: session_id.and_then(|s| s.parse::<axess::SessionId>().ok()),
                event_type,
                event_status,
                event_time,
                factor_kind,
                ip_address,
                user_agent,
                request_id,
                geo_country,
                error,
                actor_id: None,
                // Example backend doesn't yet read a `device_id` column
                // from the SQLite audit table: the device subsystem is
                // feature-gated and the example's schema predates the
                // addition. Leave None until the example schema migrates.
                device_id: None,
                factors_completed: vec![],
            });
        }
        Ok(out)
    }
}

/// Recover a `FactorKind` from its `as_str()` representation. axess-core does
/// not ship a `FromStr` impl (the enum has feature-gated variants and a
/// `Federated(_)` payload that doesn't round-trip from a bare string), so the
/// example accepts only the kinds it actually uses for audit display.
/// Returning `None` on an unknown value keeps the audit row visible with
/// `factor_kind = None` rather than dropping it.
fn parse_factor_kind(s: &str) -> Option<FactorKind> {
    match s {
        "password" => Some(FactorKind::Password),
        "totp" => Some(FactorKind::Totp),
        "hotp" => Some(FactorKind::Hotp),
        "email-otp" => Some(FactorKind::EmailOtp),
        "fido2" => Some(FactorKind::Fido2),
        "ldap-bind" => Some(FactorKind::LdapBind),
        _ => None,
    }
}
