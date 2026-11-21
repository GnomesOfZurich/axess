//! `AuditQuery` impl: tenant-scoped read with optional platform-rail
//! (`tenant_id IS NULL`) inclusion. Every returned row satisfies
//! `tenant_id = ? OR (filter.include_unscoped AND tenant_id IS NULL)`;
//! other-tenant rows are never reachable. If you copy this pattern into a
//! different backend, keep that invariant.
//!
//! A row the reader cannot read is neither returned as an event nor dropped
//! without a trace, nor does it fail the query: the answer, an
//! [`AuditTrail`], holds the events read and how many rows could not be
//! read, by reason, so a page that shows the trail can say that something
//! is missing. The text of such a row is never returned or logged: the
//! session column may hold a value a cookie carried, and any column may hold
//! text a writer chose.

use axess::SessionKey;
use axess::Timestamp;
use axess::authn::{
    AuditQuery, AuditTrail, AuthEvent, AuthEventStatus, AuthEventType, AuthFailureReason,
    EventQueryFilter, FactorKind, TenantId, UnreadableReason, UserId,
};
use axess::client_ip::Source;
use sqlx::sqlite::SqliteRow;
use sqlx::{AssertSqlSafe, Row};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::warn;

use super::{BackendError, OurBackend};

impl OurBackend {
    async fn fetch_event_rows(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> Result<Vec<SqliteRow>, BackendError> {
        // SQLite has no real bool, so encode `include_unscoped` directly
        // into the SQL via a conditional clause. Building the WHERE string
        // from typed inputs keeps the query parameterised.
        let mut sql = String::from(
            "SELECT id, user_id, tenant_id, session_id, event_type, event_status, \
             event_time, factor_kind, ip_address, ip_source, user_agent, request_id, \
             trace_id, geo_country, error \
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
        let from_str = filter.from.map(|t| t.to_rfc3339_numeric_offset());
        if from_str.is_some() {
            sql.push_str(&format!(" AND event_time >= ?{next}"));
            next += 1;
        }
        let until_str = filter.until.map(|t| t.to_rfc3339_numeric_offset());
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

        Ok(q.fetch_all(self.pool()).await?)
    }
}

impl AuditQuery for OurBackend {
    type Error = BackendError;

    /// The tenant's audit trail under `filter`: the events read, newest
    /// first, and the count of the rows that could not be read, by reason.
    /// The counts are also logged, without the rows' text.
    async fn query_events(
        &self,
        tenant_id: &TenantId,
        filter: &EventQueryFilter,
    ) -> Result<AuditTrail, Self::Error> {
        let rows = self.fetch_event_rows(tenant_id, filter).await?;
        let mut trail = AuditTrail {
            events: Vec::with_capacity(rows.len()),
            ..AuditTrail::default()
        };
        for row in &rows {
            match read_row(row) {
                Ok(event) => trail.events.push(event),
                Err(reason) => trail.unreadable.count(reason),
            }
        }
        let unreadable = trail.unreadable;
        if unreadable.total() > 0 {
            warn!(
                unreadable_session = unreadable.session,
                unreadable_event_type = unreadable.event_type,
                unreadable_other = unreadable.other,
                "audit query: rows that could not be read were left out of the trail"
            );
        }
        Ok(trail)
    }
}

/// One audit row as an event, or the reason it cannot be read. A row that
/// fails here means a writer corrupted the table or a newer release wrote a
/// value this one does not know; it is counted rather than poisoning the
/// whole query or being read as something it is not.
fn read_row(row: &SqliteRow) -> Result<AuthEvent, UnreadableReason> {
    let user_id: Option<String> = row.get("user_id");
    let tenant_id: Option<String> = row.get("tenant_id");
    let session_id: Option<String> = row.get("session_id");
    let event_type: String = row.get("event_type");
    let event_status: String = row.get("event_status");
    let event_time: String = row.get("event_time");
    let factor_kind: Option<String> = row.get("factor_kind");
    let ip_address: Option<String> = row.get("ip_address");
    let ip_source: String = row.get("ip_source");
    let user_agent: Option<String> = row.get("user_agent");
    let request_id: Option<String> = row.get("request_id");
    let trace_id: Option<String> = row.get("trace_id");
    let geo_country: Option<String> = row.get("geo_country");
    let error: Option<String> = row.get("error");

    let event_type =
        AuthEventType::from_str(&event_type).map_err(|_| UnreadableReason::EventType)?;
    let event_status =
        AuthEventStatus::from_str(&event_status).map_err(|_| UnreadableReason::Other)?;
    // The column holds the session's key, 64 hexadecimal characters. A row
    // written before 0.20.0 holds the session id there, which reads as the
    // key of that id, so an old row and a new one name one session alike.
    // Any other text is a row a writer corrupted: it is counted, as a bad
    // event type is, rather than read as an event of no session.
    let session_id = session_id
        .as_deref()
        .map(SessionKey::from_recorded)
        .transpose()
        .map_err(|_| UnreadableReason::Session)?;
    let event_time = Timestamp::parse_rfc3339(&event_time)
        .map_err(|_| UnreadableReason::Other)?
        .unix_micros();
    // FactorKind has no `FromStr`; round-trip is best-effort for the kinds
    // the example UI exercises. Anything unrecognised becomes `None` rather
    // than dropping the event.
    let factor_kind = factor_kind.as_deref().and_then(parse_factor_kind);

    // `ip_address` is a TEXT column, and rows written before 0.6.0 hold
    // whatever string the writer supplied -- including a value a client
    // forged, since the field accepted arbitrary text then. An unparseable
    // one becomes `None` rather than dropping the event: the address is
    // optional metadata, not identity, and a null address is honest where an
    // invented one is not. The text is not logged, for the same reason.
    let ip_address = ip_address.and_then(|s| match s.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(e) => {
            warn!(error = %e, "audit row: unparseable ip_address, storing none");
            None
        }
    });

    // Infallible by design: a tag this version has no variant for becomes
    // `AuthFailureReason::Other` rather than an error, so an audit row
    // written by a newer or older axess still reads back with its reason
    // intact.
    let error = error.map(AuthFailureReason::from);

    // An unrecognised value means a writer from another version, or a
    // hand-edited row. Reading it as `Unknown` keeps the rest of the event,
    // and claiming a provenance the row does not have would be worse than
    // admitting none. The text is not logged.
    let ip_source = match ip_source.as_str() {
        "peer" => Source::Peer,
        "forwarded" => Source::Forwarded,
        "supplied" => Source::Supplied,
        other => {
            if other != "unknown" {
                warn!("audit row: unrecognised ip_source");
            }
            Source::Unknown
        }
    };

    Ok(AuthEvent {
        user_id: user_id.and_then(|u| UserId::try_new(u).ok()),
        tenant_id: tenant_id.and_then(|t| TenantId::try_new(t).ok()),
        session_id,
        event_type,
        event_status,
        event_time,
        factor_kind,
        ip_address,
        ip_source,
        user_agent,
        request_id,
        trace_id,
        geo_country,
        error,
        actor_id: None,
        // Example backend doesn't yet read a `device_id` column from the
        // SQLite audit table: the device subsystem is feature-gated and the
        // example's schema predates the addition. Leave None until the
        // example schema migrates.
        device_id: None,
        factors_completed: vec![],
    })
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
        "recovery_code" => Some(FactorKind::RecoveryCode),
        _ => None,
    }
}
