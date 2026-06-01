//! Shared fixtures and helpers for axess-core integration tests.

// Each integration-test file compiles as its own binary, so a helper
// used by one sibling but not another would otherwise trip the lint.
#![allow(dead_code)]

use axess_core::authn::{
    factor::{FactorConfig, FactorKind, PasswordConfig, PasswordRules, TotpConfig, ZeroizedString},
    ids::{TenantId, UserId},
    store::AuthMethod,
    types::{AuthnScope, EntityState, Tenant, User},
};
use chrono::Utc;

// ── ID builders ──────────────────────────────────────────────────────────────

/// Shorthand for constructing a [`UserId`] fixture from a test label. Uses
/// the v5-derived [`axess_core::authn::ids::testing::user`] helper so the
/// same label always produces the same Uuid (stable across crates and runs).
pub fn uid(v: &str) -> UserId {
    axess_core::authn::ids::testing::user(v)
}

/// Shorthand for constructing a [`TenantId`] fixture from a test label.
/// See [`uid`] for the determinism note.
pub fn tid(v: &str) -> TenantId {
    axess_core::authn::ids::testing::tenant(v)
}

// ── Entity fixtures ──────────────────────────────────────────────────────────

/// A standard active tenant with id `"t1"`. Default choice for single-tenant
/// tests that don't need to exercise multi-tenant logic.
pub fn test_tenant() -> Tenant {
    let now = Utc::now();
    Tenant {
        id: tid("t1"),
        identifier: "default".into(),
        display_name: "Test Tenant".into(),
        status: EntityState::Active,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

/// A standard active user in tenant `"t1"`. Pass the `id` and `identifier`
/// separately so tests can assert on both.
pub fn test_user(id: &str, identifier: &str) -> User {
    test_user_in_tenant(id, identifier, "t1")
}

/// User fixture with explicit tenant; use when a test exercises
/// cross-tenant boundary behaviour.
pub fn test_user_in_tenant(id: &str, identifier: &str, tenant: &str) -> User {
    let now = Utc::now();
    User {
        id: uid(id),
        tenant_id: tid(tenant),
        identifier: identifier.into(),
        display_name: identifier.into(),
        status: EntityState::Active,
        webauthn_id: None,
        created_by: UserId::system(),
        created_at: now,
        updated_by: UserId::system(),
        updated_at: now,
    }
}

// ── Factor + scope fixtures ──────────────────────────────────────────────────

/// Build a [`FactorConfig::Password`] that hashes the supplied plaintext.
pub fn password_config(password: &str) -> FactorConfig {
    let hash = axess_factors::generate_password_hash(password);
    FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(hash),
        rules: PasswordRules::default(),
    })
}

/// Build a [`FactorConfig::Totp`] backed by the supplied base32 secret.
pub fn totp_config(secret: &str) -> FactorConfig {
    FactorConfig::Totp(TotpConfig {
        secret: ZeroizedString::new(secret),
        ..TotpConfig::default()
    })
}

/// The user-scope pointer for tenant `"t1"`, user `"u1"`; matches the
/// default fixtures [`test_tenant`] and [`test_user`].
pub fn user_scope() -> AuthnScope {
    AuthnScope::User {
        tenant_id: tid("t1"),
        user_id: uid("u1"),
    }
}

/// Password-only sequential auth method against [`user_scope`].
pub fn password_method() -> AuthMethod {
    AuthMethod::sequential("password", vec![FactorKind::Password], user_scope())
}

/// Password-then-TOTP sequential auth method against [`user_scope`].
pub fn password_totp_method() -> AuthMethod {
    AuthMethod::sequential(
        "password+totp",
        vec![FactorKind::Password, FactorKind::Totp],
        user_scope(),
    )
}

// ── OTP code generators ──────────────────────────────────────────────────────

/// Generate a TOTP code for the given base32 secret at the given wall time.
pub fn generate_totp_code(secret: &str, now: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let step = secs / 30;
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 0, 30, decoded).unwrap();
    totp.generate(step * 30)
}

/// Generate an HOTP code for the given base32 secret at the given counter
/// (RFC 4226). Used to validate the counter-advance + replay-rejection paths.
pub fn generate_hotp_code(secret: &str, counter: u64) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;

    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret).unwrap();
    let mut mac = Hmac::<Sha1>::new_from_slice(&decoded).unwrap();
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0f) as usize;
    let binary = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);
    format!("{:06}", binary % 1_000_000)
}
