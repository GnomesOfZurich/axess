//! Seed data: a default tenant plus two users (alice = password-only,
//! bob = password+TOTP). Idempotent so it's safe to call on every startup.

use axess::Clock;
use axess::authn::{FactorConfig, PasswordConfig, PasswordRules, TotpConfig, ZeroizedString};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Seed the database with a default tenant and two test users.
///
/// - **alice**; password-only login (`Gnomes2+`)
/// - **bob**  ; password + TOTP login (`Gnomes2+`)
///
/// Returns Bob's TOTP secret so the caller can log it.
/// Idempotent: safe to call on every startup.
pub async fn seed(
    clock: &dyn Clock,
    pool: &SqlitePool,
) -> Result<String, Box<dyn std::error::Error>> {
    let tenant_id = "00000000-0000-0000-0000-000000000001";
    let tenant_identifier = "default";
    // Seed rows are created by the reserved system user.
    let system_user_id = axess::authn::UserId::SYSTEM_STR;
    let now = clock.now().to_rfc3339();

    // Tenant
    sqlx::query(
        "INSERT INTO tenants
             (id, identifier, name, status, created_by, created_at, updated_by, updated_at)
         VALUES (?1, ?2, 'Default Tenant', 'active', ?3, ?4, ?3, ?4)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(tenant_identifier)
    .bind(system_user_id)
    .bind(&now)
    .execute(pool)
    .await?;

    // Alice (password-only)
    let alice_id = "00000000-0000-0000-0000-000000000010";
    sqlx::query(
        "INSERT INTO users
             (id, tenant_id, identifier, display_name, status,
              created_by, created_at, updated_by, updated_at)
         VALUES (?1, ?2, 'alice', 'Alice Example', 'active', ?3, ?4, ?3, ?4)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(alice_id)
    .bind(tenant_id)
    .bind(system_user_id)
    .bind(&now)
    .execute(pool)
    .await?;

    // Bob (password + TOTP)
    let bob_id = "00000000-0000-0000-0000-000000000020";
    sqlx::query(
        "INSERT INTO users
             (id, tenant_id, identifier, display_name, status,
              created_by, created_at, updated_by, updated_at)
         VALUES (?1, ?2, 'bob', 'Bob Example', 'active', ?3, ?4, ?3, ?4)
         ON CONFLICT(id) DO NOTHING",
    )
    .bind(bob_id)
    .bind(tenant_id)
    .bind(system_user_id)
    .bind(&now)
    .execute(pool)
    .await?;

    // Password hash for "Gnomes2+".
    let password_hash = axess::generate_password_hash("Gnomes2+");

    // Alice: password factor config at user scope.
    let alice_pw_config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(password_hash.clone()),
        rules: PasswordRules::default(),
    });
    let alice_pw_json = serde_json::to_string(&alice_pw_config)?;
    let alice_pw_fc_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled)
         VALUES (?1, ?2, ?3, 'password', ?4, 1)
         ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
    )
    .bind(&alice_pw_fc_id)
    .bind(alice_id)
    .bind(tenant_id)
    .bind(&alice_pw_json)
    .execute(pool)
    .await?;

    // Alice: auth_method "password" at user scope.
    let alice_method_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_methods (id, name, steps_json, user_id, tenant_id, enabled)
         VALUES (?1, 'password', '[{\"Required\":\"Password\"}]', ?2, ?3, 1)
         ON CONFLICT(user_id, tenant_id, name) DO NOTHING",
    )
    .bind(&alice_method_id)
    .bind(alice_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    // Bob: password factor config at user scope.
    let bob_pw_config = FactorConfig::Password(PasswordConfig {
        hash: ZeroizedString::new(password_hash),
        rules: PasswordRules::default(),
    });
    let bob_pw_json = serde_json::to_string(&bob_pw_config)?;
    let bob_pw_fc_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled)
         VALUES (?1, ?2, ?3, 'password', ?4, 1)
         ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
    )
    .bind(&bob_pw_fc_id)
    .bind(bob_id)
    .bind(tenant_id)
    .bind(&bob_pw_json)
    .execute(pool)
    .await?;

    // Bob: TOTP factor config at user scope.
    // Reuse existing secret if already seeded, so the TOTP app doesn't need
    // to be re-enrolled.
    let existing_totp: Option<String> = sqlx::query(
        "SELECT config_json FROM factor_configs
         WHERE user_id = ?1 AND tenant_id = ?2 AND kind = 'totp'",
    )
    .bind(bob_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .map(|r| sqlx::Row::get(&r, "config_json"));

    let totp_secret = if let Some(json) = existing_totp {
        let config: FactorConfig = serde_json::from_str(&json)?;
        if let FactorConfig::Totp(ref tc) = config {
            tc.secret.to_string()
        } else {
            axess::generate_totp_secret(&axess::SystemRng)
        }
    } else {
        let secret = axess::generate_totp_secret(&axess::SystemRng);
        let bob_totp_config = FactorConfig::Totp(TotpConfig {
            secret: ZeroizedString::new(secret.clone()),
            ..TotpConfig::default()
        });
        let bob_totp_json = serde_json::to_string(&bob_totp_config)?;
        let bob_totp_fc_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO factor_configs (id, user_id, tenant_id, kind, config_json, enabled)
             VALUES (?1, ?2, ?3, 'totp', ?4, 1)
             ON CONFLICT(user_id, tenant_id, kind) DO NOTHING",
        )
        .bind(&bob_totp_fc_id)
        .bind(bob_id)
        .bind(tenant_id)
        .bind(&bob_totp_json)
        .execute(pool)
        .await?;
        secret
    };

    // Bob: auth_method "password+totp" at user scope.
    let bob_method_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_methods (id, name, steps_json, user_id, tenant_id, enabled)
         VALUES (?1, 'password+totp', '[{\"Required\":\"Password\"},{\"Required\":\"Totp\"}]', ?2, ?3, 1)
         ON CONFLICT(user_id, tenant_id, name) DO NOTHING",
    )
    .bind(&bob_method_id)
    .bind(bob_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(totp_secret)
}
