use super::*;
use crate::authn::factor::FederatedProvider;
use axess_identity::testing::{tenant, user};
use chrono::Utc;

const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";
const OTHER: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

fn scope(t: &str, u: &str) -> AuthnScope {
    AuthnScope::User {
        tenant_id: tenant(t),
        user_id: user(u),
    }
}

#[test]
fn a_sealed_secret_opens_for_its_own_binding() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let sealed = cipher
        .seal(
            "JBSWY3DPEHPK3PXP",
            FactorSecretBinding::new(&scope, &FactorKind::Totp),
        )
        .unwrap();
    let opened = cipher
        .open(&sealed, FactorSecretBinding::new(&scope, &FactorKind::Totp))
        .unwrap();
    assert_eq!(&*opened.secret, "JBSWY3DPEHPK3PXP");
    assert!(!opened.rotated);
    assert!(!sealed.ciphertext.contains("JBSWY3DPEHPK3PXP"));
}

#[test]
fn each_part_of_the_binding_is_authenticated() {
    let cipher = FactorSecretCipher::new(KEY);
    let sealed = cipher
        .seal(
            "JBSWY3DPEHPK3PXP",
            FactorSecretBinding::new(&scope("t1", "u1"), &FactorKind::Totp),
        )
        .unwrap();
    for (other, kind) in [
        (scope("t1", "u2"), FactorKind::Totp),
        (scope("t2", "u1"), FactorKind::Totp),
        (scope("t1", "u1"), FactorKind::Hotp),
        (AuthnScope::Tenant(tenant("t1")), FactorKind::Totp),
    ] {
        assert_eq!(
            cipher
                .open(&sealed, FactorSecretBinding::new(&other, &kind))
                .err(),
            Some(FactorSecretError::Open),
            "{other:?} {kind}"
        );
    }
}

#[test]
fn a_damaged_blob_and_a_foreign_key_are_refused() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let binding = FactorSecretBinding::new(&scope, &FactorKind::Totp);
    let mut sealed = cipher.seal("JBSWY3DPEHPK3PXP", binding).unwrap();
    let foreign = FactorSecretCipher::new(OTHER);
    assert_eq!(
        foreign.open(&sealed, binding).err(),
        Some(FactorSecretError::UnknownKey)
    );
    sealed.ciphertext.insert(0, 'A');
    assert_eq!(
        cipher.open(&sealed, binding).err(),
        Some(FactorSecretError::Open)
    );
}

#[test]
fn the_previous_key_opens_and_reports_the_rotation() {
    let old = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let binding = FactorSecretBinding::new(&scope, &FactorKind::Totp);
    let sealed = old.seal("JBSWY3DPEHPK3PXP", binding).unwrap();
    let rotated = FactorSecretCipher::new(OTHER).with_previous_key(KEY);
    let opened = rotated.open(&sealed, binding).unwrap();
    assert!(opened.rotated);
    assert!(!rotated.is_current(&sealed));
}

#[test]
fn a_constant_key_is_refused_by_try_new() {
    assert!(FactorSecretCipher::try_new([0u8; 32]).is_err());
    assert!(FactorSecretCipher::try_new([7u8; 32]).is_err());
    assert!(FactorSecretCipher::try_new(KEY).is_ok());
}

#[test]
fn seal_config_seals_otp_secrets_and_leaves_the_rest() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let totp = FactorConfig::Totp(axess_factors::TotpConfig {
        secret: "JBSWY3DPEHPK3PXP".into(),
        ..Default::default()
    });
    let sealed = cipher.seal_config(totp, &scope).unwrap();
    let FactorConfig::Totp(cfg) = &sealed else {
        unreachable!()
    };
    assert!(cfg.secret.is_sealed());
    let again = cipher.seal_config(sealed.clone(), &scope).unwrap();
    assert_eq!(
        serde_json::to_value(&again).unwrap(),
        serde_json::to_value(&sealed).unwrap(),
        "an already sealed secret is left alone"
    );
}

#[test]
fn the_plain_window_follows_the_policy_and_the_clock() {
    let clock = axess_clock::testing::MockClock::at(Utc::now());
    let until = clock.now() + chrono::Duration::hours(1);
    let cipher = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_plain_secrets(LegacyBlobs::AcceptUntil(until));
    assert!(cipher.plain_secrets_readable());
    clock.advance(chrono::Duration::hours(2));
    assert!(!cipher.plain_secrets_readable());
    assert!(!FactorSecretCipher::new(KEY).plain_secrets_readable());
    assert!(
        FactorSecretCipher::new(KEY)
            .with_plain_secrets(LegacyBlobs::Accept)
            .plain_secrets_readable()
    );
}

#[test]
fn a_custom_provider_named_like_a_factor_does_not_open_that_factors_secret() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let sealed = cipher
        .seal(
            "JBSWY3DPEHPK3PXP",
            FactorSecretBinding::new(&scope, &FactorKind::Totp),
        )
        .unwrap();
    for name in ["totp", "github"] {
        let custom = FactorKind::Federated(FederatedProvider::Custom(name.to_string()));
        assert_eq!(
            cipher
                .open(&sealed, FactorSecretBinding::new(&scope, &custom))
                .err(),
            Some(FactorSecretError::Open),
            "custom {name}"
        );
    }
    let github = FactorKind::Federated(FederatedProvider::Github);
    let sealed = cipher
        .seal("s", FactorSecretBinding::new(&scope, &github))
        .unwrap();
    let custom = FactorKind::Federated(FederatedProvider::Custom("github".to_string()));
    assert!(
        cipher
            .open(&sealed, FactorSecretBinding::new(&scope, &custom))
            .is_err()
    );
}

/// A secret as the first release sealed it, with that release's binding
/// written out by hand: label, then tenant, user and kind, each
/// length-prefixed.
fn sealed_by_the_first_release(scope: &AuthnScope, kind: &str) -> SealedFactorSecret {
    let columns = scope.as_columns();
    let mut aad = b"axess.factor-secret.v1".to_vec();
    for part in [
        columns.tenant_id.to_string(),
        columns.user_id.map(|u| u.to_string()).unwrap_or_default(),
        kind.to_string(),
    ] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    let nonce_bytes = [9u8; NONCE_LEN];
    let nonce = Nonce::try_from(&nonce_bytes[..]).unwrap();
    let ciphertext = Aes256Gcm::new_from_slice(&KEY)
        .unwrap()
        .encrypt(
            &nonce,
            Payload {
                msg: b"JBSWY3DPEHPK3PXP",
                aad: &aad,
            },
        )
        .unwrap();
    SealedFactorSecret {
        key_id: key_id(&KEY),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    }
}

#[test]
fn a_secret_sealed_by_the_first_release_opens_and_asks_to_be_sealed_again() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let old = sealed_by_the_first_release(&scope, "totp");
    let opened = cipher
        .open(&old, FactorSecretBinding::new(&scope, &FactorKind::Totp))
        .unwrap();
    assert_eq!(&*opened.secret, "JBSWY3DPEHPK3PXP");
    assert!(opened.rotated, "an old binding is due a re-seal");

    let fresh = cipher
        .seal(
            &opened.secret,
            FactorSecretBinding::new(&scope, &FactorKind::Totp),
        )
        .unwrap();
    assert!(
        !cipher
            .open(&fresh, FactorSecretBinding::new(&scope, &FactorKind::Totp))
            .unwrap()
            .rotated
    );
}

#[test]
fn the_first_bindings_default_reads_and_a_rejecting_policy_or_a_lapsed_cutoff_refuses_it() {
    let scope = scope("t1", "u1");
    let old = sealed_by_the_first_release(&scope, "totp");
    let totp = FactorSecretBinding::new(&scope, &FactorKind::Totp);
    assert!(FactorSecretCipher::new(KEY).open(&old, totp).is_ok());

    let rejecting = FactorSecretCipher::new(KEY).with_first_binding(LegacyBlobs::Reject);
    assert_eq!(
        rejecting.open(&old, totp).err(),
        Some(FactorSecretError::Open)
    );
    // The collision the first binding allowed: a custom provider named
    // "totp" opened a TOTP secret.
    let custom = FactorKind::Federated(FederatedProvider::Custom("totp".to_string()));
    assert!(
        FactorSecretCipher::new(KEY)
            .open(&old, FactorSecretBinding::new(&scope, &custom))
            .is_ok()
    );
    assert_eq!(
        rejecting
            .open(&old, FactorSecretBinding::new(&scope, &custom))
            .err(),
        Some(FactorSecretError::Open)
    );

    let clock = axess_clock::testing::MockClock::at(Utc::now());
    let until = clock.now() + chrono::Duration::hours(1);
    let windowed = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_first_binding(LegacyBlobs::AcceptUntil(until));
    assert!(windowed.open(&old, totp).is_ok());
    clock.advance(chrono::Duration::hours(2));
    assert_eq!(
        windowed.open(&old, totp).err(),
        Some(FactorSecretError::Open)
    );

    // A secret in the current binding is never affected.
    let fresh = rejecting.seal("JBSWY3DPEHPK3PXP", totp).unwrap();
    assert!(rejecting.open(&fresh, totp).is_ok());
}

#[test]
fn an_old_secret_still_does_not_open_for_another_row() {
    let cipher = FactorSecretCipher::new(KEY);
    let old = sealed_by_the_first_release(&scope("t1", "u1"), "totp");
    assert!(
        cipher
            .open(
                &old,
                FactorSecretBinding::new(&scope("t1", "u2"), &FactorKind::Totp)
            )
            .is_err()
    );
}

#[test]
fn bound_context_is_authenticated() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let kind = FactorKind::Totp;
    let sealed = cipher
        .seal(
            "s",
            FactorSecretBinding::new(&scope, &kind).with_context(&["a", "b"]),
        )
        .unwrap();
    for other in [&["a", "c"][..], &["a"], &["a", "b", ""], &[]] {
        assert!(
            cipher
                .open(
                    &sealed,
                    FactorSecretBinding::new(&scope, &kind).with_context(other)
                )
                .is_err(),
            "{other:?}"
        );
    }
}
