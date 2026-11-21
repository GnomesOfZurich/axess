use super::*;
use crate::authn::factor::FederatedProvider;
use axess_clock::testing::Shift;
use axess_identity::testing::{tenant, user};
use axess_testing::mock_tracing::TracingCapture;

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
#[should_panic(expected = "factor secret encryption key is a single repeated byte")]
fn new_refuses_a_constant_key() {
    let _ = FactorSecretCipher::new([7u8; 32]);
}

#[test]
#[should_panic(expected = "previous factor secret encryption key is a single repeated byte")]
fn with_previous_key_refuses_a_constant_key() {
    let _ = FactorSecretCipher::new(KEY).with_previous_key([7u8; 32]);
}

#[test]
#[should_panic(expected = "equals the current key")]
fn with_previous_key_refuses_the_current_key() {
    let _ = FactorSecretCipher::new(KEY).with_previous_key(KEY);
}

#[test]
fn new_unchecked_accepts_a_constant_key() {
    let _ = FactorSecretCipher::new_unchecked([7u8; 32]);
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
    let clock =
        axess_clock::testing::MockClock::at(axess_clock::testing::MockClock::reference_time());
    let until = clock.now().plus(axess_clock::SignedDuration::hours(1));
    let cipher = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_plain_secrets(LegacyBlobs::AcceptUntil(until));
    assert!(cipher.plain_secrets_readable());
    clock.advance(axess_clock::SignedDuration::hours(2));
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
    let cipher = FactorSecretCipher::new(KEY).with_first_binding(LegacyBlobs::Accept);
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
fn the_first_binding_is_refused_by_default_and_read_only_when_asked() {
    let scope = scope("t1", "u1");
    let old = sealed_by_the_first_release(&scope, "totp");
    let totp = FactorSecretBinding::new(&scope, &FactorKind::Totp);
    assert_eq!(
        FactorSecretCipher::new(KEY).open(&old, totp).err(),
        Some(FactorSecretError::Open),
        "the default must not read the first release's binding"
    );
    let accepting = FactorSecretCipher::new(KEY).with_first_binding(LegacyBlobs::Accept);
    assert!(accepting.open(&old, totp).is_ok());

    let rejecting = FactorSecretCipher::new(KEY).with_first_binding(LegacyBlobs::Reject);
    assert_eq!(
        rejecting.open(&old, totp).err(),
        Some(FactorSecretError::Open)
    );
    // The collision the first binding allowed: a custom provider named
    // "totp" opened a TOTP secret.
    let custom = FactorKind::Federated(FederatedProvider::Custom("totp".to_string()));
    assert!(
        accepting
            .open(&old, FactorSecretBinding::new(&scope, &custom))
            .is_ok()
    );
    assert_eq!(
        rejecting
            .open(&old, FactorSecretBinding::new(&scope, &custom))
            .err(),
        Some(FactorSecretError::Open)
    );

    let clock =
        axess_clock::testing::MockClock::at(axess_clock::testing::MockClock::reference_time());
    let until = clock.now().plus(axess_clock::SignedDuration::hours(1));
    let windowed = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_first_binding(LegacyBlobs::AcceptUntil(until));
    assert!(windowed.open(&old, totp).is_ok());
    clock.advance(axess_clock::SignedDuration::hours(2));
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

#[test]
fn the_earlier_tenant_binding_window_follows_the_policy_and_closes_at_its_cutoff() {
    let clock =
        axess_clock::testing::MockClock::at(axess_clock::testing::MockClock::reference_time());
    let until = clock.now().plus(axess_clock::SignedDuration::hours(1));
    let windowed = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_earlier_tenant_binding(LegacyBlobs::AcceptUntil(until));
    assert!(windowed.earlier_tenant_binding_readable());
    clock.advance(axess_clock::SignedDuration::hours(1));
    assert!(
        !windowed.earlier_tenant_binding_readable(),
        "the cutoff itself is past the window"
    );
    let rejecting = FactorSecretCipher::new(KEY).with_clock(Arc::new(clock.clone()));
    assert!(!rejecting.earlier_tenant_binding_readable());
    assert!(
        rejecting
            .with_earlier_tenant_binding(LegacyBlobs::Accept)
            .earlier_tenant_binding_readable()
    );
}

#[test]
fn the_debug_form_names_the_key_id_and_every_policy_but_never_the_key() {
    let clock =
        axess_clock::testing::MockClock::at(axess_clock::testing::MockClock::reference_time());
    let cipher = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_previous_key(OTHER)
        .with_earlier_tenant_binding(LegacyBlobs::Accept);
    assert_eq!(
        format!("{cipher:?}"),
        format!(
            "FactorSecretCipher {{ current_key_id: {:?}, has_previous_key: true, \
             plain: Reject, first_binding: Reject, earlier_tenant_binding: Accept }}",
            key_id(&KEY)
        ),
        "the whole form, so no rendering of either key, as text, bytes or hex, can join it"
    );

    let single = FactorSecretCipher::new(OTHER)
        .with_clock(Arc::new(clock))
        .with_plain_secrets(LegacyBlobs::Accept);
    assert_eq!(
        format!("{single:?}"),
        format!(
            "FactorSecretCipher {{ current_key_id: {:?}, has_previous_key: false, \
             plain: Accept, first_binding: Reject, earlier_tenant_binding: Reject }}",
            key_id(&OTHER)
        )
    );
}

#[test]
fn the_plain_and_first_binding_windows_close_at_their_cutoff() {
    let clock =
        axess_clock::testing::MockClock::at(axess_clock::testing::MockClock::reference_time());
    let until = clock.now().plus(axess_clock::SignedDuration::hours(1));
    let plain = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_plain_secrets(LegacyBlobs::AcceptUntil(until));
    let first = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_first_binding(LegacyBlobs::AcceptUntil(until));

    clock.advance(
        axess_clock::SignedDuration::hours(1)
            .checked_sub(axess_clock::SignedDuration::seconds(1))
            .unwrap(),
    );
    assert!(plain.plain_secrets_readable(), "a second before the cutoff");
    assert!(first.first_binding_readable(), "a second before the cutoff");

    clock.advance(axess_clock::SignedDuration::seconds(1));
    assert!(
        !plain.plain_secrets_readable(),
        "the cutoff itself is past the window"
    );
    assert!(
        !first.first_binding_readable(),
        "the cutoff itself is past the window"
    );
}

/// The cipher's key is held in a `Zeroizing` buffer, which wipes itself
/// when the last handle to it is dropped. The key type has no `Drop` of its
/// own to keep in step with its field: taking the buffer out of it compiles
/// only while it has none.
#[test]
fn the_key_is_held_in_a_zeroizing_buffer() {
    let Key(held) = Key::new(&KEY);
    let held: &Zeroizing<[u8; 32]> = &held;
    assert_eq!(**held, KEY);
}

/// The ciphertext of an empty secret is a tag alone, and it opens.
#[test]
fn the_sealed_form_of_an_empty_secret_opens() {
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let binding = || FactorSecretBinding::new(&scope, &FactorKind::Totp);
    let sealed = cipher.seal("", binding()).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&sealed.ciphertext).unwrap().len(),
        crate::aead::TAG_LEN
    );
    let opened = cipher.open(&sealed, binding()).unwrap();
    assert_eq!(&*opened.secret, "");
}

/// A ciphertext one byte short of a tag was never sealed: it is refused,
/// and logged as damaged, before any key or binding is tried. A full-length
/// ciphertext that does not authenticate is refused without that line.
#[test]
fn a_ciphertext_shorter_than_a_tag_is_refused_before_decrypting() {
    const TOO_SHORT: &str = "too short to have been sealed";
    let capture = TracingCapture::install();
    let cipher = FactorSecretCipher::new(KEY);
    let scope = scope("t1", "u1");
    let binding = || FactorSecretBinding::new(&scope, &FactorKind::Totp);
    let sealed = cipher.seal("", binding()).unwrap();
    let with_ciphertext = |bytes: &[u8]| SealedFactorSecret {
        ciphertext: URL_SAFE_NO_PAD.encode(bytes),
        ..sealed.clone()
    };
    let raw = URL_SAFE_NO_PAD.decode(&sealed.ciphertext).unwrap();
    let too_short = || {
        capture
            .events()
            .iter()
            .filter(|event| event.message.contains(TOO_SHORT))
            .count()
    };

    let mut flipped = raw.clone();
    flipped[0] ^= 1;
    assert_eq!(
        cipher.open(&with_ciphertext(&flipped), binding()).err(),
        Some(FactorSecretError::Open)
    );
    assert_eq!(too_short(), 0, "the control is a full-length ciphertext");

    for length in [crate::aead::TAG_LEN - 1, 1, 0] {
        assert_eq!(
            cipher
                .open(&with_ciphertext(&raw[..length]), binding())
                .err(),
            Some(FactorSecretError::Open),
            "{length} bytes"
        );
    }
    assert_eq!(too_short(), 3, "{:?}", capture.events());
}
