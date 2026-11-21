//! A sealed client credential opens only for the record it was sealed for.

use super::*;
use crate::authn::factor_secret::FactorSecretCipher;
use crate::authn::ids::testing::tenant;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_clock::testing::Shift;
use axess_factors::{FactorSecret, SealedFactorSecret};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdeF";

fn record() -> TenantOAuthProviderRecord {
    TenantOAuthProviderRecord {
        tenant_id: tenant("t1"),
        name: "sso".into(),
        issuer: "https://idp.example".into(),
        client_id: "client-1".into(),
        redirect_url: "http://localhost:3000/callback".into(),
        scopes: vec![],
        credential: TenantClientCredential::Secret(FactorSecret::Plain("s3cret".into())),
        dpop: TenantDpop::Advertised,
        kind: None,
        revision: 1,
    }
}

#[test]
fn a_sealed_credential_does_not_open_after_the_issuer_or_client_id_moves() {
    let cipher = FactorSecretCipher::new(KEY);
    let mut sealed = record();
    sealed.seal(&cipher).unwrap();
    assert_eq!(&*sealed.open_secret(Some(&cipher)).unwrap(), "s3cret");

    let mut other_issuer = sealed.clone();
    other_issuer.issuer = "https://evil.example".into();
    assert!(other_issuer.open_secret(Some(&cipher)).is_err());

    let mut other_client = sealed;
    other_client.client_id = "client-2".into();
    assert!(other_client.open_secret(Some(&cipher)).is_err());
}

/// Every field that decides where the credential is presented and how is
/// bound: a row whose redirect URL, scopes, DPoP mode, credential kind or
/// signer spec was rewritten in the store does not open.
#[test]
fn a_sealed_credential_does_not_open_after_any_bound_field_moves() {
    use axess_factors::client_assertion::SignerSpec;
    use jsonwebtoken::Algorithm;
    let cipher = FactorSecretCipher::new(KEY);
    let mut sealed = record();
    sealed.seal(&cipher).unwrap();

    let mut redirect = sealed.clone();
    redirect.redirect_url = "https://attacker.example/callback".into();
    assert!(redirect.open_secret(Some(&cipher)).is_err(), "redirect_url");

    let mut scopes = sealed.clone();
    scopes.scopes = vec!["openid".into(), "offline_access".into()];
    assert!(scopes.open_secret(Some(&cipher)).is_err(), "scopes");

    let mut dpop = sealed.clone();
    dpop.dpop = TenantDpop::Off;
    assert!(dpop.open_secret(Some(&cipher)).is_err(), "dpop");

    let mut moved_kind = sealed.clone();
    let TenantClientCredential::Secret(secret) = moved_kind.credential.clone() else {
        unreachable!("a secret record");
    };
    moved_kind.credential = TenantClientCredential::PrivateKeyJwt {
        key_pem: secret,
        signer: SignerSpec::new(Algorithm::RS256),
    };
    assert!(
        moved_kind.open_secret(Some(&cipher)).is_err(),
        "credential kind"
    );

    let mut key = record();
    key.credential = TenantClientCredential::PrivateKeyJwt {
        key_pem: FactorSecret::Plain("-----BEGIN KEY-----".into()),
        signer: SignerSpec {
            key_id: Some("kid-1".into()),
            ..SignerSpec::new(Algorithm::RS256)
        },
    };
    key.seal(&cipher).unwrap();
    assert_eq!(
        &*key.open_secret(Some(&cipher)).unwrap(),
        "-----BEGIN KEY-----"
    );
    let mut other_kid = key.clone();
    let TenantClientCredential::PrivateKeyJwt { signer, .. } = &mut other_kid.credential else {
        unreachable!("a key record");
    };
    signer.key_id = Some("kid-2".into());
    assert!(other_kid.open_secret(Some(&cipher)).is_err(), "signer kid");
    let mut other_audience = key;
    let TenantClientCredential::PrivateKeyJwt { signer, .. } = &mut other_audience.credential
    else {
        unreachable!("a key record");
    };
    signer.audience = Some("https://idp.example/token".into());
    assert!(
        other_audience.open_secret(Some(&cipher)).is_err(),
        "signer audience"
    );

    // Scope order is not a field: the same set in another order opens.
    let mut ordered = record();
    ordered.scopes = vec!["profile".into(), "openid".into()];
    ordered.seal(&cipher).unwrap();
    ordered.scopes = vec!["openid".into(), "profile".into()];
    assert_eq!(&*ordered.open_secret(Some(&cipher)).unwrap(), "s3cret");
}

/// A credential sealed under the binding of the releases before every field
/// was bound (the issuer and client id as context) opens under the named
/// opt-in for a rolling upgrade, and is reported as due a re-seal, so the
/// directory seals it under every field on first use.
#[test]
fn a_credential_bound_to_the_issuer_and_client_id_only_opens_and_is_due_a_reseal() {
    use crate::authn::factor::{FactorKind, FederatedProvider};
    use crate::authn::factor_secret::FactorSecretBinding;
    use crate::authn::types::AuthnScope;
    use crate::session::legacy_blobs::LegacyBlobs;
    let cipher = FactorSecretCipher::new(KEY).with_earlier_tenant_binding(LegacyBlobs::Accept);
    let mut rec = record();
    let scope = AuthnScope::Tenant(rec.tenant_id);
    let kind = FactorKind::Federated(FederatedProvider::Custom(rec.name.clone()));
    let context = [rec.issuer.as_str(), rec.client_id.as_str()];
    let sealed = cipher
        .seal(
            "s3cret",
            FactorSecretBinding::new(&scope, &kind).with_context(&context),
        )
        .unwrap();
    rec.credential = TenantClientCredential::Secret(FactorSecret::Sealed(sealed));

    let (text, due_a_reseal) = rec.open_credential(Some(&cipher)).unwrap();
    assert_eq!(&*text, "s3cret");
    assert!(
        due_a_reseal,
        "the earlier binding is reported for a re-seal"
    );

    rec.reseal(&cipher, &text).unwrap();
    let (_, due_a_reseal) = rec.open_credential(Some(&cipher)).unwrap();
    assert!(!due_a_reseal, "re-sealed under every field");
    let mut moved = rec;
    moved.redirect_url = "https://attacker.example/callback".into();
    assert!(moved.open_secret(Some(&cipher)).is_err());
}

/// The signer's algorithm enters the binding under its JWA name, a fixed
/// string the record's own JSON carries, not a `Debug` rendering.
#[test]
fn the_binding_names_the_signers_algorithm_by_its_jwa_name() {
    use axess_factors::client_assertion::SignerSpec;
    use jsonwebtoken::Algorithm;
    let mut rec = record();
    rec.credential = TenantClientCredential::PrivateKeyJwt {
        key_pem: FactorSecret::Plain("-----BEGIN KEY-----".into()),
        signer: SignerSpec::new(Algorithm::RS256),
    };
    let fields = super::record::binding_fields(&rec);
    assert!(
        fields.contains(&"algorithm:RS256".to_string()),
        "{fields:?}"
    );
    assert_eq!(
        fields
            .iter()
            .filter(|f| f.starts_with("algorithm:"))
            .count(),
        1
    );

    let TenantClientCredential::PrivateKeyJwt { signer, .. } = &mut rec.credential else {
        unreachable!("a key record");
    };
    signer.algorithm = Algorithm::EdDSA;
    let fields = super::record::binding_fields(&rec);
    assert!(
        fields.contains(&"algorithm:EdDSA".to_string()),
        "{fields:?}"
    );
    assert_eq!(
        serde_json::to_value(&rec).unwrap()["credential"]["PrivateKeyJwt"]["algorithm"],
        serde_json::json!("EdDSA"),
        "the stored JSON carries the same name"
    );
}

/// Whether the earlier binding is still read is the cipher's named policy:
/// the default refuses it as a credential that does not open, `Accept` reads
/// it, and a cutoff reads it until then.
#[test]
fn the_earlier_binding_is_read_by_the_ciphers_policy() {
    use crate::authn::factor::{FactorKind, FederatedProvider};
    use crate::authn::factor_secret::{FactorSecretBinding, FactorSecretError};
    use crate::authn::types::AuthnScope;
    use crate::session::legacy_blobs::LegacyBlobs;
    use axess_clock::Clock as _;
    use std::sync::Arc;
    let mut rec = record();
    let scope = AuthnScope::Tenant(rec.tenant_id);
    let kind = FactorKind::Federated(FederatedProvider::Custom(rec.name.clone()));
    let context = [rec.issuer.as_str(), rec.client_id.as_str()];
    let sealed = FactorSecretCipher::new(KEY)
        .seal(
            "s3cret",
            FactorSecretBinding::new(&scope, &kind).with_context(&context),
        )
        .unwrap();
    rec.credential = TenantClientCredential::Secret(FactorSecret::Sealed(sealed));

    let by_default = FactorSecretCipher::new(KEY);
    assert!(!by_default.earlier_tenant_binding_readable());
    assert!(
        matches!(
            rec.open_credential(Some(&by_default)),
            Err(FactorSecretError::Open)
        ),
        "the default does not open the earlier binding"
    );

    let accepting = FactorSecretCipher::new(KEY).with_earlier_tenant_binding(LegacyBlobs::Accept);
    assert_eq!(&*rec.open_secret(Some(&accepting)).unwrap(), "s3cret");

    let clock = axess_clock::testing::MockClock::at(
        axess_clock::Timestamp::from_unix_seconds(1_700_000_000).unwrap(),
    );
    let until = clock.now().plus(axess_clock::SignedDuration::hours(1));
    let windowed = FactorSecretCipher::new(KEY)
        .with_clock(Arc::new(clock.clone()))
        .with_earlier_tenant_binding(LegacyBlobs::AcceptUntil(until));
    assert_eq!(&*rec.open_secret(Some(&windowed)).unwrap(), "s3cret");
    clock.advance(axess_clock::SignedDuration::hours(2));
    assert!(
        matches!(
            rec.open_credential(Some(&windowed)),
            Err(FactorSecretError::Open)
        ),
        "past the cutoff the earlier binding is refused"
    );

    // A credential under the current binding is never affected.
    let mut current = record();
    current.seal(&by_default).unwrap();
    assert_eq!(&*current.open_secret(Some(&by_default)).unwrap(), "s3cret");
}

/// A credential as the first release sealed it: bound to the tenant and the
/// name only, with that binding written out by hand.
#[test]
fn a_credential_sealed_by_the_first_release_still_opens() {
    let rec = record();
    let tenant_id = rec.tenant_id.to_string();
    let mut aad = b"axess.factor-secret.v1".to_vec();
    for part in [tenant_id.as_str(), "", "sso"] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    let nonce_bytes = [3u8; 12];
    let ciphertext = Aes256Gcm::new_from_slice(&KEY)
        .unwrap()
        .encrypt(
            &Nonce::try_from(&nonce_bytes[..]).unwrap(),
            Payload {
                msg: b"s3cret",
                aad: &aad,
            },
        )
        .unwrap();
    let cipher = FactorSecretCipher::new(KEY)
        .with_first_binding(crate::session::legacy_blobs::LegacyBlobs::Accept);
    let mut old = rec;
    old.credential = TenantClientCredential::Secret(FactorSecret::Sealed(SealedFactorSecret {
        key_id: current_key_id(&cipher),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    }));
    assert_eq!(&*old.open_secret(Some(&cipher)).unwrap(), "s3cret");
}

/// The key id the cipher stamps on what it seals, read off a sealed secret.
fn current_key_id(cipher: &FactorSecretCipher) -> String {
    let mut probe = record();
    probe.seal(cipher).unwrap();
    match probe.credential {
        TenantClientCredential::Secret(FactorSecret::Sealed(s)) => s.key_id,
        _ => unreachable!("sealed above"),
    }
}

/// A record without a kind is written as before, with no `kind` key, and
/// reads back as `Custom(name)`; a kind is written, read back, and does not
/// move the binding a sealed credential opens under.
#[test]
fn a_kind_is_written_only_when_set_and_is_not_bound() {
    let plain = record();
    let json = serde_json::to_value(&plain).unwrap();
    assert!(json.get("kind").is_none(), "{json}");
    assert_eq!(
        plain.federated_kind(),
        FederatedProvider::Custom("sso".into())
    );
    let read: TenantOAuthProviderRecord = serde_json::from_value(json).unwrap();
    assert_eq!(read.kind, None);

    let cipher = FactorSecretCipher::new(KEY);
    let mut sealed = record();
    sealed.seal(&cipher).unwrap();
    let mut microsoft = sealed.clone();
    microsoft.kind = Some(FederatedProvider::Microsoft);
    assert_eq!(microsoft.federated_kind(), FederatedProvider::Microsoft);
    assert_eq!(
        &*microsoft.open_secret(Some(&cipher)).unwrap(),
        "s3cret",
        "the kind is not part of the binding"
    );
    let json = serde_json::to_value(&microsoft).unwrap();
    assert_eq!(json["kind"], serde_json::json!("Microsoft"));
    let read: TenantOAuthProviderRecord = serde_json::from_value(json).unwrap();
    assert_eq!(read.kind, Some(FederatedProvider::Microsoft));
}
