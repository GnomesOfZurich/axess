//! A sealed client credential opens only for the record it was sealed for.

use super::*;
use crate::authn::factor_secret::FactorSecretCipher;
use crate::authn::ids::testing::tenant;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
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
