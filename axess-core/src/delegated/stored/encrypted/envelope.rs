//! The envelope format of the encrypted delegated-credential store: the
//! additional authenticated data each version binds, and the AES-256-GCM
//! codec that seals and opens one token field.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axess_identity::{TenantId, UserId};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use axess_rng::SecureRng;

use super::keys::{CurrentKey, KeyProvider, KeyProviderError};
use super::{AAD_SEP, ENVELOPE_VERSION, NONCE_LEN, SCOPED_ENVELOPE_VERSION};

// ── AAD ──────────────────────────────────────────────────────────────────────

pub(super) fn build_aad(provider: &str, tenant: &TenantId, user: &UserId, field: &[u8]) -> Vec<u8> {
    let provider_bytes = provider.as_bytes();
    let tenant_bytes = tenant.as_bytes();
    let user_bytes = user.as_bytes();
    let mut buf = Vec::with_capacity(provider_bytes.len() + 16 + 16 + field.len() + 3);
    buf.extend_from_slice(provider_bytes);
    buf.push(AAD_SEP);
    buf.extend_from_slice(tenant_bytes);
    buf.push(AAD_SEP);
    buf.extend_from_slice(user_bytes);
    buf.push(AAD_SEP);
    buf.extend_from_slice(field);
    buf
}

/// Append `bytes` length-prefixed, so no value can bleed into its neighbour.
fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// The `v1` fields, then the version tag, the token type and the scope
/// set, each length-prefixed. Scopes are sorted and de-duplicated so a store
/// that reorders a set does not break authentication; changing the set does.
fn build_aad_scoped(
    version: &str,
    provider: &str,
    tenant: &TenantId,
    user: &UserId,
    field: &[u8],
    scopes: &[String],
    token_type: &str,
) -> Vec<u8> {
    let mut buf = build_aad(provider, tenant, user, field);
    buf.push(AAD_SEP);
    put(&mut buf, version.as_bytes());
    put(&mut buf, token_type.as_bytes());
    let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for scope in sorted {
        put(&mut buf, scope.as_bytes());
    }
    buf
}

/// `v2` AAD: identity fields, token type and scope set.
pub(super) fn build_aad_v2(
    provider: &str,
    tenant: &TenantId,
    user: &UserId,
    field: &[u8],
    scopes: &[String],
    token_type: &str,
) -> Vec<u8> {
    build_aad_scoped(
        SCOPED_ENVELOPE_VERSION,
        provider,
        tenant,
        user,
        field,
        scopes,
        token_type,
    )
}

/// `v3` AAD: the `v2` fields, then `expires_at` as eight big-endian bytes
/// of Unix seconds, or an empty length-prefixed value for `None`. The
/// consumer refreshes when `now` nears `expires_at`, so a writer who moves
/// it would otherwise make a stale token look fresh or a fresh one stale.
pub(super) fn build_aad_v3(
    provider: &str,
    tenant: &TenantId,
    user: &UserId,
    field: &[u8],
    scopes: &[String],
    token_type: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Vec<u8> {
    let mut buf = build_aad_scoped(
        ENVELOPE_VERSION,
        provider,
        tenant,
        user,
        field,
        scopes,
        token_type,
    );
    match expires_at {
        Some(at) => put(&mut buf, &at.timestamp().to_be_bytes()),
        None => put(&mut buf, b""),
    }
    buf
}

/// One decrypted field and what it was sealed under.
pub(super) struct Opened {
    pub(super) plain: String,
    version: String,
    key_id: String,
}

impl Opened {
    pub(super) fn is_stale(&self, current_key_id: Option<&str>) -> bool {
        current_key_id.is_some_and(|c| self.version != ENVELOPE_VERSION || self.key_id != c)
    }
}

// ── Envelope codec ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub(super) enum EnvelopeError {
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("unknown envelope version {0:?}; store written by a newer axess?")]
    UnknownVersion(String),
    #[error("a v1 envelope is refused (legacy envelopes are rejected)")]
    LegacyRefused,
    #[error("unknown key id {0:?}")]
    UnknownKeyId(String),
    #[error("key provider error: {0}")]
    KeyProvider(#[from] KeyProviderError),
    #[error("decryption failed (wrong key, corrupted ciphertext, or AAD mismatch)")]
    Decrypt,
    #[error("base64 decode failed")]
    Base64,
    #[error("encryption failed")]
    Encrypt,
}

pub(super) fn encrypt_envelope(
    current: &CurrentKey,
    rng: &dyn SecureRng,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, EnvelopeError> {
    let cipher =
        Aes256Gcm::new_from_slice(current.key.as_array()).map_err(|_| EnvelopeError::Encrypt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| EnvelopeError::Encrypt)?;

    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Encrypt)?;

    let mut body = Vec::with_capacity(NONCE_LEN + ct.len());
    body.extend_from_slice(&nonce_bytes);
    body.extend_from_slice(&ct);

    let b64 = URL_SAFE_NO_PAD.encode(&body);
    Ok(format!("{ENVELOPE_VERSION}.{}.{}", &*current.key_id, b64))
}

/// Open a `v1` envelope under the given AAD. Kept as the narrow entry the
/// codec tests drive; the store reads through [`open_envelope`].
#[cfg(test)]
pub(super) fn decrypt_envelope<K: KeyProvider>(
    keys: &K,
    envelope: &str,
    aad: &[u8],
) -> Result<String, EnvelopeError> {
    let aad_for = |version: &str| (version == super::LEGACY_ENVELOPE_VERSION).then(|| aad.to_vec());
    open_envelope(keys, envelope, &aad_for).map(|o| o.plain)
}

pub(super) fn open_envelope<K: KeyProvider>(
    keys: &K,
    envelope: &str,
    aad_for_version: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<Opened, EnvelopeError> {
    // Strictly three parts: version, key_id, body. key_id is
    // adopter-chosen but we forbid `.` at construction, so two splits
    // from the left is sufficient.
    let mut parts = envelope.splitn(3, '.');
    let version = parts.next().ok_or(EnvelopeError::Malformed("no version"))?;
    let key_id = parts.next().ok_or(EnvelopeError::Malformed("no key id"))?;
    let body_b64 = parts.next().ok_or(EnvelopeError::Malformed("no body"))?;

    let aad = aad_for_version(version)
        .ok_or_else(|| EnvelopeError::UnknownVersion(version.to_string()))?;
    if key_id.is_empty() {
        return Err(EnvelopeError::Malformed("empty key id"));
    }

    let body = URL_SAFE_NO_PAD
        .decode(body_b64)
        .map_err(|_| EnvelopeError::Base64)?;
    if body.len() <= NONCE_LEN {
        return Err(EnvelopeError::Malformed("body shorter than nonce"));
    }
    let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);

    let key = keys
        .resolve(key_id)?
        .ok_or_else(|| EnvelopeError::UnknownKeyId(key_id.to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(key.as_array()).map_err(|_| EnvelopeError::Decrypt)?;
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| EnvelopeError::Decrypt)?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::Decrypt)?;

    let plain = String::from_utf8(plaintext)
        .map_err(|_| EnvelopeError::Malformed("plaintext not utf-8"))?;
    Ok(Opened {
        plain,
        version: version.to_string(),
        key_id: key_id.to_string(),
    })
}
