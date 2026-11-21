//! Device-key proofs: a signature by a key the client holds, over a challenge
//! the server chose.
//!
//! A device-bound session rests on one statement, "this request comes from
//! the holder of the key registered for this device", and this module is the
//! verifier of it. A proof is a compact JWS signed with `ES256` over a P-256
//! key. It comes in two shapes that differ only in where the claims sit:
//!
//! | Shape | `typ` | Key | Challenge | What it is for |
//! |---|---|---|---|---|
//! | [`Browser`](KeyProofShape::Browser) | [`browser_draft::PROOF_TYP`] | per [`browser_draft::PROOF_KEY_PLACE`] | [`browser_draft::PROOF_CHALLENGE_CLAIM`] | the browser draft, where the browser signs unprompted |
//! | [`App`](KeyProofShape::App) | `dpop+jwt` | the `jwk` header | `nonce` | RFC 9449, for a client that signs itself |
//!
//! # What is and is not read
//!
//! - **For a proof that answers a challenge, the challenge is the
//!   freshness.** The server minted it and knows its age, and it is accepted
//!   once. No time claim of such a proof is read, so the client's clock
//!   decides nothing, and [`ParsedKeyProof::verify`] and [`verify_key_proof`]
//!   read no clock at all.
//! - **A request proof is the one exception.** A proof in the app shape that
//!   rides on an ordinary request answers no challenge
//!   ([`ParsedKeyProof::verify_request`]): its freshness is its `iat`, the
//!   client's clock, held to a lifetime and a clock allowance against the
//!   `now` the caller passes in, and its `jti`, which the caller records in
//!   a replay store so the proof is accepted once.
//! - **The key is the sender's only at registration.** A registration proof
//!   carries its key ([`ProofKey::Embedded`]) and proves possession of it.
//!   Every later proof is verified under the key the server stored
//!   ([`ProofKey::Stored`]); a key the proof carries is then ignored.
//! - **One algorithm.** `ES256`, for the reasons the DPoP verifier gives: the
//!   key is the client's choice, so a second algorithm buys a server nothing
//!   and costs it a second parser for a key a stranger supplies.
//!
//! # Two steps
//!
//! [`parse_key_proof`] checks the structure and yields the challenge the
//! proof answers without verifying anything, so a caller can refuse a proof
//! for a challenge that is gone before it spends a signature verification.
//! [`ParsedKeyProof::verify`] then checks the target and the signature.
//! [`verify_key_proof`] does both, challenge first. A browser-shaped proof
//! names no target in the constants' revision of the draft
//! ([`browser_draft::PROOF_AUDIENCE_CLAIM`] is `None`), so for that shape
//! the target is not compared and the challenge alone binds the proof to its
//! endpoint; an app-shaped proof is held to `htm` and `htu`.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "testing")] {
//! use axess_factors::key_proof::testing::SoftwareKey;
//! use axess_factors::key_proof::{
//!     KeyProofRequest, KeyProofShape, ProofKey, ProofTarget, verify_key_proof,
//! };
//!
//! let key = SoftwareKey::from_seed([7; 32]);
//! let target = ProofTarget { method: "POST", url: "https://app.example/axess/device-key" };
//! let proof = key.sign(KeyProofShape::App, target, "the-challenge", true);
//!
//! let verified = verify_key_proof(KeyProofRequest {
//!     jws: &proof,
//!     shape: KeyProofShape::App,
//!     target,
//!     challenge: "the-challenge",
//!     key: ProofKey::Embedded,
//! })
//! .expect("a proof over the right challenge, by the key it carries");
//! assert_eq!(verified.key, key.public());
//! # }
//! ```

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;
use subtle::ConstantTimeEq;

pub mod browser_draft;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
#[cfg(test)]
mod tests;

/// The one JWS algorithm a device-key proof may be signed with.
pub const KEY_PROOF_ALG: &str = "ES256";

/// Longest proof read, in bytes. A real one (a header with an EC key, three
/// claims, a signature) is under 1 KiB; anything past this is refused before
/// it is split or decoded.
pub const MAX_KEY_PROOF_BYTES: usize = 8 * 1024;

/// The `typ` of a proof in the [`App`](KeyProofShape::App) shape (RFC 9449).
pub const APP_PROOF_TYP: &str = "dpop+jwt";

/// Longest `jti` a request proof may carry, in bytes. A UUID is 36.
pub const MAX_REQUEST_JTI_BYTES: usize = 256;

/// A P-256 public key as its two affine coordinates.
///
/// Built from a JWK only when the JWK names `EC` and `P-256`, holds a 32-byte
/// `x` and `y` that are a point of the curve, and carries no private member.
/// The fields are public, so a key read back from storage can hold any pair:
/// a proof verified under a pair that is no point of the curve is refused as
/// [`KeyProofError::Key`] before its signature is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct P256Key {
    /// The x coordinate, big-endian.
    pub x: [u8; 32],
    /// The y coordinate, big-endian.
    pub y: [u8; 32],
}

impl P256Key {
    /// Read a public key from a JWK its sender chose.
    pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self, KeyProofError> {
        crate::jwk_p256::refuse_private_members(jwk).map_err(|_| KeyProofError::Key)?;
        let (x, y) = crate::jwk_p256::coordinates(jwk).map_err(|_| KeyProofError::Key)?;
        // The point is checked where the key enters, so a pair of
        // coordinates that is no point of the curve is never stored.
        let key = Self { x, y };
        key.check_point()?;
        Ok(key)
    }

    /// Refuse a pair of coordinates that is no point of the curve.
    fn check_point(&self) -> Result<(), KeyProofError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&self.x);
        sec1[33..].copy_from_slice(&self.y);
        p256::PublicKey::from_sec1_bytes(&sec1)
            .map(drop)
            .map_err(|_| KeyProofError::Key)
    }

    /// The key as a public JWK with exactly `crv`, `kty`, `x` and `y`.
    pub fn to_jwk(&self) -> serde_json::Value {
        crate::jwk_p256::public_jwk(&self.x, &self.y)
    }

    /// The RFC 7638 SHA-256 thumbprint of the key.
    pub fn thumbprint(&self) -> [u8; 32] {
        crate::jwk_p256::thumbprint(&self.x, &self.y)
    }
}

/// Which front-end made a proof, and so where its claims sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyProofShape {
    /// The browser draft; see [`browser_draft`] for its layout.
    Browser,
    /// RFC 9449: `htm`, `htu`, and the challenge in `nonce`.
    App,
}

/// The key a proof is verified under.
#[derive(Debug, Clone, Copy)]
pub enum ProofKey<'a> {
    /// The key the proof carries: a registration, which proves possession of
    /// the key it presents.
    Embedded,
    /// The key the server stored for the device: every later proof. A key
    /// the proof carries is not read.
    Stored(&'a P256Key),
}

/// The request a proof must have been made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofTarget<'a> {
    /// The HTTP method, compared exactly. Read in the
    /// [`App`](KeyProofShape::App) shape (`htm`).
    pub method: &'a str,
    /// Scheme, host and path, with no query or fragment: `htu` in the
    /// [`App`](KeyProofShape::App) shape, the audience claim in the
    /// [`Browser`](KeyProofShape::Browser) shape when
    /// [`browser_draft::PROOF_AUDIENCE_CLAIM`] names one.
    pub url: &'a str,
}

/// Why a proof was refused. Each variant is one check, and none carries any
/// of the sender's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyProofError {
    /// Longer than [`MAX_KEY_PROOF_BYTES`].
    #[error("the key proof is too large")]
    TooLarge,
    /// Not three base64url segments holding two JSON objects and a signature.
    #[error("the key proof is not a compact JWS of two JSON objects")]
    Malformed,
    /// `alg` is not [`KEY_PROOF_ALG`].
    #[error("the key proof is not signed with ES256")]
    Algorithm,
    /// `typ` is not the one its shape requires.
    #[error("the key proof has the wrong `typ`")]
    Type,
    /// The key it carries is missing, is not a P-256 public key, or holds a
    /// private member, or the stored key it is verified under is no point of
    /// the curve.
    #[error("the key proof has no usable P-256 public key")]
    Key,
    /// It was made for another method or URL.
    #[error("the key proof was made for another request")]
    Target,
    /// It answers another challenge, or none.
    #[error("the key proof does not answer the challenge")]
    Challenge,
    /// The signature is not the key's.
    #[error("the key proof's signature does not verify")]
    Signature,
    /// A request proof's `iat` is missing or outside the accepted window.
    #[error("the key proof's `iat` is outside the accepted window")]
    Time,
    /// A request proof carries no `jti`, or one longer than
    /// [`MAX_REQUEST_JTI_BYTES`].
    #[error("the key proof carries no usable `jti`")]
    Identifier,
}

/// A proof whose structure, algorithm and type hold. Nothing in it is
/// verified yet: the challenge it reports is the sender's claim.
#[derive(Debug, Clone)]
pub struct ParsedKeyProof<'a> {
    signing_input: &'a str,
    signature: &'a str,
    header: serde_json::Value,
    claims: serde_json::Value,
    shape: KeyProofShape,
}

/// Check a proof's size, structure, algorithm and type.
pub fn parse_key_proof(
    jws: &str,
    shape: KeyProofShape,
) -> Result<ParsedKeyProof<'_>, KeyProofError> {
    // A proof is self-signed, so anyone can mint one: the size is bounded
    // before anything is split or decoded.
    if jws.len() > MAX_KEY_PROOF_BYTES {
        return Err(KeyProofError::TooLarge);
    }
    let mut segments = jws.split('.');
    let (Some(head), Some(body), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(KeyProofError::Malformed);
    };
    let header = json_object(head)?;
    let claims = json_object(body)?;
    // No extension is understood, so none may be marked critical (RFC 7515
    // section 4.1.11): a proof that says it must be understood is not.
    if header.get("crit").is_some() {
        return Err(KeyProofError::Malformed);
    }
    if header.get("alg").and_then(|v| v.as_str()) != Some(KEY_PROOF_ALG) {
        return Err(KeyProofError::Algorithm);
    }
    let typ = match shape {
        KeyProofShape::Browser => browser_draft::PROOF_TYP,
        KeyProofShape::App => APP_PROOF_TYP,
    };
    if header.get("typ").and_then(|v| v.as_str()) != Some(typ) {
        return Err(KeyProofError::Type);
    }
    Ok(ParsedKeyProof {
        signing_input: &jws[..head.len() + 1 + body.len()],
        signature,
        header,
        claims,
        shape,
    })
}

/// One segment of a JWS as the JSON object it must hold.
fn json_object(segment: &str) -> Result<serde_json::Value, KeyProofError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| KeyProofError::Malformed)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| KeyProofError::Malformed)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(KeyProofError::Malformed)
    }
}

impl ParsedKeyProof<'_> {
    /// The challenge the proof says it answers. Unverified.
    pub fn challenge(&self) -> Option<&str> {
        let claim = match self.shape {
            KeyProofShape::Browser => browser_draft::PROOF_CHALLENGE_CLAIM,
            KeyProofShape::App => "nonce",
        };
        self.claims.get(claim).and_then(|v| v.as_str())
    }

    /// Whether the proof says it answers `challenge`, compared in constant
    /// time. A proof with no challenge answers none.
    pub fn answers(&self, challenge: &str) -> bool {
        self.challenge()
            .is_some_and(|claimed| bool::from(claimed.as_bytes().ct_eq(challenge.as_bytes())))
    }

    /// Check that the proof was made for `target` and signed by `key`.
    ///
    /// The challenge is not compared here: compare it with
    /// [`answers`](Self::answers), before or after, as the caller's order of
    /// refusals needs.
    pub fn verify(
        &self,
        target: ProofTarget<'_>,
        key: ProofKey<'_>,
    ) -> Result<VerifiedKeyProof, KeyProofError> {
        self.check_target(target)?;
        let key = match key {
            ProofKey::Stored(key) => *key,
            ProofKey::Embedded => self.embedded_key()?,
        };
        if !signature_holds(self.signing_input, self.signature, &key)? {
            return Err(KeyProofError::Signature);
        }
        Ok(VerifiedKeyProof {
            key,
            thumbprint: key.thumbprint(),
        })
    }

    fn check_target(&self, target: ProofTarget<'_>) -> Result<(), KeyProofError> {
        let claim = |name: &str| self.claims.get(name).and_then(|v| v.as_str());
        let holds = match self.shape {
            KeyProofShape::Browser => {
                audience_holds(browser_draft::PROOF_AUDIENCE_CLAIM, claim, target.url)
            }
            KeyProofShape::App => {
                claim("htm") == Some(target.method) && claim("htu") == Some(target.url)
            }
        };
        if holds {
            Ok(())
        } else {
            Err(KeyProofError::Target)
        }
    }

    /// The public key the proof carries, where its shape puts it.
    fn embedded_key(&self) -> Result<P256Key, KeyProofError> {
        let jwk = match self.shape {
            KeyProofShape::App => self.header.get("jwk"),
            KeyProofShape::Browser => match browser_draft::PROOF_KEY_PLACE {
                browser_draft::KeyPlace::Header => self.header.get(browser_draft::PROOF_KEY_MEMBER),
                browser_draft::KeyPlace::Claims => self.claims.get(browser_draft::PROOF_KEY_MEMBER),
            },
        };
        P256Key::from_jwk(jwk.ok_or(KeyProofError::Key)?)
    }
}

/// Whether a browser proof names `url` in `audience`, the claim its
/// revision of the draft carries the endpoint in. A revision with no such
/// claim binds the proof to its endpoint by the challenge alone.
fn audience_holds<'c>(
    audience: Option<&str>,
    claim: impl Fn(&str) -> Option<&'c str>,
    url: &str,
) -> bool {
    audience.is_none_or(|name| claim(name) == Some(url))
}

/// Whether `signature` is `key`'s over `signing_input`.
fn signature_holds(
    signing_input: &str,
    signature: &str,
    key: &P256Key,
) -> Result<bool, KeyProofError> {
    use jsonwebtoken::{Algorithm, DecodingKey};
    // `DecodingKey::from_jwk` joins the coordinates and checks no point, so
    // every key is checked here, as `from_jwk` checks one where it enters: a
    // stored pair, which anyone can write into the public fields, that is no
    // point of the curve is a key fault, never a signature that fails.
    key.check_point()?;
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(key.to_jwk()).map_err(|_| KeyProofError::Key)?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|_| KeyProofError::Key)?;
    crate::jwt::verify(
        signature,
        signing_input.as_bytes(),
        &decoding_key,
        Algorithm::ES256,
    )
    .map_err(|_| KeyProofError::Signature)
}

/// What a proof that rides on an ordinary request is checked against: the
/// request, the time, and the key stored for the device.
#[derive(Debug, Clone, Copy)]
pub struct RequestProofCheck<'a> {
    /// The request the proof must have been made for (`htm`, `htu`).
    pub target: ProofTarget<'a>,
    /// Now, in Unix seconds, from the caller's injected clock.
    pub now_unix: i64,
    /// How long before now the proof's `iat` may lie: the proof's
    /// lifetime. Counted in whole seconds, as `iat` and `now_unix` are, so
    /// a fraction of a second in it changes nothing.
    pub max_age: Duration,
    /// How long after now the proof's `iat` may lie: what the sender's
    /// clock may run ahead by, and no more, since a proof dated ahead is one
    /// made before it is used. Counted in whole seconds, as `max_age` is.
    pub max_ahead: Duration,
    /// The key the signature is checked under: the one the proof carries in
    /// its `jwk` header ([`ProofKey::Embedded`]), which shows the sender
    /// holds that key and costs the server no read, or one the server
    /// stored ([`ProofKey::Stored`]).
    pub key: ProofKey<'a>,
}

/// A request proof that verified. Its `jti` is the caller's to record, so
/// the same proof is not accepted twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequestProof {
    /// The key the signature held under: the stored one, or the one the
    /// proof carried. A caller that verified under the carried key compares
    /// it with the key it holds for the device before it trusts the proof.
    pub key: P256Key,
    /// The thumbprint of that key.
    pub thumbprint: [u8; 32],
    /// The proof's `jti`.
    pub jti: String,
    /// The proof's `iat`, in Unix seconds.
    pub iat: i64,
}

/// The whole seconds of a span, the largest count for one past it.
fn whole_seconds(span: Duration) -> i64 {
    i64::try_from(span.as_secs()).unwrap_or(i64::MAX)
}

impl ParsedKeyProof<'_> {
    /// Verify a proof in the [`App`](KeyProofShape::App) shape that rides on
    /// an ordinary request rather than answering a challenge: RFC 9449's
    /// `htm` and `htu`, an `iat` no more than `max_age` before now and
    /// no more than `max_ahead` after it, a `jti` of at most
    /// [`MAX_REQUEST_JTI_BYTES`], and the signature under the key
    /// [`RequestProofCheck::key`] names.
    ///
    /// Freshness here comes from the `iat` and the single use of the `jti`,
    /// so the caller must record the returned `jti` in a replay store for
    /// the whole span over which the proof is accepted (`max_age` plus
    /// `max_ahead`), and refuse one it already holds.
    pub fn verify_request(
        &self,
        check: RequestProofCheck<'_>,
    ) -> Result<VerifiedRequestProof, KeyProofError> {
        if self.shape != KeyProofShape::App {
            return Err(KeyProofError::Type);
        }
        self.check_target(check.target)?;
        let iat = self
            .claims
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or(KeyProofError::Time)?;
        // A whole count of seconds is within a span exactly when it is
        // within the span's whole seconds.
        let (max_age, max_ahead) = (whole_seconds(check.max_age), whole_seconds(check.max_ahead));
        let within = check.now_unix.checked_sub(iat).is_some_and(|age| {
            age <= max_age && age.checked_neg().is_some_and(|ahead| ahead <= max_ahead)
        });
        if !within {
            return Err(KeyProofError::Time);
        }
        let jti = self
            .claims
            .get("jti")
            .and_then(|v| v.as_str())
            .filter(|jti| !jti.is_empty() && jti.len() <= MAX_REQUEST_JTI_BYTES)
            .ok_or(KeyProofError::Identifier)?;
        let key = match check.key {
            ProofKey::Stored(key) => *key,
            ProofKey::Embedded => self.embedded_key()?,
        };
        if !signature_holds(self.signing_input, self.signature, &key)? {
            return Err(KeyProofError::Signature);
        }
        Ok(VerifiedRequestProof {
            key,
            thumbprint: key.thumbprint(),
            jti: jti.to_owned(),
            iat,
        })
    }
}

/// Everything [`verify_key_proof`] needs.
#[derive(Debug, Clone, Copy)]
pub struct KeyProofRequest<'a> {
    /// The proof, a compact JWS.
    pub jws: &'a str,
    /// The front-end that sent it.
    pub shape: KeyProofShape,
    /// The request it must have been made for.
    pub target: ProofTarget<'a>,
    /// The challenge it must answer.
    pub challenge: &'a str,
    /// The key it is verified under.
    pub key: ProofKey<'a>,
}

/// A proof that verified: the key that signed it and that key's thumbprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedKeyProof {
    /// The key the signature is by: the stored one, or at a registration the
    /// one the proof carried.
    pub key: P256Key,
    /// The key's RFC 7638 SHA-256 thumbprint.
    pub thumbprint: [u8; 32],
}

/// Verify a proof: structure, then the challenge, then the target and the
/// signature. Reads no clock.
pub fn verify_key_proof(request: KeyProofRequest<'_>) -> Result<VerifiedKeyProof, KeyProofError> {
    let parsed = parse_key_proof(request.jws, request.shape)?;
    if !parsed.answers(request.challenge) {
        return Err(KeyProofError::Challenge);
    }
    parsed.verify(request.target, request.key)
}
