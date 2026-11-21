//! RFC 7523 client assertions: the signed JWT a client presents to a token
//! endpoint in place of a shared secret (`private_key_jwt`, OpenID Connect
//! Core section 9).
//!
//! One signer serves the outbound `client_credentials` client, the user
//! login's token requests and a tenant's stored provider (through
//! [`SignerSpec`](crate::client_assertion::SignerSpec)), so the claims, the
//! headers, the `jti` and the clock are decided in one place. Nothing here reads the wall clock or the system
//! random source: the caller passes both, and a test injects a `MockClock`
//! and a seeded RNG to reproduce an assertion byte for byte.
//!
//! An RSA key (`RS*`, `PS*`) signs only where the build chose it. Its
//! signature runs in whichever `jsonwebtoken` crypto provider the process
//! installed: in aws-lc-rs where axess installed that one, which it does on
//! the `jwt-aws-lc` backend unless another provider was installed first,
//! and otherwise possibly in `rsa` 0.9, whose private-key operations leak
//! timing (RUSTSEC-2023-0071). So a signer for an RSA algorithm is refused
//! when it is built, before its key is read, unless the
//! `client-assertion-rsa` feature names that choice or axess's own aws-lc
//! install is the one in place. `jsonwebtoken` offers no read of which
//! provider another crate or the application installed, so a build that
//! installs one itself before axess does, aws-lc included, is refused as
//! well.

use axess_clock::Clock;
use axess_rng::SecureRng;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Builder as UuidBuilder;

/// The default lifetime of one assertion. RFC 7523 section 3 wants it short;
/// an IdP that sees an `exp` far in the future may refuse it.
pub const DEFAULT_ASSERTION_TTL: Duration = Duration::from_secs(60);

/// RFC 7523 client-assertion JWT body.
#[derive(Serialize)]
struct ClientAssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: String,
}

/// Why a [`ClientAssertionSigner`] could not be built, or could not sign.
/// No variant carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientAssertionError {
    /// The text does not start with a PEM block.
    #[error("not a PEM block")]
    NotPem,
    /// The PEM block has an encryption header; decrypt the key where it is
    /// stored.
    #[error("an encrypted PEM key is not supported")]
    Encrypted,
    /// The PEM block has no `-----END` line.
    #[error("the PEM block is not closed")]
    Unclosed,
    /// The PEM body is not base64.
    #[error("the PEM body is not base64")]
    NotBase64,
    /// A PKCS#8 `PRIVATE KEY` whose structure does not parse.
    #[error("the PKCS#8 key is malformed")]
    MalformedPkcs8,
    /// The PEM label does not suit the algorithm (an EC algorithm needs a
    /// PKCS#8 `PRIVATE KEY`, an RSA algorithm a PKCS#1 or PKCS#8 key).
    #[error("{algorithm:?} cannot use a `{label}` PEM")]
    LabelMismatch {
        /// The algorithm asked for.
        algorithm: Algorithm,
        /// The label of the PEM block given.
        label: String,
    },
    /// `private_key_jwt` signs with an asymmetric algorithm only: `RS*`,
    /// `PS*`, `ES256`, `ES384` or `EdDSA`. An `HS*` assertion would be
    /// `client_secret_jwt`, keyed by a secret the IdP also holds.
    #[error(
        "private_key_jwt needs an asymmetric algorithm (RS*, PS*, ES256, ES384 or EdDSA), \
         not {0:?}"
    )]
    Symmetric(Algorithm),
    /// An RSA algorithm (`RS*`, `PS*`) where its signature may run in
    /// `rsa` 0.9, whose private-key operations leak timing
    /// (RUSTSEC-2023-0071): a build without `jwt-aws-lc`, or one with it
    /// where a `jsonwebtoken` crypto provider was installed before axess
    /// installed aws-lc (by the application or another crate; which one
    /// cannot be read back, so any). Refused before the key is read. Enable
    /// `client-assertion-rsa` to choose it, build with `jwt-aws-lc` and leave
    /// installing the provider to axess, or sign with `ES256`, `ES384` or
    /// `EdDSA`.
    #[error(
        "{0:?} signs with an RSA key, which may run in rsa 0.9 (RUSTSEC-2023-0071): the build \
         lacks jwt-aws-lc, or a jsonwebtoken crypto provider was installed before axess \
         installed aws-lc. Enable the `client-assertion-rsa` feature to choose it, build with \
         `jwt-aws-lc` and leave installing the provider to axess, or sign with ES256, ES384 \
         or EdDSA"
    )]
    RsaNotChosen(Algorithm),
    /// The key does not sign under the algorithm (an EC key for `RS256`).
    #[error("the key does not sign under {algorithm:?}: {reason}")]
    KeyMismatch {
        /// The algorithm asked for.
        algorithm: Algorithm,
        /// What the signer reported.
        reason: String,
    },
    /// Signing one assertion failed after the signer was built.
    #[error("signing the client assertion failed: {0}")]
    Signing(String),
    /// The assertion lifetime is no time, or has a fraction of a second: the
    /// `exp` it sets is a whole count of seconds after `iat` (RFC 7519
    /// NumericDate), and an assertion is not accepted on or after its `exp`.
    #[error(
        "the assertion lifetime of {0:?} is refused: `assertion_ttl` is a whole, non-zero \
         number of seconds, since `exp` is whole seconds after `iat`"
    )]
    AssertionTtl(Duration),
}

/// `ttl`, when an assertion can be given it: a whole, non-zero number of
/// seconds.
fn checked_ttl(ttl: Duration) -> Result<Duration, ClientAssertionError> {
    if ttl.is_zero() || ttl.subsec_nanos() != 0 {
        return Err(ClientAssertionError::AssertionTtl(ttl));
    }
    Ok(ttl)
}

/// How a `private_key_jwt` signer shapes its assertions, apart from the key
/// and the client id: what a stored configuration (a tenant's provider
/// record) keeps beside the sealed key, and turns into a signer with
/// [`ClientAssertionSigner::from_spec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSpec {
    /// JWA algorithm: `RS256`, `PS256`, `ES256` or `EdDSA` are the usual.
    pub algorithm: Algorithm,
    /// `kid` header, when the IdP selects the key by it.
    #[serde(default)]
    pub key_id: Option<String>,
    /// `x5t#S256` header (certificate SHA-256 thumbprint, base64url);
    /// Microsoft Entra requires it or `x5t`.
    #[serde(default)]
    pub x5t_s256: Option<String>,
    /// `x5t` header (certificate SHA-1 thumbprint, base64url).
    #[serde(default)]
    pub x5t: Option<String>,
    /// Fixed `aud`; by default the endpoint called, or the issuer under the
    /// FAPI profile.
    #[serde(default)]
    pub audience: Option<String>,
    /// Lifetime of one assertion, a whole, non-zero number of seconds; by
    /// default [`DEFAULT_ASSERTION_TTL`].
    /// [`from_spec`](ClientAssertionSigner::from_spec) refuses another.
    /// Stored as a count of seconds under `assertion_ttl_secs`, as before.
    #[serde(
        rename = "assertion_ttl_secs",
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::whole_seconds::option_u64_seconds"
    )]
    pub assertion_ttl: Option<Duration>,
}

impl SignerSpec {
    /// A spec for `algorithm` with no headers beyond it, the default
    /// audience and lifetime.
    #[must_use]
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            key_id: None,
            x5t_s256: None,
            x5t: None,
            audience: None,
            assertion_ttl: None,
        }
    }
}

/// A client's signing identity for `private_key_jwt`: the client id, the
/// private key, and how its assertions are shaped.
///
/// The one representation of `private_key_jwt` in axess: hand it to
/// [`OAuthProviderBuilder::with_private_key_jwt`](crate::oauth::OAuthProviderBuilder::with_private_key_jwt)
/// to authenticate a user login's code exchange, refresh, PAR, revocation
/// and `client_credentials` requests, or to the outbound client as
/// `ClientAuthMethod::PrivateKeyJwt`; a stored configuration keeps a
/// [`SignerSpec`] and builds one with [`from_spec`](Self::from_spec).
#[derive(Clone)]
pub struct ClientAssertionSigner {
    client_id: String,
    key: EncodingKey,
    header: Header,
    audience: Option<String>,
    ttl: Duration,
}

impl std::fmt::Debug for ClientAssertionSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAssertionSigner")
            .field("client_id", &self.client_id)
            .field("algorithm", &self.header.alg)
            .field("key_id", &self.header.kid)
            .field("audience", &self.audience)
            .field("ttl", &self.ttl)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Whether `algorithm` is one `private_key_jwt` signs with.
fn is_asymmetric(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

/// Whether `algorithm` signs with an RSA key.
fn is_rsa(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
    )
}

/// Whether this process signs with an RSA key: where `client-assertion-rsa`
/// chose it whatever the provider, or where the provider in place is the
/// aws-lc one axess installed.
///
/// The second half is read at run time, not from the build's features: a
/// build that compiles `jwt-aws-lc` may still have another provider in
/// place, installed by the application or another crate before axess
/// installed its own, and with both backends compiled that one may be
/// RustCrypto's, which signs RSA in `rsa` 0.9. Which provider is in place
/// cannot be read back (see
/// [`axess_installed_aws_lc`](crate::jwt::axess_installed_aws_lc)), so the
/// answer is yes only where axess's own install is known to have taken,
/// and no for every other provider, aws-lc installed by someone else
/// included. Without `jwt-aws-lc` axess never installs aws-lc, so the
/// question is not asked.
fn rsa_signs() -> bool {
    cfg!(feature = "client-assertion-rsa")
        || (cfg!(feature = "jwt-aws-lc") && crate::jwt::axess_installed_aws_lc())
}

/// [`ClientAssertionError::RsaNotChosen`] for an RSA algorithm when
/// `rsa_signs` is false; every other algorithm passes.
fn check_rsa_choice(algorithm: Algorithm, rsa_signs: bool) -> Result<(), ClientAssertionError> {
    if is_rsa(algorithm) && !rsa_signs {
        Err(ClientAssertionError::RsaNotChosen(algorithm))
    } else {
        Ok(())
    }
}

impl ClientAssertionSigner {
    /// A signer for `client_id` with `key` under `algorithm`, no `kid`, the
    /// default audience (see [`with_audience`](Self::with_audience)) and a
    /// 60 second lifetime.
    ///
    /// One throw-away assertion is signed here, so a key that does not suit
    /// the algorithm fails at startup rather than at the first request.
    ///
    /// # Errors
    ///
    /// [`ClientAssertionError::Symmetric`] for an algorithm that is not
    /// asymmetric, [`ClientAssertionError::RsaNotChosen`] for an RSA
    /// algorithm the build did not choose or the installed crypto provider
    /// does not sign safely (see the module documentation),
    /// both before the key is used, and [`ClientAssertionError::KeyMismatch`]
    /// when the key does not sign under it.
    pub fn new(
        client_id: impl Into<String>,
        key: EncodingKey,
        algorithm: Algorithm,
    ) -> Result<Self, ClientAssertionError> {
        if !is_asymmetric(algorithm) {
            return Err(ClientAssertionError::Symmetric(algorithm));
        }
        check_rsa_choice(algorithm, rsa_signs())?;
        let signer = Self {
            client_id: client_id.into(),
            key,
            header: Header::new(algorithm),
            audience: None,
            ttl: DEFAULT_ASSERTION_TTL,
        };
        signer
            .sign("probe", 0, [0; 16])
            .map_err(|reason| ClientAssertionError::KeyMismatch { algorithm, reason })?;
        Ok(signer)
    }

    /// A signer from a PEM private key, the form a key is usually kept in.
    ///
    /// Accepted: `RSA PRIVATE KEY` (PKCS#1) and `PRIVATE KEY` (PKCS#8) for
    /// the RSA algorithms (`RS*`, `PS*`), and PKCS#8 `PRIVATE KEY` for
    /// `ES256`, `ES384` and `EdDSA`. An encrypted key is not: decrypt it
    /// where it is stored.
    ///
    /// # Errors
    ///
    /// A [`ClientAssertionError`] (never containing key material) when
    /// `algorithm` is a symmetric one or an RSA algorithm the build did not
    /// choose or the installed provider does not sign safely (both before
    /// the text is read), the text is not PEM, the label
    /// does not suit the algorithm, or the key does not sign under it.
    pub fn from_pem(
        client_id: impl Into<String>,
        pem: &str,
        algorithm: Algorithm,
    ) -> Result<Self, ClientAssertionError> {
        if !is_asymmetric(algorithm) {
            return Err(ClientAssertionError::Symmetric(algorithm));
        }
        check_rsa_choice(algorithm, rsa_signs())?;
        let (label, der) = decode_pem(pem)?;
        let mismatch = |label: &str| ClientAssertionError::LabelMismatch {
            algorithm,
            label: label.to_string(),
        };
        let key = match algorithm {
            Algorithm::ES256 | Algorithm::ES384 | Algorithm::EdDSA => {
                if label != "PRIVATE KEY" {
                    return Err(mismatch(&label));
                }
                if algorithm == Algorithm::EdDSA {
                    EncodingKey::from_ed_der(&der)
                } else {
                    EncodingKey::from_ec_der(&der)
                }
            }
            _ => match label.as_str() {
                "RSA PRIVATE KEY" => EncodingKey::from_rsa_der(&der),
                "PRIVATE KEY" => EncodingKey::from_rsa_der(
                    pkcs8_private_key(&der).ok_or(ClientAssertionError::MalformedPkcs8)?,
                ),
                other => return Err(mismatch(other)),
            },
        };
        Self::new(client_id, key, algorithm)
    }

    /// The signer a stored configuration describes: the key from `pem`, the
    /// headers, audience and lifetime from `spec`.
    ///
    /// # Errors
    ///
    /// As [`from_pem`](Self::from_pem), and
    /// [`ClientAssertionError::AssertionTtl`] for a lifetime that is no time
    /// or has a fraction of a second.
    pub fn from_spec(
        client_id: impl Into<String>,
        pem: &str,
        spec: &SignerSpec,
    ) -> Result<Self, ClientAssertionError> {
        let mut signer = Self::from_pem(client_id, pem, spec.algorithm)?;
        signer.header.kid.clone_from(&spec.key_id);
        signer.header.x5t_s256.clone_from(&spec.x5t_s256);
        signer.header.x5t.clone_from(&spec.x5t);
        signer.audience.clone_from(&spec.audience);
        if let Some(ttl) = spec.assertion_ttl {
            signer.ttl = checked_ttl(ttl)?;
        }
        Ok(signer)
    }

    /// Put `kid` in the assertion's header, so the IdP picks the matching
    /// key from the JWKS or certificate set it holds for this client.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.header.kid = Some(key_id.into());
        self
    }

    /// Put the certificate's SHA-256 thumbprint (`x5t#S256`, base64url
    /// without padding) in the assertion's header. Microsoft Entra finds a
    /// registered certificate credential by this header (or by `x5t`, its
    /// SHA-1 form), so a client authenticating there sets it.
    #[must_use]
    pub fn with_x5t_s256(mut self, thumbprint: impl Into<String>) -> Self {
        self.header.x5t_s256 = Some(thumbprint.into());
        self
    }

    /// Put the certificate's SHA-1 thumbprint (`x5t`, base64url without
    /// padding) in the assertion's header; see
    /// [`with_x5t_s256`](Self::with_x5t_s256).
    #[must_use]
    pub fn with_x5t(mut self, thumbprint: impl Into<String>) -> Self {
        self.header.x5t = Some(thumbprint.into());
        self
    }

    /// Fix the `aud` claim. Without it the audience is chosen per request:
    /// the endpoint being called (the token endpoint, for the outbound
    /// client), or the issuer under the FAPI profile. Set it for an IdP that
    /// accepts only one value (Microsoft Entra takes the token endpoint,
    /// Keycloak takes the issuer or the token endpoint).
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Change how long one assertion lives (default 60 seconds).
    ///
    /// # Errors
    ///
    /// [`ClientAssertionError::AssertionTtl`] for a lifetime that is no time
    /// or has a fraction of a second: the `exp` it sets is a whole count of
    /// seconds after `iat`.
    pub fn with_assertion_ttl(mut self, ttl: Duration) -> Result<Self, ClientAssertionError> {
        self.ttl = checked_ttl(ttl)?;
        Ok(self)
    }

    /// The client id the assertions name as `iss` and `sub`.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The audience fixed by [`with_audience`](Self::with_audience), if any.
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// Sign one assertion for a request to `default_audience`, unless an
    /// audience was fixed.
    ///
    /// `iss` and `sub` are the client id (RFC 7523 section 3), `iat` is the
    /// clock's now, `exp` is the lifetime later, and `jti` is a version-4
    /// UUID built from 16 bytes of `rng`, so a replayed assertion is
    /// distinguishable. Nothing here reads the wall clock or the system
    /// random source.
    ///
    /// # Errors
    ///
    /// [`ClientAssertionError::Signing`] when the signature fails, which a
    /// signer that built does not do in practice.
    pub fn mint(
        &self,
        default_audience: &str,
        clock: &dyn Clock,
        rng: &dyn SecureRng,
    ) -> Result<String, ClientAssertionError> {
        let mut jti = [0u8; 16];
        rng.fill_bytes(&mut jti);
        self.sign(
            self.audience.as_deref().unwrap_or(default_audience),
            clock.now().unix_seconds(),
            jti,
        )
        .map_err(ClientAssertionError::Signing)
    }

    /// One assertion for `audience`, issued at `iat`, with the `jti` built
    /// from `jti_bytes`.
    fn sign(&self, audience: &str, iat: i64, jti_bytes: [u8; 16]) -> Result<String, String> {
        let ttl = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let claims = ClientAssertionClaims {
            iss: &self.client_id,
            sub: &self.client_id,
            aud: audience,
            exp: iat.saturating_add(ttl),
            iat,
            // RFC 4122 v4 from random bytes (sets version + variant bits).
            jti: UuidBuilder::from_random_bytes(jti_bytes)
                .into_uuid()
                .to_string(),
        };
        crate::jwt::encode(&self.header, &claims, &self.key).map_err(|e| e.to_string())
    }
}

/// The `client_assertion_type` form value for a JWT assertion (RFC 7523
/// section 2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The label and DER bytes of the first PEM block in `pem`.
fn decode_pem(pem: &str) -> Result<(String, Vec<u8>), ClientAssertionError> {
    use base64::Engine as _;
    let mut lines = pem.lines().map(str::trim).filter(|l| !l.is_empty());
    let label = lines
        .next()
        .and_then(|l| l.strip_prefix("-----BEGIN "))
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or(ClientAssertionError::NotPem)?
        .to_string();
    let end = format!("-----END {label}-----");
    let mut body = String::new();
    let mut closed = false;
    for line in lines {
        if line == end {
            closed = true;
            break;
        }
        if line.contains(':') {
            return Err(ClientAssertionError::Encrypted);
        }
        body.push_str(line);
    }
    if !closed {
        return Err(ClientAssertionError::Unclosed);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| ClientAssertionError::NotBase64)?;
    Ok((label, der))
}

/// One DER element with `tag` at the start of `bytes`: its content and the
/// bytes after it.
fn der_take(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    if first != tag {
        return None;
    }
    let (&len_byte, rest) = rest.split_first()?;
    let (len, rest) = if len_byte < 0x80 {
        (usize::from(len_byte), rest)
    } else {
        let n = usize::from(len_byte & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| rest.split_at(len))
}

/// The `privateKey` octets of a PKCS#8 `PrivateKeyInfo`: for an RSA key, its
/// PKCS#1 `RSAPrivateKey`.
fn pkcs8_private_key(der: &[u8]) -> Option<&[u8]> {
    let (info, _) = der_take(der, 0x30)?;
    let (_, rest) = der_take(info, 0x02)?;
    let (_, rest) = der_take(rest, 0x30)?;
    der_take(rest, 0x04).map(|(key, _)| key)
}

#[cfg(test)]
mod tests;
