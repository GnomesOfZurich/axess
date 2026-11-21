//! Shared JWT primitives for signature verification and claim validation.
//!
//! Reusable helpers, not a bearer-token authentication layer. Axess is
//! session-based; these primitives exist so that adopters performing JWT
//! verification (e.g. workload identity, federated OIDC checks, custom
//! logout flows) can share the same hardened parse-and-verify code paths
//! used internally by OAuth and backchannel logout.

// `jsonwebtoken` 11 takes its crypto provider from a cargo feature, and with
// neither compiled in it panics on the first verification. A missing backend
// is a build-time mistake, so it is stated at build time.
#[cfg(not(any(feature = "jwt-aws-lc", feature = "jwt-rust-crypto")))]
compile_error!(
    "axess-factors: the `jwt` feature needs a crypto backend. Enable \
     `jwt-aws-lc` (aws-lc-rs: FIPS-capable, needs a C toolchain and NASM on \
     Windows) or `jwt-rust-crypto` (pure Rust, builds anywhere). \
     axess-factors enables neither, so a build that already uses one of the \
     two crypto libraries can keep to it."
);

/// Make sure `jsonwebtoken` has a crypto provider before anything signs or
/// verifies.
///
/// With both backends compiled in (`--all-features`, or an adopter that
/// enabled one while a dependency enabled the other) `jsonwebtoken` cannot
/// derive a default and panics on the first signature or verification, in
/// production, about a provider nobody knew they had to install. Feature unification is
/// not a mistake an adopter can always avoid, so this settles it instead:
/// aws-lc-rs when it is present, the RustCrypto family otherwise, installed
/// once per process.
///
/// It is deliberately *not* an error to have both. An adopter who wants the
/// other one enables only that one, which is the case this module's
/// `compile_error!` guards; two crates disagreeing about the backend is a
/// packaging fact, not a bug in either of them.
///
/// Installing is best-effort: `install_default` succeeds once per process,
/// and a provider already installed, by an adopter with a preference or by
/// an earlier call here, is left alone. Whether axess's own aws-lc install
/// took is kept: without `client-assertion-rsa`, an RSA client assertion
/// signs only where it did.
///
/// The first `jsonwebtoken` operation in a process that signs or verifies
/// fixes the provider for the rest of it. When no provider is installed by
/// then and both backends are compiled in, what it fixes is
/// `jsonwebtoken`'s fallback, which panics on that operation and on every
/// later one, axess's own verification included, and no install can
/// replace it. So every operation of axess goes through [`encode`],
/// [`decode`], [`sign`] or [`verify`], which call this first, and
/// `scripts/check-jwt-provider-sites.sh` refuses any other call in the
/// repository, its tests and examples included.
///
/// It is public for code that reaches `jsonwebtoken` another way: an
/// adopter's own signing or verification that does not go through those
/// four, or an operation they do not cover (`Jwk::from_encoding_key`,
/// `Jwk::thumbprint`). Called before that code's first operation, it
/// settles the provider without depending on which features are on.
pub fn ensure_crypto_provider() {
    axess_installed_aws_lc();
}

/// Sign `claims` under `header` as a compact JWT: [`jsonwebtoken::encode`],
/// after [`ensure_crypto_provider`].
///
/// # Errors
///
/// `jsonwebtoken`'s error when `key` is not of the family `header.alg`
/// names, the backend refuses the key, or `claims` does not serialise.
pub fn encode<T: serde::Serialize>(
    header: &jsonwebtoken::Header,
    claims: &T,
    key: &jsonwebtoken::EncodingKey,
) -> jsonwebtoken::errors::Result<String> {
    ensure_crypto_provider();
    jsonwebtoken::encode(header, claims, key)
}

/// Check `token`'s signature under `key` and its claims as `validation`
/// says: [`jsonwebtoken::decode`], after [`ensure_crypto_provider`].
///
/// To verify a token against a key set, [`validation::verify_jwt`] and
/// [`verifier::JwtVerifier`] are the hardened path: they bound the token's
/// size, refuse symmetric algorithms and read the time from an injected
/// clock. This is `jsonwebtoken`'s own decode, for code that already uses it.
///
/// # Errors
///
/// `jsonwebtoken`'s error when the token is malformed, its algorithm is not
/// in `validation`, the signature does not hold, or a claim fails a check.
pub fn decode<T: serde::de::DeserializeOwned>(
    token: impl AsRef<[u8]>,
    key: &jsonwebtoken::DecodingKey,
    validation: &jsonwebtoken::Validation,
) -> jsonwebtoken::errors::Result<jsonwebtoken::TokenData<T>> {
    ensure_crypto_provider();
    jsonwebtoken::decode(token, key, validation)
}

/// The base64url signature of `message` under `key` with `algorithm`:
/// [`jsonwebtoken::crypto::sign`], after [`ensure_crypto_provider`]. For a
/// JWS whose header `jsonwebtoken`'s [`Header`](jsonwebtoken::Header) cannot
/// carry, such as a DPoP proof's embedded `jwk`.
///
/// # Errors
///
/// `jsonwebtoken`'s error when the backend refuses `key` for `algorithm`.
pub fn sign(
    message: &[u8],
    key: &jsonwebtoken::EncodingKey,
    algorithm: jsonwebtoken::Algorithm,
) -> jsonwebtoken::errors::Result<String> {
    ensure_crypto_provider();
    jsonwebtoken::crypto::sign(message, key, algorithm)
}

/// Whether the base64url `signature` is `key`'s over `message` with
/// `algorithm`: [`jsonwebtoken::crypto::verify`], after
/// [`ensure_crypto_provider`]. The check of a JWS signing input only; to
/// verify a token, [`validation::verify_jwt`].
///
/// # Errors
///
/// `jsonwebtoken`'s error when `signature` is not base64url or the backend
/// refuses `key` for `algorithm`; a signature that does not hold is
/// `Ok(false)`.
pub fn verify(
    signature: &str,
    message: &[u8],
    key: &jsonwebtoken::DecodingKey,
    algorithm: jsonwebtoken::Algorithm,
) -> jsonwebtoken::errors::Result<bool> {
    ensure_crypto_provider();
    jsonwebtoken::crypto::verify(signature, message, key, algorithm)
}

/// Whether the provider `jsonwebtoken` signs with is the aws-lc one this
/// crate installed, after making sure a provider is installed.
///
/// `jsonwebtoken` gives no public read of the installed provider: its
/// getter is crate-private, and `install_default` hands back, on refusal,
/// the provider it was given rather than the one in place. The one fact
/// this crate can know is whether its own install took: when it did, the
/// provider is aws-lc for the rest of the process, since a provider once
/// installed is never replaced. When it did not, another provider was
/// installed first, by the application or another crate, and nothing here
/// can tell which: false, the answer that refuses. False also on a build
/// without `jwt-aws-lc`, where the install, when it takes, is RustCrypto's.
pub(crate) fn axess_installed_aws_lc() -> bool {
    use std::sync::OnceLock;
    static INSTALLED_AWS_LC: OnceLock<bool> = OnceLock::new();
    *INSTALLED_AWS_LC.get_or_init(|| {
        // Keyed on *this* crate's feature, which is the only one visible from
        // here, and which selects `jsonwebtoken`'s to match. Installing
        // whenever a backend is compiled in, rather than only when both of
        // ours are, is what makes this work under feature unification: cargo
        // unifies `jsonwebtoken`'s features across the whole graph, so it can
        // hold both while axess-factors holds one. `cfg(all(ours, ours))` then
        // reads false, installs nothing, and the panic this exists to prevent
        // happens anyway, which is what the workload-identity example did.
        #[cfg(feature = "jwt-aws-lc")]
        let installed = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .is_ok();
        #[cfg(not(feature = "jwt-aws-lc"))]
        let installed = {
            #[cfg(feature = "jwt-rust-crypto")]
            let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
            false
        };
        installed
    })
}

pub mod claims;
#[cfg(test)]
pub(crate) mod provider_tests;
#[cfg(feature = "jwt-svid")]
pub mod svid;
pub mod validation;
pub mod verifier;
