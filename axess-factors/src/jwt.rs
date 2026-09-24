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
     Windows) or `jwt-rust-crypto` (pure Rust, builds anywhere). Until 0.5.1 \
     aws-lc-rs was pinned here, which chose for an adopter that had already \
     chosen the other."
);

/// Make sure `jsonwebtoken` has a crypto provider before anything verifies.
///
/// With both backends compiled in (`--all-features`, or an adopter that
/// enabled one while a dependency enabled the other) `jsonwebtoken` cannot
/// derive a default and panics on the first verification, in production,
/// about a provider nobody knew they had to install. Feature unification is
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
/// an earlier call here, is left alone.
///
/// Verification calls it for you. It is public for the other direction:
/// **an adopter that signs**, a test harness or a local issuer, reaches
/// `jsonwebtoken::encode` directly, which needs the same provider, and this
/// is how they get one without depending on which features happen to be on.
pub fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Keyed on *this* crate's feature, which is the only one visible from
        // here, and which selects `jsonwebtoken`'s to match. Installing
        // whenever a backend is compiled in, rather than only when both of
        // ours are, is what makes this work under feature unification: cargo
        // unifies `jsonwebtoken`'s features across the whole graph, so it can
        // hold both while axess-factors holds one. `cfg(all(ours, ours))` then
        // reads false, installs nothing, and the panic this exists to prevent
        // happens anyway, which is what the workload-identity example did.
        #[cfg(feature = "jwt-aws-lc")]
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        #[cfg(all(feature = "jwt-rust-crypto", not(feature = "jwt-aws-lc")))]
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

pub mod claims;
#[cfg(feature = "jwt-svid")]
pub mod svid;
pub mod validation;
pub mod verifier;
