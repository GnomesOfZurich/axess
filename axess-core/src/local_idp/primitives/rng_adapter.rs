//! The RNG bridge key generation uses, so a DST-injected RNG drives `p256`
//! (and `rsa`, with `local-idp-rsa`) without touching `OsRng`.

/// Bridges [`axess_rng::SecureRng`] to the random-number traits key
/// generation asks for: `rand_core` 0.10's `TryRng + TryCryptoRng` for
/// `p256`, here, and `rand_core` 0.6's `RngCore + CryptoRng` for `rsa`, in
/// the `rsa_key` module beside this one. Lets keygen run against any
/// DST-injected RNG without depending on `OsRng` directly.
pub(super) struct SecureRngAdapter<'a>(pub(super) &'a dyn axess_rng::SecureRng);

impl p256::elliptic_curve::rand_core::TryRng for SecureRngAdapter<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.0.fill_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.0.fill_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl p256::elliptic_curve::rand_core::TryCryptoRng for SecureRngAdapter<'_> {}
