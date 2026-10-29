//! The RNG bridge key generation uses, so a DST-injected RNG drives `rsa`
//! and `p256` without touching `OsRng`.

/// Bridges [`axess_rng::SecureRng`] to the `rand_core::RngCore +
/// CryptoRng` trait pair used by `rsa` and `p256`. Lets keygen run
/// against any DST-injected RNG without depending on `OsRng` directly.
pub(super) struct SecureRngAdapter<'a>(pub(super) &'a dyn axess_rng::SecureRng);

impl rsa::rand_core::RngCore for SecureRngAdapter<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for SecureRngAdapter<'_> {}
