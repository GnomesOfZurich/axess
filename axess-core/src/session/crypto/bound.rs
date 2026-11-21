//! The seal and the two opens of the row-bound formats.
//!
//! [`SessionCrypto::seal_bound`] writes the current form of a
//! [`BoundFormat`]. [`SessionCrypto::open_current`] reads that form and
//! nothing else, and is what the session stores use.
//! [`SessionCrypto::open_bound`] also reads the earlier forms the
//! [`LegacyBlobs`](super::LegacyBlobs) policy allows, and is what the
//! device stores use.

#[cfg(any(
    test,
    all(
        feature = "device",
        any(
            feature = "sqlite",
            feature = "sqlite-unbundled",
            feature = "postgres",
            feature = "mysql",
            feature = "valkey"
        )
    )
))]
use super::Binding;
use super::{BoundFormat, CryptoError, Opened, SessionCrypto, subkey};

impl SessionCrypto {
    /// Open a subkeyed body under the current key, then the previous key. A
    /// body shorter than a salt and a tag was never sealed and is refused
    /// before either key is tried.
    fn open_subkeyed(&self, aad: &[u8], body: &[u8]) -> Result<Opened, CryptoError> {
        if body.len() < subkey::MIN_BODY_LEN {
            tracing::warn!("refusing a blob too short to have been sealed");
            return Err(CryptoError);
        }
        if let Ok(plaintext) = subkey::open(&self.current.0, aad, body) {
            return Ok(Opened {
                plaintext,
                stale: false,
                #[cfg(any(
                    test,
                    all(
                        feature = "device",
                        any(
                            feature = "sqlite",
                            feature = "sqlite-unbundled",
                            feature = "postgres",
                            feature = "mysql",
                            feature = "valkey"
                        )
                    )
                ))]
                binding: Binding::Current,
            });
        }
        if let Some(prev) = &self.previous
            && let Ok(plaintext) = subkey::open(&prev.0, aad, body)
        {
            tracing::debug!("blob opened with the previous (rotated) key");
            self.metrics.encryption_key_fallback();
            return Ok(Opened {
                plaintext,
                stale: true,
                #[cfg(any(
                    test,
                    all(
                        feature = "device",
                        any(
                            feature = "sqlite",
                            feature = "sqlite-unbundled",
                            feature = "postgres",
                            feature = "mysql",
                            feature = "valkey"
                        )
                    )
                ))]
                binding: Binding::Current,
            });
        }
        tracing::warn!("blob decryption failed with the configured keys");
        Err(CryptoError)
    }

    /// A blob in `format`'s earlier direct layout: the plain marker, then a
    /// seal under the configured key itself with a random nonce. For tests
    /// that plant what a release before the per-record subkey wrote.
    #[cfg(test)]
    pub(crate) fn seal_direct_layout(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut out = format.magic.to_vec();
        out.extend_from_slice(&self.seal_direct(&format.aad(row_id), plaintext)?);
        Ok(out)
    }

    /// Encrypt `plaintext` bound to `row_id`: `magic' || salt || ciphertext`
    /// under a subkey derived for this record, with AAD
    /// `label || 0x00 || row_id` (see [`BoundFormat`] and the module
    /// documentation).
    pub(crate) fn seal_bound(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let marker = format.subkeyed_magic();
        let body = subkey::seal(&self.current.0, &*self.rng, &format.aad(row_id), plaintext)
            .map_err(|_| CryptoError)?;
        let mut out = Vec::with_capacity(marker.len() + body.len());
        out.extend_from_slice(&marker);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Open a blob sealed in `format`'s current layout for `row_id`, under the
    /// current key and then the previous one. Any other blob is refused,
    /// whatever the legacy policy says.
    ///
    /// The session stores open a row through this and never through
    /// [`open_bound`](Self::open_bound). A deployment may set
    /// [`LegacyBlobs::Accept`] on the one `SessionCrypto` it shares with its
    /// device rows, and under `open_bound` a blob without a binding then
    /// opens under any row id, which for a session is the row swap the
    /// binding exists to refuse. Here the refusal holds for every policy,
    /// because the policy is never read: a blob that does not start with the
    /// format's marker is refused before a key is tried, and one that does
    /// must authenticate under `label || 0x00 || row_id`, which only a blob
    /// sealed for this row does.
    pub(crate) fn open_current(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        data: &[u8],
    ) -> Result<Opened, CryptoError> {
        let Some(body) = data.strip_prefix(&format.subkeyed_magic()[..]) else {
            tracing::warn!("refusing a blob that is not in the current sealed form");
            return Err(CryptoError);
        };
        self.open_subkeyed(&format.aad(row_id), body)
    }

    /// Open a blob for `row_id`, reading the earlier forms the legacy policy
    /// allows. For the device stores; a session is opened with
    /// [`open_current`](Self::open_current).
    ///
    /// A blob that starts with the current format's marker is tried under
    /// that format's AAD. A blob that starts with the marker of one of the
    /// `earlier` formats is tried under that format's AAD and the row id it
    /// paired with (an earlier release derived the id differently), and is
    /// flagged `stale` and `legacy`. A blob with none of these markers is a
    /// pre-binding blob, tried under the empty AAD and flagged the same way.
    ///
    /// The earlier layout of the current format (the key used directly) counts
    /// as a legacy blob too.
    ///
    /// All three kinds are refused unless the crypto's
    /// [`LegacyBlobs`] policy reads them. Under a policy that reads them, a
    /// blob whose first four bytes happen to equal a marker (of either layout
    /// of the current format) but which does not open under that format (a
    /// pre-binding nonce is random, so this is about one blob in 2^31) is
    /// tried under the empty AAD as a whole. That cannot open a smuggled
    /// marked blob: the marker and the nonce that follow it would have to
    /// authenticate under the empty AAD. Under a policy that refuses them the
    /// ambiguous blob is refused, which fails closed.
    #[cfg(any(
        test,
        all(
            feature = "device",
            any(
                feature = "sqlite",
                feature = "sqlite-unbundled",
                feature = "postgres",
                feature = "mysql",
                feature = "valkey"
            )
        )
    ))]
    pub(crate) fn open_bound(
        &self,
        format: BoundFormat,
        row_id: &[u8],
        earlier: &[(BoundFormat, Vec<u8>)],
        data: &[u8],
    ) -> Result<Opened, CryptoError> {
        let legacy_readable = self.legacy_blobs_readable();
        if let Some(body) = data.strip_prefix(&format.subkeyed_magic()[..]) {
            // A failure is final unless legacy blobs are still read: a legacy
            // blob's random nonce can begin with this marker too.
            match self.open_subkeyed(&format.aad(row_id), body) {
                Ok(opened) => return Ok(opened),
                Err(error) if !legacy_readable => return Err(error),
                Err(_) => {}
            }
        } else if let Some(body) = data.strip_prefix(&format.magic[..]) {
            // The earlier layout of the current format: the key used
            // directly. It is a legacy blob like the earlier formats, read
            // only while legacy blobs are, and stale so that it is re-sealed
            // under a subkey. The public `encrypt_with_aad` seals under the
            // same key, so output an application made with an AAD it did not
            // fully control must not open as a row under the default policy.
            // A failure here is final unless legacy blobs are still read,
            // because a legacy blob's random nonce can begin with this
            // marker (about one in 2^32), and then it is tried as one below.
            if !legacy_readable {
                tracing::warn!(
                    "refusing a blob in the earlier direct layout (legacy blobs are not read)"
                );
                return Err(CryptoError);
            }
            match self.decrypt_with_aad_reporting(&format.aad(row_id), body) {
                Ok((plaintext, _)) => {
                    return Ok(Opened {
                        plaintext,
                        stale: true,
                        binding: Binding::Current,
                    });
                }
                Err(error) if !legacy_readable => return Err(error),
                Err(_) => {}
            }
        } else {
            for (old, old_id) in earlier {
                if let Some(body) = data.strip_prefix(&old.magic[..]) {
                    if !legacy_readable {
                        tracing::warn!(
                            "refusing a blob in an earlier row-bound format (legacy blobs are not read)"
                        );
                        return Err(CryptoError);
                    }
                    if let Ok(plaintext) = self.decrypt_with_aad(&old.aad(old_id), body) {
                        return Ok(Opened {
                            plaintext,
                            stale: true,
                            binding: Binding::Earlier,
                        });
                    }
                }
            }
        }
        if !legacy_readable {
            tracing::warn!("refusing a blob without a row binding (legacy blobs are not read)");
            return Err(CryptoError);
        }
        Ok(Opened {
            plaintext: self.decrypt_unbound(data)?,
            stale: true,
            binding: Binding::Unbound,
        })
    }
}
