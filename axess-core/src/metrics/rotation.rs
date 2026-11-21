//! The rotation concern: how often the previous key is still needed, and
//! whether the credentials a SPIRE agent rotates are arriving.

/// What a SPIRE Workload API watcher keeps current. A closed set, so it is
/// safe as a metric label; a SPIFFE ID or a trust domain is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadCredentialKind {
    /// The workload's own X.509 SVID, with the bundles that came with it.
    X509Svid,
    /// A JWT SVID for one audience.
    JwtSvid,
    /// The X.509 bundles of the trust domains the workload may verify.
    X509Bundles,
    /// The JWT bundles of the trust domains the workload may verify.
    JwtBundles,
}

impl WorkloadCredentialKind {
    /// The snake_case label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X509Svid => "x509_svid",
            Self::JwtSvid => "jwt_svid",
            Self::X509Bundles => "x509_bundles",
            Self::JwtBundles => "jwt_bundles",
        }
    }
}

impl std::fmt::Display for WorkloadCredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::X509Svid => "X.509 SVID",
            Self::JwtSvid => "JWT SVID",
            Self::X509Bundles => "X.509 bundle set",
            Self::JwtBundles => "JWT bundle set",
        })
    }
}

/// Counters that tell an operator when a key rotation window can close.
///
/// A previous key stays configured until nothing needs it. Each method fires
/// when the previous key did work, so a rate that falls to zero is the signal
/// to drop the previous key.
pub trait RotationMetrics: Send + Sync + 'static {
    /// A session or device blob opened only under the previous encryption key
    /// (see [`SessionCrypto::with_previous_key`](crate::session::SessionCrypto::with_previous_key)).
    /// The blob is re-sealed under the current key as it is read.
    fn encryption_key_fallback(&self) {}

    /// A stored session fingerprint matched only under the previous signing
    /// key. The fingerprint is re-stored under the current key.
    fn fingerprint_key_fallback(&self) {}

    /// A SPIRE Workload API watcher replaced what it holds of `kind` with
    /// what the agent sent: an SVID was rotated, or a bundle set changed.
    /// The SPIFFE ID and the expiry are in the `axess::workload::spire`
    /// event.
    fn workload_credential_rotated(&self, kind: WorkloadCredentialKind) {
        let _ = kind;
    }

    /// A refresh of `kind` failed: the agent was unreachable, the stream
    /// dropped, or the answer was refused. What the watcher holds keeps
    /// serving while it is valid, and the watcher retries with back-off. A
    /// rate that does not fall back to zero means the next expiry will not
    /// be met.
    fn workload_credential_refresh_failed(&self, kind: WorkloadCredentialKind) {
        let _ = kind;
    }

    /// The watcher stopped serving what it held of `kind` with no
    /// replacement, and readers are refused from here on: an SVID reached
    /// its expiry, the agent did not confirm a bundle set within the
    /// client's maximum bundle age, or the agent withdrew it. Any count is
    /// an outage, of the workload's identity or of its means to verify its
    /// peers; the event says which of the three.
    fn workload_credential_expired(&self, kind: WorkloadCredentialKind) {
        let _ = kind;
    }

    /// The agent withdrew what the watcher holds of `kind` with
    /// `PERMISSION_DENIED`, and the client's withdrawal grace keeps it
    /// served for now. A count with no `workload_credential_expired` after
    /// it is an agent that answered so for a moment; one followed by it is
    /// a withdrawal that the grace delayed.
    fn workload_credential_withdrawal_deferred(&self, kind: WorkloadCredentialKind) {
        let _ = kind;
    }

    /// The agent sent a bundle entry of another trust domain, with what
    /// the watcher took of `kind`, that did not read, and it was left out.
    /// Any count: that trust domain's peers cannot be verified. The entry
    /// and the reason are in the `axess::workload::spire` event.
    fn workload_bundle_skipped(&self, kind: WorkloadCredentialKind) {
        let _ = kind;
    }
}
