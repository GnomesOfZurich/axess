//! The device-key concern: registrations, proofs, and what the session layer
//! does with sessions held to a key.

/// Counters for device keys: the key service and the session layer that
/// enforces it. Fed when the service is given the sinks
/// (`DeviceKeyService::with_metrics`).
pub trait DeviceKeyMetrics: Send + Sync + 'static {
    /// A freshly authenticated session on a device without a key was
    /// offered a key registration. Against
    /// [`key_registered`](Self::key_registered), the share of sign-ins whose
    /// client takes a key: the number to read before requiring keys.
    fn key_offered(&self) {}

    /// A device took a key.
    fn key_registered(&self) {}

    /// A key registration was refused (a proof that does not stand, a
    /// device that already has a key or belongs to another user).
    fn key_registration_refused(&self) {}

    /// A proof over a device's current challenge was accepted and a proof
    /// cookie issued.
    fn key_proof_accepted(&self) {}

    /// A proof answered a challenge that is not the current one, or none was
    /// presented, and the current challenge was handed out. A refresh that
    /// returns after the challenge lifetime makes one; a steady rate is
    /// clients racing their own refreshes.
    fn key_proof_challenged(&self) {}

    /// A device's current challenge came back with a signature that is not
    /// its key's, or a keyed device's refresh token without the key: the
    /// caller holds what was copied from the device and not the key. Each
    /// writes a `Suspicious` audit row.
    fn key_proof_refused(&self) {}

    /// A proof riding on an ordinary request was accepted.
    fn request_proof_accepted(&self) {}

    /// A proof riding on a request that held a session bound to the device
    /// did not stand (a replayed `jti`, an `iat` outside the accepted span,
    /// another key, a revoked device, a device with no key).
    fn request_proof_refused(&self) {}

    /// A proof riding on a request that held no session bound to the device
    /// it names did not stand. Anybody can send one beside a device's
    /// identifier, so it is counted apart and never hides a refusal under a
    /// bound session.
    fn unbound_request_proof_refused(&self) {}

    /// A proof riding on an ordinary request could not be judged, because
    /// the device store or the replay store did not answer. The request was
    /// not served as its session; the fault is the store's, not the
    /// client's, so it is counted apart from the refusals.
    fn request_proof_unanswered(&self) {}

    /// A request of a session bound to a key arrived without a proof of the
    /// key and ran as a guest. A copied session cookie is one; so is a
    /// client whose proof expired before it refreshed.
    fn bound_session_unproven(&self) {}

    /// [`KeyBindingPolicy::Require`](crate::device_key::KeyBindingPolicy::Require)
    /// ended a signed-in session (in a step-up too) that was not bound when
    /// its registration window, counted from its login, passed. Counted once
    /// per ending, by the request that recorded it.
    fn unbound_session_ended(&self) {}
}
