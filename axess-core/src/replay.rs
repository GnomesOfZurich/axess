//! Replay stores: where a `jti` that may be presented once is recorded.
//!
//! A token or proof that may be presented once carries a `jti`, and the
//! verifier records it so a second presentation is refused. The stores here
//! implement the [`JtiReplayStore`](axess_factors::jwt::verifier::JtiReplayStore)
//! trait that the JWT verifier
//! ([`JwtVerifier::with_replay_store`](axess_factors::jwt::verifier::JwtVerifier::with_replay_store)),
//! the DPoP verifier (`verify_dpop_proof_with_store`, with the `oauth`
//! feature) and device-key request proofs
//! (`DeviceKeyService::with_request_proofs`, with `device-keys`) record
//! into.
//!
//! - [`MemoryJtiReplayStore`] keeps the record in the process. It protects
//!   one process: behind a load balancer the same token is accepted once
//!   per node.
//! - `ValkeyJtiReplayStore` (with the `valkey` feature) keeps it in Valkey
//!   or Redis, where every node sees it.

mod memory;
#[cfg(feature = "valkey")]
mod valkey;

pub use memory::{DEFAULT_MEMORY_JTI_CAPACITY, MemoryJtiReplayStore};
#[cfg(feature = "valkey")]
pub use valkey::{DEFAULT_JTI_PREFIX, EvictionPolicyError, SetOnce, ValkeyJtiReplayStore};
