//! Two test stores that let the conditional-write contract tell a single
//! conditional write from a read followed by a write.
//!
//! The contract runs two conditional writes at once on one task. A store
//! whose methods never suspend (the memory store, and anything that only
//! forwards to it) runs the first to its end before the second starts, so a
//! read followed by a write would pass as well as a single step does.
//!
//! [`Interleaved`] forwards every call to the store it wraps after yielding
//! once, so both calls have started before either reaches the store, and
//! every call a composite method makes is a point where the other can run.
//! A single conditional write beneath it still has one winner.
//! [`ReadThenWrite`] is the control: the three conditional writes as a load
//! followed by an unconditional write. Over an [`Interleaved`] store both
//! of its calls read before either writes, and the contract must refuse it.

use std::future::Future;

use axess_clock::Timestamp;

use super::consistency;
use super::{
    BindingsUpdate, DeviceStore, MemoryDeviceStore, OwnerClaim, SweepCounts, TrustTransition,
};
use crate::authn::ids::{DeviceId, TenantId, UserId};
use crate::device::types::{Device, DeviceBinding, DeviceTrustLevel, FingerprintHash};

/// A store whose every call yields to the scheduler once before it reaches
/// the store beneath.
#[derive(Clone, Default)]
pub(crate) struct Interleaved<S>(pub(crate) S);

/// Let whatever else is ready on this task run first.
async fn yielded() {
    tokio::task::yield_now().await;
}

impl<S: DeviceStore> DeviceStore for Interleaved<S> {
    type Error = S::Error;

    async fn load(&self, t: &TenantId, id: &DeviceId) -> Result<Option<Device>, Self::Error> {
        yielded().await;
        self.0.load(t, id).await
    }
    async fn load_fresh(&self, t: &TenantId, id: &DeviceId) -> Result<Option<Device>, Self::Error> {
        yielded().await;
        self.0.load_fresh(t, id).await
    }
    async fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> Result<Option<Device>, Self::Error> {
        yielded().await;
        self.0.find_by_fingerprint(t, h).await
    }
    async fn find_for_user(
        &self,
        t: &TenantId,
        u: &UserId,
        limit: usize,
    ) -> Result<Vec<Device>, Self::Error> {
        yielded().await;
        self.0.find_for_user(t, u, limit).await
    }
    async fn find_by_refresh_family(
        &self,
        t: &TenantId,
        f: &str,
    ) -> Result<Vec<Device>, Self::Error> {
        yielded().await;
        self.0.find_by_refresh_family(t, f).await
    }
    async fn save(&self, d: &Device, now: Timestamp) -> Result<(), Self::Error> {
        yielded().await;
        self.0.save(d, now).await
    }
    async fn create_or_find(&self, d: &Device, now: Timestamp) -> Result<Device, Self::Error> {
        yielded().await;
        self.0.create_or_find(d, now).await
    }
    async fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: Timestamp,
    ) -> Result<DeviceTrustLevel, Self::Error> {
        yielded().await;
        self.0.record_sighting(t, id, now).await
    }
    async fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> Result<(), Self::Error> {
        yielded().await;
        self.0.set_trust_level(t, id, level, now).await
    }
    async fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> Result<TrustTransition, Self::Error> {
        yielded().await;
        self.0.set_trust_level_if(t, id, expected, level, now).await
    }
    async fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: Timestamp,
    ) -> Result<BindingsUpdate, Self::Error> {
        yielded().await;
        self.0
            .replace_bindings(t, id, expected, bindings, now)
            .await
    }
    async fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<OwnerClaim, Self::Error> {
        yielded().await;
        self.0.claim_owner(t, id, user, now).await
    }
    async fn delete(&self, t: &TenantId, id: &DeviceId) -> Result<(), Self::Error> {
        yielded().await;
        self.0.delete(t, id).await
    }
    async fn sweep(&self, t: &TenantId, now: Timestamp) -> Result<SweepCounts, Self::Error> {
        yielded().await;
        self.0.sweep(t, now).await
    }
}

/// The control: a store whose three conditional writes are a load followed
/// by an unconditional write, which is what a body built from the trait's
/// other methods amounts to. Everything else forwards.
#[derive(Clone, Default)]
pub(crate) struct ReadThenWrite<S>(pub(crate) S);

impl<S: DeviceStore> DeviceStore for ReadThenWrite<S> {
    type Error = S::Error;

    fn load(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.load(t, id)
    }
    fn load_fresh(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.load_fresh(t, id)
    }
    fn find_by_fingerprint(
        &self,
        t: &TenantId,
        h: &FingerprintHash,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.find_by_fingerprint(t, h)
    }
    fn find_for_user(
        &self,
        t: &TenantId,
        u: &UserId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.0.find_for_user(t, u, limit)
    }
    fn find_by_refresh_family(
        &self,
        t: &TenantId,
        f: &str,
    ) -> impl Future<Output = Result<Vec<Device>, Self::Error>> + Send {
        self.0.find_by_refresh_family(t, f)
    }
    fn save(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.save(d, now)
    }
    fn create_or_find(
        &self,
        d: &Device,
        now: Timestamp,
    ) -> impl Future<Output = Result<Device, Self::Error>> + Send {
        self.0.create_or_find(d, now)
    }
    fn record_sighting(
        &self,
        t: &TenantId,
        id: &DeviceId,
        now: Timestamp,
    ) -> impl Future<Output = Result<DeviceTrustLevel, Self::Error>> + Send {
        self.0.record_sighting(t, id, now)
    }
    fn set_trust_level(
        &self,
        t: &TenantId,
        id: &DeviceId,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.set_trust_level(t, id, level, now)
    }
    async fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> Result<TrustTransition, Self::Error> {
        let Some(device) = self.0.load(t, id).await? else {
            return Ok(TrustTransition::Missing);
        };
        if device.trust_level != expected {
            return Ok(TrustTransition::Refused {
                current: device.trust_level,
            });
        }
        self.0.set_trust_level(t, id, level, now).await?;
        Ok(TrustTransition::Applied)
    }
    async fn replace_bindings(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: &[DeviceBinding],
        bindings: &[DeviceBinding],
        now: Timestamp,
    ) -> Result<BindingsUpdate, Self::Error> {
        let Some(mut device) = self.0.load(t, id).await? else {
            return Ok(BindingsUpdate::Missing);
        };
        if device.trust_level == DeviceTrustLevel::Revoked {
            return Ok(BindingsUpdate::Revoked);
        }
        if device.bindings != expected {
            return Ok(BindingsUpdate::Conflict);
        }
        device.bindings = bindings.to_vec();
        self.0.save(&device, now).await?;
        Ok(BindingsUpdate::Written)
    }
    async fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<OwnerClaim, Self::Error> {
        let Some(mut device) = self.0.load(t, id).await? else {
            return Ok(OwnerClaim::Missing);
        };
        match device.user_id.as_ref() {
            Some(owner) if owner == user => Ok(OwnerClaim::Claimed),
            Some(_) => Ok(OwnerClaim::OwnedByOther),
            None => {
                device.user_id = Some(*user);
                self.0.save(&device, now).await?;
                Ok(OwnerClaim::Claimed)
            }
        }
    }
    fn delete(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.delete(t, id)
    }
    fn sweep(
        &self,
        t: &TenantId,
        now: Timestamp,
    ) -> impl Future<Output = Result<SweepCounts, Self::Error>> + Send {
        self.0.sweep(t, now)
    }
}

fn interleaved_memory() -> Interleaved<MemoryDeviceStore> {
    Interleaved(MemoryDeviceStore::new())
}

/// A store whose conditional writes are single steps keeps the contract
/// when its calls interleave.
#[tokio::test]
async fn single_conditional_writes_keep_the_contract_when_calls_interleave() {
    consistency::two_swaps_from_one_read_have_one_winner(interleaved_memory()).await;
    consistency::two_trust_changes_from_one_level_have_one_winner(interleaved_memory()).await;
    consistency::two_claims_of_one_unowned_device_have_one_winner(interleaved_memory()).await;
}

/// The control for the bindings swap: a load followed by a save writes
/// twice, and the contract says so.
#[tokio::test]
#[should_panic(expected = "one swap is written and one conflicts")]
async fn a_swap_that_reads_then_writes_fails_the_contract() {
    consistency::two_swaps_from_one_read_have_one_winner(ReadThenWrite(interleaved_memory())).await;
}

/// The control for the conditional trust change: a load followed by an
/// unconditional write applies both changes, and the contract says so.
#[tokio::test]
#[should_panic(expected = "one change is applied and one refused")]
async fn a_trust_change_that_reads_then_writes_fails_the_contract() {
    consistency::two_trust_changes_from_one_level_have_one_winner(ReadThenWrite(
        interleaved_memory(),
    ))
    .await;
}

/// The control for the owner claim: a load followed by a save answers both
/// users `Claimed`, and the contract says so.
#[tokio::test]
#[should_panic(expected = "one claim wins and one is refused")]
async fn a_claim_that_reads_then_writes_fails_the_contract() {
    consistency::two_claims_of_one_unowned_device_have_one_winner(ReadThenWrite(
        interleaved_memory(),
    ))
    .await;
}
