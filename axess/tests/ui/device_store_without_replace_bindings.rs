// A store implements every required method of `DeviceStore`, and
// `replace_bindings` is one of them: a body the trait provided would be a
// load followed by a save, which two concurrent editors both pass, so a
// store that leaves the swap out must be refused by the compiler rather
// than inherit a write that loses one of two changes.
use std::future::Future;

use axess_core::{
    Device, DeviceId, DeviceStore, DeviceTrustLevel, FingerprintHash, MemoryDeviceStore,
    OwnerClaim, SweepCounts, TenantId, TrustTransition, UserId,
};
use axess_core::Timestamp;

#[derive(Clone)]
struct Wrapped(MemoryDeviceStore);

impl DeviceStore for Wrapped {
    type Error = <MemoryDeviceStore as DeviceStore>::Error;

    fn load_fresh(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.load_fresh(t, id)
    }
    fn load(
        &self,
        t: &TenantId,
        id: &DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, Self::Error>> + Send {
        self.0.load(t, id)
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
    fn set_trust_level_if(
        &self,
        t: &TenantId,
        id: &DeviceId,
        expected: DeviceTrustLevel,
        level: DeviceTrustLevel,
        now: Timestamp,
    ) -> impl Future<Output = Result<TrustTransition, Self::Error>> + Send {
        self.0.set_trust_level_if(t, id, expected, level, now)
    }
    fn claim_owner(
        &self,
        t: &TenantId,
        id: &DeviceId,
        user: &UserId,
        now: Timestamp,
    ) -> impl Future<Output = Result<OwnerClaim, Self::Error>> + Send {
        self.0.claim_owner(t, id, user, now)
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

fn main() {}
