//! Lock helpers for the in-memory stores: a poisoned lock is recovered, as in
//! the rest of the crate, because every critical section here leaves the map
//! consistent at each step.

use std::sync::{Mutex, MutexGuard, PoisonError};
#[cfg(any(test, feature = "memory"))]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(any(test, feature = "memory"))]
pub(crate) fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(any(test, feature = "memory"))]
pub(crate) fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}
