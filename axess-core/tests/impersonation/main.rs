//! Impersonation against one rig: what an impersonation that stands may
//! and may not do, the refusals and what each leaves behind, and the
//! release of the administrator's anchor entry.
//!
//! One binary, a module per topic, because the topics share the rig: each
//! part of it is used by one of them at least, and the compiler reports a
//! part that none uses.

#![cfg(feature = "testing")]

mod anchor_release;
mod fixture;
mod refusals;
mod standing;
