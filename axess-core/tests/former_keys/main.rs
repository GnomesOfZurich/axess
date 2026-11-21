#![cfg(all(feature = "testing", feature = "memory", feature = "oauth"))]
//! A key a session held before a rotation still finds the session.
//!
//! The sid store holds the key an OAuth login registered, and an
//! administrator's list holds the key a session was under when it was read.
//! A step-up, `rotate_session` or `regenerate` moves the session to a new
//! key afterwards. Every test runs through a real session layer and a real
//! service over one registry and one sid store, with the identity
//! provider's back-channel and front-channel handlers beside them: a
//! logout the provider sends, the sweep of the subject records and a kick
//! each reach the session under the key it is under now, and a logout for a
//! session that is gone records no ending.

#[cfg(feature = "valkey")]
mod live;
mod memory;
mod scenarios;
mod world;
