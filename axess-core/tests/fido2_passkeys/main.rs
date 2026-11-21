//! Passkey ceremonies against one fixture: who may enrol and delete a
//! passkey, what a registration and a deletion keep, the claim on a
//! credential id, and a step-up raced by another request.
//!
//! One binary, a module per topic, because the topics share the fixture:
//! each part of it is used by one of them at least, and the compiler
//! reports a part that none uses.

#![cfg(all(feature = "testing", feature = "fido2"))]

mod enrolment_rules;
mod factor_swap_contract;
mod fixture;
mod login_step_up_race;
mod registration;
mod registration_claims;
