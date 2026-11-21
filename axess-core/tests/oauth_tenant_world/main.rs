//! Two tenants, each with its own identity provider, in one world: the
//! by-name OAuth helpers follow the tenant a session logged in through, a
//! token revocation writes its audit rows, and a callback is finished only
//! on the route of the registration its login began with.
//!
//! One binary, a module per topic, because the topics share the world: each
//! part of it is used by one of them at least, and the compiler reports a
//! part that none uses.

#![cfg(all(feature = "testing", feature = "oauth"))]

mod callback_route;
mod helpers;
mod provider_kind;
mod revocation_audit;
mod world;
