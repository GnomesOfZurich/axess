#![cfg(all(feature = "testing", feature = "memory"))]
//! The rotation of a signed-in session through a real session layer and a
//! real authentication service: the handler asks for the rotation, the
//! layer moves the registry entry in one step after the row has moved, and
//! every session ended on the way is claimed and recorded.

mod handler_endings;
mod keys;
mod leaves_registry;
mod logout;
mod service_rotation;
mod step_up;
mod validator;
mod world;
