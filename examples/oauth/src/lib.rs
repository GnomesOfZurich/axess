//! # axess-example-oauth
//!
//! Federated login with axess that ends in a session: the OpenID Connect
//! flow, a federated-identity table, just-in-time provisioning under a tenant
//! policy, the claim lock, logout from both ends, and a `/profile` that reads
//! the axess session.
//!
//! - [`identities`]: the `(issuer, subject)` to local-user table.
//! - [`provisioning`]: claims to a local user, found or created.
//! - [`app`]: provider setup, router and handlers.
//!
//! The binary (`main.rs`) reads the environment and serves [`app::build`].

pub mod app;
pub mod identities;
pub mod provisioning;
