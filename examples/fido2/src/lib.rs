//! # axess-example-fido2
//!
//! FIDO2 and WebAuthn end to end, in the browser and on the server, with no
//! outside service: every account, credential and session lives in memory.
//!
//! | In the page | On the server |
//! |---|---|
//! | Add a passkey | `begin_fido2_registration_with` running `Fido2Ceremony::Passkey`: user verification required, no attestation |
//! | Add a security key | the same call running `Fido2Ceremony::SecurityKey`, user verification preferred |
//! | Add an attested passkey | the same call running `Fido2Ceremony::AttestedPasskey`: direct attestation, verified against the roots you name |
//! | Sign in with a security key | `begin_login`, then `prepare_factor_choice(Fido2)`: the login ceremony, user verification preferred |
//! | Sign in with a passkey | `begin_discoverable_login_with`: no username, user verification required |
//! | Use a passkey on another device | the same call with `DiscoverablePrompt::CrossDevice` (cross-device authentication, the hybrid transport) |
//! | Approve a payment | `require_authz!` over a Cedar policy; a session that falls short is answered `step_up_required`, and the page runs the step-up the answer names |
//!
//! ```sh
//! cargo run -p axess-example-fido2
//! ```
//!
//! Then open <http://localhost:3000> (the name, not `127.0.0.1`: a WebAuthn
//! relying party is a domain) and sign in as `alice` with `Sample2+`.
//!
//! [`app::build_router`] is the whole application; [`app::build_router_on`]
//! is the same on a clock and a FIDO2 provider of the caller's choosing,
//! which is how the tests drive it without a browser.

pub mod app;
mod login;
mod passkeys;
mod payments;
mod reply;
