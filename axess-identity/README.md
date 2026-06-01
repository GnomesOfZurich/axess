# axess-identity

[![Version](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/version.svg)](https://crates.io/crates/axess-identity)
[![Status](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/status.svg)](https://github.com/GnomesOfZurich/axess)
[![License](https://raw.githubusercontent.com/GnomesOfZurich/axess/main/.github/badges/license.svg)](https://github.com/GnomesOfZurich/axess#licence)

[crates.io](https://crates.io/crates/axess-identity) · [docs.rs](https://docs.rs/axess-identity) · [GitHub](https://github.com/GnomesOfZurich/axess)

Identity primitives for the [Axess](https://github.com/GnomesOfZurich/axess) workspace.

Foundation crate, deliberately small: depends only on [`axess-rng`](https://crates.io/crates/axess-rng) (for the DST-injectable `SecureRng` trait), `uuid`, and `thiserror`. No tokio, no axum, no Cedar; axess-core layers session integration + Cedar entity emission on top of these primitives.

## What's in here

- **Typed identifiers**; `TenantId`, `UserId`, `DeviceId`, `SessionId`, `EventId`. All `FooId(Uuid)` newtypes via the `define_id!` macro, with optional `serde` / `rkyv` / `sqlx` derives gated by features on the umbrella `axess-core` crate.
- **Principal abstraction**; unified `Principal { Human, Workload }` enum + the SPIFFE-shaped `WorkloadId` / `TrustDomain` / `Issuer` types, plus the async `PrincipalResolver` trait every inbound auth surface implements. See [`docs/workload-identity/README.md`](https://github.com/GnomesOfZurich/axess/blob/main/docs/workload-identity/README.md) for the design rationale.

## Usage

```rust
use axess_identity::{TenantId, UserId, define_id};

let tenant = TenantId::new();              // fresh v4 UUID
let user = UserId::new();
let parsed: TenantId = "0193...".parse()?; // FromStr from hyphenated string

// Adopters can mint their own ID types:
define_id!(InvoiceId);
```

## Licence

Dual-licensed under [MIT](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-MIT) and [Apache-2.0](https://github.com/GnomesOfZurich/axess/blob/main/LICENSE-APACHE).
