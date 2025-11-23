# Project Context for GitHub Copilot

## Project Overview
This is an authentication and authorization library called "axess" for the Axum web framework in Rust. It provides middleware for request extractors for authentication, authorization via Cedar Policy, and request tracing/ID generation.

## Rust Edition and Toolchain

- Axess targets Rust 2024 edition.
- Use the latest stable toolchain (`rustup update`).

## Directory Structure

- `axess/`
    - `src/`
        - `authorization.rs` — Top-level authorization logic
        - `lib.rs` — Library entry point
    - `Cargo.toml` — Package manifest for axess

- `axess-core/`
    - `src/`
        - `authn/` — Core authentication logic
        - `authz/` — Core authorization logic
        - `extras/` — Additional core features
        - `storage/` — Core storage interfaces
        - `utils/` — Core utilities and error handling
        - `lib.rs` — Core library entry point
    - `Cargo.toml` — Package manifest for axess-core

- `axess-macros/`
    - `src/lib.rs` — Procedural macros for axess
    - `Cargo.toml` — Package manifest for axess-macros

- `axess-factors/`
    - `src/` — Implementations for authentication factors (TOTP, HOTP, password hashing)
    - `Cargo.toml` — Package manifest for axess-factors

- `examples/`
    - `sqlite/`
        - `src/` — Example SQLite backend and app
        - `db/`, `migrations/`, `templates/` — Supporting files
        - `.env`, `.gitignore`, `Cargo.toml` — Example project setup

- `.github/`
    - `copilot-instructions.md` — Copilot and contributor instructions

- `Cargo.toml`, `Cargo.lock`, `README.md` — Workspace-level manifest and documentation

## Coding Guidelines
- Follow Rust's standard naming conventions (e.g., snake_case for functions and variables, CamelCase for types).
- Use idiomatic Rust patterns and practices.
- Prefer using traits for abstraction over concrete types. 
- Use `async`/`await` for all IO operations.
- Use "thiserror" crate for handling the library's error management.
- Use "tracing" crate for logging and tracing, when applicable.
- Ensure that the code supports Deterministic Simulation Testing (DST) principles.
- Write unit tests for all public functions and methods.
- Write clear and concise documentation for public APIs.

## Instructions for Copilot
When answering questions about this code base or when generating code:
1. Consider the authentication and authorization context of web services.
2. Reference relevant files from the workspace when appropriate.
3. Prefer suggested solutions that align with the existing architecture, but consider breaking or adding to this whenever there are potential significant gains to be gotten in terms of:
    - Lower Latency.
    - Lower Memory Usage.
    - Improved developer user ergonomics.
4. Be aware of the depencies in the `Cargo.toml` file and ensure compatibility with the versions specified.
5. Provide code exampes that follow the Coding Guidelines of the workspace.

## Feature Flags

Axess uses Cargo feature flags to enable/disable major components:
- `authn`: Authentication layer and extractors
- `authz`: Authorization via Cedar Policy
- `admin`: Administrative features for user/tenant management
- `request_id`: Request ID middleware
- `trace_id`: Tracing ID middleware
- `memory`: In-memory session/storage backends
- `valkey`: Valkey (Redis-compatible) session/storage backends

Enable features as needed in your `Cargo.toml`.

### Feature Flag Combinations

| Use Case         | Features                                    |
|------------------|---------------------------------------------|
| Minimal Authn    | `authn`, `memory`                           |
| Full Suite       | `authn`, `authz`, `admin`, `request_id`, `trace_id`, `memory`, `valkey` |
| Testing/DST      | `authn`, `memory`, `admin`                  |

## Testing

- Write unit tests for all public functions and methods.
- Prefer deterministic simulation testing (DST) for reproducibility.
- Write integration tests for middleware and backend contracts.
- Include doc-tests for important types and functions.
- Run all tests with:
  ```bash
  cargo test --workspace --all-features
  ```

## Contributing

See [CONTRIBUTE.md](../CONTRIBUTE.md) for contribution guidelines, coding standards, and maintainer availability.

## Security

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and security recommendations.

## License

Axess is licensed under the MIT License. See [LICENSE](../LICENSE).

---
