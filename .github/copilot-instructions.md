# Project Context for GitHub Copilot

## Project Overview
This is an authentication and authorization library called "axess" for the Axum web framework in Rust. It provides middleware for request extractors for authentication, authorization via Cedar Policy, and request tracing/ID generation.

## Directory Structure

- `axess/`
    - `src/`
        - `authn/` — Authentication-related code
        - `authz/` — Authorization-related code
        - `storage/` — Storage interfaces and implementations
        - `utils/` — Utility functions, types, and error handling
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
