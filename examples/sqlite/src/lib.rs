//! Library surface for `axess-example-sqlite`.
//!
//! Mirrors the binary's module tree so integration tests in `tests/`
//! can import `models` + `web` without duplicating setup. The binary
//! at `src/main.rs` consumes this lib via
//! `use axess_example_sqlite::{models, web};`.

pub mod models;
pub mod web;
