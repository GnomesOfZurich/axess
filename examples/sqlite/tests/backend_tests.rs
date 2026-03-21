//! Integration tests for the sqlite example backend.
//!
//! These tests were written against the old monolithic `AuthnBackend` API and
//! are being rewritten incrementally alongside the new `IdentityStore` /
//! `FactorStore` API.
//!
//! TODO: add new integration tests here once the schema stabilises.

#[tokio::test]
async fn placeholder_passes() {
    // Nothing to assert — this keeps the test binary compiling.
}
