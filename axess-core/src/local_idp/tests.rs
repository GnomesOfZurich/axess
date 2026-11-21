//! Tests for the production `LocalIdp`, split by topic.

mod basics;
#[cfg(feature = "local-idp-rsa")]
mod discovery;
mod rotation;
mod support;
