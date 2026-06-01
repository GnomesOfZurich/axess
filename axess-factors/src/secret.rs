//! Secret-string primitive shared across factor configs and other
//! credential-bearing types in the axess workspace.

use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref, sync::Arc};
use zeroize::Zeroize;

/// A `String` that is zeroed in memory on drop.
///
/// Used for secrets at rest in memory (password hashes, OTP secrets,
/// OAuth bearer tokens, refresh tokens, stored delegated credentials)
/// to reduce the window during which sensitive data is recoverable
/// from a process dump.
#[derive(Clone, Serialize, Deserialize)]
pub struct ZeroizedString(String);

impl ZeroizedString {
    /// Wrap an owned string so its bytes are zeroed on drop.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Drop for ZeroizedString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for ZeroizedString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Deref for ZeroizedString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ZeroizedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizedString(***)")
    }
}

impl From<String> for ZeroizedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ZeroizedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<ZeroizedString> for Arc<str> {
    fn from(s: ZeroizedString) -> Self {
        // NOTE: this copies the string into an Arc; the original ZeroizedString
        // will still be zeroized when dropped.
        Arc::from(s.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_clears_contents_in_place() {
        let mut s = ZeroizedString::new("super-secret-password");
        assert_eq!(&*s, "super-secret-password");
        s.zeroize();
        assert!(s.is_empty(), "zeroize() must empty the inner string");
    }

    #[test]
    fn debug_redacts_payload() {
        let s = ZeroizedString::new("super-secret-password");
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "ZeroizedString(***)");
        assert!(!rendered.contains("super-secret-password"));
    }

    #[test]
    fn from_string_and_from_str_round_trip_through_deref() {
        let owned: ZeroizedString = String::from("alpha").into();
        let borrowed: ZeroizedString = "beta".into();
        assert_eq!(&*owned, "alpha");
        assert_eq!(&*borrowed, "beta");
    }

    #[test]
    fn from_zeroized_into_arc_str_preserves_bytes() {
        let s = ZeroizedString::new("gamma");
        let arc: Arc<str> = s.into();
        assert_eq!(&*arc, "gamma");
    }
}
