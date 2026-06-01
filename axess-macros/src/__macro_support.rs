//! Internal helpers used by macro expansions.
//!
//! Not part of the stable public API. Items here may change between
//! patch releases. Do not depend on this module from application code.

use std::collections::HashMap;

/// Substitute `{name}` placeholders in `template` with values from `params`.
///
/// Used by [`require_authz!`](crate::require_authz) to resolve resource
/// templates like `"Ledger:{id}"` against extracted axum path parameters.
/// Placeholders with no matching key are left literal so the resulting
/// `EntityUid::from_str` will fail with a useful error rather than
/// silently producing the wrong UID.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// let params = HashMap::from([
///     ("id".to_string(), "abc-123".to_string()),
/// ]);
/// let resolved = axess_macros::__macro_support::interpolate_path_params(
///     "Ledger:{id}", &params);
/// assert_eq!(resolved, "Ledger:abc-123");
/// ```
pub fn interpolate_path_params(template: &str, params: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            let mut closed = false;
            for next in chars.by_ref() {
                if next == '}' {
                    closed = true;
                    break;
                }
                name.push(next);
            }
            if closed {
                if let Some(value) = params.get(&name) {
                    result.push_str(value);
                } else {
                    // Leave the placeholder literal so EntityUid::from_str
                    // fails loudly with a meaningful error.
                    result.push('{');
                    result.push_str(&name);
                    result.push('}');
                }
            } else {
                // Unmatched '{'; push as-is to preserve the original.
                result.push('{');
                result.push_str(&name);
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn substitutes_single_placeholder() {
        let p = params(&[("id", "abc-123")]);
        assert_eq!(interpolate_path_params("Ledger:{id}", &p), "Ledger:abc-123");
    }

    #[test]
    fn substitutes_multiple_placeholders() {
        let p = params(&[("tenant", "t1"), ("id", "x")]);
        assert_eq!(interpolate_path_params("Doc:{tenant}/{id}", &p), "Doc:t1/x");
    }

    #[test]
    fn leaves_unknown_placeholder_literal() {
        let p = params(&[]);
        assert_eq!(
            interpolate_path_params("Ledger:{id}", &p),
            "Ledger:{id}",
            "missing key should leave placeholder literal so Cedar parse fails loudly"
        );
    }

    #[test]
    fn handles_no_placeholders() {
        let p = params(&[]);
        assert_eq!(interpolate_path_params("Platform", &p), "Platform");
    }

    #[test]
    fn handles_unmatched_open_brace() {
        let p = params(&[]);
        assert_eq!(
            interpolate_path_params("Bad:{unterm", &p),
            "Bad:{unterm",
            "unmatched '{{' preserved literally"
        );
    }
}
