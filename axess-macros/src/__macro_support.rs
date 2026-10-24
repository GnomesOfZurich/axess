//! Internal helpers used by macro expansions.
//!
//! Not part of the stable public API. Items here may change between
//! patch releases. Do not depend on this module from application code.

use std::collections::HashMap;

use axess_core::authz::{AuthzError, make_entity_uid};
use cedar_policy::EntityUid;

/// Build the principal, action and resource UIDs for `require_authz!`.
///
/// The resource template is split into `Type:id` *before* path parameters are
/// substituted, so a parameter value can never move the split point. Every UID
/// is built through [`make_entity_uid`], which stores the id as an opaque
/// string: quotes, backslashes and `\u{..}` escapes in a user id or path
/// parameter stay data and cannot become another principal or resource.
pub fn build_uids(
    namespace: &str,
    action: &str,
    resource_template: &str,
    params: &HashMap<String, String>,
    user_id: &str,
) -> Result<(EntityUid, EntityUid, EntityUid), AuthzError> {
    let (type_template, id_template) = resource_template.split_once(':').ok_or_else(|| {
        AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` must be 'TypeName:id' shape"
        ))
    })?;
    if let Some(name) = unknown_placeholder(resource_template, params) {
        return Err(AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` names path parameter `{name}`, which the route does not have"
        )));
    }
    let resource_type = interpolate_path_params(type_template, params);
    let resource_id = interpolate_path_params(id_template, params);
    let principal = make_entity_uid(namespace, "User", user_id)?;
    let action = make_entity_uid(namespace, "Action", action)?;
    let resource = make_entity_uid(namespace, &resource_type, &resource_id)?;
    Ok((principal, action, resource))
}

/// The first `{name}` placeholder in `template` with no matching key, if any.
fn unknown_placeholder(template: &str, params: &HashMap<String, String>) -> Option<String> {
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Some(after.to_string());
        };
        let name = &after[..close];
        if !params.contains_key(name) {
            return Some(name.to_string());
        }
        rest = &after[close + 1..];
    }
    None
}

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

    #[test]
    fn unicode_escape_in_user_id_stays_data() {
        let p = params(&[("id", "x")]);
        let (principal, _, _) = build_uids("App", "Read", "Doc:{id}", &p, r"al\u{69}ce").unwrap();
        assert_eq!(principal.id().unescaped(), r"al\u{69}ce");
        assert_ne!(principal.id().unescaped(), "alice");
    }

    #[test]
    fn quote_and_escape_in_path_param_stay_data() {
        let p = params(&[("id", r#"a" } \u{41}"#)]);
        let (_, _, resource) = build_uids("App", "Read", "Doc:{id}", &p, "u1").unwrap();
        assert_eq!(resource.id().unescaped(), r#"a" } \u{41}"#);
        assert_eq!(resource.type_name().to_string(), "App::Doc");
    }

    #[test]
    fn colon_in_param_does_not_move_the_split() {
        let p = params(&[("id", "Admin:1")]);
        let (_, _, resource) = build_uids("App", "Read", "Doc:{id}", &p, "u1").unwrap();
        assert_eq!(resource.type_name().to_string(), "App::Doc");
        assert_eq!(resource.id().unescaped(), "Admin:1");
    }

    #[test]
    fn unknown_placeholder_is_refused() {
        assert!(build_uids("App", "Read", "Doc:{id}", &params(&[]), "u1").is_err());
    }

    #[test]
    fn template_without_colon_is_refused() {
        assert!(build_uids("App", "Read", "Doc", &params(&[]), "u1").is_err());
    }

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
