//! Internal helpers used by macro expansions.
//!
//! Not part of the stable public API. Items here may change between
//! patch releases. Do not depend on this module from application code.

use std::collections::HashMap;

use axess_core::authz::{AuthzError, make_entity_uid};
use cedar_policy::EntityUid;

/// Emit the authorization decision event for a gate that denied before the
/// policy evaluator ran (see `axess_core::authz::audit`).
pub fn audit_early_deny(
    principal: &EntityUid,
    action: &EntityUid,
    resource: Option<&EntityUid>,
    reason: &str,
) {
    axess_core::authz::audit::emit_early_deny(
        &principal.to_string(),
        &action.to_string(),
        &resource.map(ToString::to_string).unwrap_or_default(),
        reason,
    );
}

/// Emit the authorization decision event for a gate that denied because a
/// UID could not be built, so the audit trail has a denial for it. The
/// principal, action and resource are the strings the UIDs would have been
/// built from (the user id, the action name, the resource template), since
/// no UID exists to render.
pub fn audit_unbuilt_deny(user_id: &str, action: &str, resource_template: &str, reason: &str) {
    axess_core::authz::audit::emit_early_deny(user_id, action, resource_template, reason);
}

/// The refusal of a denied `require_authz!` request: `step_up_required` with
/// the step-up when the store says one would permit it
/// ([`PolicyEvaluator::step_up_for`](axess_core::authz::PolicyEvaluator::step_up_for)),
/// the plain denial otherwise.
pub fn refusal(
    store: &axess_core::authz::PolicyStore,
    entities: &cedar_policy::Entities,
    principal: cedar_policy::EntityUid,
    action: cedar_policy::EntityUid,
    resource: cedar_policy::EntityUid,
    context: cedar_policy::Context,
) -> axess_core::authz::AuthzRefusal {
    use axess_core::authz::PolicyEvaluator as _;
    match store.step_up_for(entities, principal, action, resource, context) {
        Some(step_up) => {
            crate::tracing::debug!(
                macro_name = "require_authz!",
                %step_up,
                "denied; a step-up the policies name would permit"
            );
            axess_core::authz::AuthzRefusal::StepUpRequired(step_up)
        }
        None => axess_core::authz::AuthzRefusal::Denied,
    }
}

/// Whether `require_authz!` must refuse because the policies in force read
/// `context` and the installation holds no context provider; logs the
/// refusal at error level when it must. The caller asks only for an
/// installation without a provider.
///
/// `AuthzInstallation::new` refuses such a pair where the installation is
/// built, which covers the policies known at that moment. This refusal is
/// for what a reload can change afterwards: the installation holds the
/// store by `Arc`, a reload replaces the set behind it, and a set that
/// begins to read `context` then meets an installation built without a
/// provider. That is the only way here, and it is decided per request
/// because the next reload can take the read out again.
///
/// Such a policy set would decide on an empty context: a rule that requires
/// `context.mfa_verified` denies every request, and a `forbid` written as
/// `context has mfa_verified && !context.mfa_verified` stops matching, so the
/// `permit` beside it allows. The gate answers 500, as it does without an
/// installation. A store that does not read `context` keeps the
/// empty-context path.
pub fn refuse_without_context_provider(
    store: &axess_core::authz::PolicyStore,
    action: &str,
) -> bool {
    if !store.mentions_context() {
        return false;
    }
    crate::tracing::error!(
        macro_name = "require_authz!",
        action,
        "the policies in force read `context` and the AuthzInstallation holds no \
         RequestContextProvider (a policy reload brought the read in after it was built); \
         build the AuthzInstallation with a context provider"
    );
    true
}

/// A UID of the request could not be built; `reason` names which one, in
/// the words of the decision event (`invalid_resource`, `invalid_action`,
/// `invalid_principal`).
#[derive(Debug)]
pub struct InvalidUid {
    /// The decision-event `reason` for this failure.
    pub reason: &'static str,
    /// What went wrong.
    pub error: AuthzError,
}

impl InvalidUid {
    const fn resource(error: AuthzError) -> Self {
        Self {
            reason: "invalid_resource",
            error,
        }
    }
}

impl std::fmt::Display for InvalidUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.error)
    }
}

impl std::error::Error for InvalidUid {}

/// A path parameter was not valid UTF-8 once percent-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPathParam;

/// Path parameters of the matched route, percent-decoded.
///
/// A request that carries no routing information (a bare service, a
/// fallback) has no parameters, which is an empty map and not an error. Only
/// a parameter that is not valid UTF-8 once decoded is an error.
pub async fn path_params(
    parts: &mut axess_core::axum::http::request::Parts,
) -> Result<HashMap<String, String>, InvalidPathParam> {
    use axess_core::axum::extract::{
        FromRequestParts, RawPathParams, rejection::RawPathParamsRejection,
    };
    match RawPathParams::from_request_parts(parts, &()).await {
        Ok(raw) => Ok(raw
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()),
        Err(RawPathParamsRejection::MissingPathParams(_)) => Ok(HashMap::new()),
        Err(_) => Err(InvalidPathParam),
    }
}

/// Index of the `:` that separates the entity type from the id in a
/// resource template: the first colon that is not half of a `::`.
const fn type_id_separator(template: &str) -> Option<usize> {
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            if i + 1 < bytes.len() && bytes[i + 1] == b':' {
                i += 2;
                continue;
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Compile-time check used by `require_authz!`: the type part of the
/// resource template must not contain a `{placeholder}`, so a request value
/// can only ever become the entity id.
pub const fn assert_resource_type_is_literal(template: &str) {
    let Some(end) = type_id_separator(template) else {
        return;
    };
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < end {
        assert!(
            bytes[i] != b'{' && bytes[i] != b'}',
            "require_authz! resource type must be a literal; only the id part may use placeholders"
        );
        i += 1;
    }
}

/// Compile-time check used by `require_authz!`: the id part of the resource
/// template may name at most one path placeholder.
///
/// Two request-supplied values in one id, joined by literal characters,
/// can be re-split by the caller: `Doc:{a}/{b}` gives the same id for
/// `a = "x/y", b = "z"` and `a = "x", b = "y/z"`. Session-derived
/// placeholders (`{$tenant}`, `{$user}`) are not counted, because their
/// values come from the authenticated session and not from the request.
///
/// Two placeholders of any kind with nothing between them (`{$tenant}{id}`)
/// are refused as well: the values cannot be told apart in the result.
pub const fn assert_one_path_placeholder(template: &str) {
    let bytes = template.as_bytes();
    let start = match type_id_separator(template) {
        Some(sep) => sep + 1,
        None => 0,
    };
    let mut count = 0;
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'{' && !(i + 1 < bytes.len() && bytes[i + 1] == b'$') {
            count += 1;
        }
        assert!(
            !(bytes[i] == b'}' && i + 1 < bytes.len() && bytes[i + 1] == b'{'),
            "require_authz! resource id must put a literal separator between two placeholders; `}}{{` cannot be split back into its values"
        );
        i += 1;
    }
    assert!(
        count <= 1,
        "require_authz! resource id may use at most one path placeholder; use the dollar-prefixed tenant or user placeholder for session values"
    );
}

/// Build the principal, action and resource UIDs for `require_authz!`.
///
/// Besides the route's path parameters the id part may use two
/// session-derived placeholders: `{$tenant}`, the authenticated session's
/// tenant id, and `{$user}`, its user id. They let a resource be qualified
/// by tenant without trusting a tenant segment in the URL. Use them for
/// tenant-qualified ids; never take the qualifier from a path segment.
///
/// The id part holds at most one path placeholder (see
/// [`assert_one_path_placeholder`]); a template with two is refused.
///
/// The resource template is split into `Type:id` *before* path parameters are
/// substituted, at the first `:` that is not half of a `::` (so a namespaced
/// type such as `Sub::Doc:{id}` keeps its whole namespace). Only the id part
/// is interpolated: a placeholder in the type part is refused, so a request
/// value can never choose the entity type. Every UID is built through
/// [`make_entity_uid`], which stores the id as an opaque string: quotes,
/// backslashes and `\u{..}` escapes in a user id or path parameter stay data
/// and cannot become another principal or resource.
///
/// # Errors
///
/// [`InvalidUid`] naming the UID that could not be built, so the caller can
/// record the denial under the right reason.
pub fn build_uids(
    namespace: &str,
    action: &str,
    resource_template: &str,
    params: &HashMap<String, String>,
    user_id: &str,
    tenant_id: &str,
) -> Result<(EntityUid, EntityUid, EntityUid), InvalidUid> {
    let split = type_id_separator(resource_template).ok_or_else(|| {
        InvalidUid::resource(AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` must be 'TypeName:id' shape"
        )))
    })?;
    let (resource_type, id_template) =
        (&resource_template[..split], &resource_template[split + 1..]);
    if resource_type.contains(['{', '}']) {
        return Err(InvalidUid::resource(AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` has a placeholder in its type; only the id may come from the request"
        ))));
    }
    let path_placeholders = id_template
        .match_indices('{')
        .filter(|(at, _)| !id_template[at + 1..].starts_with('$'))
        .count();
    if path_placeholders > 1 {
        return Err(InvalidUid::resource(AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` has more than one path placeholder; the values would be ambiguous"
        ))));
    }
    // Session values are inserted last so a route parameter can never shadow
    // them.
    let mut values = params.clone();
    values.insert("$tenant".to_string(), tenant_id.to_string());
    values.insert("$user".to_string(), user_id.to_string());
    let params = &values;
    if let Some(name) = unknown_placeholder(id_template, params) {
        return Err(InvalidUid::resource(AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` names path parameter `{name}`, which the route does not have"
        ))));
    }
    if let Some(reason) = ambiguous_id(id_template, params) {
        return Err(InvalidUid::resource(AuthzError::InvalidEntityUid(format!(
            "resource template `{resource_template}` {reason}"
        ))));
    }
    let resource_id = interpolate_path_params(id_template, params);
    let principal = make_entity_uid(namespace, "User", user_id).map_err(|error| InvalidUid {
        reason: "invalid_principal",
        error,
    })?;
    let action = make_entity_uid(namespace, "Action", action).map_err(|error| InvalidUid {
        reason: "invalid_action",
        error,
    })?;
    let resource =
        make_entity_uid(namespace, resource_type, &resource_id).map_err(InvalidUid::resource)?;
    Ok((principal, action, resource))
}

/// The characters a value under a template's only placeholder may not
/// hold: the separators a template with several placeholders puts between
/// them. An id with one placeholder has fixed text around its value and
/// cannot be misread within its own template, but another route of the
/// same resource type may split the id with one of these, and `Doc:{id}`
/// with `t1/x` would then be the resource `Doc:{$tenant}/{id}` renders
/// for `t1` and `x`. Keeping these out of a single value keeps the two
/// layouts apart.
const SINGLE_VALUE_SEPARATORS: &str = "/:";

/// Why an id built from `id_template` and `params` could be read back as a
/// different set of values, or `None` when it cannot.
///
/// An id with two or more placeholders is the literal text of the template
/// with each value in between. It reads back as one set of values only if
/// no two placeholders touch and no value holds a character that the
/// template's literal text uses as a separator: then a value ends exactly
/// where a separator character begins. Without that, tenant `t1` with id
/// `a/b` and tenant `t1/a` with id `b` both give `t1/a/b` under
/// `{$tenant}/{id}`. An id with one placeholder may not hold
/// [`SINGLE_VALUE_SEPARATORS`], so it never equals an id another template
/// of the same type builds from several values. A template that opens a
/// placeholder and never closes it is ambiguous too, not a literal brace.
fn ambiguous_id(id_template: &str, params: &HashMap<String, String>) -> Option<String> {
    let mut names: Vec<&str> = Vec::new();
    let mut separators = String::new();
    let mut rest = id_template;
    let mut touching = false;
    while let Some(open) = rest.find('{') {
        separators.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Some("opens a placeholder it never closes".to_string());
        };
        names.push(&after[..close]);
        rest = &after[close + 1..];
        touching |= rest.starts_with('{');
    }
    separators.push_str(rest);
    if touching {
        return Some(
            "puts two placeholders next to each other; put a literal separator between them"
                .to_string(),
        );
    }
    let (separators, which) = if names.len() < 2 {
        (
            SINGLE_VALUE_SEPARATORS.to_string(),
            "`/` or `:`, which templates of several placeholders use as separators",
        )
    } else {
        (separators, "a separator character of the template")
    };
    names.iter().find_map(|name| {
        let value = params.get(*name)?;
        value
            .chars()
            .any(|c| separators.contains(c))
            .then(|| format!("cannot take the value of `{name}`: it holds {which}, so the id could be read as other values"))
    })
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
mod macro_support_tests;
