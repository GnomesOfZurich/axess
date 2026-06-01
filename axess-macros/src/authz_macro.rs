//! `require_authz!` macro: Cedar authorization gate for Axum routes.
//!
//! See macro-level documentation on [`require_authz!`](crate::require_authz).

/// Cedar authorization gate for Axum routes. Implies authentication, then
/// evaluates a Cedar policy decision and rejects with 403 on deny.
///
/// Returns a tower `Layer` ready for `.layer(...)` / `.route_layer(...)`.
/// Same macro works for normal handlers and WebSocket upgrade handlers
/// (the upgrade is a normal HTTP request from the middleware's perspective,
/// so the gate runs before the upgrade succeeds).
///
/// # Naming
///
/// Follows the axess `Authn*` / `Authz*` convention. See also
/// [`require_authn!`](crate::require_authn) for authentication-state gating;
/// [`predicate_required!`](crate::predicate_required) is the foundation
/// escape hatch for custom predicates.
///
/// # Arguments
///
/// Three positional string literals:
///
/// 1. **`namespace`**: Cedar namespace, e.g. `"Gnomes"` or `"MyApp"`.
///    Must match the namespace used in the loaded Cedar policy file.
/// 2. **`action`**: Cedar action name, e.g. `"ViewLedger"`.
///    Combined with namespace into `Namespace::Action::"ActionName"`.
/// 3. **`resource`**: Resource pattern, e.g. `"Ledger:{id}"` or
///    `"Platform:tenant"`. Format is `"<TypeName>:<id>"`. Path parameters
///    matching `{name}` are substituted from the request's path-params at
///    runtime. Combined with namespace into `Namespace::TypeName::"id"`.
///
/// # Required request extensions
///
/// The macro pulls the following from `request.extensions()`. Apps must
/// install them via tower layers earlier in the middleware chain:
///
/// - `Arc<axess_core::authz::PolicyStore>`: the loaded Cedar policies,
///   typically constructed once at app startup.
/// - `Arc<cedar_policy::Entities>`: the Cedar entity set for this
///   request's principal (and the resources they may touch). Apps populate
///   this via their own entity-provider layer.
///
/// If either extension is missing, the macro returns `500 Internal Server
/// Error` and logs at `error!` level; this is a configuration bug, not
/// a per-request error.
///
/// # Failure responses
///
/// - **401 Unauthorized**: caller is not authenticated.
/// - **403 Forbidden**: Cedar policy denied the request
///   (returns `axess_core::authz::AuthzDenied`).
/// - **500 Internal Server Error**: missing extensions, malformed
///   namespace/action/resource that can't be parsed as `EntityUid`.
///
/// # Examples
///
/// ```ignore
/// use axess_macros::require_authz;
/// use axum::{Router, routing::get};
///
/// let app = Router::new()
///     // Resource ID extracted from `:id` path param at runtime:
///     .route("/ledgers/{id}",
///            get(get_ledger).layer(require_authz!("MyApp", "ViewLedger", "Ledger:{id}")))
///     // Static resource, no path params needed:
///     .route("/users",
///            get(list_users).layer(require_authz!("MyApp", "ManageUsers", "Platform:global")));
/// ```
///
/// # Path-param interpolation
///
/// Placeholders like `{id}` are substituted at request time using
/// `axum::extract::Path<HashMap<String, String>>`. The macro registers
/// this extractor automatically; it doesn't conflict with handler-side
/// `Path<T>` extractors because they share the same parsed path data.
///
/// Unknown placeholders (no matching path param) are left literal,
/// causing `EntityUid::from_str` to fail and the macro to return 500;
/// fail-loud rather than evaluating Cedar against a malformed UID.
#[macro_export]
macro_rules! require_authz {
    // PD-073: `$namespace` is `:expr` rather than `:literal` so consuming
    // crates can pass a runtime value (e.g. `$crate::cedar_namespace()`)
    // and switch Cedar namespaces per-deployment without recompiling. The
    // `$action` and `$resource` matchers stay `:literal` because they
    // identify the policy decision point and shouldn't change at runtime.
    ($namespace:expr, $action:literal, $resource:literal) => {{
        $crate::axum::middleware::from_fn(
            |path_params: $crate::axum::extract::Path<
                ::std::collections::HashMap<::std::string::String, ::std::string::String>,
             >,
             auth_session: $crate::AuthSession,
             req: $crate::axum::extract::Request,
             next: $crate::axum::middleware::Next| async move {
                use ::std::str::FromStr;
                use ::std::sync::Arc;
                use $crate::axum::response::IntoResponse;

                // 1. Authn; Cedar deny is wasted work for an anonymous caller.
                if !auth_session.is_authenticated().await {
                    return $crate::axum::http::StatusCode::UNAUTHORIZED.into_response();
                }
                let user_id = match auth_session.user_id().await {
                    ::std::option::Option::Some(id) => id.to_string(),
                    ::std::option::Option::None => {
                        return $crate::axum::http::StatusCode::UNAUTHORIZED.into_response();
                    }
                };

                // 2. Pull required extensions.
                let store = match req
                    .extensions()
                    .get::<Arc<$crate::__authz::PolicyStore>>()
                {
                    ::std::option::Option::Some(s) => Arc::clone(s),
                    ::std::option::Option::None => {
                        $crate::tracing::error!(
                            macro_name = "require_authz!",
                            namespace = $namespace,
                            action = $action,
                            "missing PolicyStore extension; install Extension(Arc<PolicyStore>) earlier in the middleware chain"
                        );
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let provider = match req
                    .extensions()
                    .get::<Arc<dyn $crate::__authz::RequestEntityProvider>>()
                {
                    ::std::option::Option::Some(p) => Arc::clone(p),
                    ::std::option::Option::None => {
                        $crate::tracing::error!(
                            macro_name = "require_authz!",
                            namespace = $namespace,
                            action = $action,
                            "missing RequestEntityProvider extension; install Extension(Arc<dyn RequestEntityProvider>) earlier in the middleware chain"
                        );
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };

                // 3. Substitute path params in resource template.
                let resource_str = $crate::__macro_support::interpolate_path_params(
                    $resource, &path_params.0
                );

                // 4. Build EntityUids. The format strings are namespaced.
                let principal_uid = format!(
                    "{}::User::\"{}\"", $namespace, user_id
                );
                let action_uid = format!(
                    "{}::Action::\"{}\"", $namespace, $action
                );
                // Resource template is "TypeName:id"; we wrap the id half in quotes.
                let (resource_type, resource_id) = match resource_str.split_once(':') {
                    ::std::option::Option::Some(parts) => parts,
                    ::std::option::Option::None => {
                        $crate::tracing::error!(
                            macro_name = "require_authz!",
                            resource_template = $resource,
                            resolved = %resource_str,
                            "resource must be 'TypeName:id' shape"
                        );
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let resource_uid = format!(
                    "{}::{}::\"{}\"", $namespace, resource_type, resource_id
                );

                let principal = match $crate::__cedar::EntityUid::from_str(&principal_uid) {
                    ::std::result::Result::Ok(u) => u,
                    ::std::result::Result::Err(e) => {
                        $crate::tracing::error!(uid = %principal_uid, ?e, "invalid principal UID");
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let action_uid_parsed = match $crate::__cedar::EntityUid::from_str(&action_uid) {
                    ::std::result::Result::Ok(u) => u,
                    ::std::result::Result::Err(e) => {
                        $crate::tracing::error!(uid = %action_uid, ?e, "invalid action UID");
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let resource = match $crate::__cedar::EntityUid::from_str(&resource_uid) {
                    ::std::result::Result::Ok(u) => u,
                    ::std::result::Result::Err(e) => {
                        $crate::tracing::error!(uid = %resource_uid, ?e, "invalid resource UID");
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };

                // 5. Build entities via the provider (cache-aware via decorator chain).
                //    The provider receives `&auth_session` so it can read
                //    tenant_id (and any other session state) when constructing
                //    principal attributes.
                let entities = match provider
                    .entities_for(&auth_session, &principal, &resource, &action_uid_parsed)
                    .await
                {
                    ::std::result::Result::Ok(e) => e,
                    ::std::result::Result::Err(e) => {
                        $crate::tracing::warn!(
                            ?e,
                            principal = %principal,
                            resource = %resource,
                            action = %action_uid_parsed,
                            "entities_for failed; treating as deny"
                        );
                        return $crate::__authz::AuthzDenied.into_response();
                    }
                };

                // 6. Cedar evaluation. AuthzDenied is the standard 403 response.
                let decision = $crate::__authz::PolicyEvaluator::is_authorized(
                    &*store,
                    &entities,
                    principal,
                    action_uid_parsed,
                    resource,
                    $crate::__cedar::Context::empty(),
                );
                match decision {
                    $crate::__authz::AuthzDecision::Allow => next.run(req).await,
                    $crate::__authz::AuthzDecision::Deny => {
                        $crate::__authz::AuthzDenied.into_response()
                    }
                }
            },
        )
    }};
}
