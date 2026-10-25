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
///    `"Platform:tenant"`. Format is `"<TypeName>:<id>"`, split at the first
///    single `:` (a `::` belongs to a namespaced type such as
///    `"Sub::Ledger:{id}"`). Path parameters matching `{name}` are
///    substituted into the id part only, at runtime; a placeholder in the
///    type part is rejected at compile time, so a request can never choose
///    the entity type. Combined with namespace into
///    `Namespace::TypeName::"id"`.
///
/// # Required request extensions
///
/// The macro pulls the following from `request.extensions()`. Apps must
/// install them via tower layers earlier in the middleware chain:
///
/// - `Arc<axess_core::authz::PolicyStore>`: the loaded Cedar policies,
///   typically constructed once at app startup.
/// - `Arc<dyn axess_core::authz::RequestEntityProvider>`: builds the Cedar
///   entity set for each request from the session, the principal, the
///   resource and the action (`entities_for`). Wrap it in the caching
///   decorators from `axess_core::authz::cache` where entity construction is
///   costly. The extension must be stored under exactly this type: an
///   `Arc<MyProvider>` is a different type to the extension map.
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
/// - **400 Bad Request**: a path parameter is not valid UTF-8 after
///   percent-decoding.
/// - **500 Internal Server Error**: missing extensions, malformed
///   namespace/action/resource that can't be parsed as `EntityUid`.
///
/// # Examples
///
/// ```ignore
/// use std::sync::Arc;
/// use axess_core::authz::{PolicyStore, RequestEntityProvider};
/// use axess_macros::require_authz;
/// use axum::{Extension, Router, routing::get};
///
/// let store: Arc<PolicyStore> = Arc::new(load_policies()?);
/// let provider: Arc<dyn RequestEntityProvider> = Arc::new(MyEntityProvider::new(db));
///
/// let app = Router::new()
///     // Resource ID extracted from `{id}` path param at runtime:
///     .route("/ledgers/{id}",
///            get(get_ledger).layer(require_authz!("MyApp", "ViewLedger", "Ledger:{id}")))
///     // Static resource, no path params needed:
///     .route("/users",
///            get(list_users).layer(require_authz!("MyApp", "ManageUsers", "Platform:global")))
///     // The two extensions every `require_authz!` reads, installed outside
///     // the gates (layers added last run first):
///     .layer(Extension(store))
///     .layer(Extension(provider));
/// ```
///
/// # Path-param interpolation
///
/// Placeholders like `{id}` are substituted at request time from the
/// matched route's raw path parameters. The macro reads them itself; it
/// doesn't conflict with handler-side `Path<T>` extractors because they
/// share the same parsed path data. A route with no path parameters (or a
/// request that never went through a router) evaluates from the attribute
/// alone.
///
/// Unknown placeholders (no matching path param) make the macro return 500;
/// fail-loud rather than evaluating Cedar against a malformed UID. Substituted
/// values are opaque ids: quotes, backslashes and `\u{..}` escapes stay data.
#[macro_export]
macro_rules! require_authz {
    // `$namespace` is `:expr` rather than `:literal` so consuming
    // crates can pass a runtime value (e.g. `$crate::cedar_namespace()`)
    // and switch Cedar namespaces per-deployment without recompiling. The
    // `$action` and `$resource` matchers stay `:literal` because they
    // identify the policy decision point and shouldn't change at runtime.
    ($namespace:expr, $action:literal, $resource:literal) => {{
        $crate::axum::middleware::from_fn(
            |auth_session: $crate::AuthSession,
             req: $crate::axum::extract::Request,
             next: $crate::axum::middleware::Next| async move {
                use ::std::sync::Arc;
                use $crate::axum::response::IntoResponse;

                // The entity TYPE comes from the attribute alone: a
                // placeholder in the type position is a compile error.
                const _: () = $crate::__macro_support::assert_resource_type_is_literal($resource);

                // Path parameters, if the route has any. A request that
                // reached this gate without routing (no parameters at all)
                // simply has none.
                let (mut req_parts, req_body) = req.into_parts();
                let path_params =
                    match $crate::__macro_support::path_params(&mut req_parts).await {
                        ::std::result::Result::Ok(p) => p,
                        ::std::result::Result::Err(_) => {
                            return $crate::axum::http::StatusCode::BAD_REQUEST.into_response();
                        }
                    };
                let req = $crate::axum::extract::Request::from_parts(req_parts, req_body);

                // 1. Authn; Cedar deny is wasted work for an anonymous caller.
                //    One read of the session answers both "is it authenticated"
                //    and "as whom", so the id cannot come from a different
                //    state than the check.
                let user_id = match auth_session.snapshot().await {
                    ::std::option::Option::Some(snapshot) => snapshot.user_id.to_string(),
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

                // 3. Build EntityUids. Ids are opaque strings, never re-parsed
                //    from formatted text, so request data cannot inject syntax.
                let (principal, action_uid_parsed, resource) =
                    match $crate::__macro_support::build_uids(
                        $namespace, $action, $resource, &path_params, &user_id,
                    ) {
                        ::std::result::Result::Ok(uids) => uids,
                        ::std::result::Result::Err(e) => {
                            $crate::tracing::error!(
                                macro_name = "require_authz!",
                                resource_template = $resource,
                                ?e,
                                "invalid Cedar UID"
                            );
                            return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };

                // 5. Build entities via the provider (cache-aware via decorator chain).
                //    The provider receives `&auth_session` so it can read
                //    tenant_id (and any other session state) when constructing
                //    principal attributes.
                let entities = match provider
                    .shared_entities_for(&auth_session, &principal, &resource, &action_uid_parsed)
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
