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
/// Three positional string literals, then the session validator:
///
/// 1. **`namespace`**: Cedar namespace, e.g. `"Acme"` or `"MyApp"`.
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
///    `Namespace::TypeName::"id"`. The id part may also use two
///    session-derived placeholders, `{$tenant}` and `{$user}`, the
///    authenticated session's tenant and user ids, to qualify a resource by
///    tenant (`"Ledger:{$tenant}/{id}"`). Never take a tenant qualifier from
///    a path segment: the caller chooses the URL. An id may name at most one
///    path placeholder, checked at compile time, because two caller-supplied
///    values joined by a literal can be re-split into other pairs. For the
///    same reason two placeholders may not touch (`"Doc:{$tenant}{id}"` does
///    not compile), and when an id has two or more placeholders a value that
///    holds a character of the template's literal text (the `/` of
///    `"Ledger:{$tenant}/{id}"`) is denied as an invalid resource.
///
/// The principal is always `User:<id>` with the id the authenticated session
/// carries: user ids are issued by the application and held in the session,
/// never read from the request, so the principal needs no tenant-qualified
/// form. A policy that must tell tenants apart does so on the resource id
/// (above).
///
/// # Session validator
///
/// The fourth argument is required: `validator = authn.session_validator()`
/// makes the gate consult the session registry first, as the validator form of
/// [`require_authn!`](crate::require_authn) does, and answer 401 (clearing the
/// stored session) when the session is no longer live. A gate that read the
/// session record alone would let through a session the registry ended (a
/// password reset, a suspension, an administrator's kick). A bare
/// `require_authz!("ns", "action", "Type:id")` does not compile.
///
/// ```ignore
/// require_authz!("MyApp", "ViewLedger", "Ledger:{id}", validator = authn.session_validator())
/// ```
///
/// # The installation
///
/// The gate reads one thing from the request: an
/// `axess_core::authz::AuthzInstallation`, added as a layer outside the
/// gates. It is built once, where the router is built, from:
///
/// - the `Arc<PolicyStore>` holding the loaded Cedar policies;
/// - an `Arc<dyn RequestEntityProvider>`, which builds the Cedar entity set
///   for each request from the session, the principal, the resource and the
///   action (`entities_for`). Wrap it in the caching decorators from
///   `axess_core::authz::cache` where entity construction is costly;
/// - an `Arc<dyn RequestContextProvider>` when the policies read `context`,
///   or `None` when they never do.
///
/// `AuthzInstallation::new` refuses a policy store that reads `context`
/// without a context provider, so that mistake is an error at startup. A
/// gate that finds no installation in the request answers `500 Internal
/// Server Error` and logs at `error!` level; this is a configuration bug,
/// not a per-request error. No other request extension reaches the gate: a
/// policy store or a provider installed on its own is not read.
///
/// # Request context
///
/// The installation's context provider builds the Cedar context
/// (`context.mfa_verified` and similar attributes) from the session and the
/// request head. When the provider returns an error the gate answers 403.
/// An installation built without one belongs to a policy store that never
/// reads `context`, and its gates evaluate with an empty context.
///
/// A policy reload can change that after the installation was built: when
/// the store is reloaded to a set that reads `context` and the installation
/// holds no provider, the gate answers 500 and logs an error for every
/// request, because an empty context turns a `forbid` that guards an
/// optional attribute with `context has ..` into nothing while the `permit`
/// beside it allows. An application that reloads policies gives the
/// installation a context provider from the start.
///
/// # Failure responses
///
/// - **401 Unauthorized**: caller is not authenticated.
/// - **403 Forbidden**: Cedar policy denied the request
///   (returns `axess_core::authz::AuthzDenied`), or, when a step-up named by
///   a policy's `@step_up` annotation would permit it, answers
///   `{"error": "step_up_required", "step_up": "<name>"}`
///   (`axess_core::authz::AuthzRefusal::StepUpRequired`), naming the
///   step-up and nothing of the policy.
/// - **400 Bad Request**: a path parameter is not valid UTF-8 after
///   percent-decoding, for an authenticated caller (an anonymous one is
///   401 first).
/// - **500 Internal Server Error**: no installation in the request, a
///   reloaded policy set that reads `context` on an installation without a
///   context provider, or a malformed namespace/action/resource that can't
///   be parsed as `EntityUid`.
///
/// # Examples
///
/// ```ignore
/// use std::sync::Arc;
/// use axess_core::authz::{AuthzInstallation, PolicyStore};
/// use axess_macros::require_authz;
/// use axum::{Router, routing::get};
///
/// let store: Arc<PolicyStore> = Arc::new(load_policies()?);
/// // `None`: these policies never read `context`. A store that does is
/// // refused here unless a context provider is passed.
/// let installation =
///     AuthzInstallation::new(store, Arc::new(MyEntityProvider::new(db)), None)?;
///
/// let app = Router::new()
///     // Resource ID extracted from `{id}` path param at runtime:
///     .route("/ledgers/{id}",
///            get(get_ledger).layer(require_authz!(
///                "MyApp", "ViewLedger", "Ledger:{id}",
///                validator = authn.session_validator())))
///     // Static resource, no path params needed:
///     .route("/users",
///            get(list_users).layer(require_authz!(
///                "MyApp", "ManageUsers", "Platform:global",
///                validator = authn.session_validator())))
///     // What every `require_authz!` reads, installed outside the gates
///     // (layers added last run first):
///     .layer(installation);
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
    //
    // The gate itself, with the session check `$validator` makes. First:
    // an `:expr` matcher fails the whole call on a token it cannot parse.
    (@gate $namespace:expr, $action:literal, $resource:literal, $validator:expr) => {{
        let validator = $validator;
        $crate::axum::middleware::from_fn(
            move |auth_session: $crate::AuthSession,
             req: $crate::axum::extract::Request,
             next: $crate::axum::middleware::Next| {
              let validator = validator.clone();
              async move {
                use $crate::axum::response::IntoResponse;

                // The entity TYPE comes from the attribute alone: a
                // placeholder in the type position is a compile error.
                const _: () = $crate::__macro_support::assert_resource_type_is_literal($resource);
                // At most one request-supplied value in an id, so two
                // values cannot be re-split by the caller.
                const _: () = $crate::__macro_support::assert_one_path_placeholder($resource);

                // 1. Authn; Cedar deny is wasted work for an anonymous caller.
                //    One read of the session answers both "is it authenticated"
                //    and "as whom", so the id cannot come from a different
                //    state than the check.
                if !validator.enforce(&auth_session).await {
                    return $crate::axum::http::StatusCode::UNAUTHORIZED.into_response();
                }
                let (user_id, tenant_id) = match auth_session.snapshot().await {
                    ::std::option::Option::Some(snapshot) => {
                        (snapshot.user_id.to_string(), snapshot.tenant_id.to_string())
                    }
                    ::std::option::Option::None => {
                        return $crate::axum::http::StatusCode::UNAUTHORIZED.into_response();
                    }
                };

                // Path parameters, if the route has any (after the authn check,
                // so an anonymous caller is 401 whatever the path). A request that
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

                // 2. The installation: the policies and their providers,
                //    the one thing the gate reads from the request.
                let installation = match req
                    .extensions()
                    .get::<$crate::__authz::AuthzInstallation>()
                {
                    ::std::option::Option::Some(i) => i.clone(),
                    ::std::option::Option::None => {
                        $crate::tracing::error!(
                            macro_name = "require_authz!",
                            namespace = $namespace,
                            action = $action,
                            "no AuthzInstallation in the request; build one with AuthzInstallation::new and add it as a layer outside the gates"
                        );
                        return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let store = installation.store();

                // 3. Build EntityUids. Ids are opaque strings, never re-parsed
                //    from formatted text, so request data cannot inject syntax.
                let (principal, action_uid_parsed, resource) =
                    match $crate::__macro_support::build_uids(
                        $namespace, $action, $resource, &path_params, &user_id, &tenant_id,
                    ) {
                        ::std::result::Result::Ok(uids) => uids,
                        ::std::result::Result::Err(e) => {
                            $crate::tracing::error!(
                                macro_name = "require_authz!",
                                resource_template = $resource,
                                error = ?e.error,
                                "invalid Cedar UID"
                            );
                            // No UID exists to render, so the decision event
                            // carries the strings the UIDs were built from.
                            $crate::__macro_support::audit_unbuilt_deny(
                                &user_id, $action, $resource, e.reason,
                            );
                            return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };

                // 5. Build entities via the provider (cache-aware via decorator chain).
                //    The provider receives `&auth_session` so it can read
                //    tenant_id (and any other session state) when constructing
                //    principal attributes.
                let entities = match installation
                    .entities()
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
                        $crate::__macro_support::audit_early_deny(
                            &principal,
                            &action_uid_parsed,
                            ::std::option::Option::Some(&resource),
                            "entity_provider_error",
                        );
                        return $crate::__authz::AuthzDenied.into_response();
                    }
                };

                // 6. The request context. The installation's provider builds
                //    it from the session and the request head; an error is a
                //    denial. An installation without one decides on an empty
                //    context, unless a reload has put policies that read
                //    `context` in force since it was built: then the gate
                //    refuses with a 500.
                let (req_parts, req_body) = req.into_parts();
                let context = match installation.context() {
                    ::std::option::Option::Some(cp) => {
                        match cp.context_for(&auth_session, &req_parts).await {
                            ::std::result::Result::Ok(c) => c,
                            ::std::result::Result::Err(e) => {
                                $crate::tracing::warn!(
                                    ?e,
                                    principal = %principal,
                                    resource = %resource,
                                    action = %action_uid_parsed,
                                    "context_for failed; treating as deny"
                                );
                                $crate::__macro_support::audit_early_deny(
                                    &principal,
                                    &action_uid_parsed,
                                    ::std::option::Option::Some(&resource),
                                    "context_error",
                                );
                                return $crate::__authz::AuthzDenied.into_response();
                            }
                        }
                    }
                    ::std::option::Option::None => {
                        if $crate::__macro_support::refuse_without_context_provider(
                            store, $action,
                        ) {
                            return $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR
                                .into_response();
                        }
                        $crate::__cedar::Context::empty()
                    }
                };
                let req = $crate::axum::extract::Request::from_parts(req_parts, req_body);

                // 7. Cedar evaluation. AuthzDenied is the standard 403
                //    response; a denial a step-up the policies name would
                //    cure answers `step_up_required` with that step-up.
                let decision = $crate::__authz::PolicyEvaluator::is_authorized(
                    &**store,
                    &entities,
                    principal.clone(),
                    action_uid_parsed.clone(),
                    resource.clone(),
                    context.clone(),
                );
                match decision {
                    $crate::__authz::AuthzDecision::Allow => next.run(req).await,
                    $crate::__authz::AuthzDecision::Deny => {
                        $crate::__macro_support::refusal(
                            store,
                            &entities,
                            principal,
                            action_uid_parsed,
                            resource,
                            context,
                        )
                        .into_response()
                    }
                }
              }
            },
        )
    }};

    // The session must be live in the registry, as with
    // `require_authn!(validator = ..)`. There is no form without one: a gate
    // that reads the stored session record alone trusts a session the
    // registry has ended.
    ($namespace:expr, $action:literal, $resource:literal, validator = $validator:expr) => {
        $crate::require_authz!(@gate $namespace, $action, $resource, $validator)
    };
}
