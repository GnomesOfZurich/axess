//! Authentication / authorization middleware macros for Axess.
//!
//! Generates Axum middleware (tower `Layer`s) that enforce authentication
//! state ([`require_authn!`], [`require_partial_authn!`]) or Cedar
//! authorization decisions ([`require_authz!`], behind the `authz` feature).
//! All variants support both 401/403 status responses (API endpoints) and
//! redirect responses (HTML endpoints).
//!
//! # Macro family
//!
//! | Macro | Concern | Feature |
//! |---|---|---|
//! | [`predicate_required!`] | foundation: gate by custom predicate | always on |
//! | [`require_authn!`] | gate: caller must be Authenticated | always on |
//! | [`require_partial_authn!`] | gate: caller mid-MFA (Authenticating) | always on |
//! | [`require_authz!`] | gate: Cedar policy decision (RBAC + ABAC + ReBAC) | `authz` |
//!
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use axess_core::{
    AuthSession,
    axum::{
        self,
        http::{self, Uri},
    },
    tracing,
};

// Re-export cedar_policy types used by the `require_authz!` expansion.
// Hidden from public docs; the macro expands to fully-qualified paths.
#[cfg(feature = "authz")]
#[doc(hidden)]
pub mod __cedar {
    pub use cedar_policy::{Context, Entities, EntityUid};
}

// Re-export the axess-core authz facade items needed by `require_authz!`'s
// expansion. Behind the `authz` feature so consumers without Cedar don't
// pay the dep cost.
#[cfg(feature = "authz")]
#[doc(hidden)]
pub mod __authz {
    pub use axess_core::authz::{
        AuthzDecision, AuthzDenied, PolicyEvaluator, PolicyStore, RequestEntityProvider,
    };
}

// Internal helpers used by macro expansions.
#[cfg(feature = "authz")]
#[doc(hidden)]
pub mod __macro_support;

#[cfg(feature = "authz")]
mod authz_macro;

fn update_query(uri: &Uri, new_query: String) -> Result<Uri, http::Error> {
    let query = form_urlencoded::parse(uri.query().map(|q| q.as_bytes()).unwrap_or_default());
    let updated_query = form_urlencoded::Serializer::new(new_query)
        .extend_pairs(query)
        .finish();

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(format!("{}?{}", uri.path(), updated_query).parse()?);

    Ok(Uri::from_parts(parts)?)
}

/// This is intended for internal use only and subject to change in the future
/// without warning!
#[doc(hidden)]
pub fn url_with_redirect_query(
    url: &str,
    redirect_field: &str,
    redirect_uri: Uri,
) -> Result<Uri, http::Error> {
    let uri = url.parse::<Uri>()?;

    if uri.query().is_some_and(|q| q.contains(redirect_field)) {
        return Ok(uri);
    };

    let redirect_uri_string = redirect_uri.to_string();
    let redirect_uri_encoded: String =
        form_urlencoded::byte_serialize(redirect_uri_string.as_bytes()).collect();
    let redirect_query = format!("{redirect_field}={redirect_uri_encoded}");

    update_query(&uri, redirect_query)
}

/// Predicate middleware.
///
/// Can be specified with a login URL and next redirect field or an alternative
/// which implements [`IntoResponse`](axum::response::IntoResponse).
///
/// When the predicate passes, the request processes normally. On failure,
/// either a redirect to the specified login URL is issued or the alternative is
/// used as the response.
///
/// # Variants
///
/// ```text
/// // Status code response:
/// predicate_required!(my_check, StatusCode::FORBIDDEN)
///
/// // Redirect with named args:
/// predicate_required!(my_check, url = "/login", param = "next")
/// ```
#[macro_export]
macro_rules! predicate_required {
    // Named args form
    ($predicate:expr, url = $login_url:expr, param = $redirect_field:expr) => {
        $crate::predicate_required!($predicate, login_url = $login_url, redirect_field = $redirect_field)
    };

    ($predicate:expr, $alternative:expr) => {{
        use axum::{
            middleware::{from_fn, Next},
            response::IntoResponse,
        };

        from_fn(
            |auth_session: $crate::AuthSession, req, next: Next| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    $alternative.into_response()
                }
            },
        )
    }};

    ($predicate:expr, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        use axum::{
            extract::OriginalUri,
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $crate::AuthSession,
             OriginalUri(original_uri): OriginalUri,
             req,
             next: Next| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    match $crate::url_with_redirect_query(
                        $login_url,
                        $redirect_field,
                        original_uri
                    ) {
                        Ok(login_url) => {
                            Redirect::temporary(&login_url.to_string()).into_response()
                        }

                        Err(err) => {
                            $crate::tracing::error!(err = %err, "Failed to build redirect URL");
                            $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            },
        )
    }};
}

/// Authentication-required middleware macro.
///
/// Generates Axum middleware that ensures the caller is fully authenticated
/// (i.e. `AuthState::Authenticated`) before allowing access. If not
/// authenticated, returns 401 or redirects to a login page depending on
/// parameters.
///
/// Naming follows the axess `Authn*` convention. See also
/// [`require_partial_authn!`] for mid-MFA gating and
/// [`predicate_required!`] for the underlying foundation.
///
/// Works with both `.layer()` (all routes) and `.route_layer()` (specific routes):
///
/// ```text
/// // Protect all routes in this router:
/// Router::new()
///     .route("/api/data", get(data_handler))
///     .layer(require_authn!())
///
/// // Protect only the routes defined on this router (not nested):
/// Router::new()
///     .route("/dashboard", get(dashboard_handler))
///     .route_layer(require_authn!(url = "/login"))
/// ```
///
/// # Variants
///
/// ## Return 401 Unauthorized (API endpoints)
/// ```text
/// .layer(require_authn!())
/// ```
///
/// ## Redirect to login page (named args, preferred)
/// ```text
/// .layer(require_authn!(url = "/login"))
/// .layer(require_authn!(url = "/auth/login", param = "return_to"))
/// ```
///
/// ## Redirect to login page (positional args, legacy)
/// ```text
/// .layer(require_authn!("/login"))
/// .layer(require_authn!("/auth/login", "return_to"))
/// ```
#[macro_export]
macro_rules! require_authn {
    // Named args: URL and custom redirect field
    (url = $login_url:expr, param = $redirect_field:expr) => {
        $crate::require_authn!($login_url, $redirect_field)
    };

    // Named args: URL with default "next" field
    (url = $login_url:expr) => {
        $crate::require_authn!($login_url, "next")
    };

    // Positional: login URL and custom redirect field
    ($login_url:expr, $redirect_field:expr) => {{
        use axum::{
            extract::OriginalUri,
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $crate::AuthSession,
             OriginalUri(original_uri): OriginalUri,
             req,
             next: Next| async move {
                if auth_session.is_authenticated().await {
                    next.run(req).await
                } else {
                    match $crate::url_with_redirect_query(
                        $login_url,
                        $redirect_field,
                        original_uri
                    ) {
                        Ok(login_url) => {
                            Redirect::temporary(&login_url.to_string()).into_response()
                        }
                        Err(err) => {
                            $crate::tracing::error!(err = %err, "Failed to build login redirect URL");
                            $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            },
        )
    }};

    // Redirect with default "next" field
    ($login_url:expr) => {
        $crate::require_authn!($login_url, "next")
    };

    // Status code only (no redirect)
    () => {{
        use axum::{
            middleware::{from_fn, Next},
            response::IntoResponse,
        };

        from_fn(
            |auth_session: $crate::AuthSession, req, next: Next| async move {
                if auth_session.is_authenticated().await {
                    next.run(req).await
                } else {
                    $crate::axum::http::StatusCode::UNAUTHORIZED.into_response()
                }
            },
        )
    }};
}

/// Partial authentication-required middleware macro.
///
/// Generates Axum middleware that ensures the user is in the `Authenticating`
/// state (i.e., has started but not completed a multi-factor flow) before
/// allowing access. Use this to guard MFA verification routes; it prevents
/// users from accessing the TOTP/FIDO2 input page without first having
/// entered their username/password.
///
/// Works with both `.layer()` and `.route_layer()`.
///
/// # Variants
///
/// ## Return 401 Unauthorized (API endpoints)
/// ```text
/// .route_layer(require_partial_authn!())
/// ```
///
/// ## Redirect to login page (preferred short form)
/// ```text
/// .route_layer(require_partial_authn!(url = "/login"))
/// .route_layer(require_partial_authn!(url = "/login", param = "next"))
/// ```
///
/// ## Redirect to login page (long form)
/// ```text
/// .route_layer(require_partial_authn!(login_url = "/login"))
/// .route_layer(require_partial_authn!(login_url = "/login", redirect_field = "next"))
/// ```
#[macro_export]
macro_rules! require_partial_authn {
    // Short named args (preferred)
    (url = $login_url:expr, param = $redirect_field:expr) => {
        $crate::require_partial_authn!(login_url = $login_url, redirect_field = $redirect_field)
    };

    (url = $login_url:expr) => {
        $crate::require_partial_authn!(login_url = $login_url, redirect_field = "next")
    };

    // Status code only
    () => {{
        async fn is_partial_authenticated(auth_session: $crate::AuthSession) -> bool {
            auth_session.auth_state().await.is_authenticating()
        }

        $crate::predicate_required!(
            is_partial_authenticated,
            $crate::axum::http::StatusCode::UNAUTHORIZED
        )
    }};

    // Redirect with custom field
    (login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        async fn is_partial_authenticated(auth_session: $crate::AuthSession) -> bool {
            auth_session.auth_state().await.is_authenticating()
        }

        $crate::predicate_required!(
            is_partial_authenticated,
            login_url = $login_url,
            redirect_field = $redirect_field
        )
    }};

    // Redirect with default "next" field
    (login_url = $login_url:expr) => {
        $crate::require_partial_authn!(login_url = $login_url, redirect_field = "next")
    };
}
