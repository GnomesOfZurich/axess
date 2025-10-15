//! Authentication/authorization middleware macros for Axess.
//!
//! This module provides macros for generating Axum middleware to enforce authentication and partial authentication requirements.
//! The macros are intended for use in Axum route definitions and support both status code and redirect-based responses.
//!
#![forbid(unsafe_code)]

pub use axess_core::{
    authn::session::auth_session::AuthSession,
    axum::{
        self,
        http::{self, Uri},
    },
    tracing,
};

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
    let redirect_uri_encoded = urlencoding::encode(&redirect_uri_string);
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
#[macro_export]
macro_rules! predicate_required {
    ($predicate:expr, $alternative:expr) => {{
        use axum::{
            middleware::{from_fn, Next},
            response::IntoResponse,
        };

        from_fn(
            |auth_session: $crate::AuthSession<_>, req, next: Next| async move {
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
            |auth_session: $crate::AuthSession<_>,
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

/// Login-required middleware macro.
///
/// This macro generates Axum middleware that ensures the user is authenticated before allowing access to a route.
/// If the user is not authenticated, it either returns an HTTP 401 Unauthorized response or redirects to a login page,
/// depending on the macro parameters.
///
/// # Usage
///
/// ## Return 401 Unauthorized (API endpoints)
/// ```ignore
/// use axess_macros::login_required;
/// use axum::{routing::get, Router};
///
/// let app = Router::new()
///     .route("/api/protected", get(api_handler))
///     .layer(login_required!(Backend));
/// ```
///
/// ## Redirect to login page (web pages)
/// ```ignore
/// use axess_macros::login_required;
/// use axum::{routing::get, Router};
///
/// let app = Router::new()
///     .route("/dashboard", get(dashboard_handler))
///     .layer(login_required!(Backend, "/login"));
/// ```
///
/// ## Redirect with custom query parameter
/// ```ignore
/// use axess_macros::login_required;
/// use axum::{routing::get, Router};
///
/// let app = Router::new()
///     .route("/admin", get(admin_handler))
///     .layer(login_required!(Backend, "/auth/login", "return_to"));
/// ```
///
/// # Parameters
///
/// - `$auth_session_type`: The full `AuthSession` type (e.g., `AuthSession<Backend, Store>`).
/// - `$login_url`: (Optional) The URL to redirect unauthenticated users to.
/// - `$redirect_field`: (Optional) The query parameter name for the original URI (default: `"next"`).
///
/// # Notes
///
/// When a redirect URL is provided, the middleware will append the original request URI as a query parameter,
/// allowing the login page to redirect back after successful authentication.
#[macro_export]
macro_rules! login_required {
    // Full form: auth session type, login URL, and custom redirect field
    ($auth_session_type:ty, $login_url:expr, $redirect_field:expr) => {{
        use axum::{
            extract::OriginalUri,
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $auth_session_type,
             OriginalUri(original_uri): OriginalUri,
             req,
             next: Next| async move {
                if auth_session.is_authenticated() {
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
    ($auth_session_type:ty, $login_url:expr) => {
        $crate::login_required!($auth_session_type, $login_url, "next")
    };

    // Status code only (no redirect)
    ($auth_session_type:ty) => {{
        use axum::{
            middleware::{from_fn, Next},
            response::IntoResponse,
        };

        from_fn(
            |auth_session: $auth_session_type, req, next: Next| async move {
                if auth_session.is_authenticated() {
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
/// This macro generates Axum middleware that ensures the user is partially authenticated before allowing access to a route.
/// "Partial authentication" typically means the user has completed some, but not all, authentication steps (e.g., username/password but not MFA).
///
/// # Usage
///
/// ## Return 401 Unauthorized (API endpoints)
/// ```ignore
/// use axess_macros::require_partial_authn;
/// use axum::{routing::get, Router};
///
/// let app = Router::new()
///     .route("/mfa/verify", get(mfa_handler))
///     .layer(require_partial_authn!(Backend));
/// ```
///
/// ## Redirect to login page (web pages)
/// ```ignore
/// use axess_macros::require_partial_authn;
/// use axum::{routing::get, Router};
///
/// let app = Router::new()
///     .route("/mfa", get(mfa_page))
///     .layer(require_partial_authn!(Backend, login_url = "/login"));
/// ```
///
/// ## Redirect with custom query parameter
/// ```ignore
/// use axess_macros::require_partial_authn;
/// use axum::{routing::get, Router};
///
/// let app = Router::new()
///     .route("/auth/step2", get(step2_handler))
///     .layer(require_partial_authn!(Backend, login_url = "/login", redirect_field = "continue"));
/// ```
///
/// # Parameters
///
/// - `$auth_session_type`: The full `AuthSession` type (e.g., `AuthSession<Backend, Store>`).
/// - `login_url`: (Optional) The URL to redirect unauthenticated users to.
/// - `redirect_field`: (Optional) The query parameter name for the original URI (default: `"next"`).
///
/// # Notes
///
/// This macro is intended for use with Axum extractors and middleware.
/// Use this macro for routes that require the user to have started, but not necessarily completed, the authentication process (e.g., MFA verification pages).
#[macro_export]
macro_rules! require_partial_authn {
    // Status code only
    ($auth_session_type:ty) => {{
        async fn is_partial_authenticated(auth_session: $auth_session_type) -> bool {
            auth_session.is_partial_authenticated()
        }

        $crate::predicate_required!(
            is_partial_authenticated,
            $crate::axum::http::StatusCode::UNAUTHORIZED
        )
    }};

    // Redirect with custom field
    ($auth_session_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        async fn is_partial_authenticated(auth_session: $auth_session_type) -> bool {
            auth_session.is_partial_authenticated()
        }

        $crate::predicate_required!(
            is_partial_authenticated,
            login_url = $login_url,
            redirect_field = $redirect_field
        )
    }};

    // Redirect with default "next" field
    ($auth_session_type:ty, login_url = $login_url:expr) => {
        $crate::require_partial_authn!(
            $auth_session_type,
            login_url = $login_url,
            redirect_field = "next"
        )
    };
}
