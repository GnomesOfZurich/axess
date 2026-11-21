//! The route a request matched, as a log field: the template the adopter
//! registered (`/invites/{id}`), never the path the client sent.
//!
//! A concrete path can carry a credential (an invitation token, a reset
//! code, a share link), and a log line outlives the request and reaches
//! readers the request never did. axum records the template in the
//! request's extensions when a router matched it. Middleware added with
//! `Router::layer` or `Router::route_layer` sees that record; a layer
//! wrapped around the whole router, or a route reached through
//! `nest_service`, does not, and there the field reads [`UNMATCHED`].

use axum::extract::MatchedPath;
use axum::http::Extensions;

/// What the field reads when no router matched the request.
pub(crate) const UNMATCHED: &str = "-";

/// The route template `extensions` record, for a log field, or
/// [`UNMATCHED`].
pub(crate) fn logged_route(extensions: &Extensions) -> &str {
    extensions
        .get::<MatchedPath>()
        .map_or(UNMATCHED, MatchedPath::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    /// A router records the template, and the field reads it, not the path.
    #[tokio::test]
    async fn a_matched_request_reads_its_template() {
        let app = axum::Router::new().route(
            "/invites/{token}",
            get(|req: Request<Body>| async move { logged_route(req.extensions()).to_owned() }),
        );
        let response = app
            .oneshot(
                Request::get("/invites/marker-0f3a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], b"/invites/{token}");
    }

    /// A request no router matched reads the placeholder.
    #[test]
    fn an_unmatched_request_reads_the_placeholder() {
        let req = Request::get("/invites/marker-0f3a")
            .body(Body::empty())
            .unwrap();
        assert_eq!(logged_route(req.extensions()), UNMATCHED);
    }
}
