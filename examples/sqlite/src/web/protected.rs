use askama::Template;
use axess::login_required;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};

use crate::models::authn::Session;

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
    messages: &'a [&'a str],
}

pub fn router() -> Router {
    Router::new()
        .route("/main", get(get::protected))
        .route_layer(login_required!(Session, "/login"))
}

mod get {
    use super::*;
    use tracing::error;

    pub async fn protected(session: Session) -> impl IntoResponse {
        match session.user() {
            Ok(user) => {
                match (ProtectedTemplate {
                    username: &user.username,
                    messages: &[],
                }
                .render())
                {
                    Ok(body) => Html(body).into_response(),
                    Err(e) => {
                        error!(error = %e, "failed to render protected template");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            }
            Err(_err) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
