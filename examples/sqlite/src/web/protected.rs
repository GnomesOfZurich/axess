use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};

use crate::models::authn::OurAuthSession;

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
    messages: &'a [&'a str],
}

pub fn router() -> Router<()> {
    Router::new().route("/", get(self::get::protected))
}

mod get {
    use super::*;

    pub async fn protected(auth_session: OurAuthSession) -> impl IntoResponse {
        match auth_session.user() {
            Ok(user) => Html(
                ProtectedTemplate {
                    username: &user.username,
                    messages: &[], // Provide an empty array or actual messages as needed
                }
                .render()
                .unwrap(),
            )
            .into_response(),
            Err(_err) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
