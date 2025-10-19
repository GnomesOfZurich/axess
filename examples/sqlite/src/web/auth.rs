// use std::sync::Arc;

use askama::Template;
use axess::authn::methods::form::PasswordForm;
use axum::{
    Form, Router,
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use axum_messages::{Message, Messages};
use serde::Deserialize;

// use crate::models::authn::OurAuthSession;

pub fn router() -> Router {
    Router::new()
        .route("/login", post(self::post::login))
        .route("/login", get(self::get::login))
        .route("/logout", get(self::get::logout))
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    messages: Vec<Message>,
    next: Option<String>,
}

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub mod post {
    use super::*;

    #[axum::debug_handler]
    pub async fn login(_messages: Messages, Form(form): Form<PasswordForm>) -> impl IntoResponse {
        // Here you would typically handle the login logic, e.g., checking credentials.
        // For now, we just redirect to the next URL or to a default page.
        let redirect_url = form.next.unwrap_or_else(|| "/".to_string());
        Redirect::to(&redirect_url)
    }
}

pub mod get {
    use super::*;
    use crate::models::authn::OurAuthSession;

    #[axum::debug_handler]
    pub async fn login(
        messages: Messages,
        Query(NextUrl { next }): Query<NextUrl>,
    ) -> Html<String> {
        Html(
            LoginTemplate {
                messages: messages.into_iter().collect(),
                next,
            }
            .to_string(),
        )
    }

    #[axum::debug_handler]
    pub async fn logout(mut session: OurAuthSession) -> impl IntoResponse {
        match session.logout().await {
            Ok(_) => Redirect::to("/login").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}
