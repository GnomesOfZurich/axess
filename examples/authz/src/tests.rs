//! The handlers, called as the router calls them, against the example's own
//! policies and data. The policies read `context` (deleting needs MFA), so
//! every handler begins its authorization session with the request context;
//! these tests hold each route to an answer, where a session begun without
//! a context would be an error on all of them.

use crate::app_state;
use crate::handlers::{self, AppError, RequestFacts};
use axess::authorization::AuthzError;
use axum::extract::{Path, Query, State};

fn facts(mfa: Option<bool>) -> Query<RequestFacts> {
    Query(RequestFacts { mfa })
}

fn doc(user: &str, doc: &str) -> Path<(String, String)> {
    Path((user.to_string(), doc.to_string()))
}

#[test]
fn the_policies_read_context_so_a_session_without_one_is_refused() {
    let state = app_state().expect("the example's policies load");
    assert!(matches!(
        state.authz.for_user_id("bob"),
        Err(AuthzError::ContextRequired)
    ));
}

#[tokio::test]
async fn a_viewer_views_and_cannot_edit() {
    let state = app_state().expect("the example's policies load");

    let viewed =
        handlers::view_document(State(state.clone()), doc("bob", "doc-1"), facts(None)).await;
    assert!(viewed.is_ok(), "bob is a viewer");

    let edited = handlers::edit_document(State(state), doc("bob", "doc-1"), facts(None)).await;
    assert!(matches!(edited, Err(AppError::Denied)));
}

#[tokio::test]
async fn an_owner_edits_her_document() {
    let state = app_state().expect("the example's policies load");
    let edited = handlers::edit_document(State(state), doc("carol", "doc-1"), facts(None)).await;
    assert!(edited.is_ok(), "carol owns doc-1");
}

#[tokio::test]
async fn an_admin_deletes_only_with_mfa() {
    let state = app_state().expect("the example's policies load");

    for unverified in [None, Some(false)] {
        let refused = handlers::delete_document(
            State(state.clone()),
            doc("alice", "doc-1"),
            facts(unverified),
        )
        .await;
        assert!(matches!(refused, Err(AppError::Denied)), "{unverified:?}");
    }

    let deleted =
        handlers::delete_document(State(state), doc("alice", "doc-1"), facts(Some(true))).await;
    assert!(deleted.is_ok());
}

#[tokio::test]
async fn the_permissions_of_a_document_follow_the_request_context() {
    let state = app_state().expect("the example's policies load");

    let without_mfa =
        handlers::document_permissions(State(state.clone()), doc("alice", "doc-1"), facts(None))
            .await;
    let Ok(without_mfa) = without_mfa else {
        panic!("the permissions route answers");
    };
    assert!(without_mfa.0.can_view && without_mfa.0.can_edit);
    assert!(!without_mfa.0.can_delete, "deleting needs MFA");

    let with_mfa =
        handlers::document_permissions(State(state), doc("alice", "doc-1"), facts(Some(true)))
            .await;
    let Ok(with_mfa) = with_mfa else {
        panic!("the permissions route answers");
    };
    assert!(with_mfa.0.can_delete);
}

#[tokio::test]
async fn the_capabilities_of_a_user_list_every_document() {
    let state = app_state().expect("the example's policies load");
    let documents = state.data.documents.len();

    let listed =
        handlers::user_capabilities(State(state), Path("bob".to_string()), facts(None)).await;
    let Ok(listed) = listed else {
        panic!("the capabilities route answers");
    };
    assert_eq!(listed.0.len(), documents);
    for entry in &listed.0 {
        let allowed = |action: &str| {
            entry
                .permissions
                .iter()
                .any(|p| p.action == action && p.allowed)
        };
        assert!(allowed("ViewDocument"), "bob views {}", entry.document_id);
        // A viewer edits nothing but the document he owns.
        assert_eq!(
            allowed("EditDocument"),
            entry.document_id == "doc-3",
            "bob edits doc-3, which he owns, and no other: {}",
            entry.document_id
        );
    }
}
