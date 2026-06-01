//! RFC 8414 / OIDC Discovery document for [`LocalIdp`], plus axum
//! handler functions that serve it. The document is the minimal subset
//! that lets a downstream verifier locate the JWKS and confirm issuer
//! identity; extra fields go through [`LocalIdp::with_metadata_field`].
//!
//! # Auto-populated fields
//!
//! - `issuer`: the issuer string passed to [`LocalIdp::from_key_store`].
//! - `jwks_uri`: `{base_url}/jwks.json`. `base_url` defaults to the
//!   issuer and is overridden by [`LocalIdp::with_base_url`].
//! - `id_token_signing_alg_values_supported`: mirrors
//!   [`LocalIdp::verifier_algorithms`] so verifiers know which
//!   algorithms to expect mid-rotation.
//!
//! Most adopters mount both endpoints via [`LocalIdp::router`]. The
//! standalone [`handlers`](crate::local_idp::discovery::handlers) surface custom paths.
//!
//! [`LocalIdp`]: crate::local_idp::LocalIdp
//! [`LocalIdp::from_key_store`]: crate::local_idp::LocalIdp::from_key_store
//! [`LocalIdp::with_base_url`]: crate::local_idp::LocalIdp::with_base_url
//! [`LocalIdp::with_metadata_field`]: crate::local_idp::LocalIdp::with_metadata_field
//! [`LocalIdp::verifier_algorithms`]: crate::local_idp::LocalIdp::verifier_algorithms
//! [`LocalIdp::router`]: crate::local_idp::LocalIdp::router

use serde_json::{Map, Value};

/// Issuer metadata document for [`crate::local_idp::LocalIdp`].
///
/// Produced by [`crate::local_idp::LocalIdp::metadata`]; serialised
/// to JSON via [`to_json`](Self::to_json) (typed `serde_json::Value`)
/// or [`to_json_string`](Self::to_json_string) (string). The JSON
/// shape matches OIDC Discovery 1.0 §3 / RFC 8414 §2: a flat object
/// of named fields where adopter extras land alongside the
/// auto-populated ones.
#[derive(Debug, Clone)]
pub struct LocalIdpMetadata {
    /// The `issuer` claim. Verifiers MUST compare this against the
    /// issuer URL they fetched the document from (RFC 8414 §3.3).
    pub issuer: String,
    /// Absolute URL of the JWKS endpoint. Verifiers fetch this to
    /// obtain the public keys used to verify token signatures.
    pub jwks_uri: String,
    /// JWA algorithm names (`RS256`, `ES256`, …) the IdP currently
    /// signs tokens with: the union of the current signing key and
    /// every historical key still present in the JWKS.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Adopter-supplied extension fields, in insertion order. Appear
    /// in the JSON output after the auto-populated fields.
    pub extra: Vec<(String, Value)>,
}

impl LocalIdpMetadata {
    /// Serialise to a `serde_json::Value`. Auto-populated fields
    /// come first in insertion order, followed by adopter extras.
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("issuer".to_string(), Value::String(self.issuer.clone()));
        obj.insert("jwks_uri".to_string(), Value::String(self.jwks_uri.clone()));
        obj.insert(
            "id_token_signing_alg_values_supported".to_string(),
            Value::Array(
                self.id_token_signing_alg_values_supported
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        for (k, v) in &self.extra {
            obj.insert(k.clone(), v.clone());
        }
        Value::Object(obj)
    }

    /// Serialise to a JSON string (compact form). Equivalent to
    /// `serde_json::to_string(&self.to_json()).unwrap()`.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(&self.to_json())
            .expect("LocalIdpMetadata JSON serialisation always succeeds")
    }
}

/// Axum handler functions for the two discovery endpoints. Adopters
/// who want custom paths or different middleware stacks wire these
/// directly:
///
/// ```rust,ignore
/// use axum::{Router, routing::get};
/// use axess::local_idp::discovery::handlers::{openid_configuration, jwks};
///
/// let app: Router = Router::new()
///     .route("/idp/discover", get(openid_configuration::<MyKeyStore>))
///     .route("/idp/keys", get(jwks::<MyKeyStore>))
///     .with_state(local_idp.clone());
/// ```
pub mod handlers {
    use crate::local_idp::{LocalIdp, LocalIdpKeyStore};
    use axum::extract::State;
    use axum::response::Json;
    use jsonwebtoken::jwk::JwkSet;

    /// Handler for `GET /.well-known/openid-configuration`: returns
    /// the discovery document as `application/json`.
    pub async fn openid_configuration<K: LocalIdpKeyStore + 'static>(
        State(idp): State<LocalIdp<K>>,
    ) -> Json<serde_json::Value> {
        Json(idp.metadata().await.to_json())
    }

    /// Handler for `GET /jwks.json`: returns the current JWKS as
    /// `application/json`. Reflects rotations performed via
    /// [`crate::local_idp::LocalIdp::rotate_signing_key`] (the
    /// handler reads through the live state, not a snapshot taken at
    /// router-build time).
    pub async fn jwks<K: LocalIdpKeyStore + 'static>(
        State(idp): State<LocalIdp<K>>,
    ) -> Json<JwkSet> {
        Json(idp.jwks().await)
    }
}
