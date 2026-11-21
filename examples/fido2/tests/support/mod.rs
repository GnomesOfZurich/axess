//! What the tests drive the example with: an authenticator that answers a
//! ceremony as one holding the named credential would, and a browser that
//! keeps the session cookie.
//!
//! No test signs anything. Every ceremony is begun by `webauthn-rs`, so the
//! challenges are the ones a browser would receive, and the authenticator
//! stands in for the signature check alone: it accepts an answer from a
//! credential the challenge offered and reports the flags it was told to.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use axess::federation::fido2::{
    DefaultFido2Provider, Fido2Authentication, Fido2Ceremony, Fido2Key, Fido2Provider,
    Fido2Registration,
};
use axess::testing::MockClock;
use axess_example_fido2::app::{LOCAL_ORIGIN, Settings, build_router_on};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use tower::ServiceExt;
use webauthn_rs::prelude::*;

/// A credential id, as WebAuthn writes one: the URL-safe base64 of `name`.
pub fn id(name: &str) -> String {
    URL_SAFE_NO_PAD.encode(name)
}

/// What `navigator.credentials.create()` answers for a new credential `id`.
pub fn registration(id: &str) -> Value {
    json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "attestationObject": "AAAA", "clientDataJSON": "AAAA",
            "transports": ["internal"]
        },
        "clientExtensionResults": {}
    })
}

/// What `navigator.credentials.get()` answers when the passkey `id` signs:
/// an assertion that carries the user handle the authenticator stored with
/// the credential, as every discoverable credential's does.
pub fn passkey_assertion(id: &str, user_handle: &str) -> Value {
    let mut assertion = assertion(id);
    assertion["response"]["userHandle"] = json!(user_handle);
    assertion
}

/// The WebAuthn user handle a registration challenge names, which the
/// authenticator stores with the credential it creates.
pub fn user_handle(registration_challenge: &Value) -> String {
    registration_challenge["publicKey"]["user"]["id"]
        .as_str()
        .expect("a registration challenge names its user")
        .to_string()
}

/// What `navigator.credentials.get()` answers when the credential `id`, one
/// the server named, signs: a security key returns no user handle.
pub fn assertion(id: &str) -> Value {
    json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
            "signature": "AAAA", "userHandle": null
        },
        "clientExtensionResults": {}
    })
}

#[derive(Default)]
struct Behaviour {
    /// The authenticator answers without verifying the user.
    presence_only: AtomicBool,
    /// The authenticator reports its credentials as backed up.
    synced: AtomicBool,
    /// The signature counter of the last assertion.
    counter: AtomicU32,
    /// The credential ids the last named-credential challenge offered.
    offered: Mutex<Vec<String>>,
}

/// The authenticator the tests answer ceremonies with.
///
/// It begins every ceremony with the example's own provider. It finishes a
/// registration as the credential the ceremony's type registers, under the
/// id the response names, and an authentication as that id's assertion,
/// refusing an id the challenge did not offer as the real check would.
#[derive(Clone)]
pub struct Authenticator {
    relying_party: Arc<DefaultFido2Provider>,
    behaviour: Arc<Behaviour>,
}

impl Authenticator {
    pub fn new(relying_party: DefaultFido2Provider) -> Self {
        Self {
            relying_party: Arc::new(relying_party),
            behaviour: Arc::new(Behaviour::default()),
        }
    }

    /// From now on the authenticator answers without verifying the user.
    pub fn stop_verifying_the_user(&self) {
        self.behaviour.presence_only.store(true, Ordering::SeqCst);
    }

    /// From now on the authenticator reports its credentials as backed up.
    pub fn sync_its_credentials(&self) {
        self.behaviour.synced.store(true, Ordering::SeqCst);
    }

    fn stored(&self, id: &str, registration_policy: &str) -> Value {
        let coord = "A".repeat(43);
        let synced = self.behaviour.synced.load(Ordering::SeqCst);
        json!({
            "cred": {
                "cred_id": id,
                "cred": { "type_": "ES256",
                    "key": { "EC_EC2": { "curve": "SECP256R1", "x": coord, "y": coord } } },
                "counter": 0,
                "transports": ["internal"],
                "user_verified": !self.behaviour.presence_only.load(Ordering::SeqCst),
                "backup_eligible": synced,
                "backup_state": synced,
                "registration_policy": registration_policy,
                "extensions": {},
                "attestation": { "data": "None", "metadata": "None" },
                "attestation_format": "none"
            }
        })
    }

    fn asserted(&self, id: &str) -> AuthenticationResult {
        let synced = self.behaviour.synced.load(Ordering::SeqCst);
        serde_json::from_value(json!({
            "cred_id": id,
            "needs_update": true,
            "user_verified": !self.behaviour.presence_only.load(Ordering::SeqCst),
            "backup_state": synced,
            "backup_eligible": synced,
            "counter": self.behaviour.counter.fetch_add(1, Ordering::SeqCst) + 1,
            "extensions": {}
        }))
        .expect("an authentication result")
    }
}

impl Fido2Provider for Authenticator {
    fn relying_party_id(&self) -> &str {
        self.relying_party.relying_party_id()
    }

    fn start_authentication(
        &self,
        ceremony: &Fido2Ceremony,
        credentials: &[Fido2Key],
    ) -> WebauthnResult<(RequestChallengeResponse, Fido2Authentication)> {
        let (challenge, state) = self
            .relying_party
            .start_authentication(ceremony, credentials)?;
        let offered =
            serde_json::to_value(&challenge).expect("a challenge")["publicKey"]["allowCredentials"]
                .as_array()
                .expect("the credentials a named-credential challenge offers")
                .iter()
                .map(|credential| credential["id"].as_str().expect("an id").to_string())
                .collect();
        *self.behaviour.offered.lock().unwrap() = offered;
        Ok((challenge, state))
    }

    fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: &Fido2Authentication,
    ) -> WebauthnResult<AuthenticationResult> {
        let id = URL_SAFE_NO_PAD.encode(assertion.get_credential_id());
        if !self.behaviour.offered.lock().unwrap().contains(&id) {
            tracing::debug!(ceremony = %state.ceremony(), "the challenge did not offer this credential");
            return Err(WebauthnError::CredentialNotFound);
        }
        Ok(self.asserted(&id))
    }

    fn start_registration(
        &self,
        ceremony: &Fido2Ceremony,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
        exclude: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, Fido2Registration)> {
        self.relying_party
            .start_registration(ceremony, user_id, user_name, display_name, exclude)
    }

    fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &Fido2Registration,
    ) -> WebauthnResult<Fido2Key> {
        let id = URL_SAFE_NO_PAD.encode(&response.raw_id);
        let key = |policy: &str| self.stored(&id, policy);
        Ok(match state {
            Fido2Registration::Passkey(_) => {
                Fido2Key::Passkey(serde_json::from_value(key("required")).expect("a passkey"))
            }
            Fido2Registration::SecurityKey { .. } => Fido2Key::SecurityKey(
                serde_json::from_value(key("preferred")).expect("a security key"),
            ),
            Fido2Registration::AttestedPasskey { trust_anchor, .. } => Fido2Key::AttestedPasskey {
                key: serde_json::from_value(key("required")).expect("an attested passkey"),
                trust_anchor: trust_anchor.clone(),
            },
        })
    }

    fn start_discoverable_authentication(
        &self,
    ) -> WebauthnResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.relying_party.start_discoverable_authentication()
    }

    fn finish_discoverable_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> WebauthnResult<AuthenticationResult> {
        // Like the real check: with no key to verify against, nothing does.
        if keys.is_empty() {
            tracing::debug!(?state, "no stored key to verify the assertion against");
            return Err(WebauthnError::CredentialNotFound);
        }
        Ok(self.asserted(&URL_SAFE_NO_PAD.encode(assertion.get_credential_id())))
    }
}

/// One answer of the application.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub text: String,
    /// The body as JSON, `Null` when it is not JSON.
    pub json: Value,
}

/// A browser on the application: it sends the page's origin with every
/// state-changing request and keeps the cookies it is given.
pub struct Browser {
    app: Router,
    cookies: BTreeMap<String, String>,
}

impl Browser {
    pub fn new(app: Router) -> Self {
        Self {
            app,
            cookies: BTreeMap::new(),
        }
    }

    pub async fn get(&mut self, path: &str) -> Reply {
        self.send(Request::get(path).body(Body::empty()).unwrap())
            .await
    }

    pub async fn post(&mut self, path: &str, body: Value) -> Reply {
        self.send(
            Request::post(path)
                .header(header::ORIGIN, LOCAL_ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// A state-changing request with no body, from the page's origin.
    pub async fn act(&mut self, method: Method, path: &str) -> Reply {
        self.send(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::ORIGIN, LOCAL_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// Send `request` with the cookies held, and keep the ones set.
    pub async fn send(&mut self, mut request: Request<Body>) -> Reply {
        if !self.cookies.is_empty() {
            let jar = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request
                .headers_mut()
                .insert(header::COOKIE, jar.parse().unwrap());
        }
        let response = self.app.clone().oneshot(request).await.unwrap();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let pair = cookie.to_str().unwrap().split(';').next().unwrap();
            if let Some((name, value)) = pair.split_once('=') {
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            text: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }
}

/// The application on a mock clock, with the authenticator that answers its
/// ceremonies and a browser on it.
pub struct World {
    pub app: Router,
    pub clock: MockClock,
    pub authenticator: Authenticator,
    pub browser: Browser,
}

/// The application as `cargo run` serves it: on `http://localhost:3000`,
/// with no attestation root.
pub async fn world() -> World {
    world_with(Settings::new(LOCAL_ORIGIN).expect("the local origin")).await
}

pub async fn world_with(settings: Settings) -> World {
    let clock = MockClock::at_reference();
    let authenticator = Authenticator::new(settings.provider().expect("a relying party"));
    let (app, _) = build_router_on(Arc::new(clock.clone()), authenticator.clone(), &settings)
        .await
        .expect("the application builds");
    World {
        browser: Browser::new(app.clone()),
        app,
        clock,
        authenticator,
    }
}
