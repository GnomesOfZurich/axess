//! The example driven as its page drives it: every route, with the
//! ceremonies begun by `webauthn-rs` and answered by an authenticator that
//! stands in for the signature check (see `support`).

mod support;

use axess_example_fido2::app::{DEMO_PASSWORD, DEMO_USER, LOCAL_ORIGIN, Settings};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use support::{
    Browser, World, assertion, id, passkey_assertion, registration, user_handle, world, world_with,
};

const APPROVE: &str = "/api/payments/42/approve";

async fn sign_in(browser: &mut Browser) {
    let reply = browser
        .post(
            "/api/login/password",
            json!({ "username": DEMO_USER, "password": DEMO_PASSWORD }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.json, json!({ "authenticated": true }));
}

async fn sign_out(browser: &mut Browser) {
    let reply = browser.act(Method::POST, "/api/logout").await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.text);
}

/// Register a credential of `kind` under `name`; the challenge the browser
/// was sent.
async fn register(browser: &mut Browser, kind: &str, name: &str) -> Value {
    let begun = browser
        .post("/api/passkeys/begin", json!({ "kind": kind }))
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let finished = browser
        .post(
            "/api/passkeys/finish",
            json!({ "name": name, "credential": registration(&id(name)) }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::CREATED, "{}", finished.text);
    begun.json
}

/// Sign in with the passkey `name` and no username, prompted as `prompt`;
/// the challenge and the answer to the finish.
async fn passkey_sign_in(browser: &mut Browser, prompt: &str, credential: Value) -> (Value, Value) {
    let begun = browser
        .post("/api/login/passkey/begin", json!({ "prompt": prompt }))
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let finished = browser.post("/api/login/passkey/finish", credential).await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.text);
    (begun.json, finished.json)
}

/// Run the step-up `name` with the passkey `credential`.
async fn step_up_with_passkey(browser: &mut Browser, name: &str, credential: &str) -> Value {
    let begun = browser
        .post("/api/step-up/begin", json!({ "step_up": name }))
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    assert_eq!(begun.json["factor"], "fido2");
    let finished = browser
        .post(
            "/api/step-up/finish",
            json!({ "credential": assertion(&id(credential)) }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.text);
    begun.json["challenge"].clone()
}

async fn session(browser: &mut Browser) -> Value {
    let reply = browser.get("/api/session").await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    reply.json
}

fn step_up_required(name: &str) -> Value {
    json!({ "error": "step_up_required", "step_up": name })
}

// ── The page ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_page_and_its_files_are_served_under_a_same_origin_policy() {
    let World { mut browser, .. } = world().await;
    for (path, kind, fragment) in [
        ("/", "text/html", "axess FIDO2 example"),
        ("/app.js", "text/javascript", "navigator.credentials.create"),
        ("/style.css", "text/css", "color-scheme"),
    ] {
        let reply = browser.get(path).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        let sent = |name| reply.headers[name].to_str().unwrap().to_string();
        assert!(sent(header::CONTENT_TYPE).starts_with(kind), "{path}");
        assert_eq!(
            sent(header::CONTENT_SECURITY_POLICY),
            "default-src 'self'; frame-ancestors 'none'"
        );
        assert!(reply.text.contains(fragment), "{path}");
    }
}

#[tokio::test]
async fn a_request_from_another_origin_changes_nothing() {
    let World { mut browser, .. } = world().await;
    let login = json!({ "username": DEMO_USER, "password": DEMO_PASSWORD }).to_string();
    // A sign-in sent with this `Origin` and this `Sec-Fetch-Site`, either
    // of which a browser may leave out.
    let from = |origin: Option<&str>, fetch_site: Option<&str>| {
        let mut request =
            Request::post("/api/login/password").header(header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(fetch_site) = fetch_site {
            request = request.header("sec-fetch-site", fetch_site);
        }
        request.body(Body::from(login.clone())).unwrap()
    };
    for (origin, fetch_site) in [
        (Some("https://attacker.example"), None),
        (None, None),
        // Without an `Origin`, only `same-origin` is the page.
        (None, Some("cross-site")),
        (None, Some("same-site")),
        (None, Some("none")),
        // An `Origin` that is not the page's is refused whatever else says.
        (Some("https://attacker.example"), Some("same-origin")),
    ] {
        let reply = browser.send(from(origin, fetch_site)).await;
        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "{origin:?} {fetch_site:?}"
        );
        assert_eq!(reply.json, json!({ "error": "cross_origin_request" }));
    }
    assert_eq!(session(&mut browser).await["authenticated"], false);

    for (origin, fetch_site) in [
        (None, Some("same-origin")),
        (Some(LOCAL_ORIGIN), None),
        (Some(LOCAL_ORIGIN), Some("cross-site")),
    ] {
        let reply = browser.send(from(origin, fetch_site)).await;
        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{origin:?} {fetch_site:?}: {}",
            reply.text
        );
        sign_out(&mut browser).await;
    }
}

// ── Passwords ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_password_signs_in_and_signing_out_ends_the_session() {
    let World { mut browser, .. } = world().await;
    assert_eq!(
        session(&mut browser).await,
        json!({
            "authenticated": false,
            "pending": false,
            "registration_kinds": ["passkey", "security_key"],
        })
    );

    sign_in(&mut browser).await;
    let signed_in = session(&mut browser).await;
    assert_eq!(signed_in["username"], DEMO_USER);
    assert_eq!(signed_in["factors"][0]["kind"], "password");
    assert_eq!(signed_in["factors"][0]["credential"], "not_applicable");
    assert_eq!(signed_in["credentials"], json!([]));

    sign_out(&mut browser).await;
    assert_eq!(session(&mut browser).await["authenticated"], false);
}

/// The cookies a reply sets, each with its value blanked: whether a cookie
/// is set and with which attributes, and nothing that differs by chance.
fn cookie_shapes(reply: &support::Reply) -> Vec<String> {
    reply
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|cookie| {
            let cookie = cookie.to_str().unwrap();
            let (pair, attributes) = cookie.split_once(';').unwrap_or((cookie, ""));
            let name = pair.split('=').next().unwrap_or_default();
            format!("{name}=<value>;{attributes}")
        })
        .collect()
}

/// A wrong password for a real account and any password for an unknown one
/// get the same answer, set the same cookies, and leave the same session
/// behind, so neither the reply nor what the session says afterwards tells
/// which usernames exist.
#[tokio::test]
async fn a_wrong_password_and_an_unknown_user_get_one_answer() {
    let World { app, .. } = world().await;
    let mut seen = Vec::new();
    for (username, password) in [(DEMO_USER, "not the password"), ("mallory", DEMO_PASSWORD)] {
        // Each attempt from a browser of its own, as two strangers would.
        let mut browser = Browser::new(app.clone());
        let reply = browser
            .post(
                "/api/login/password",
                json!({ "username": username, "password": password }),
            )
            .await;
        let after = session(&mut browser).await;
        seen.push((
            reply.status,
            reply.json.clone(),
            cookie_shapes(&reply),
            after,
        ));
    }
    assert_eq!(seen[0].0, StatusCode::UNAUTHORIZED);
    assert_eq!(seen[0].1, json!({ "error": "invalid_credentials" }));
    assert_eq!(seen[0].3["authenticated"], false);
    assert_eq!(
        seen[0].3["pending"], false,
        "the refused login is not left open"
    );
    assert_eq!(seen[0], seen[1], "{DEMO_USER} against an unknown username");
}

/// The routes that finish a sign-in or a step-up count requests per client
/// address as the routes that begin one do, so guesses cannot move to them.
#[tokio::test]
async fn the_finish_routes_are_rate_limited() {
    let World { mut browser, .. } = world().await;
    for path in [
        "/api/login/passkey/finish",
        "/api/login/security-key/finish",
        "/api/step-up/finish",
    ] {
        let body = match path {
            "/api/login/passkey/finish" => assertion(&id("stranger")),
            "/api/step-up/finish" => json!({ "password": "guess" }),
            _ => json!({ "credential": assertion(&id("stranger")) }),
        };
        for attempt in 1..=10 {
            let reply = browser.post(path, body.clone()).await;
            assert_ne!(
                reply.status,
                StatusCode::TOO_MANY_REQUESTS,
                "{path}: attempt {attempt} is within the limit"
            );
        }
        let limited = browser.post(path, body).await;
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS, "{path}");
    }
}

// ── Registration ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_passkey_is_registered_with_verification_required_and_no_attestation() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;

    let challenge = register(&mut browser, "passkey", "laptop").await;
    let options = &challenge["publicKey"];
    assert_eq!(options["rp"]["id"], "localhost");
    assert_eq!(options["user"]["name"], DEMO_USER);
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    // A passkey signs in with no username only if the authenticator stores
    // it, so the application registers passkeys as discoverable credentials.
    assert_eq!(options["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(options["attestation"], "none");

    let listed = session(&mut browser).await["credentials"].clone();
    assert_eq!(listed[0]["id"], id("laptop"));
    assert_eq!(listed[0]["name"], "laptop");
    assert_eq!(listed[0]["kind"], "passkey");
    assert_eq!(listed[0]["last_used_at"], Value::Null);
}

#[tokio::test]
async fn a_second_registration_excludes_the_credentials_already_held() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;

    let challenge = register(&mut browser, "security_key", "token").await;
    let options = &challenge["publicKey"];
    assert_eq!(options["excludeCredentials"][0]["id"], id("laptop"));
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    // A security key is named by the server at sign-in and stores nothing.
    assert_eq!(
        options["authenticatorSelection"]["residentKey"],
        "discouraged"
    );
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["hints"], json!(["security-key"]));

    let kinds: Vec<_> = session(&mut browser).await["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|credential| credential["kind"].clone())
        .collect();
    assert_eq!(kinds, [json!("passkey"), json!("security_key")]);
}

#[tokio::test]
async fn a_credential_id_already_registered_is_refused() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;

    let begun = browser
        .post("/api/passkeys/begin", json!({ "kind": "passkey" }))
        .await;
    assert_eq!(begun.status, StatusCode::OK);
    let again = browser
        .post(
            "/api/passkeys/finish",
            json!({ "name": "again", "credential": registration(&id("laptop")) }),
        )
        .await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    assert_eq!(again.json, json!({ "error": "registration_refused" }));
    assert_eq!(
        session(&mut browser).await["credentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_registration_needs_a_signed_in_user_and_a_name() {
    let World { mut browser, .. } = world().await;
    let anonymous = browser
        .post("/api/passkeys/begin", json!({ "kind": "passkey" }))
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    sign_in(&mut browser).await;
    browser
        .post("/api/passkeys/begin", json!({ "kind": "passkey" }))
        .await;
    for name in ["", "   ", &"n".repeat(65)] {
        let reply = browser
            .post(
                "/api/passkeys/finish",
                json!({ "name": name, "credential": registration(&id("laptop")) }),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name:?}");
        assert_eq!(reply.json, json!({ "error": "invalid_name" }));
    }
}

/// A root that attests authenticators, as the PEM file
/// `FIDO2_ATTESTATION_ROOT` names.
fn attestation_root() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut root = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root.distinguished_name
        .push(rcgen::DnType::CommonName, "attestation root");
    root.self_signed(&key).unwrap().pem()
}

#[tokio::test]
async fn an_attested_registration_asks_for_direct_attestation() {
    let settings = Settings::new(LOCAL_ORIGIN)
        .unwrap()
        .with_trust_anchor_pem(attestation_root().as_bytes())
        .unwrap();
    let World { mut browser, .. } = world_with(settings).await;
    sign_in(&mut browser).await;
    assert_eq!(
        session(&mut browser).await["registration_kinds"],
        json!(["passkey", "security_key", "attested_passkey"])
    );

    let challenge = register(&mut browser, "attested_passkey", "token").await;
    let options = &challenge["publicKey"];
    assert_eq!(options["attestation"], "direct");
    assert_eq!(
        options["authenticatorSelection"]["userVerification"],
        "required"
    );
    // An authenticator that syncs its keys cannot be attested, so the
    // browser is not asked to offer one on another device.
    assert_eq!(options["hints"], json!(["client-device", "security-key"]));
    assert_eq!(
        session(&mut browser).await["credentials"][0]["kind"],
        "attested_passkey"
    );
}

#[tokio::test]
async fn an_attested_registration_is_not_offered_without_a_root() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    let reply = browser
        .post("/api/passkeys/begin", json!({ "kind": "attested_passkey" }))
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.json, json!({ "error": "attestation_not_configured" }));
}

#[tokio::test]
async fn a_registration_five_minutes_after_signing_in_asks_for_the_password_again() {
    let World {
        mut browser, clock, ..
    } = world().await;
    sign_in(&mut browser).await;
    clock.advance_secs(301);

    let stale = browser
        .post("/api/passkeys/begin", json!({ "kind": "passkey" }))
        .await;
    assert_eq!(stale.status, StatusCode::FORBIDDEN);
    assert_eq!(stale.json, step_up_required("password"));

    let begun = browser
        .post("/api/step-up/begin", json!({ "step_up": "password" }))
        .await;
    assert_eq!(begun.json, json!({ "factor": "password" }));
    let finished = browser
        .post("/api/step-up/finish", json!({ "password": DEMO_PASSWORD }))
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.text);

    register(&mut browser, "passkey", "laptop").await;
}

#[tokio::test]
async fn a_deleted_passkey_no_longer_signs_in() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    let handle = user_handle(&register(&mut browser, "passkey", "laptop").await);

    let unknown = browser
        .act(Method::DELETE, &format!("/api/passkeys/{}", id("other")))
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let deleted = browser
        .act(Method::DELETE, &format!("/api/passkeys/{}", id("laptop")))
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.text);
    assert_eq!(session(&mut browser).await["credentials"], json!([]));

    sign_out(&mut browser).await;
    browser
        .post("/api/login/passkey/begin", json!({ "prompt": "modal" }))
        .await;
    let refused = browser
        .post(
            "/api/login/passkey/finish",
            passkey_assertion(&id("laptop"), &handle),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.json, json!({ "error": "invalid_credentials" }));
}

// ── Signing in with a security key ──────────────────────────────────────────

#[tokio::test]
async fn a_security_key_signs_in_by_username_with_verification_preferred() {
    let World {
        mut browser, clock, ..
    } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;
    register(&mut browser, "security_key", "token").await;
    sign_out(&mut browser).await;

    let begun = browser
        .post(
            "/api/login/security-key/begin",
            json!({ "username": DEMO_USER }),
        )
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let options = &begun.json["publicKey"];
    assert_eq!(options["userVerification"], "preferred");
    // The login ceremony offers the security key and not the passkey.
    let offered: Vec<_> = options["allowCredentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|credential| credential["id"].clone())
        .collect();
    assert_eq!(offered, [json!(id("token"))]);

    // The route takes an assertion and nothing else: the step's password
    // is no way in here.
    let password = browser
        .post(
            "/api/login/security-key/finish",
            json!({ "password": DEMO_PASSWORD }),
        )
        .await;
    assert!(password.status.is_client_error(), "{}", password.status);
    assert_eq!(session(&mut browser).await["authenticated"], false);

    // The passkey was not offered, so its assertion does not finish the
    // step, and the refused login is not left open.
    let other = browser
        .post(
            "/api/login/security-key/finish",
            json!({ "credential": assertion(&id("laptop")) }),
        )
        .await;
    assert_eq!(other.status, StatusCode::UNAUTHORIZED);
    // A failed attempt slows the next one down; wait the longest delay out.
    clock.advance_secs(65);
    // The login the refusal ended does not take the key that was offered.
    let after = browser
        .post(
            "/api/login/security-key/finish",
            json!({ "credential": assertion(&id("token")) }),
        )
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);

    let begun = browser
        .post(
            "/api/login/security-key/begin",
            json!({ "username": DEMO_USER }),
        )
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let finished = browser
        .post(
            "/api/login/security-key/finish",
            json!({ "credential": assertion(&id("token")) }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.text);
    let signed_in = session(&mut browser).await;
    assert_eq!(signed_in["factors"][0]["kind"], "fido2");
    assert_eq!(signed_in["factors"][0]["credential"], "device_bound");
}

#[tokio::test]
async fn a_user_with_no_security_key_is_answered_as_a_failed_sign_in() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;
    sign_out(&mut browser).await;

    for username in [DEMO_USER, "mallory"] {
        let reply = browser
            .post(
                "/api/login/security-key/begin",
                json!({ "username": username }),
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{username}");
        assert_eq!(reply.json, json!({ "error": "invalid_credentials" }));
        // The login is not left open.
        assert_eq!(session(&mut browser).await["pending"], false, "{username}");
    }
}

// ── Signing in with a passkey ───────────────────────────────────────────────

#[tokio::test]
async fn a_passkey_signs_in_with_no_username_and_approves_a_payment_at_once() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    let handle = user_handle(&register(&mut browser, "passkey", "laptop").await);
    sign_out(&mut browser).await;

    let mut local = passkey_assertion(&id("laptop"), &handle);
    local["authenticatorAttachment"] = json!("platform");
    let (challenge, answer) = passkey_sign_in(&mut browser, "modal", local).await;
    assert!(challenge.get("mediation").is_none(), "{challenge}");
    let request = &challenge["publicKey"];
    assert_eq!(request["userVerification"], "required");
    assert_eq!(request["allowCredentials"], json!([]));
    assert!(request.get("hints").is_none(), "{challenge}");
    assert_eq!(
        answer,
        json!({
            "authenticated": true,
            "attachment": "platform",
            "offer_local_passkey": false,
        })
    );

    let signed_in = session(&mut browser).await;
    assert_eq!(signed_in["factors"][0]["kind"], "fido2");
    assert_eq!(signed_in["factors"][0]["user_verified"], true);
    assert!(signed_in["credentials"][0]["last_used_at"].is_string());

    // A passkey that verified the user seconds ago is what the policy asks.
    let approved = browser.act(Method::POST, APPROVE).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    assert_eq!(approved.json, json!({ "approved": "42" }));
}

#[tokio::test]
async fn the_autofill_prompt_is_the_default_and_asks_for_conditional_mediation() {
    let World { mut browser, .. } = world().await;
    for body in [json!({}), json!({ "prompt": "autofill" })] {
        let begun = browser.post("/api/login/passkey/begin", body).await;
        assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
        assert_eq!(begun.json["mediation"], "conditional");
    }
    let unknown = browser
        .post("/api/login/passkey/begin", json!({ "prompt": "hybrid" }))
        .await;
    assert!(unknown.status.is_client_error(), "{}", unknown.status);
}

/// Cross-device authentication, as the relying party sees it: the request
/// hints at the hybrid transport, the phone's assertion is finished like
/// any other, and the browser's report that the authenticator is another
/// device prompts an offer to create a passkey on this one.
#[tokio::test]
async fn a_passkey_on_another_device_signs_in_and_a_local_passkey_is_offered() {
    let World {
        app, mut browser, ..
    } = world().await;
    sign_in(&mut browser).await;
    let handle = user_handle(&register(&mut browser, "passkey", "phone").await);

    // A second browser, on a machine that holds no passkey.
    let mut laptop = Browser::new(app);
    let mut from_the_phone = passkey_assertion(&id("phone"), &handle);
    from_the_phone["authenticatorAttachment"] = json!("cross-platform");
    let (challenge, answer) = passkey_sign_in(&mut laptop, "cross_device", from_the_phone).await;

    assert!(challenge.get("mediation").is_none(), "{challenge}");
    let request = &challenge["publicKey"];
    assert_eq!(request["hints"], json!(["hybrid"]));
    assert_eq!(request["userVerification"], "required");
    assert_eq!(request["allowCredentials"], json!([]));
    assert_eq!(
        answer,
        json!({
            "authenticated": true,
            "attachment": "cross-platform",
            "offer_local_passkey": true,
        })
    );

    // The offer is an ordinary registration on the fresh session.
    register(&mut laptop, "passkey", "laptop").await;
    let names: Vec<_> = session(&mut laptop).await["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|credential| credential["name"].clone())
        .collect();
    assert_eq!(names, [json!("phone"), json!("laptop")]);
}

/// A challenge is answered once. A credential nobody registered is refused
/// and takes the challenge with it: the passkey that would have signed in
/// is refused on the same challenge and signs in on a new one.
#[tokio::test]
async fn a_passkey_nobody_registered_is_refused_and_uses_the_challenge_up() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    let handle = user_handle(&register(&mut browser, "passkey", "laptop").await);
    sign_out(&mut browser).await;
    let laptop = passkey_assertion(&id("laptop"), &handle);

    browser
        .post("/api/login/passkey/begin", json!({ "prompt": "modal" }))
        .await;
    let unknown = browser
        .post(
            "/api/login/passkey/finish",
            passkey_assertion(&id("stranger"), &handle),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.json, json!({ "error": "invalid_credentials" }));
    let second_answer = browser
        .post("/api/login/passkey/finish", laptop.clone())
        .await;
    assert_eq!(second_answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(session(&mut browser).await["authenticated"], false);

    // The same for a body that is no assertion at all.
    browser
        .post("/api/login/passkey/begin", json!({ "prompt": "modal" }))
        .await;
    let malformed = browser
        .post("/api/login/passkey/finish", json!({ "id": "x" }))
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    let second_answer = browser
        .post("/api/login/passkey/finish", laptop.clone())
        .await;
    assert_eq!(second_answer.status, StatusCode::UNAUTHORIZED);

    let (_, answer) = passkey_sign_in(&mut browser, "modal", laptop).await;
    assert_eq!(answer["authenticated"], true);
}

/// The assertion names its user: a passkey's assertion that carries no user
/// handle, or another account's, does not sign in.
#[tokio::test]
async fn a_passkey_assertion_must_carry_its_users_handle() {
    let World {
        mut browser, clock, ..
    } = world().await;
    sign_in(&mut browser).await;
    let handle = user_handle(&register(&mut browser, "passkey", "laptop").await);
    sign_out(&mut browser).await;

    for wrong in [
        assertion(&id("laptop")),
        passkey_assertion(&id("laptop"), &id("someone else")),
    ] {
        browser
            .post("/api/login/passkey/begin", json!({ "prompt": "modal" }))
            .await;
        let refused = browser.post("/api/login/passkey/finish", wrong).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        assert_eq!(session(&mut browser).await["authenticated"], false);
        // The refusal counted as a failed attempt; wait its delay out.
        clock.advance_secs(65);
    }
    let (_, answer) = passkey_sign_in(
        &mut browser,
        "modal",
        passkey_assertion(&id("laptop"), &handle),
    )
    .await;
    assert_eq!(answer["authenticated"], true);
}

/// A sign-in the page abandons (a dismissed dialog, a refused or timed-out
/// browser call) is reported to the server, which ends it: the login in
/// progress and the challenge are gone, and the answer the browser might
/// still produce for them finishes nothing.
#[tokio::test]
async fn an_abandoned_sign_in_is_ended_by_the_cancel_route() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "security_key", "token").await;
    let handle = user_handle(&register(&mut browser, "passkey", "laptop").await);
    sign_out(&mut browser).await;

    // A security-key sign-in, abandoned.
    let begun = browser
        .post(
            "/api/login/security-key/begin",
            json!({ "username": DEMO_USER }),
        )
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let cancelled = browser.act(Method::POST, "/api/login/cancel").await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    let late = browser
        .post(
            "/api/login/security-key/finish",
            json!({ "credential": assertion(&id("token")) }),
        )
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
    assert_eq!(session(&mut browser).await["authenticated"], false);

    // A passwordless sign-in, abandoned.
    let laptop = passkey_assertion(&id("laptop"), &handle);
    browser
        .post("/api/login/passkey/begin", json!({ "prompt": "modal" }))
        .await;
    let cancelled = browser.act(Method::POST, "/api/login/cancel").await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    let late = browser
        .post("/api/login/passkey/finish", laptop.clone())
        .await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
    assert_eq!(session(&mut browser).await["authenticated"], false);

    // Nothing was counted against the account: a new sign-in goes through.
    let (_, answer) = passkey_sign_in(&mut browser, "modal", laptop).await;
    assert_eq!(answer["authenticated"], true);
}

/// The cancel route ends a sign-in and nothing else: a signed-in session
/// stays signed in, and an open step-up stays open and can be finished.
#[tokio::test]
async fn the_cancel_route_leaves_a_signed_in_session_and_a_step_up_alone() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;

    let cancelled = browser.act(Method::POST, "/api/login/cancel").await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    assert_eq!(session(&mut browser).await["authenticated"], true);

    let begun = browser
        .post("/api/step-up/begin", json!({ "step_up": "passkey" }))
        .await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let cancelled = browser.act(Method::POST, "/api/login/cancel").await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    assert_eq!(session(&mut browser).await["pending"], true);
    let finished = browser
        .post(
            "/api/step-up/finish",
            json!({ "credential": assertion(&id("laptop")) }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{}", finished.text);
    assert_eq!(session(&mut browser).await["authenticated"], true);
}

// ── The step-up ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_payment_after_a_password_sign_in_is_approved_once_the_named_step_up_is_done() {
    let World { mut browser, .. } = world().await;
    let anonymous = browser.act(Method::POST, APPROVE).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;

    let refused = browser.act(Method::POST, APPROVE).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json, step_up_required("passkey"));

    let challenge = step_up_with_passkey(&mut browser, "passkey", "laptop").await;
    let request = &challenge["publicKey"];
    assert_eq!(request["userVerification"], "required");
    assert_eq!(request["allowCredentials"][0]["id"], id("laptop"));

    let approved = browser.act(Method::POST, APPROVE).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    assert_eq!(approved.json, json!({ "approved": "42" }));

    // The session keeps the password's proof and gains the passkey's.
    let kinds: Vec<_> = session(&mut browser).await["factors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|factor| factor["kind"].clone())
        .collect();
    assert_eq!(kinds, [json!("password"), json!("fido2")]);
}

#[tokio::test]
async fn a_step_up_older_than_five_minutes_is_asked_for_again() {
    let World {
        mut browser, clock, ..
    } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;
    step_up_with_passkey(&mut browser, "passkey", "laptop").await;

    clock.advance_secs(300);
    assert_eq!(
        browser.act(Method::POST, APPROVE).await.status,
        StatusCode::OK
    );
    clock.advance_secs(1);
    let stale = browser.act(Method::POST, APPROVE).await;
    assert_eq!(stale.status, StatusCode::FORBIDDEN);
    assert_eq!(stale.json, step_up_required("passkey"));
}

#[tokio::test]
async fn a_synced_passkey_satisfies_the_policy_and_the_session_says_it_is_synced() {
    let World {
        mut browser,
        authenticator,
        ..
    } = world().await;
    authenticator.sync_its_credentials();
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "phone").await;
    step_up_with_passkey(&mut browser, "passkey", "phone").await;

    assert_eq!(
        session(&mut browser).await["factors"][1]["credential"],
        "synced"
    );
    assert_eq!(
        browser.act(Method::POST, APPROVE).await.status,
        StatusCode::OK
    );
}

/// The gate decides again on what the step-up recorded. An assertion that
/// did not verify the user leaves the policy unsatisfied, and the answer
/// names the step-up once more.
#[tokio::test]
async fn an_assertion_that_did_not_verify_the_user_does_not_approve_a_payment() {
    let World {
        mut browser,
        authenticator,
        ..
    } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;
    authenticator.stop_verifying_the_user();
    step_up_with_passkey(&mut browser, "passkey", "laptop").await;

    assert_eq!(
        session(&mut browser).await["factors"][1]["user_verified"],
        false
    );
    let refused = browser.act(Method::POST, APPROVE).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json, step_up_required("passkey"));
}

/// A step-up moves the session out of `Authenticated` until its factor is
/// verified, so one that no credential can answer is refused before it
/// begins.
#[tokio::test]
async fn a_step_up_no_credential_can_answer_leaves_the_session_signed_in() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    // A security key is not a credential the passkey ceremony accepts.
    register(&mut browser, "security_key", "token").await;

    let refused = browser.act(Method::POST, APPROVE).await;
    assert_eq!(refused.json, step_up_required("passkey"));
    let begun = browser
        .post("/api/step-up/begin", json!({ "step_up": "passkey" }))
        .await;
    assert_eq!(begun.status, StatusCode::CONFLICT);
    assert_eq!(begun.json, json!({ "error": "no_credential_for_step_up" }));
    assert_eq!(session(&mut browser).await["authenticated"], true);

    let unknown = browser
        .post("/api/step-up/begin", json!({ "step_up": "retina" }))
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.json, json!({ "error": "unknown_step_up" }));
}

/// The step-up routes act on a step-up only. A security-key login in
/// progress is also a session waiting for a factor, and its step would take
/// the password: sent to the step-up routes, it is ended and refused, so the
/// password form stays the one route that takes a password for a login.
#[tokio::test]
async fn a_login_in_progress_is_ended_by_the_step_up_routes_and_takes_no_password_there() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "security_key", "token").await;
    sign_out(&mut browser).await;
    let begin_login = json!({ "username": DEMO_USER });

    for (route, body) in [
        ("/api/step-up/finish", json!({ "password": DEMO_PASSWORD })),
        ("/api/step-up/begin", json!({ "step_up": "password" })),
    ] {
        let begun = browser
            .post("/api/login/security-key/begin", begin_login.clone())
            .await;
        assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);

        let refused = browser.post(route, body).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{route}");
        assert_eq!(refused.json, json!({ "error": "not_authenticated" }));
        let after = session(&mut browser).await;
        assert_eq!(after["authenticated"], false, "{route}");
        assert_eq!(after["pending"], false, "{route}");

        // The login it ended does not take the key that was offered.
        let finished = browser
            .post(
                "/api/login/security-key/finish",
                json!({ "credential": assertion(&id("token")) }),
            )
            .await;
        assert_eq!(finished.status, StatusCode::UNAUTHORIZED, "{route}");
    }

    // With nothing open there is no step-up to finish.
    let nothing = browser
        .post("/api/step-up/finish", json!({ "password": DEMO_PASSWORD }))
        .await;
    assert_eq!(nothing.status, StatusCode::CONFLICT);
    assert_eq!(nothing.json, json!({ "error": "no_step_up_open" }));
}

#[tokio::test]
async fn a_dismissed_step_up_is_prepared_again_and_then_finishes() {
    let World { mut browser, .. } = world().await;
    sign_in(&mut browser).await;
    register(&mut browser, "passkey", "laptop").await;

    let first = browser
        .post("/api/step-up/begin", json!({ "step_up": "passkey" }))
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    // The step is open: the session is not signed in until it is finished.
    let open = session(&mut browser).await;
    assert_eq!(open["authenticated"], false);
    assert_eq!(open["pending"], true);
    assert_eq!(
        browser.act(Method::POST, APPROVE).await.status,
        StatusCode::UNAUTHORIZED
    );

    let challenge = step_up_with_passkey(&mut browser, "passkey", "laptop").await;
    assert_ne!(
        challenge["publicKey"]["challenge"],
        first.json["challenge"]["publicKey"]["challenge"]
    );
    assert_eq!(session(&mut browser).await["authenticated"], true);
    assert_eq!(
        browser.act(Method::POST, APPROVE).await.status,
        StatusCode::OK
    );
}
