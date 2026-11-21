//! The identifier header, which names a device to the refresh path and to a
//! request proof and is the one value there that any caller chooses; and
//! the registration window as the registration path and the offer read it.

use super::*;
use axess_clock::testing::Shift;
use proptest::prelude::*;

fn headers(value: &str) -> Option<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(draft::SESSION_ID_HEADER),
        HeaderValue::from_str(value).ok()?,
    );
    Some(headers)
}

/// The identifier the layer hands out reads back as the tenant and the
/// device it was made for, bare as the draft's algorithm appends it and
/// quoted as the draft defines the header, with parameters ignored; nothing
/// shorter, longer or otherwise shaped names a device.
#[test]
fn the_identifier_names_one_tenant_and_one_device() {
    let tenant = crate::authn::ids::testing::tenant("t");
    let device = crate::authn::ids::testing::device("d");
    let written = identifier(&tenant, &device);
    for value in [
        written.clone(),
        format!("\"{written}\""),
        format!("\"{written}\";v=1"),
        format!(" {written}"),
    ] {
        assert_eq!(
            named_device(&headers(&value).unwrap()),
            Some((tenant, device)),
            "{value:?}"
        );
    }
    assert_eq!(named_device(&HeaderMap::new()), None);
    let tenant_only = tenant.to_string();
    let doubled = format!("{written}.{device}");
    let unclosed = format!("\"{written}");
    for value in [
        "",
        ".",
        "a.b",
        "\"\"",
        tenant_only.as_str(),
        doubled.as_str(),
        unclosed.as_str(),
        "not-an-identifier",
    ] {
        assert_eq!(named_device(&headers(value).unwrap()), None, "{value:?}");
    }
}

/// The browser's proof is read from its header quoted or bare, and the
/// app's from its own header as it stands.
#[test]
fn a_presented_proof_is_read_quoted_or_bare() {
    let with = |name: &'static str, value: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    };
    for value in ["a.b.c", "\"a.b.c\"", "\"a.b.c\";x=1"] {
        assert_eq!(
            presented_proof(&with(draft::RESPONSE_HEADER, value)),
            Some(("a.b.c", KeyProofShape::Browser)),
            "{value:?}"
        );
    }
    assert_eq!(
        presented_proof(&with(draft::RESPONSE_HEADER, "\"a.b.c")),
        None
    );
    assert_eq!(
        presented_proof(&with(APP_PROOF_HEADER, "a.b.c")),
        Some(("a.b.c", KeyProofShape::App))
    );
    assert_eq!(presented_proof(&HeaderMap::new()), None);
}

/// An answer of a key path may not be embedded or read by another origin.
#[test]
fn a_key_path_answer_is_not_embeddable() {
    let response = not_embeddable(refused());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()["cross-origin-resource-policy"],
        "same-origin"
    );
    assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
}

proptest! {
    /// Arbitrary text in the header never panics, and names no device
    /// unless it holds the dot that joins the two ids.
    #[test]
    fn arbitrary_text_without_a_dot_names_no_device(value in "[^.]{0,96}") {
        if let Some(headers) = headers(&value) {
            prop_assert_eq!(named_device(&headers), None);
        }
    }

    /// Arbitrary text never panics the reader.
    #[test]
    fn arbitrary_text_never_panics(value in "\\PC{0,96}") {
        if let Some(headers) = headers(&value) {
            let named = named_device(&headers);
            prop_assert!(named.is_none() || value.contains('.'));
        }
    }
}

// ── The registration window ──────────────────────────────────────────────

/// The default registration window, in seconds.
const WINDOW: i64 = 120;

fn at(secs: i64) -> Timestamp {
    axess_clock::testing::MockClock::reference_time()
        .plus(axess_clock::SignedDuration::seconds(secs))
}

fn user() -> UserId {
    crate::authn::ids::testing::user("u")
}

fn tenant() -> TenantId {
    crate::authn::ids::testing::tenant("t")
}

fn device() -> DeviceId {
    crate::authn::ids::testing::device("d")
}

/// A key gate on the default configuration, whose clock reads `now`.
fn gate_at(now: Timestamp) -> Arc<KeyGate> {
    gate_over(crate::device::store::MemoryDeviceStore::new(), now)
}

/// [`gate_at`] over the devices `store` holds.
fn gate_over(store: crate::device::store::MemoryDeviceStore, now: Timestamp) -> Arc<KeyGate> {
    let service = crate::device_key::DeviceKeyService::new(
        store,
        crate::device_key::DeviceKeyConfig::new("https://app.example"),
    )
    .expect("the default configuration");
    let keys: Arc<dyn ErasedDeviceKeys> = Arc::new(service);
    let ring = SigningKeyRing::from_master(&crate::testing::test_key(5));
    let ending = LayerEnding {
        audit: Arc::new(crate::session::layer::audit::UnrecordedSessionEnds),
        ttl: std::time::Duration::from_secs(3600),
        registry: None,
    };
    KeyGate::new(
        keys,
        &ring,
        Arc::new(axess_clock::testing::MockClock::at(now)),
        SameSite::Lax,
        ending,
    )
    .expect("the default policy enforces keys")
}

/// Signed in at 0 s, its last factor verified at `authn_secs`: a step-up
/// finished then.
fn authenticated(authn_secs: i64) -> AuthState {
    AuthState::Authenticated {
        user_id: user(),
        tenant_id: tenant(),
        authn_time: at(authn_secs),
        signed_in_at: at(0),
        factors_completed: Vec::new(),
        impersonator: None,
        ldap_groups: None,
        assurance: Vec::new(),
    }
}

/// Pending a factor: a step-up of a session signed in at 0 s, or a login.
fn authenticating(flow: crate::session::data::AuthFlow, admin: Option<UserId>) -> AuthState {
    AuthState::Authenticating {
        user_id: user(),
        tenant_id: tenant(),
        method_name: Arc::from("password"),
        remaining: Vec::new(),
        completed: Vec::new(),
        attempt_count: 0,
        last_attempt: None,
        ldap_groups: None,
        impersonator: admin.map(|admin| crate::session::data::Impersonation {
            admin,
            since: at(0),
        }),
        assurance: Vec::new(),
        flow,
    }
}

fn stepping_up(admin: Option<UserId>) -> AuthState {
    authenticating(
        crate::session::data::AuthFlow::StepUp {
            signed_in_at: at(0),
        },
        admin,
    )
}

/// A session in `state` on the device, proven by its token.
fn session_in(state: AuthState) -> AuthSession {
    let session = crate::testing::test_session();
    {
        let mut inner = session
            .0
            .0
            .try_write()
            .expect("a fresh session is unshared");
        inner.data.auth_state = state;
        inner.data.device_id = Some(device());
        inner.data.device_proven = true;
    }
    session
}

/// The registration window runs from the login: a step-up finished late in
/// it does not extend it.
#[tokio::test]
async fn the_registration_window_runs_from_the_login() {
    let gate = gate_at(at(0));
    let session = session_in(authenticated(WINDOW - 20));
    assert!(registrant(&gate, &session, at(WINDOW)).await.is_some());
    assert!(registrant(&gate, &session, at(WINDOW + 1)).await.is_none());
}

/// A session in a step-up registers as the signed-in session it is, inside
/// the window its login opened; a login in progress registers nothing.
#[tokio::test]
async fn a_session_in_a_step_up_registers_as_the_signed_in_one() {
    let gate = gate_at(at(0));
    let admin = crate::authn::ids::testing::user("admin");
    let session = session_in(stepping_up(Some(admin)));
    let who = registrant(&gate, &session, at(60))
        .await
        .expect("signed in, inside the window");
    assert_eq!(
        (who.user, who.admin, who.tenant, who.device),
        (user(), Some(admin), tenant(), device())
    );
    assert_eq!(who.owner(), &admin);
    assert!(registrant(&gate, &session, at(WINDOW + 1)).await.is_none());

    let login = session_in(authenticating(crate::session::data::AuthFlow::Login, None));
    assert!(registrant(&gate, &login, at(0)).await.is_none());
}

/// The offer a response carries, if any.
async fn offered(gate: &KeyGate, session: &AuthSession, due: OfferDue) -> Option<String> {
    let finalized = FinalizeOutcome {
        session: session.0.0.read().await.session,
        session_changed: true,
        rotation: None,
        released: Vec::new(),
    };
    let mut response = axum::http::Response::new(());
    offer(Some(gate), &session.0, &finalized, due, &mut response).await;
    let value = response.headers().get(draft::REGISTRATION_HEADER)?;
    // `(ES256);path="<path>";challenge="<offer>"`
    value.to_str().ok()?.split('"').nth(3).map(str::to_owned)
}

/// A registration window or an acceptance grace too long to hold never
/// ends, on every side of the setting: the session's own reading of the
/// window, the offer cookie that carries the window's end, and a proof read
/// with the grace. A window and a grace that fit still end.
#[test]
fn a_window_or_a_grace_too_long_to_hold_never_ends() {
    use axess_clock::Until;
    use std::time::Duration;

    let (start, latest) = (at(0), Timestamp::MAX);
    let keys = KeyCookieKeys {
        current: [1; 32],
        previous: None,
    };
    let rng = crate::testing::mock_random::MockRng::new(7);
    let session = SessionKey::of(&crate::session::id::SessionId::new(&rng));
    let proven = ProvenKey {
        tenant: tenant(),
        device: device(),
        thumbprint: KeyThumbprint::from_bytes([9; 32]),
    };
    let expired_proof = key_cookie::mint_proof(&keys, &proven, Until::At(start));

    for too_long in [
        Duration::MAX,
        Duration::from_secs(i64::MAX.unsigned_abs()),
        latest.since(start).unsigned_abs(),
    ] {
        // The window: the session reads it as open at the latest reading,
        // and the offer made for it holds there too.
        assert!(window_holds(start, too_long, latest), "{too_long:?}");
        let end = Until::after(start, too_long);
        assert_eq!(end, Until::Forever, "{too_long:?}");
        let offer = key_cookie::mint_offer(&keys, &session, &tenant(), &device(), end);
        assert!(
            key_cookie::offer_holds(&keys, &offer, &session, &tenant(), &device(), latest),
            "{too_long:?}"
        );
        // The grace: a proof past its expiry is accepted at the latest
        // reading.
        assert_eq!(
            key_cookie::read_proof(&keys, &expired_proof, latest, too_long),
            Some(proven),
            "{too_long:?}"
        );
    }

    // What fits ends: the window with its last second included, the offer
    // and the grace at theirs.
    let fits = Duration::from_secs(WINDOW.unsigned_abs());
    assert!(window_holds(start, fits, at(WINDOW)));
    assert!(!window_holds(start, fits, at(WINDOW + 1)));
    let offer = key_cookie::mint_offer(
        &keys,
        &session,
        &tenant(),
        &device(),
        Until::after(start, fits),
    );
    assert!(key_cookie::offer_holds(
        &keys,
        &offer,
        &session,
        &tenant(),
        &device(),
        at(WINDOW - 1)
    ));
    assert!(!key_cookie::offer_holds(
        &keys,
        &offer,
        &session,
        &tenant(),
        &device(),
        at(WINDOW)
    ));
    assert!(key_cookie::read_proof(&keys, &expired_proof, at(WINDOW - 1), fits).is_some());
    assert_eq!(
        key_cookie::read_proof(&keys, &expired_proof, at(WINDOW), fits),
        None
    );
}

/// An offer made after a step-up (the request gave the session its device)
/// expires with the window its login opened, not one the step-up would open.
#[tokio::test]
async fn the_offer_expires_with_the_logins_window() {
    let gate = gate_at(at(90));
    let session = session_in(authenticated(60));
    let due = OfferDue {
        signed_in_at_before: Some(at(0)),
        device_changed: true,
    };
    let made = offered(&gate, &session, due).await.expect("an offer");
    let key = *session.0.0.read().await.session.key();
    let holds = |secs| {
        key_cookie::offer_holds(
            &gate.cookie_keys,
            &made,
            &key,
            &tenant(),
            &device(),
            at(secs),
        )
    };
    assert!(holds(WINDOW - 1));
    assert!(!holds(WINDOW), "the offer ends with the login's window");
}

/// A step-up, begun or finished, keeps the login's time, and a response
/// that changed nothing else carries no offer.
#[tokio::test]
async fn a_step_up_carries_no_offer() {
    let gate = gate_at(at(90));
    let due = OfferDue {
        signed_in_at_before: Some(at(0)),
        device_changed: false,
    };
    let finished = session_in(authenticated(60));
    assert_eq!(offered(&gate, &finished, due).await, None);
    let open = session_in(stepping_up(None));
    assert_eq!(offered(&gate, &open, due).await, None);
    // The request that signed the session in carries one.
    let signing_in = OfferDue {
        signed_in_at_before: None,
        device_changed: false,
    };
    assert!(offered(&gate, &finished, signing_in).await.is_some());
}

// ── A bind after the handler ─────────────────────────────────────────────

/// A session signed in as the owner of a keyed device, on a request that
/// proved that device by its key, still holds a binding made for another
/// person (as a row a sign-out raced with a bind could hold): that binding
/// is not in force and does not stand in the way, so the session is bound
/// to the key of the person signed in now, for that person.
#[tokio::test]
async fn a_binding_made_for_another_person_does_not_stop_a_bind() {
    use crate::device::store::consistency;
    use crate::device::{DeviceStore, DeviceTrustLevel};

    let now = consistency::at(10);
    let store = crate::device::store::MemoryDeviceStore::new();
    let mut row = consistency::device("keyed", 1, DeviceTrustLevel::Seen, consistency::at(0));
    row.bindings = vec![crate::device::store::key_contract::key_binding(1, 1)];
    store.save(&row, consistency::at(0)).await.unwrap();
    let gate = gate_over(store, now);

    let owner = consistency::user();
    let earlier = crate::device_key::SessionKeyBinding {
        owner: crate::authn::ids::testing::user("someone-else"),
        tenant_id: tenant(),
        device_id: device(),
        thumbprint: KeyThumbprint::from_bytes([3; 32]),
        bound_at: consistency::at(0),
    };
    let proven = ProvenKey {
        tenant: consistency::tenant(),
        device: consistency::dev_id("keyed"),
        thumbprint: KeyThumbprint::from_bytes([0x11; 32]),
    };
    let session = crate::testing::test_session();
    {
        let mut inner = session.0.0.write().await;
        inner.data.auth_state = AuthState::Authenticated {
            user_id: owner,
            tenant_id: consistency::tenant(),
            authn_time: now,
            signed_in_at: now,
            factors_completed: Vec::new(),
            impersonator: None,
            ldap_groups: None,
            assurance: Vec::new(),
        };
        inner.data.device_id = Some(proven.device);
        inner.data.device_proven = true;
        inner.data.device_key = Some(proven);
        inner.data.key_binding = Some(earlier);
    }

    super::super::bind_after_handler(&gate, &session.0).await;

    let inner = session.0.0.read().await;
    let bound = inner.data.key_binding.expect("the session is bound");
    assert_eq!(
        (
            bound.owner,
            bound.tenant_id,
            bound.device_id,
            bound.thumbprint
        ),
        (owner, proven.tenant, proven.device, proven.thumbprint),
        "the binding is the key of the person signed in now, made for them"
    );
    assert!(inner.modified);
}
