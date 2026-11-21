//! The two device-key paths, registration and refresh: what a request to
//! either is answered, and how the browser draft's and the app's headers
//! are read and written.

use super::*;
use crate::session::id::SessionKey;

// ── The two paths ────────────────────────────────────────────────────────────

/// The routes a key is registered and proven at. Merge them into the router
/// inside the session layer; the layer supplies everything they need.
pub(crate) fn routes<St>(registration_path: &str, refresh_path: &str) -> axum::Router<St>
where
    St: Clone + Send + Sync + 'static,
{
    axum::Router::new()
        .route(
            registration_path,
            axum::routing::post(|request: Request<Body>| async move {
                not_embeddable(register(request).await)
            }),
        )
        .route(
            refresh_path,
            axum::routing::post(|request: Request<Body>| async move {
                not_embeddable(refresh(request).await)
            }),
        )
}

/// Mark an answer of a key path as one no other origin may embed or read.
/// The draft recommends it for the refresh endpoint, whose timing says
/// whether a session exists.
fn not_embeddable(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// A final refusal at the refresh path: not the challenge's status, which a
/// browser answers by sending the same refresh again.
fn refused() -> Response {
    empty(StatusCode::from_u16(draft::REFRESH_REFUSED_STATUS).unwrap_or(StatusCode::BAD_REQUEST))
}

/// The proof a request carries and the front-end that sent it.
fn presented_proof(headers: &HeaderMap) -> Option<(&str, KeyProofShape)> {
    let read = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    read(draft::RESPONSE_HEADER)
        .and_then(draft::request_header_string)
        .map(|jws| (jws, KeyProofShape::Browser))
        .or_else(|| read(APP_PROOF_HEADER).map(|jws| (jws, KeyProofShape::App)))
}

fn empty(status: StatusCode) -> Response {
    let mut response = status.into_response();
    crate::session::layer::lifecycle::mark_cookie_response(response.headers_mut());
    response
}

fn identifier(tenant: &TenantId, device: &DeviceId) -> String {
    format!("{tenant}.{device}")
}

/// Add the challenge to a response in both front-ends' headers.
fn put_challenge(headers: &mut HeaderMap, challenge: &KeyChallenge, id: &str) {
    let text = challenge.to_text();
    let browser = draft::challenge_header_value(&text, id);
    if let Ok(value) = HeaderValue::from_str(&browser) {
        headers.insert(HeaderName::from_static(draft::CHALLENGE_HEADER), value);
    }
    if let Ok(value) = HeaderValue::from_str(&text) {
        headers.insert(HeaderName::from_static(APP_CHALLENGE_HEADER), value);
    }
}

impl KeyGate {
    /// The attributes the proof cookie is set with, as the registration's
    /// description states them.
    fn cookie_attributes(&self) -> String {
        let secure = if self.keys.config().secure() {
            "; Secure"
        } else {
            ""
        };
        format!("Path=/{secure}; HttpOnly; SameSite={}", self.same_site)
    }

    fn proof_cookie(
        &self,
        (tenant, device): (&TenantId, &DeviceId),
        value: String,
        max_age_secs: i64,
    ) -> Option<HeaderValue> {
        let config = self.keys.config();
        let name = key_cookie::proof_cookie_name(config.proof_cookie_name(), tenant, device);
        let mut cookie = Cookie::new(name, value);
        cookie.set_http_only(true);
        cookie.set_secure(config.secure());
        cookie.set_same_site(self.same_site);
        cookie.set_path("/");
        cookie.set_max_age(time::Duration::seconds(max_age_secs));
        HeaderValue::from_str(&cookie.to_string()).ok()
    }

    /// Put a fresh proof cookie for `proven` on a response.
    fn put_proof(&self, headers: &mut HeaderMap, proven: &ProvenKey, now: Timestamp) {
        let ttl = self.keys.config().proof_ttl();
        let expires = axess_clock::Until::after(now, ttl);
        let value = key_cookie::mint_proof(&self.cookie_keys, proven, expires);
        let max_age = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
        if let Some(cookie) = self.proof_cookie((&proven.tenant, &proven.device), value, max_age) {
            headers.append(header::SET_COOKIE, cookie);
        }
    }

    /// The answer that ends a registration: the device is revoked, gone or
    /// has no key. The client's proof cookie is expired with it.
    fn ended(&self, tenant: &TenantId, device: &DeviceId) -> Response {
        let status = StatusCode::from_u16(draft::ENDED_STATUS).unwrap_or(StatusCode::OK);
        let mut response = (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            draft::ENDED_BODY,
        )
            .into_response();
        if let Some(cookie) = self.proof_cookie((tenant, device), String::new(), 0) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
        crate::session::layer::lifecycle::mark_cookie_response(response.headers_mut());
        response
    }

    /// The answer that only hands out the challenge to sign.
    fn challenged(&self, challenge: &KeyChallenge, id: &str) -> Response {
        let status = StatusCode::from_u16(draft::CHALLENGE_STATUS).unwrap_or(StatusCode::FORBIDDEN);
        let mut response = empty(status);
        put_challenge(response.headers_mut(), challenge, id);
        response
    }

    /// The body a registration is answered with.
    fn description(
        &self,
        id: &str,
        (tenant, device): (&TenantId, &DeviceId),
        origin: &str,
    ) -> serde_json::Value {
        use draft::session as s;
        let config = self.keys.config();
        serde_json::json!({
            (s::IDENTIFIER): id,
            (s::REFRESH_URL): config.refresh_path(),
            (s::SCOPE): { (s::SCOPE_ORIGIN): origin, (s::SCOPE_INCLUDE_SITE): false },
            (s::CREDENTIALS): [{
                (s::CREDENTIAL_TYPE): s::CREDENTIAL_TYPE_COOKIE,
                (s::CREDENTIAL_NAME): key_cookie::proof_cookie_name(config.proof_cookie_name(), tenant, device),
                (s::CREDENTIAL_ATTRIBUTES): self.cookie_attributes(),
            }],
        })
    }
}

/// What a registration needs of its session.
struct Registrant {
    /// The key of the session the offer was made to.
    session: SessionKey,
    user: UserId,
    /// The administrator, for a session that is an impersonation: the
    /// browser, and so the device and its key, is theirs.
    admin: Option<UserId>,
    tenant: TenantId,
    device: DeviceId,
}

impl Registrant {
    /// Whose the device must be, or is claimed for.
    fn owner(&self) -> &UserId {
        self.admin.as_ref().unwrap_or(&self.user)
    }
}

/// The session's standing to register a key now: signed in (authenticated,
/// or in a step-up of that session), inside the registration window its
/// login opened, with a device.
async fn registrant(gate: &KeyGate, session: &AuthSession, now: Timestamp) -> Option<Registrant> {
    let inner = session.0.0.read().await;
    let signed_in = inner.data.auth_state.signed_in()?;
    if !gate.in_window(*signed_in.signed_in_at, now) {
        return None;
    }
    Some(Registrant {
        session: *inner.session.key(),
        user: *signed_in.user_id,
        admin: signed_in.impersonator.map(|by| by.admin),
        tenant: *signed_in.tenant_id,
        device: inner.device_in_force()?,
    })
}

/// `POST` on the registration path: add the key a proof carries to the
/// session's device, and bind the session to it.
async fn register(request: Request<Body>) -> Response {
    // Without the gate the layer does not enforce keys (no key service, or
    // the policy is off), and without a session there is no layer at all:
    // the path is then not one this deployment answers.
    let (Some(gate), Some(session)) = (
        request.extensions().get::<Arc<KeyGate>>().cloned(),
        request.extensions().get::<SessionHandle>().cloned(),
    ) else {
        return empty(StatusCode::NOT_FOUND);
    };
    let config = gate.keys.config();
    // A host this deployment does not serve has no registration path.
    let Some(origin) = config.origin_for(RequestHead::of(&request)) else {
        return empty(StatusCode::NOT_FOUND);
    };
    let (session, headers) = (AuthSession(session), request.headers());
    let now = gate.now();
    let (Some(who), Some((jws, shape))) = (
        registrant(&gate, &session, now).await,
        presented_proof(headers),
    ) else {
        return empty(StatusCode::FORBIDDEN);
    };
    // The offer is whatever the proof says it answers; it must be one this
    // layer made to this session for this device, and not expired.
    let offer = axess_factors::key_proof::parse_key_proof(jws, factor_shape(shape))
        .ok()
        .and_then(|parsed| parsed.challenge().map(str::to_owned));
    let Some(offer) = offer.filter(|offer| {
        key_cookie::offer_holds(
            &gate.cookie_keys,
            offer,
            &who.session,
            &who.tenant,
            &who.device,
            now,
        )
    }) else {
        return empty(StatusCode::FORBIDDEN);
    };
    let url = config.registration_url(&origin);
    let registered = gate
        .keys
        .register(Registration {
            tenant: &who.tenant,
            device: &who.device,
            owner: who.owner(),
            proof: KeyProof {
                jws,
                shape,
                method: "POST",
                url: &url,
            },
            offer: &offer,
            now,
        })
        .await;
    let registered = match registered {
        Ok(registered) => registered,
        Err(DeviceKeyError::Store(e)) => {
            tracing::warn!(error = %e, "device key registration: the device store failed");
            return empty(StatusCode::SERVICE_UNAVAILABLE);
        }
        // The row kept changing under the write: nothing is wrong with the
        // request, and it may be sent again.
        Err(DeviceKeyError::Contended) => return empty(StatusCode::SERVICE_UNAVAILABLE),
        // A proof that does not stand, a second key, another user's device,
        // a device that is revoked or gone: no registration.
        Err(_) => return empty(StatusCode::FORBIDDEN),
    };
    bind_registrant(&session, &who, registered.thumbprint, now).await;

    let id = identifier(&who.tenant, &who.device);
    let mut response =
        axum::Json(gate.description(&id, (&who.tenant, &who.device), &origin)).into_response();
    let proven = ProvenKey {
        tenant: who.tenant,
        device: who.device,
        thumbprint: registered.thumbprint,
    };
    // An app where request proofs are taken signs every request and needs
    // no proof cookie; giving it one would hand it a bearer value it never
    // asked for. It gets one at the refresh path if it calls it.
    let signs_every_request = shape == KeyProofShape::App && gate.keys.takes_request_proofs();
    if !signs_every_request {
        gate.put_proof(response.headers_mut(), &proven, now);
    }
    put_challenge(response.headers_mut(), &registered.challenge, &id);
    crate::session::layer::lifecycle::mark_cookie_response(response.headers_mut());
    response
}

/// Bind the session that registered a key to it, unless it is bound already.
/// The binding's `SessionKeyBound` row is written by the layer once the
/// response's write has stored it
/// ([`record_binding`](super::record_binding)).
async fn bind_registrant(
    session: &AuthSession,
    who: &Registrant,
    thumbprint: KeyThumbprint,
    now: Timestamp,
) {
    let mut inner = session.0.0.write().await;
    // A session that is bound stays bound to what it was bound to: the
    // registration added a key to its device and binds nothing anew.
    if inner.data.key_binding_in_force().is_some() {
        return;
    }
    inner.data.key_binding = Some(SessionKeyBinding {
        owner: *who.owner(),
        tenant_id: who.tenant,
        device_id: who.device,
        thumbprint,
        bound_at: now,
    });
    inner.modified = true;
}

fn factor_shape(shape: KeyProofShape) -> axess_factors::key_proof::KeyProofShape {
    match shape {
        KeyProofShape::Browser => axess_factors::key_proof::KeyProofShape::Browser,
        KeyProofShape::App => axess_factors::key_proof::KeyProofShape::App,
    }
}

/// The device a refresh names: `<tenant>.<device>` in the identifier header.
pub(crate) fn named_device(headers: &HeaderMap) -> Option<(TenantId, DeviceId)> {
    let value = headers.get(draft::SESSION_ID_HEADER)?.to_str().ok()?;
    let (tenant, device) = draft::request_header_string(value)?.split_once('.')?;
    Some((
        TenantId::try_new(tenant).ok()?,
        DeviceId::try_new(device).ok()?,
    ))
}

/// `POST` on the refresh path: answer a proof over the device's current
/// challenge with a fresh proof cookie, and anything else with the
/// challenge to sign. Needs no session: a signed-out client keeps its proof
/// fresh, so the request that signs its user in is already proven.
async fn refresh(request: Request<Body>) -> Response {
    let Some(gate) = request.extensions().get::<Arc<KeyGate>>().cloned() else {
        return empty(StatusCode::NOT_FOUND);
    };
    // A host this deployment does not serve has no refresh path.
    let Some(origin) = gate.keys.config().origin_for(RequestHead::of(&request)) else {
        return empty(StatusCode::NOT_FOUND);
    };
    let headers = request.headers();
    let Some((tenant, device)) = named_device(headers) else {
        return refused();
    };
    let now = gate.now();
    let id = identifier(&tenant, &device);
    let url = gate.keys.config().refresh_url(&origin);
    let outcome = match presented_proof(headers) {
        Some((jws, shape)) => {
            let proof = KeyProof {
                jws,
                shape,
                method: "POST",
                url: &url,
            };
            gate.keys.prove(&tenant, &device, proof, now).await
        }
        // No proof: hand out the challenge.
        None => match gate.keys.challenge(&tenant, &device, now).await {
            Ok((_, current)) => {
                gate.keys.metrics().key_proof_challenged();
                Err(DeviceKeyError::Stale { current })
            }
            Err(refusal) => Err(refusal),
        },
    };
    match outcome {
        Ok(proved) => {
            let mut response = empty(StatusCode::OK);
            let proven = ProvenKey {
                tenant,
                device,
                thumbprint: proved.thumbprint,
            };
            gate.put_proof(response.headers_mut(), &proven, now);
            put_challenge(response.headers_mut(), &proved.next_challenge, &id);
            response
        }
        Err(DeviceKeyError::Stale { current }) => gate.challenged(&current, &id),
        Err(DeviceKeyError::Ended | DeviceKeyError::Keyless) => gate.ended(&tenant, &device),
        Err(DeviceKeyError::Store(e)) => {
            tracing::warn!(error = %e, "device key refresh: the device store failed");
            empty(StatusCode::SERVICE_UNAVAILABLE)
        }
        Err(DeviceKeyError::Contended) => empty(StatusCode::SERVICE_UNAVAILABLE),
        // A value that is no proof, a proof for another request, a
        // signature that is not the key's: final, and said with a status a
        // browser does not read as "sign again".
        Err(_) => refused(),
    }
}

#[cfg(test)]
mod tests;
