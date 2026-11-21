// The browser half of the axess FIDO2 example.
//
// The server sends each WebAuthn challenge as JSON, with every binary field
// in URL-safe base64, and expects the authenticator's answer in the same
// form. The four functions below are that translation. Everything else is
// one `fetch` per ceremony step.
'use strict';

// ── Binary fields ───────────────────────────────────────────────────────────

function decode(text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/')
    .padEnd(Math.ceil(text.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function encode(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// What `navigator.credentials.create` takes, from the server's challenge.
function creationOptions(challenge) {
  const options = challenge.publicKey;
  return {
    publicKey: {
      ...options,
      challenge: decode(options.challenge),
      user: { ...options.user, id: decode(options.user.id) },
      excludeCredentials: (options.excludeCredentials || [])
        .map((entry) => ({ ...entry, id: decode(entry.id) })),
    },
  };
}

// What `navigator.credentials.get` takes. `mediation` and `publicKey.hints`
// are the server's choice of prompt and pass through as they came:
// conditional mediation for the autofill prompt, the `hybrid` hint for a
// passkey on another device.
function requestOptions(challenge) {
  const options = challenge.publicKey;
  const request = {
    publicKey: {
      ...options,
      challenge: decode(options.challenge),
      allowCredentials: (options.allowCredentials || [])
        .map((entry) => ({ ...entry, id: decode(entry.id) })),
    },
  };
  if (challenge.mediation) request.mediation = challenge.mediation;
  return request;
}

// A new credential, as the server reads it.
function registrationJSON(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      attestationObject: encode(response.attestationObject),
      clientDataJSON: encode(response.clientDataJSON),
      transports: response.getTransports ? response.getTransports() : undefined,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

// An assertion, as the server reads it. `authenticatorAttachment` says
// whether the authenticator is this device (`platform`) or another one
// (`cross-platform`); the server uses it only to offer a local passkey.
function assertionJSON(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      authenticatorData: encode(response.authenticatorData),
      clientDataJSON: encode(response.clientDataJSON),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

// ── The server ──────────────────────────────────────────────────────────────

async function api(method, path, body) {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  return { ok: response.ok, status: response.status, data };
}

// Send `request`; when the server refuses with `step_up_required`, run the
// step-up it names and send the request once more. This is the whole client
// side of a step-up, for every route that can ask for one.
async function withStepUp(request) {
  const first = await request();
  if (first.status !== 403 || !first.data || first.data.error !== 'step_up_required') {
    return first;
  }
  log(`the server asks for the step-up "${first.data.step_up}"`);
  if (!(await stepUp(first.data.step_up))) return first;
  return request();
}

// Begin the named step-up, collect what it asks for, finish it. Until it is
// finished the session is not signed in, so a dismissed prompt leaves a
// step-up open; "Continue it" on the sign-in form prepares it again. The
// server runs these routes for a step-up only, never for a login.
async function stepUp(name) {
  const begun = await api('POST', '/api/step-up/begin', { step_up: name });
  if (!begun.ok) {
    log(`the step-up could not begin: ${begun.data ? begun.data.error : begun.status}`, true);
    return false;
  }
  let proof;
  if (begun.data.factor === 'fido2') {
    const credential = await ask(() =>
      navigator.credentials.get(requestOptions(begun.data.challenge)));
    if (!credential) return false;
    proof = { credential: assertionJSON(credential) };
  } else {
    const password = await askPassword();
    if (!password) return false;
    proof = { password };
  }
  const finished = await api('POST', '/api/step-up/finish', proof);
  log(finished.ok ? 'step-up verified' : 'step-up refused', !finished.ok);
  return finished.ok;
}

// Ask for the password in a dialog with a password field, so it is not
// shown as typed and a password manager can fill it. Null when cancelled.
function askPassword() {
  const dialog = document.getElementById('password-dialog');
  const field = document.getElementById('step-up-password');
  field.value = '';
  return new Promise((resolve) => {
    dialog.addEventListener('close', () => {
      const password = dialog.returnValue === 'confirm' ? field.value : '';
      field.value = '';
      resolve(password || null);
    }, { once: true });
    dialog.showModal();
  });
}

// Tell the server that a sign-in was abandoned: the dialog was dismissed, or
// the browser refused the request or let it time out. The server ends the
// login in progress and the challenge it handed out, so nothing stays open.
async function cancelSignIn() {
  await api('POST', '/api/login/cancel');
}

// ── Ceremonies ──────────────────────────────────────────────────────────────

// A pending autofill request, so a button can cancel it: a browser runs one
// WebAuthn request at a time.
let autofill = null;

function cancelAutofill() {
  if (autofill) autofill.abort();
  autofill = null;
}

// Run a WebAuthn call; a dismissed or failed prompt is logged and is null.
async function ask(call) {
  try {
    return await call();
  } catch (error) {
    if (error.name !== 'AbortError') log(`the browser's prompt ended: ${error.name}`, true);
    return null;
  }
}

async function register(kind) {
  const begun = await withStepUp(() => api('POST', '/api/passkeys/begin', { kind }));
  if (!begun.ok) {
    log(`registration refused: ${begun.data ? begun.data.error : begun.status}`, true);
    return refresh();
  }
  const options = begun.data.publicKey;
  log(`registering a ${kind}: user verification ${options.authenticatorSelection.userVerification}, ` +
    `attestation ${options.attestation}`);
  const credential = await ask(() => navigator.credentials.create(creationOptions(begun.data)));
  if (!credential) return;
  const name = window.prompt('A name for this credential', kind.replace(/_/g, ' ')) || kind;
  const finished = await api('POST', '/api/passkeys/finish', {
    name,
    credential: registrationJSON(credential),
  });
  log(finished.ok ? `registered "${name}"` : 'the server refused the credential', !finished.ok);
  return refresh();
}

async function signInWithPassword(username, password) {
  cancelAutofill();
  const reply = await api('POST', '/api/login/password', { username, password });
  log(reply.ok ? 'signed in with the password' : 'sign-in refused', !reply.ok);
  return refresh();
}

async function signInWithSecurityKey(username) {
  cancelAutofill();
  const begun = await api('POST', '/api/login/security-key/begin', { username });
  if (!begun.ok) {
    log('sign-in refused', true);
    return refresh();
  }
  log(`security-key sign-in: user verification ${begun.data.publicKey.userVerification}`);
  const credential = await ask(() => navigator.credentials.get(requestOptions(begun.data)));
  if (!credential) {
    await cancelSignIn();
    return refresh();
  }
  const finished = await api('POST', '/api/login/security-key/finish', {
    credential: assertionJSON(credential),
  });
  log(finished.ok ? 'signed in with the security key' : 'sign-in refused', !finished.ok);
  return refresh();
}

// `prompt` is `modal` (the browser's dialog), `cross_device` (the dialog,
// led by the QR code for a phone) or `autofill` (no dialog: the passkeys
// appear in the username field).
async function signInWithPasskey(prompt) {
  cancelAutofill();
  const quiet = prompt === 'autofill';
  // The autofill request is registered before its challenge is fetched, so
  // a button pressed meanwhile cancels it rather than racing it.
  const controller = quiet ? new AbortController() : null;
  if (controller) autofill = controller;
  const begun = await api('POST', '/api/login/passkey/begin', { prompt });
  if (controller && controller.signal.aborted) return;
  if (!begun.ok) {
    if (controller) autofill = null;
    if (!quiet) log('the passkey sign-in could not begin', true);
    return;
  }
  const request = requestOptions(begun.data);
  if (controller) {
    request.signal = controller.signal;
  } else {
    log(`passkey sign-in: prompt ${prompt}, hints ${JSON.stringify(begun.data.publicKey.hints || [])}`);
  }
  const credential = await ask(() => navigator.credentials.get(request));
  // The autofill request is over either way; the next refresh may offer it
  // again.
  if (controller && autofill === controller) autofill = null;
  if (!credential) {
    // An autofill request this page cancelled is replaced by whatever runs
    // next, whose begin retires the challenge. Any other request that ended
    // without a credential was abandoned, and the server is told.
    if (controller && controller.signal.aborted) return;
    await cancelSignIn();
    // A dismissed dialog goes back to the autofill offer; a failed autofill
    // request is not started again.
    return quiet ? undefined : refresh();
  }
  const finished = await api('POST', '/api/login/passkey/finish', assertionJSON(credential));
  log(finished.ok ? 'signed in with a passkey' : 'sign-in refused', !finished.ok);
  await refresh();
  if (finished.ok && finished.data.offer_local_passkey) {
    document.getElementById('offer').hidden = false;
  }
}

async function approve() {
  const reply = await withStepUp(() => api('POST', '/api/payments/42/approve'));
  log(reply.ok ? `payment ${reply.data.approved} approved`
    : `payment refused: ${reply.data ? reply.data.error : reply.status}`, !reply.ok);
  return refresh();
}

async function remove(id) {
  const reply = await withStepUp(() => api('DELETE', `/api/passkeys/${id}`));
  log(reply.ok ? 'credential deleted' : 'deletion refused', !reply.ok);
  return refresh();
}

// ── The page ────────────────────────────────────────────────────────────────

function log(message, refused) {
  const entry = document.createElement('li');
  entry.textContent = message;
  if (refused) entry.className = 'refused';
  document.getElementById('log').prepend(entry);
}

function row(cells) {
  const tr = document.createElement('tr');
  for (const cell of cells) {
    const td = document.createElement('td');
    if (cell instanceof Node) td.append(cell);
    else td.textContent = cell;
    tr.append(td);
  }
  return tr;
}

function when(timestamp) {
  return timestamp ? new Date(timestamp).toLocaleString() : 'never';
}

async function refresh() {
  const { data } = await api('GET', '/api/session');
  if (!data) return;
  document.getElementById('signed-in').hidden = !data.authenticated;
  document.getElementById('signed-out').hidden = data.authenticated;
  document.getElementById('pending').hidden = !data.pending;
  for (const button of document.querySelectorAll('[data-register]')) {
    button.hidden = !data.registration_kinds.includes(button.dataset.register);
  }
  if (!data.authenticated) {
    document.getElementById('offer').hidden = true;
    return startAutofill();
  }
  document.getElementById('who').textContent = data.username;
  document.getElementById('factors').replaceChildren(...data.factors.map((factor) => row([
    factor.kind,
    factor.user_verified ? 'yes' : 'no',
    factor.credential.replace(/_/g, ' '),
    `${factor.age_seconds} s`,
  ])));
  document.getElementById('credentials').replaceChildren(...data.credentials.map((credential) => {
    const button = document.createElement('button');
    button.textContent = 'Delete';
    button.addEventListener('click', () => remove(credential.id));
    return row([
      credential.name,
      credential.kind.replace(/_/g, ' '),
      when(credential.registered_at),
      when(credential.last_used_at),
      button,
    ]);
  }));
}

// Offer passkeys in the username field where the browser can. The request
// stays pending until the user picks one, or a button cancels it.
async function startAutofill() {
  if (!window.PublicKeyCredential
    || !PublicKeyCredential.isConditionalMediationAvailable
    || !(await PublicKeyCredential.isConditionalMediationAvailable())) return;
  // Checked after the await: two refreshes in flight start one request.
  if (autofill) return;
  signInWithPasskey('autofill');
}

document.getElementById('password-form').addEventListener('submit', (event) => {
  event.preventDefault();
  signInWithPassword(
    document.getElementById('username').value,
    document.getElementById('password').value,
  );
});
document.getElementById('security-key-login').addEventListener('click', () =>
  signInWithSecurityKey(document.getElementById('username').value));
document.getElementById('passkey-login').addEventListener('click', () => signInWithPasskey('modal'));
document.getElementById('cross-device-login').addEventListener('click', () =>
  signInWithPasskey('cross_device'));
document.getElementById('resume').addEventListener('click', async () => {
  cancelAutofill();
  // The name is not read for a step-up that is already open.
  await stepUp('password');
  refresh();
});
document.getElementById('logout').addEventListener('click', async () => {
  await api('POST', '/api/logout');
  log('signed out');
  refresh();
});
document.getElementById('approve').addEventListener('click', approve);
document.getElementById('offer-accept').addEventListener('click', () => {
  document.getElementById('offer').hidden = true;
  register('passkey');
});
for (const button of document.querySelectorAll('[data-register]')) {
  button.addEventListener('click', () => register(button.dataset.register));
}

if (window.PublicKeyCredential) {
  refresh();
} else {
  document.getElementById('unsupported').hidden = false;
}
