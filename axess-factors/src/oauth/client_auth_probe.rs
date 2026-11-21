//! Whether a token endpoint authenticates a client: one token request made
//! as the client, for a grant it does not hold, read for what the refusal
//! says about the client's authentication.
//!
//! RFC 6749 section 5.2 separates the two refusals a token endpoint gives
//! such a request. `invalid_client` means the client's authentication
//! failed, sent with HTTP 400 or 401. `unauthorized_client`,
//! `unsupported_grant_type`, `invalid_grant` and `invalid_scope` are
//! refusals of the grant, sent with HTTP 400, which the endpoint can only
//! give a client it has authenticated; one under any other status (a
//! gateway's error page, a misrouted endpoint) is not read as one. So a
//! caller holding a client id and
//! a credential learns, without obtaining any token, whether the identity
//! provider accepts that credential for that client: the proof that whoever
//! holds the credential holds the client.
//!
//! The request is an `authorization_code` grant with a code drawn from the
//! RNG, which the endpoint never issued. It goes through a
//! [`ScreenedClient`], so it follows no redirect and, under a screened
//! policy, reaches no reserved address.
//!
//! A refusal of the grant proves the client only if the endpoint checked
//! the credential first, and not every endpoint does: one may skip client
//! authentication for a client it holds as public, check the code before
//! the client, or refuse a client id it does not know as
//! `unauthorized_client`. So the client's own request comes between two
//! controls, the same request for a credential known to be wrong (the secret
//! with one character changed, so its length, character classes and prefix
//! still match, or the assertion with the lowest bit of its signature
//! flipped), and a refusal of the grant counts only when both controls are
//! refused as `invalid_client`: the one before shows the endpoint checks the
//! credential, the one after that it still did once the client's own request
//! was answered (no lockout, rate limit or outage in between).
//!
//! The probe detects an endpoint that ignores the secret's value, not one
//! that validates a structured secret's format (a checksum, a canonical
//! base64 suffix) and then skips the value check. One changed character
//! cannot keep an arbitrary checksum valid, so such an endpoint refuses the
//! control as malformed, while a guess its holder formed correctly passes
//! the format and gets the grant's refusal: the guess reads as proven. For
//! an identity provider that issues structured secrets and may check only
//! their format, accept an operator's attestation alone for the tenants
//! that use it.

use crate::client_assertion::{CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAssertionSigner};
use crate::egress::ScreenedClient;
use crate::http_body::ErrorBody;
use crate::secret::ZeroizedString;
use axess_clock::Clock;
use axess_rng::SecureRng;

#[cfg(test)]
mod tests;

/// The most bytes of an endpoint's `error` code a probe's answer carries.
const ERROR_CODE_BYTES: usize = 128;

/// The OAuth errors that refuse the grant and so say the client was
/// authenticated (RFC 6749 section 5.2).
pub const AUTHENTICATED_ERRORS: [&str; 4] = [
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_grant",
    "invalid_scope",
];

/// The OAuth error that says the client's authentication failed.
pub const NOT_AUTHENTICATED_ERROR: &str = "invalid_client";

/// How the probe authenticates as the client at the token endpoint.
#[derive(Clone, Copy)]
pub enum ProbeClientAuth<'a> {
    /// `client_secret_basic`: the client id and secret in an
    /// `Authorization: Basic` header (RFC 6749 section 2.3.1).
    SecretBasic {
        /// The client id.
        client_id: &'a str,
        /// The client secret.
        client_secret: &'a str,
    },
    /// `client_secret_post`: the client id and secret as form fields.
    SecretPost {
        /// The client id.
        client_id: &'a str,
        /// The client secret.
        client_secret: &'a str,
    },
    /// `private_key_jwt` (RFC 7523): an assertion the signer makes for the
    /// token endpoint, or for the audience the signer fixes.
    PrivateKeyJwt(&'a ClientAssertionSigner),
}

/// What a token endpoint's answer to the probe says about the client's
/// authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthProbe {
    /// The endpoint refused the grant with one of
    /// [`AUTHENTICATED_ERRORS`], which it gives only a client it has
    /// authenticated: the credential is the client's.
    Authenticated {
        /// The OAuth error the endpoint answered with.
        error: String,
    },
    /// The endpoint answered [`NOT_AUTHENTICATED_ERROR`]: the client's
    /// authentication failed.
    NotAuthenticated,
    /// The answer says neither: another OAuth error, no OAuth error, a token,
    /// a redirect, or no answer at all. Nothing is proven either way.
    Unproven {
        /// What the answer was, naming the error code or the status, never
        /// the endpoint's URL.
        reason: String,
    },
}

impl ClientAuthProbe {
    /// The verdict an OAuth `error` code sent with HTTP `status` gives: a
    /// refusal of the grant only under 400, `invalid_client` only under 400
    /// or 401, as RFC 6749 section 5.2 sends them. Anything else is
    /// [`Unproven`](Self::Unproven), naming the code and the status.
    #[must_use]
    pub fn of_answer(status: u16, error: &str) -> Self {
        match (status, error) {
            (400 | 401, NOT_AUTHENTICATED_ERROR) => Self::NotAuthenticated,
            (400, _) if AUTHENTICATED_ERRORS.contains(&error) => Self::Authenticated {
                error: error.to_string(),
            },
            _ => Self::Unproven {
                reason: format!(
                    "the token endpoint answered `{}` with HTTP {status}, which says nothing of \
                     the client's authentication",
                    crate::http_body::log_safe(error, ERROR_CODE_BYTES)
                ),
            },
        }
    }

    fn unproven(reason: impl Into<String>) -> Self {
        Self::Unproven {
            reason: reason.into(),
        }
    }
}

/// Ask `token_endpoint`, as the client `auth` names, to redeem an
/// authorization code it never issued, and read the answer as
/// [`ClientAuthProbe`].
///
/// The token endpoint URL is checked against the client's policy first; a
/// refused URL, an assertion that cannot be signed, a transport failure, a
/// redirect, a success and an answer with no OAuth error are each
/// [`ClientAuthProbe::Unproven`], with the reason. Up to three requests are
/// made, in this order: a control with a credential known to be wrong, the
/// client's own, and the control again. The answer is
/// [`ClientAuthProbe::Authenticated`] only when both controls are refused as
/// `invalid_client` and the client's own request as a grant; a first control
/// refused otherwise ends the probe as unproven before the client's
/// credential is sent, and a client's request refused as `invalid_client`
/// ends it as [`ClientAuthProbe::NotAuthenticated`]. `redirect_uri` is sent
/// as an authorization-code request carries it. `clock` and `rng` sign a
/// `private_key_jwt` assertion; `rng` also draws the codes.
pub async fn probe_client_authentication(
    client: &ScreenedClient,
    token_endpoint: &str,
    auth: ProbeClientAuth<'_>,
    redirect_uri: &str,
    clock: &dyn Clock,
    rng: &dyn SecureRng,
) -> ClientAuthProbe {
    if let Err(refusal) = client.policy().check_url(token_endpoint, "token_endpoint") {
        return ClientAuthProbe::unproven(refusal.to_string());
    }
    let request = ProbeRequest {
        client,
        token_endpoint,
        redirect_uri,
        clock,
        rng,
    };
    if let Some(unproven) = control_unproven(
        request.ask(auth, Presented::WrongCredential).await,
        "before",
    ) {
        return unproven;
    }
    let answer = request.ask(auth, Presented::Credential).await;
    let ClientAuthProbe::Authenticated { .. } = &answer else {
        return answer;
    };
    match control_unproven(request.ask(auth, Presented::WrongCredential).await, "after") {
        Some(unproven) => unproven,
        None => answer,
    }
}

/// `None` when a control was refused as `invalid_client`, as a credential
/// known to be wrong must be; otherwise why the probe proves nothing.
/// `when` says whether it came before or after the client's own request.
fn control_unproven(control: ClientAuthProbe, when: &str) -> Option<ClientAuthProbe> {
    match control {
        ClientAuthProbe::NotAuthenticated => None,
        ClientAuthProbe::Authenticated { error } => Some(ClientAuthProbe::unproven(format!(
            "the token endpoint refused the grant as `{error}` for a credential known to be \
             wrong, sent {when} the client's own: the provider does not authenticate this \
             client; an operator must attest it"
        ))),
        ClientAuthProbe::Unproven { reason } => Some(ClientAuthProbe::unproven(format!(
            "a credential known to be wrong, sent {when} the client's own, was not refused as \
             invalid_client: {reason}"
        ))),
    }
}

/// Which credential a probe request presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presented {
    /// The client's own.
    Credential,
    /// One known to be wrong: the control.
    WrongCredential,
}

/// What every request of one probe shares.
struct ProbeRequest<'a> {
    client: &'a ScreenedClient,
    token_endpoint: &'a str,
    redirect_uri: &'a str,
    clock: &'a dyn Clock,
    rng: &'a dyn SecureRng,
}

impl ProbeRequest<'_> {
    /// One token request for a code the endpoint never issued, presenting
    /// the credential `presented` names, and its verdict.
    async fn ask(&self, auth: ProbeClientAuth<'_>, presented: Presented) -> ClientAuthProbe {
        let mut code = [0u8; 32];
        self.rng.fill_bytes(&mut code);
        let code = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(code)
        };
        // The form carries the secret or the assertion, so every value is
        // zeroized with it.
        let mut form: Vec<(&str, ZeroizedString)> = vec![
            ("grant_type", "authorization_code".into()),
            ("code", ZeroizedString::new(code)),
            ("redirect_uri", self.redirect_uri.into()),
        ];
        let mut request = self.client.inner().post(self.token_endpoint);
        match auth {
            ProbeClientAuth::SecretBasic {
                client_id,
                client_secret,
            } => {
                let secret = self.secret(client_secret, presented);
                let header = match crate::http_basic::authorization(client_id, &secret) {
                    Ok(header) => header,
                    Err(e) => {
                        return ClientAuthProbe::unproven(format!(
                            "the authorization header could not be built: {e}"
                        ));
                    }
                };
                request = request.header(reqwest::header::AUTHORIZATION, header);
            }
            ProbeClientAuth::SecretPost {
                client_id,
                client_secret,
            } => {
                form.push(("client_id", client_id.into()));
                form.push(("client_secret", self.secret(client_secret, presented)));
            }
            ProbeClientAuth::PrivateKeyJwt(signer) => {
                let assertion = match signer.mint(self.token_endpoint, self.clock, self.rng) {
                    Ok(assertion) => assertion,
                    Err(e) => {
                        return ClientAuthProbe::unproven(format!(
                            "the client assertion could not be signed: {e}"
                        ));
                    }
                };
                let assertion = match presented {
                    Presented::Credential => Some(assertion),
                    Presented::WrongCredential => with_signature_altered(&assertion),
                };
                let Some(assertion) = assertion else {
                    return ClientAuthProbe::unproven("the client assertion is not a JWS");
                };
                form.push((
                    "client_assertion_type",
                    CLIENT_ASSERTION_TYPE_JWT_BEARER.into(),
                ));
                form.push(("client_assertion", ZeroizedString::new(assertion)));
                form.push(("client_id", signer.client_id().into()));
            }
        }
        // `without_url`: reqwest's message names the URL it was sent to.
        let mut response = match request.form(&form).send().await {
            Ok(response) => response,
            Err(e) => {
                return ClientAuthProbe::unproven(format!(
                    "the token endpoint did not answer: {}",
                    e.without_url()
                ));
            }
        };
        read_answer(&mut response).await
    }

    /// The secret to present: the client's, or the control
    /// [`wrong_secret`] derives from it.
    fn secret(&self, client_secret: &str, presented: Presented) -> ZeroizedString {
        match presented {
            Presented::Credential => client_secret.into(),
            Presented::WrongCredential => wrong_secret(client_secret),
        }
    }
}

/// The ASCII punctuation, in pairs: a character's partner is the one beside
/// it, so a punctuation character becomes another punctuation character.
const PUNCTUATION: &[u8; 32] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// `secret` with one character changed, so it is not `secret` but has the
/// same length in bytes and characters, the same character classes and the
/// same prefix: a provider that refuses a malformed secret as
/// `invalid_client` and answers a well-formed one with a grant refusal sees
/// the control as well-formed too. The character changed is the last ASCII
/// letter or digit, or the last character when there is none; a letter or
/// digit becomes its neighbour in its own class (`a` and `b`, `0` and `1`,
/// `y` and `z`), so a hex secret stays hex, a punctuation character another
/// punctuation character, and any other character the one whose code point
/// differs in the lowest bit, which UTF-8 encodes in as many bytes.
pub(super) fn wrong_secret(secret: &str) -> ZeroizedString {
    let mut chars: Vec<char> = secret.chars().collect();
    let at = chars
        .iter()
        .rposition(char::is_ascii_alphanumeric)
        .or_else(|| chars.len().checked_sub(1));
    match at {
        Some(at) => chars[at] = partner(chars[at]),
        None => chars.push('A'),
    }
    ZeroizedString::new(chars.into_iter().collect::<String>())
}

/// Another character of `c`'s class and UTF-8 length.
fn partner(c: char) -> char {
    let swap_in = |first: u8| char::from(first + ((c as u8 - first) ^ 1));
    match c {
        '0'..='9' => swap_in(b'0'),
        'a'..='z' => swap_in(b'a'),
        'A'..='Z' => swap_in(b'A'),
        c if c.is_ascii_punctuation() => PUNCTUATION
            .iter()
            .position(|p| char::from(*p) == c)
            .map_or(c, |i| char::from(PUNCTUATION[i ^ 1])),
        // Flipping the lowest bit never crosses a UTF-8 length boundary or
        // lands in the surrogate range: both start at even code points.
        c => char::from_u32(u32::from(c) ^ 1).unwrap_or(c),
    }
}

/// `assertion` with the lowest bit of its signature's last byte flipped: the
/// same header and claims, and a signature of the same length and encoding,
/// that its key never made. `None` when it is not a compact JWS with a
/// signature.
pub(super) fn with_signature_altered(assertion: &str) -> Option<String> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (signed, signature) = assertion.rsplit_once('.')?;
    let mut altered = engine.decode(signature).ok()?;
    *altered.last_mut()? ^= 1;
    Some(format!("{signed}.{}", engine.encode(altered)))
}

/// The verdict of the endpoint's answer.
async fn read_answer(response: &mut reqwest::Response) -> ClientAuthProbe {
    let status = response.status();
    if status.is_redirection() {
        return ClientAuthProbe::unproven(format!(
            "the token endpoint answered with a redirect (HTTP {})",
            status.as_u16()
        ));
    }
    if status.is_success() {
        return ClientAuthProbe::unproven(format!(
            "the token endpoint accepted a code it never issued (HTTP {})",
            status.as_u16()
        ));
    }
    match ErrorBody::read(response).await.string_member("error") {
        Some(error) => ClientAuthProbe::of_answer(status.as_u16(), &error),
        None => ClientAuthProbe::unproven(format!(
            "the token endpoint answered HTTP {} with no OAuth error",
            status.as_u16()
        )),
    }
}
