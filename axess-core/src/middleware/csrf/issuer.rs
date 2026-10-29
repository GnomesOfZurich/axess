//! The CSRF token handed to handlers and the issuer that mints post-rotation tokens.

use super::token::mint_token;
use crate::session::id::SessionId;
use crate::session::layer::SessionHandle;
use axess_rng::SecureRng;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// The CSRF token for the current request.
///
/// Available as a request extension after [`CsrfLayer`](super::CsrfLayer) runs. Inject it
/// into HTML forms as a hidden field or expose it to your SPA via a
/// dedicated endpoint. The token is HMAC-bound to the session and
/// rotated automatically when no cookie was present.
///
/// Using the token is what tells the layer the session is needed: reading
/// it with [`as_str`](Self::as_str) or extracting it (which clones it) counts.
/// A request that arrived without a session cookie then stores a session and
/// sets the cookies; one whose handlers never touch the token does not.
#[derive(Debug)]
pub struct CsrfToken {
    value: String,
    /// Set when the token is read; shared with the layer. `None` for a token
    /// built by hand.
    read: Option<Arc<AtomicBool>>,
}

impl CsrfToken {
    /// Wrap a token value that no layer is watching.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            read: None,
        }
    }

    pub(super) fn tracked(value: String, read: Arc<AtomicBool>) -> Self {
        Self {
            value,
            read: Some(read),
        }
    }

    fn note_read(&self) {
        if let Some(read) = &self.read {
            read.store(true, Ordering::Relaxed);
        }
    }

    /// Borrow the token as a `&str` for templating into forms or headers.
    pub fn as_str(&self) -> &str {
        self.note_read();
        &self.value
    }
}

impl Clone for CsrfToken {
    /// Cloning counts as reading: the `Extension` extractor hands a handler
    /// a clone, so extracting the token is how a handler asks for it.
    fn clone(&self) -> Self {
        self.note_read();
        Self {
            value: self.value.clone(),
            read: self.read.clone(),
        }
    }
}

impl std::fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hands a handler the CSRF token that is valid for the session id *as it is
/// now*, including after the handler has rotated the session.
///
/// Injected as a request extension by [`CsrfLayer`](super::CsrfLayer) next to [`CsrfToken`].
/// Call [`token`](Self::token) after rotating the session and embed the
/// result: it is the token the layer sets as the response cookie, so a
/// client that submits it passes the double-submit check on its next
/// request. Cheap to clone.
#[derive(Clone)]
pub struct CsrfIssuer {
    state: Arc<IssuerState>,
}

struct IssuerState {
    signing_key: Arc<Zeroizing<[u8; 32]>>,
    rng: Arc<dyn SecureRng>,
    handle: Option<SessionHandle>,
    /// Session id observed at request entry and the token handed out for it.
    entry: Option<(SessionId, String)>,
    /// Token minted for a session id the handler rotated to.
    rotated: std::sync::Mutex<Option<(SessionId, String)>>,
    /// Set once the handler reads the token, from the extension or here.
    read: Arc<AtomicBool>,
}

impl CsrfIssuer {
    pub(super) fn new(
        signing_key: Arc<Zeroizing<[u8; 32]>>,
        rng: Arc<dyn SecureRng>,
        handle: Option<SessionHandle>,
        entry: Option<(SessionId, String)>,
        read: Arc<AtomicBool>,
    ) -> Self {
        Self {
            state: Arc::new(IssuerState {
                signing_key,
                rng,
                handle,
                entry,
                rotated: std::sync::Mutex::new(None),
                read,
            }),
        }
    }

    /// The token bound to the session's current id.
    ///
    /// Equal to the [`CsrfToken`] extension until the session id changes;
    /// after a rotation, a token bound to the new id (minted once, then
    /// returned unchanged on every later call and used for the response
    /// cookie). Empty when the request carries no session handle.
    pub async fn token(&self) -> CsrfToken {
        self.state.read.store(true, Ordering::Relaxed);
        let Some(handle) = &self.state.handle else {
            return CsrfToken::new(String::new());
        };
        let current = handle.0.read().await.id;
        CsrfToken::tracked(self.token_for(current), self.state.read.clone())
    }

    pub(super) fn token_for(&self, current: SessionId) -> String {
        if let Some((entry_id, token)) = &self.state.entry
            && *entry_id == current
        {
            return token.clone();
        }
        let mut rotated = self
            .state
            .rotated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match rotated.as_ref() {
            Some((id, token)) if *id == current => token.clone(),
            _ => {
                let token = mint_token(
                    current.as_bytes(),
                    &self.state.signing_key,
                    &*self.state.rng,
                );
                *rotated = Some((current, token.clone()));
                token
            }
        }
    }
}
