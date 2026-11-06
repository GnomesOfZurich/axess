//! What the middleware hands out: the token the handler sees at entry, the
//! replacement token after it ran, and the `Set-Cookie` value that carries one.

use super::*;

/// The token handed to the handler before it runs.
pub(super) struct EntryToken {
    /// A fresh token minted for this response, when the client has no usable one.
    pub(super) provisional_mint: Option<String>,
    /// The value the handler sees in the [`CsrfToken`] extension.
    pub(super) extension_token: String,
}

/// Decide which token the handler sees at request entry.
///
/// Handlers
/// that read `CsrfToken` from the request extension (to embed
/// in an HTML form, say) need SOME value; give them either
/// the presented cookie or a fresh mint bound to the current
/// session id. A token can only be minted when a session id
/// is present to bind it to; without one we leave the client
/// tokenless rather than issue an unbound token.
///
/// A presented cookie that does not verify against the session id
/// at entry (left over from before the id changed) is not handed
/// to the handler: embedding it would render a form whose first
/// submit is refused. It is treated as absent here, so the handler
/// sees a fresh token bound to the current id, and the same token
/// goes out as the replacement cookie. Validation of a
/// state-changing request is unchanged and has already run.
pub(super) fn entry_token(
    config: &CsrfConfig,
    cookie_token: Option<&str>,
    session_id: Option<SessionId>,
) -> EntryToken {
    if session_id.is_none() {
        use std::sync::Once;
        static WARN: Once = Once::new();
        WARN.call_once(|| {
            tracing::warn!(
                "csrf: no session in request extensions; handlers get an empty CsrfToken. \
                 Put the session layer outside the CSRF layer."
            );
        });
    }
    // Only a cookie that verifies against the session id is handed on. With
    // no session id there is nothing to verify it against, and the value is
    // the client's own.
    let usable_cookie = cookie_token.filter(|c| {
        !c.is_empty()
            && session_id
                .as_ref()
                .is_some_and(|sid| validate_token(c, sid.as_bytes(), &config.signing_key))
    });
    let provisional_mint = match (usable_cookie, session_id.as_ref()) {
        (Some(_), _) => None,
        (None, Some(sid_at_entry)) => Some(mint_token(
            sid_at_entry.as_bytes(),
            &config.signing_key,
            &*config.rng,
        )),
        (None, None) => None,
    };
    let extension_token = provisional_mint
        .clone()
        .or_else(|| usable_cookie.map(str::to_owned))
        .unwrap_or_default();
    EntryToken {
        provisional_mint,
        extension_token,
    }
}

/// The token to ship as `Set-Cookie` after the handler ran, if any.
///
/// The post-handler session id decides: if the cookie the client will present
/// next no longer verifies against it (typical after `session.regenerate()`), a
/// token for the new id is issued; otherwise only a token minted at entry is sent.
pub(super) fn replacement_token(
    config: &CsrfConfig,
    issuer: &CsrfIssuer,
    provisional_mint: Option<String>,
    cookie_token: Option<&str>,
    session_id_after: Option<SessionId>,
) -> Option<String> {
    // The token the client would present next request: either the
    // freshly-provisioned mint (if we issued one) or the cookie
    // they sent this request. Empty string means "no token to
    // present": treat as absent.
    let effective_cookie = provisional_mint
        .as_deref()
        .or(cookie_token)
        .filter(|t| !t.is_empty());
    match (effective_cookie, session_id_after.as_ref()) {
        (Some(existing), Some(sid_after))
            if validate_token(existing, sid_after.as_bytes(), &config.signing_key) =>
        {
            // Cookie still binds to the post-handler session id
            // (usually because the handler didn't rotate). Mint
            // only if we chose to at entry.
            provisional_mint
        }
        (_, Some(sid_after)) => {
            // Either no effective cookie, or the effective cookie
            // no longer binds to the current session id (typical
            // after `session.regenerate()`). Use the issuer's token
            // for the new id: it is the one a handler that rotated
            // may already have embedded in its response body.
            Some(issuer.token_for(*sid_after))
        }
        (_, None) => None,
    }
}

pub(super) fn build_cookie(config: &CsrfConfig, token: &str) -> String {
    use cookie::Cookie;

    let mut cookie = Cookie::new(
        config.effective_cookie_name().to_string(),
        token.to_string(),
    );
    // Intentionally NOT HttpOnly; JavaScript needs to read the token to
    // include it in headers (the double-submit pattern requires this).
    cookie.set_http_only(false);
    cookie.set_secure(config.secure);
    cookie.set_same_site(config.same_site);
    cookie.set_path(config.path.as_ref().to_string());
    cookie.to_string()
}
