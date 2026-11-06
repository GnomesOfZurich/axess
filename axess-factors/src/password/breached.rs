//! Breached-password screening at password choice.
//!
//! [`BreachedPasswordCheck`] is the question "is this password known from a
//! breach?", answered by whatever the adopter wires in: a list, a local
//! corpus, or the k-anonymity range protocol over an HTTP API. This crate
//! ships no HTTP client. [`range_prefix`] and [`count_in_range`] are the
//! protocol's two pure halves, so an adapter is the HTTP call alone.
//!
//! The range protocol hashes the password with SHA-1 and sends the first
//! five upper-case hex digits of the digest; the answer lists every digest
//! suffix in that range with how often it was seen. SHA-1 is the protocol's
//! hash, not this crate's choice: it identifies a password to the corpus and
//! protects nothing, which is why only a 20-bit prefix leaves the host and
//! the password itself never does.
//!
//! [`check_password_breached`] is the screening the password flows run: it
//! honours a tenant's [`PasswordRules::breached_check`], refuses a breached
//! password by name, and refuses a password the check could not screen
//! unless the policy ([`BreachCheckUnavailable`]) says to let it through.

use super::{NewPasswordError, PasswordRules};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// A breached-password check could not answer.
///
/// Carries the implementation's sentence (a timeout, a status code, a
/// parse failure) for the operator's log. It is never shown to the person
/// choosing the password: they see [`NewPasswordError::BreachCheckUnavailable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachCheckError {
    sentence: String,
}

impl BreachCheckError {
    /// An error carrying `sentence`, what the implementation can say about
    /// why it could not answer.
    pub fn new(sentence: impl Into<String>) -> Self {
        Self {
            sentence: sentence.into(),
        }
    }
}

impl fmt::Display for BreachCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sentence)
    }
}

impl std::error::Error for BreachCheckError {}

/// What becomes of a chosen password when the breach check cannot answer.
///
/// The default is [`Refuse`](Self::Refuse): an outage of the check does not
/// admit a password nobody screened. [`Allow`](Self::Allow) is the named
/// opt-out for a deployment that would rather accept an unscreened password
/// than turn signups and resets away while the check is down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BreachCheckUnavailable {
    /// Refuse the password with [`NewPasswordError::BreachCheckUnavailable`].
    #[default]
    Refuse,
    /// Accept the password unscreened, as if no check were configured. The
    /// acceptance is logged at `warn`.
    Allow,
}

/// Answers whether a password is known from a breach.
///
/// Implement it over a list, a local corpus or the range protocol (see the
/// module docs and [`range_prefix`]). Answer `Ok(true)` only for a password
/// the corpus holds, `Ok(false)` for one it does not, and `Err` when the
/// question could not be put: the caller's policy, not the implementation,
/// decides what an outage means. Implementations receive the plaintext and
/// must not log or store it.
pub trait BreachedPasswordCheck: Send + Sync + 'static {
    /// Whether `password` appears in the breach corpus.
    fn is_breached<'a>(
        &'a self,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BreachCheckError>> + Send + 'a>>;
}

/// Hex digits of the SHA-1 digest the range protocol sends.
pub const RANGE_PREFIX_LEN: usize = 5;

/// The range protocol's split of a password's SHA-1 digest: the five
/// upper-case hex digits an adapter sends as the range, and the remaining
/// thirty-five it looks for in the answer.
///
/// SHA-1 here is the protocol's identifier for a password, not a protection
/// of it; see the module docs. The digest is computed over the password's
/// UTF-8 bytes.
pub fn range_prefix(password: &str) -> (String, String) {
    use sha1::Digest as _;
    let digest: String = sha1::Sha1::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let suffix = digest[RANGE_PREFIX_LEN..].to_owned();
    let mut prefix = digest;
    prefix.truncate(RANGE_PREFIX_LEN);
    (prefix, suffix)
}

/// How often `suffix` was seen, read from a range answer.
///
/// `body` is the protocol's answer for the prefix: one `SUFFIX:COUNT` line
/// per digest in the range, in any case, with `\n` or `\r\n` endings. The
/// answer is `Some(count)` for the line whose suffix matches (compared
/// without regard to case) and `None` when no line does, which is the
/// common answer for a password not in the corpus. A padded answer carries
/// `SUFFIX:0` rows for digests the corpus does not hold, so `Some(0)` also
/// means not breached: test `count > 0`, not `is_some()`. A line that does
/// not parse is skipped, so a damaged line cannot read as a match.
pub fn count_in_range(body: &str, suffix: &str) -> Option<u64> {
    body.lines().find_map(|line| {
        let (candidate, count) = line.trim().split_once(':')?;
        if !candidate.eq_ignore_ascii_case(suffix) {
            return None;
        }
        count.trim().parse().ok()
    })
}

/// Screen a chosen password against `check`, under the tenant's `rules` and
/// the deployment's `policy`.
///
/// Answers `Ok(())` when `check` is `None` (no check configured), when
/// `rules.breached_check` is false (the tenant is exempt on purpose), or
/// when the check answers that the password is not breached. Refuses with
/// [`NewPasswordError::Breached`] when it is, and with
/// [`NewPasswordError::BreachCheckUnavailable`] when the check errs under
/// [`BreachCheckUnavailable::Refuse`]; under [`BreachCheckUnavailable::Allow`]
/// the error is logged and the password passes. The check's sentence goes to
/// the log at `warn`, never into the answer.
pub async fn check_password_breached(
    password: &str,
    rules: &PasswordRules,
    check: Option<&dyn BreachedPasswordCheck>,
    policy: BreachCheckUnavailable,
) -> Result<(), NewPasswordError> {
    let Some(check) = check else {
        return Ok(());
    };
    if !rules.breached_check {
        return Ok(());
    }
    match check.is_breached(password).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(NewPasswordError::Breached),
        Err(error) => match policy {
            BreachCheckUnavailable::Refuse => {
                tracing::warn!(%error, "breached-password check unavailable: password refused");
                Err(NewPasswordError::BreachCheckUnavailable)
            }
            BreachCheckUnavailable::Allow => {
                tracing::warn!(
                    %error,
                    "breached-password check unavailable: password accepted unscreened"
                );
                Ok(())
            }
        },
    }
}

/// A [`BreachedPasswordCheck`] over a fixed set of passwords: a deny-list of
/// the passwords a deployment knows to refuse (the most common ones, its own
/// product names), compared exactly. A corpus of hundreds of millions of
/// breached entries is reached through the range protocol instead; a short
/// list is a floor under that, not a substitute for it.
#[derive(Debug, Clone, Default)]
pub struct BreachedPasswordList(std::collections::HashSet<String>);

impl BreachedPasswordList {
    /// A list holding `passwords`, compared exactly.
    pub fn new<S: Into<String>>(passwords: impl IntoIterator<Item = S>) -> Self {
        Self(passwords.into_iter().map(Into::into).collect())
    }
}

impl BreachedPasswordCheck for BreachedPasswordList {
    fn is_breached<'a>(
        &'a self,
        password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BreachCheckError>> + Send + 'a>> {
        Box::pin(std::future::ready(Ok(self.0.contains(password))))
    }
}

/// A [`BreachedPasswordCheck`] that never answers, for tests of what a
/// deployment does while its check is down.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone)]
pub struct BreachCheckOutage(String);

#[cfg(any(test, feature = "testing"))]
impl BreachCheckOutage {
    /// An outage whose every answer is [`BreachCheckError`] with `sentence`.
    pub fn new(sentence: impl Into<String>) -> Self {
        Self(sentence.into())
    }
}

#[cfg(any(test, feature = "testing"))]
impl BreachedPasswordCheck for BreachCheckOutage {
    fn is_breached<'a>(
        &'a self,
        _password: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, BreachCheckError>> + Send + 'a>> {
        Box::pin(std::future::ready(Err(BreachCheckError::new(
            self.0.clone(),
        ))))
    }
}

#[cfg(test)]
mod tests;
