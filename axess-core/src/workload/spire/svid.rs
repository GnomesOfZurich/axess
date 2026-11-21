//! The SVIDs an agent issues to this workload, checked before they are
//! kept.
//!
//! The agent is the workload's root of trust, so nothing here verifies a
//! signature: an X.509 SVID is checked for shape (a leaf with exactly one
//! URI name, which is the SPIFFE ID the agent says it is, and which may
//! sign nothing), a JWT SVID for the claims a holder needs to read (`sub`,
//! `aud`, `exp`). Both are checked against the trust domain the client was
//! built for and against the clock: an SVID that has expired is never
//! admitted.

use std::sync::Arc;

use axess_clock::Timestamp;
use axess_identity::{TrustDomain, WorkloadId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use super::bundle::{X509Bundle, X509BundleSet, read_bundle_map, split_certificates};
use super::error::{SpireError, remote_text};
use super::key::{KeyMatch, private_key_matches};
use super::proto::{RawJwtSvid, RawX509Svid, RawX509SvidResponse};

/// The most bytes of a JWT SVID this client reads. A token is a header, a
/// handful of claims and a signature; one of 16 KiB is not an SVID.
pub(crate) const MAX_JWT_SVID_BYTES: usize = 16 * 1024;

/// Which of the SVIDs an agent returns a watcher keeps. An agent returns
/// one SVID for each registration entry that matches the workload, the
/// default first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SvidSelector {
    /// The first SVID of the response: the agent's default.
    #[default]
    First,
    /// The SVID issued for this SPIFFE ID.
    SpiffeId(WorkloadId),
    /// The SVID the operator gave this hint in its registration entry.
    Hint(String),
}

/// An X.509 SVID: the workload's certificate chain and private key.
#[derive(Clone)]
pub struct X509Svid {
    spiffe_id: WorkloadId,
    trust_domain: TrustDomain,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: Zeroizing<Vec<u8>>,
    not_before: Timestamp,
    not_after: Timestamp,
    hint: String,
}

impl std::fmt::Debug for X509Svid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509Svid")
            .field("spiffe_id", &self.spiffe_id)
            .field("cert_chain_len", &self.cert_chain.len())
            .field("private_key", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("hint", &self.hint)
            .finish()
    }
}

impl X509Svid {
    /// The SPIFFE ID the SVID was issued for.
    pub fn spiffe_id(&self) -> &WorkloadId {
        &self.spiffe_id
    }

    /// The trust domain of the SPIFFE ID.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// The certificate chain, leaf first, then any intermediates.
    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    /// The leaf certificate, which carries the SPIFFE ID.
    pub fn leaf(&self) -> &CertificateDer<'static> {
        &self.cert_chain[0]
    }

    /// A copy of the private key, PKCS#8 DER. The SVID keeps its own copy
    /// and wipes it when the last holder drops it; the copy returned here
    /// is the caller's to guard.
    pub fn private_key(&self) -> PrivatePkcs8KeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key.to_vec())
    }

    /// The start of the leaf's validity.
    pub fn not_before(&self) -> Timestamp {
        self.not_before
    }

    /// The end of the leaf's validity: the SVID's expiry.
    pub fn not_after(&self) -> Timestamp {
        self.not_after
    }

    /// The operator's hint for this SVID; empty when the entry has none.
    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// Read and check one SVID of a response, with the bundle that came
    /// with it, read at `now`. The SVID's trust domain and expiry are the
    /// caller's to check, with [`admit_x509`].
    fn from_raw(raw: RawX509Svid, now: Timestamp) -> Result<(Self, X509Bundle), SpireError> {
        let spiffe_id = WorkloadId::parse(&raw.spiffe_id).map_err(|_| {
            SpireError::refused("the SVID's SPIFFE ID is not valid", &raw.spiffe_id)
        })?;
        let trust_domain = spiffe_id.trust_domain();
        let cert_chain = split_certificates(&raw.cert_chain, "SVID's certificate chain")?;
        let Some(leaf) = cert_chain.first() else {
            return Err(SpireError::Refused(
                "the SVID holds no certificate".to_owned(),
            ));
        };
        let facts = read_leaf(leaf)?;
        if facts.spiffe_id != raw.spiffe_id {
            return Err(SpireError::refused(
                "the leaf certificate names another SPIFFE ID than the SVID",
                &facts.spiffe_id,
            ));
        }
        if facts.not_after < facts.not_before {
            return Err(SpireError::Refused(
                "the leaf certificate's validity ends before it begins".to_owned(),
            ));
        }
        if raw.private_key.is_empty() {
            return Err(SpireError::Refused(
                "the SVID holds no private key".to_owned(),
            ));
        }
        check_private_key(&raw.private_key, &facts.public_key)?;
        let bundle = X509Bundle::from_der(trust_domain.clone(), &raw.bundle, now)?;
        let svid = Self {
            spiffe_id,
            trust_domain,
            cert_chain,
            private_key: raw.private_key,
            not_before: facts.not_before,
            not_after: facts.not_after,
            hint: raw.hint,
        };
        Ok((svid, bundle))
    }
}

/// Refuse a private key that is not the leaf certificate's, before the SVID
/// it came with can replace one that works.
///
/// The encodings are compared first ([`super::key`]). Where the build has a
/// TLS stack, the key is also loaded by it, which refuses bytes that are no
/// usable key and derives the public key of one that carries none. A key
/// that carries no public key, in a build with nothing to derive it, is
/// refused: it cannot be shown to be the certificate's.
fn check_private_key(pkcs8: &[u8], leaf_public_key: &[u8]) -> Result<(), SpireError> {
    let carried = private_key_matches(pkcs8, leaf_public_key)
        .map_err(|mismatch| SpireError::Refused(format!("the SVID is refused: {mismatch}")))?;
    #[cfg(feature = "outbound-mtls")]
    let derived = super::tls::derived_key_is(pkcs8, leaf_public_key)?;
    #[cfg(not(feature = "outbound-mtls"))]
    let derived = false;
    if carried == KeyMatch::Proven || derived {
        return Ok(());
    }
    Err(SpireError::Refused(
        "the SVID is refused: its private key carries no public key, and nothing in this \
         build derives one to compare with the leaf certificate's (`outbound-mtls` does)"
            .to_owned(),
    ))
}

/// What an `X509SVIDResponse` carries: the workload's SVIDs and the bundles
/// to verify its peers with.
#[derive(Debug, Clone)]
pub struct X509Context {
    svids: Vec<Arc<X509Svid>>,
    selected: usize,
    bundles: Arc<X509BundleSet>,
}

impl X509Context {
    /// The SVID the client's [`SvidSelector`] chose.
    pub fn svid(&self) -> &Arc<X509Svid> {
        &self.svids[self.selected]
    }

    /// Where in [`svids`](Self::svids) the chosen SVID is.
    pub(crate) fn selected(&self) -> usize {
        self.selected
    }

    /// Every SVID the agent returned for the client's trust domain that had
    /// not expired, in the agent's order. A context read from an
    /// [`X509Source`](super::X509Source) is checked against the clock at each
    /// read, so no SVID in it has expired.
    pub fn svids(&self) -> &[Arc<X509Svid>] {
        &self.svids
    }

    /// The context without the SVIDs that have expired by `now`, or `None`
    /// when none has. The selected SVID is kept: the caller has checked it.
    pub(crate) fn without_expired(&self, now: Timestamp) -> Option<Self> {
        if self.svids.iter().all(|svid| svid.not_after > now) {
            return None;
        }
        let chosen = self.svid().clone();
        let svids: Vec<_> = self
            .svids
            .iter()
            .filter(|svid| svid.not_after > now || Arc::ptr_eq(svid, &chosen))
            .cloned()
            .collect();
        let selected = svids
            .iter()
            .position(|svid| Arc::ptr_eq(svid, &chosen))
            .unwrap_or_default();
        Some(Self {
            svids,
            selected,
            bundles: self.bundles.clone(),
        })
    }

    /// The bundle of the workload's own trust domain and of every trust
    /// domain federated with it.
    pub fn bundles(&self) -> &Arc<X509BundleSet> {
        &self.bundles
    }
}

/// The context a response carries, admitted for `trust_domain` at `now`.
///
/// The response is refused as a whole when it holds no SVID, when the
/// selector matches none, when an SVID is malformed, or when the selected
/// SVID is for another trust domain or has expired. An SVID the selector
/// did not choose is kept when it is well-formed, of the client's trust
/// domain and not expired, and left out otherwise. A federated bundle that
/// does not read is left out and recorded in the bundle set's `skipped`.
pub(crate) fn admit_x509(
    raw: RawX509SvidResponse,
    trust_domain: &TrustDomain,
    selector: &SvidSelector,
    now: Timestamp,
) -> Result<X509Context, SpireError> {
    // A federated entry that does not read is left out and recorded: the
    // workload's own bundle comes with its SVID and does not depend on it.
    let (federated, skipped) =
        read_bundle_map(&raw.federated_bundles, None, |trust_domain, der| {
            X509Bundle::from_der(trust_domain, der, now)
        })?;
    let mut bundles = X509BundleSet::new(federated);
    bundles.set_crls(raw.crls);
    bundles.set_skipped(skipped);

    let none_sent = raw.svids.is_empty();
    let mut svids = Vec::with_capacity(raw.svids.len());
    let mut selected = None;
    for (index, raw_svid) in raw.svids.into_iter().enumerate() {
        let chosen = match selector {
            SvidSelector::First => index == 0,
            SvidSelector::SpiffeId(id) => id.as_str() == raw_svid.spiffe_id,
            SvidSelector::Hint(hint) => *hint == raw_svid.hint,
        };
        let chosen = chosen && selected.is_none();
        let (svid, bundle) = X509Svid::from_raw(raw_svid, now)?;
        if svid.trust_domain != *trust_domain {
            if chosen {
                return Err(SpireError::TrustDomainMismatch {
                    expected: trust_domain.clone(),
                    presented: remote_text(svid.trust_domain.as_str()),
                });
            }
            continue;
        }
        if svid.not_after <= now {
            if chosen {
                return Err(SpireError::Refused(format!(
                    "the SVID expired at {}",
                    svid.not_after.to_rfc3339_numeric_offset()
                )));
            }
            // An expired SVID the selector did not choose is never served.
            continue;
        }
        if chosen {
            selected = Some(svids.len());
        }
        // The SVID's own bundle is the trust domain's, whatever a
        // federated entry of the same name says.
        bundles.insert(bundle);
        svids.push(Arc::new(svid));
    }
    let Some(selected) = selected else {
        // An answer with no SVID at all lacks a mandatory field and is
        // discarded. One with SVIDs and none for the selected identity is
        // the agent no longer issuing that identity.
        return Err(match selector {
            SvidSelector::SpiffeId(id) if !none_sent => SpireError::NotIssued(id.to_string()),
            SvidSelector::Hint(hint) if !none_sent => {
                SpireError::NotIssued(format!("the hint {}", remote_text(hint)))
            }
            _ => SpireError::Refused("the response holds no SVID".to_owned()),
        });
    };
    Ok(X509Context {
        svids,
        selected,
        bundles: Arc::new(bundles),
    })
}

/// What the leaf of an SVID says about itself.
pub(crate) struct LeafFacts {
    /// The one URI of the subject alternative name.
    pub(crate) spiffe_id: String,
    /// The `SubjectPublicKeyInfo`, DER.
    pub(crate) public_key: Vec<u8>,
    /// `notBefore`.
    pub(crate) not_before: Timestamp,
    /// `notAfter`.
    pub(crate) not_after: Timestamp,
}

/// Read the leaf of an X.509 SVID. The X.509-SVID profile gives a leaf
/// exactly one URI name, the SPIFFE ID, and forbids it to be a certificate
/// authority; a certificate that breaks either rule is refused.
pub(crate) fn read_leaf(leaf: &CertificateDer<'_>) -> Result<LeafFacts, SpireError> {
    fn parse_failed(error: &dyn std::fmt::Display) -> SpireError {
        SpireError::refused("the leaf certificate does not parse", &error.to_string())
    }
    let (_, certificate) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|error| parse_failed(&error))?;
    let names = certificate
        .subject_alternative_name()
        .map_err(|error| parse_failed(&error))?
        .ok_or_else(|| {
            SpireError::Refused("the leaf certificate has no subject alternative name".to_owned())
        })?;
    let mut uris = names
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        });
    let Some(spiffe_id) = uris.next() else {
        return Err(SpireError::Refused(
            "the leaf certificate has no URI name".to_owned(),
        ));
    };
    if uris.next().is_some() {
        return Err(SpireError::Refused(
            "the leaf certificate has more than one URI name".to_owned(),
        ));
    }
    // X509-SVID standard, sections 3.1 and 5.2: a leaf names a workload,
    // so its SPIFFE ID has a path. A name with none is a trust domain's,
    // which only a signing certificate carries.
    let names_a_workload = spiffe_id
        .get(..9)
        .filter(|scheme| scheme.eq_ignore_ascii_case("spiffe://"))
        .and_then(|_| spiffe_id.get(9..))
        .is_some_and(|rest| rest.contains('/'));
    if !names_a_workload {
        return Err(SpireError::refused(
            "the leaf certificate's URI name is not a SPIFFE ID with a path",
            spiffe_id,
        ));
    }
    let constraints = certificate
        .basic_constraints()
        .map_err(|error| parse_failed(&error))?;
    if constraints.is_some_and(|constraints| constraints.value.ca) {
        return Err(SpireError::Refused(
            "the leaf certificate is a certificate authority".to_owned(),
        ));
    }
    let usage = certificate
        .key_usage()
        .map_err(|error| parse_failed(&error))?;
    if usage.is_some_and(|usage| usage.value.key_cert_sign() || usage.value.crl_sign()) {
        return Err(SpireError::Refused(
            "the leaf certificate may sign certificates or revocation lists".to_owned(),
        ));
    }
    let validity = certificate.validity();
    let instant = |seconds: i64| {
        Timestamp::from_unix_seconds(seconds).ok_or_else(|| {
            SpireError::Refused("the leaf certificate's validity is out of range".to_owned())
        })
    };
    Ok(LeafFacts {
        spiffe_id: spiffe_id.to_owned(),
        public_key: certificate.public_key().raw.to_vec(),
        not_before: instant(validity.not_before.timestamp())?,
        not_after: instant(validity.not_after.timestamp())?,
    })
}

/// A JWT SVID: a token the workload presents as a bearer credential to the
/// audience it was minted for.
#[derive(Clone)]
pub struct JwtSvid {
    spiffe_id: WorkloadId,
    trust_domain: TrustDomain,
    token: Zeroizing<String>,
    audience: Vec<String>,
    issued_at: Timestamp,
    expires_at: Timestamp,
    hint: String,
}

impl std::fmt::Debug for JwtSvid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtSvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("token", &"<redacted>")
            .field("audience", &self.audience)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("hint", &self.hint)
            .finish()
    }
}

impl JwtSvid {
    /// The SPIFFE ID in the token's `sub`.
    pub fn spiffe_id(&self) -> &WorkloadId {
        &self.spiffe_id
    }

    /// The trust domain of the SPIFFE ID.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// The token in compact serialization, to present as a bearer
    /// credential: the value of an `Authorization: Bearer` header, the
    /// `web_identity_token` of an STS exchange, a `client_assertion`.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The audiences in the token's `aud`.
    pub fn audience(&self) -> &[String] {
        &self.audience
    }

    /// The token's `iat`, or the time it was fetched when it carries none.
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// The token's `exp`.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// The operator's hint for this SVID; empty when the entry has none.
    pub fn hint(&self) -> &str {
        &self.hint
    }
}

/// One JWT SVID of a response, admitted for `trust_domain` at `now`.
///
/// The token's payload is read without verifying the signature, which is
/// the agent's to have made: `sub` must be the SPIFFE ID the agent names,
/// `aud` must hold every audience that was asked for, `exp` must be in the
/// future, and an `iat` must not be after it.
pub(crate) fn admit_jwt(
    raw: RawJwtSvid,
    trust_domain: &TrustDomain,
    requested_audience: &[String],
    now: Timestamp,
) -> Result<JwtSvid, SpireError> {
    let spiffe_id = WorkloadId::parse(&raw.spiffe_id)
        .map_err(|_| SpireError::refused("the SVID's SPIFFE ID is not valid", &raw.spiffe_id))?;
    let presented = spiffe_id.trust_domain();
    if presented != *trust_domain {
        return Err(SpireError::TrustDomainMismatch {
            expected: trust_domain.clone(),
            presented: remote_text(presented.as_str()),
        });
    }
    let claims = unverified_claims(&raw.token)?;
    let refuse = |why: &str| SpireError::Refused(format!("the JWT SVID {why}"));
    if claims.get("sub").and_then(|sub| sub.as_str()) != Some(raw.spiffe_id.as_str()) {
        return Err(refuse(
            "names another subject than the SPIFFE ID it came with",
        ));
    }
    let audience = match claims.get("aud") {
        Some(serde_json::Value::String(audience)) => vec![audience.clone()],
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| refuse("has an audience that is not a string"))?,
        _ => return Err(refuse("has no audience")),
    };
    if !requested_audience
        .iter()
        .all(|wanted| audience.contains(wanted))
    {
        return Err(refuse("is not for the audience that was asked for"));
    }
    let seconds = |claim: &str| {
        claims
            .get(claim)
            .and_then(|value| value.as_i64().or_else(|| value.as_f64().map(|f| f as i64)))
            .and_then(Timestamp::from_unix_seconds)
    };
    let Some(expires_at) = seconds("exp") else {
        return Err(refuse("has no expiry"));
    };
    if expires_at <= now {
        return Err(SpireError::Refused(format!(
            "the JWT SVID expired at {}",
            expires_at.to_rfc3339_numeric_offset()
        )));
    }
    // A token with no `iat` has lived since it was fetched, as far as the
    // holder can tell.
    let issued_at = seconds("iat").unwrap_or(now);
    if issued_at > expires_at {
        return Err(refuse("was issued after it expires"));
    }
    Ok(JwtSvid {
        spiffe_id,
        trust_domain: presented,
        token: raw.token,
        audience,
        issued_at,
        expires_at,
        hint: raw.hint,
    })
}

/// The claims of a token in compact serialization, read without verifying
/// the signature.
fn unverified_claims(
    token: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, SpireError> {
    let refuse = |why: &str| SpireError::Refused(format!("the JWT SVID {why}"));
    if token.len() > MAX_JWT_SVID_BYTES {
        return Err(refuse("is longer than this client reads"));
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(refuse("is not three segments"));
    };
    if header.is_empty() || signature.is_empty() {
        return Err(refuse("has an empty segment"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| refuse("has a payload that is not base64url"))?;
    match serde_json::from_slice(&payload) {
        Ok(serde_json::Value::Object(claims)) => Ok(claims),
        Ok(_) => Err(refuse("has a payload that is not a JSON object")),
        Err(error) => Err(SpireError::refused(
            "the JWT SVID's payload is not JSON",
            &error.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests;
