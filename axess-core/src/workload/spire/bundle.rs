//! Trust bundles as the agent serves them: the X.509 authorities and the
//! JWT signing keys of each trust domain this workload may verify.
//!
//! A bundle set holds the workload's own trust domain and every trust domain
//! federated with it. Holding a federated bundle does not mean accepting
//! that trust domain: which domains a service admits is the deployment's
//! decision, made where the bundle is used.
//!
//! An entry of another trust domain than the workload's that does not read
//! (its key is no trust domain, or its bundle does not parse) is left out of
//! the set and recorded in [`X509BundleSet::skipped`] and
//! [`JwtBundleSet::skipped`]: one partner's broken bundle does not stop the
//! workload's own from being followed. An answer whose entry for the
//! workload's own trust domain does not read, or that has no such entry, is
//! refused as a whole.

use std::collections::BTreeMap;

use axess_clock::Timestamp;
use axess_identity::TrustDomain;
use rustls_pki_types::CertificateDer;
use serde_json::Value;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::error::{SpireError, remote_text};
use super::proto::RawBundles;

/// The most certificates one chain or one bundle may hold.
pub(crate) const MAX_CERTIFICATES: usize = 64;
/// The most keys one JWT bundle may hold.
pub(crate) const MAX_JWT_KEYS: usize = 256;

/// The X.509 authorities of one trust domain.
///
/// An authority is a trust anchor until its `notAfter`. A TLS stack that
/// is handed a root does not read the root's own validity, so the bundle
/// does: [`valid_at`](Self::valid_at) leaves out the authorities that have
/// expired, and that is what the verifiers of this module build their roots
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Bundle {
    trust_domain: TrustDomain,
    authorities: Vec<CertificateDer<'static>>,
    /// The `notAfter` of each authority, in the order of `authorities`.
    not_after: Vec<Timestamp>,
}

impl X509Bundle {
    /// A bundle from authorities already held as certificates, for a
    /// deployment that configures a trust domain's bundle by hand beside
    /// the agent's. Each is parsed for its validity; one that does not
    /// parse refuses the bundle.
    pub fn new(
        trust_domain: TrustDomain,
        authorities: Vec<CertificateDer<'static>>,
    ) -> Result<Self, SpireError> {
        let not_after = authorities
            .iter()
            .map(authority_not_after)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trust_domain,
            authorities,
            not_after,
        })
    }

    /// The trust domain these authorities sign for.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// Every authority the agent served, DER, in the agent's order, the
    /// expired ones included. To verify with, take [`valid_at`](Self::valid_at).
    pub fn authorities(&self) -> &[CertificateDer<'static>] {
        &self.authorities
    }

    /// The authorities that have not expired at `now`: the trust anchors.
    pub fn valid_at(&self, now: Timestamp) -> impl Iterator<Item = &CertificateDer<'static>> {
        self.authorities
            .iter()
            .zip(&self.not_after)
            .filter(move |(_, not_after)| now <= **not_after)
            .map(|(authority, _)| authority)
    }

    /// The bundle an agent served for `trust_domain`, read at `now`. A
    /// bundle with no certificate, or with none that is still valid, is
    /// refused: it holds no trust anchor.
    pub(crate) fn from_der(
        trust_domain: TrustDomain,
        der: &[u8],
        now: Timestamp,
    ) -> Result<Self, SpireError> {
        let authorities = split_certificates(der, "bundle")?;
        if authorities.is_empty() {
            return Err(SpireError::Refused(format!(
                "the X.509 bundle of {trust_domain} holds no certificate"
            )));
        }
        let bundle = Self::new(trust_domain, authorities)?;
        if bundle.valid_at(now).next().is_none() {
            return Err(SpireError::AuthoritiesExpired(bundle.trust_domain));
        }
        Ok(bundle)
    }
}

/// The `notAfter` of an authority.
fn authority_not_after(authority: &CertificateDer<'static>) -> Result<Timestamp, SpireError> {
    let (_, certificate) = X509Certificate::from_der(authority.as_ref())
        .map_err(|error| SpireError::refused("an authority does not parse", &error.to_string()))?;
    Timestamp::from_unix_seconds(certificate.validity().not_after.timestamp())
        .ok_or_else(|| SpireError::Refused("an authority's validity is out of range".to_owned()))
}

/// An entry of a bundle map that was left out because it did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedBundle {
    key: String,
    error: SpireError,
}

impl SkippedBundle {
    fn new(key: &str, error: SpireError) -> Self {
        Self {
            key: remote_text(key),
            error,
        }
    }

    /// The entry's key as the agent wrote it, escaped and cut.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Why the entry was left out.
    pub fn error(&self) -> &SpireError {
        &self.error
    }
}

impl std::fmt::Display for SkippedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bundle entry {} left out: {}", self.key, self.error)
    }
}

/// Read every entry of a bundle map with `read`. An entry that does not
/// read is skipped and recorded, unless it belongs to `own`, the workload's
/// trust domain, whose failure is returned.
pub(crate) fn read_bundle_map<B>(
    entries: &[(String, Vec<u8>)],
    own: Option<&TrustDomain>,
    read: impl Fn(TrustDomain, &[u8]) -> Result<B, SpireError>,
) -> Result<(Vec<B>, Vec<SkippedBundle>), SpireError> {
    let mut kept = Vec::with_capacity(entries.len());
    let mut skipped = Vec::new();
    for (key, bytes) in entries {
        let trust_domain = match trust_domain_key(key) {
            Ok(trust_domain) => trust_domain,
            Err(error) => {
                skipped.push(SkippedBundle::new(key, error));
                continue;
            }
        };
        let own_entry = own == Some(&trust_domain);
        match read(trust_domain, bytes) {
            Ok(bundle) => kept.push(bundle),
            Err(error) if own_entry => return Err(error),
            Err(error) => skipped.push(SkippedBundle::new(key, error)),
        }
    }
    Ok((kept, skipped))
}

/// The X.509 bundles of every trust domain the agent serves this workload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct X509BundleSet {
    bundles: BTreeMap<String, X509Bundle>,
    crls: Vec<Vec<u8>>,
    skipped: Vec<SkippedBundle>,
}

impl X509BundleSet {
    /// A set of the given bundles; a later bundle replaces an earlier one
    /// of the same trust domain.
    pub fn new(bundles: impl IntoIterator<Item = X509Bundle>) -> Self {
        let mut set = Self::default();
        for bundle in bundles {
            set.insert(bundle);
        }
        set
    }

    /// The bundle of `trust_domain`, when the agent serves one.
    pub fn get(&self, trust_domain: &TrustDomain) -> Option<&X509Bundle> {
        self.bundles.get(trust_domain.as_str())
    }

    /// The trust domains in the set, in name order.
    pub fn trust_domains(&self) -> impl Iterator<Item = &TrustDomain> {
        self.bundles.values().map(X509Bundle::trust_domain)
    }

    /// How many trust domains the set holds.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Whether the set holds no trust domain.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// The certificate revocation lists the agent sent with the bundles,
    /// DER. The verifiers of this module do not consult them; they are
    /// here for a TLS stack configured to.
    pub fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }

    /// The entries the agent sent that were left out because they did not
    /// read, each with its reason. Empty when every entry read.
    pub fn skipped(&self) -> &[SkippedBundle] {
        &self.skipped
    }

    pub(crate) fn insert(&mut self, bundle: X509Bundle) {
        self.bundles
            .insert(bundle.trust_domain.as_str().to_owned(), bundle);
    }

    pub(crate) fn set_crls(&mut self, crls: Vec<Vec<u8>>) {
        self.crls = crls;
    }

    pub(crate) fn set_skipped(&mut self, skipped: Vec<SkippedBundle>) {
        self.skipped = skipped;
    }

    /// The set an `X509BundlesResponse` carries, for a workload of `own`,
    /// read at `now`. An entry of another trust domain that does not read is
    /// skipped and recorded. An answer whose entry for `own` does not read,
    /// or that has none, is refused: an agent always serves a workload its
    /// own trust domain's bundle, so an answer without it is not a state to
    /// replace the last good set with.
    pub(crate) fn from_raw(
        raw: RawBundles,
        own: &TrustDomain,
        now: Timestamp,
    ) -> Result<Self, SpireError> {
        let (bundles, skipped) = read_bundle_map(&raw.bundles, Some(own), |trust_domain, der| {
            X509Bundle::from_der(trust_domain, der, now)
        })?;
        let mut set = Self::new(bundles);
        if set.get(own).is_none() {
            return Err(SpireError::Refused(format!(
                "the answer holds no X.509 bundle for {own}"
            )));
        }
        set.set_crls(raw.crls);
        set.set_skipped(skipped);
        Ok(set)
    }
}

/// The JWT signing keys of one trust domain, as a JWKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtBundle {
    trust_domain: TrustDomain,
    jwks: Value,
}

impl JwtBundle {
    /// The trust domain these keys sign for.
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    /// The key set as a JWKS document, `{"keys": [...]}`, with the SPIFFE
    /// `use` values taken out so that a JOSE library reads it: a key marked
    /// `jwt-svid` has no `use` here, and a key marked `x509-svid`, which
    /// signs no token, is not in it.
    pub fn jwks(&self) -> &Value {
        &self.jwks
    }

    /// The `kid` of each key that has one, in the bundle's order.
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys()
            .iter()
            .filter_map(|key| key.get("kid").and_then(Value::as_str))
            .collect()
    }

    fn keys(&self) -> &[Value] {
        self.jwks
            .get("keys")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn from_json(trust_domain: TrustDomain, json: &[u8]) -> Result<Self, SpireError> {
        let refuse =
            |why: &str| SpireError::Refused(format!("the JWT bundle of {trust_domain} {why}"));
        let document: Value = serde_json::from_slice(json).map_err(|error| {
            // serde quotes what it could not read; the head of its message
            // and the position are enough to find the fault.
            SpireError::refused(
                &format!("the JWT bundle of {trust_domain} is not JSON"),
                &error.to_string(),
            )
        })?;
        let Some(keys) = document.get("keys").and_then(Value::as_array) else {
            return Err(refuse("has no `keys` array"));
        };
        if keys.len() > MAX_JWT_KEYS {
            return Err(refuse("holds more keys than this client reads"));
        }
        let mut kept = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(members) = key.as_object() else {
                return Err(refuse("holds a key that is not an object"));
            };
            if !members.get("kty").is_some_and(Value::is_string) {
                return Err(refuse("holds a key with no `kty`"));
            }
            // A JWT bundle holds JWT-SVID signing keys. The agent marks one
            // `jwt-svid`, as the SPIFFE bundle it comes from does, or leaves
            // the JWK Set standard with `sig` or no `use` at all. A key
            // marked for anything else (`x509-svid`, `wit-svid`, `enc`, a
            // use this client does not know) is ignored, as the bundle
            // standard has a client ignore it: it signs no JWT-SVID.
            //
            // A key with no `use` is kept. That every key carries a `use` is
            // a rule of the SPIFFE bundle document (Trust Domain and Bundle
            // standard, section 4.2.2), and this is not that document: the
            // Workload API answers with JWK Sets as RFC 7517 defines them,
            // holding the JWT-SVID signing keys of a trust domain and no
            // key with another use (Workload API standard, section 6.2.2),
            // and in a JWK Set `use` is optional. No code of this crate
            // reads a bundle document; one that did would hold each key to
            // the strict rule.
            let mut members = members.clone();
            match members.get("use").map(Value::as_str) {
                None | Some(Some("sig")) => {}
                Some(Some("jwt-svid")) => {
                    members.remove("use");
                }
                Some(_) => continue,
            }
            kept.push(Value::Object(members));
        }
        Ok(Self {
            trust_domain,
            jwks: serde_json::json!({ "keys": kept }),
        })
    }
}

/// The JWT bundles of every trust domain the agent serves this workload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtBundleSet {
    bundles: BTreeMap<String, JwtBundle>,
    skipped: Vec<SkippedBundle>,
}

impl JwtBundleSet {
    /// The bundle of `trust_domain`, when the agent serves one.
    pub fn get(&self, trust_domain: &TrustDomain) -> Option<&JwtBundle> {
        self.bundles.get(trust_domain.as_str())
    }

    /// The trust domains in the set, in name order.
    pub fn trust_domains(&self) -> impl Iterator<Item = &TrustDomain> {
        self.bundles.values().map(JwtBundle::trust_domain)
    }

    /// How many trust domains the set holds.
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Whether the set holds no trust domain.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// The entries the agent sent that were left out because they did not
    /// read, each with its reason. Empty when every entry read.
    pub fn skipped(&self) -> &[SkippedBundle] {
        &self.skipped
    }

    /// The set a `JWTBundlesResponse` carries, for a workload of `own`. An
    /// entry of another trust domain that does not read is skipped and
    /// recorded. An answer whose entry for `own` does not read, or that has
    /// none, is refused, as for the X.509 bundles.
    pub(crate) fn from_raw(raw: RawBundles, own: &TrustDomain) -> Result<Self, SpireError> {
        let (bundles, skipped) = read_bundle_map(&raw.bundles, Some(own), JwtBundle::from_json)?;
        let mut set = Self {
            bundles: BTreeMap::new(),
            skipped,
        };
        for bundle in bundles {
            set.bundles
                .insert(bundle.trust_domain.as_str().to_owned(), bundle);
        }
        if set.get(own).is_none() {
            return Err(SpireError::Refused(format!(
                "the answer holds no JWT bundle for {own}"
            )));
        }
        Ok(set)
    }
}

/// The trust domain a bundle map's key names. Agents write the key as the
/// trust domain's SPIFFE ID (`spiffe://example.org`) or as its bare name
/// (`example.org`); both are read, and anything with a path is refused.
pub(crate) fn trust_domain_key(key: &str) -> Result<TrustDomain, SpireError> {
    // The scheme of a SPIFFE ID is case-insensitive.
    let name = key
        .get(..9)
        .filter(|scheme| scheme.eq_ignore_ascii_case("spiffe://"))
        .and_then(|_| key.get(9..))
        .unwrap_or(key);
    TrustDomain::new(name).map_err(|_| {
        SpireError::refused(
            "a bundle is keyed by something that is no trust domain",
            key,
        )
    })
}

/// The certificates in `der`, which holds DER certificates end to end.
/// `what` names the field in a refusal.
pub(crate) fn split_certificates(
    der: &[u8],
    what: &str,
) -> Result<Vec<CertificateDer<'static>>, SpireError> {
    let mut certificates = Vec::new();
    let mut rest = der;
    while !rest.is_empty() {
        if certificates.len() == MAX_CERTIFICATES {
            return Err(SpireError::Refused(format!(
                "the {what} holds more than {MAX_CERTIFICATES} certificates"
            )));
        }
        let (tail, _) = X509Certificate::from_der(rest).map_err(|error| {
            SpireError::Refused(format!(
                "certificate {} of the {what} does not parse: {}",
                certificates.len() + 1,
                remote_text(&error.to_string())
            ))
        })?;
        let (certificate, _) = rest.split_at(rest.len() - tail.len());
        certificates.push(CertificateDer::from(certificate.to_vec()));
        rest = tail;
    }
    Ok(certificates)
}

#[cfg(test)]
mod tests;
